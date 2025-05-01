import random
import socket
from datetime import datetime
import netifaces
import pandas as pd
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.l2 import ARP
from scapy.layers.netbios import NBNSQueryRequest, NBNSHeader, NBNSNodeStatusResponse
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1, send, srp1, srp
from IPy import IP as IPY
from scapy.layers.l2 import ARP, Ether

# LLMNR多播地址配置
LLMNR_MAC = "01:00:5e:00:00:fc"  # IPv4 LLMNR多播MAC
LLMNR_IP = "224.0.0.252"  # IPv4 LLMNR地址
LLMNR_PORT = "5355"
LLA_PREFIX = ["fe80:"]
GUA_PREFIX = ["2", "3"]
INTERFACE_ID = {
    "ETH": "{E9812809-EC44-4F9B-AA3F-A4EDF0835213}",
    "WLAN": "{F52FC252-BAEC-4BA6-A8CA-8706641245A6}"
}


def is_lla(ip):
    if ip.startswith("fe80:"):
        return True


# unicast address
def is_gua(ip):
    if ip.startswith("2"):
        return True


class Conf:
    hostname = "DESKTOP-8DUN5OR"
    interface = "WLAN"
    mac = "48:a4:72:e6:72:bf"
    ipv4 = "172.31.99.79"
    ipv6_lla = "fe80::910c:e419:64df:f2f1"
    ipv6_gua = ["2001:250:2003:8890:e4ba:2bc9:db45:472e"]

    def __init__(self, interface):
        """
        获取指定网卡的网络配置信息
        :param interface: 网卡名称，如'eth0'、'ens33'、'wlan0'等
        :return: 包含网络配置的字典
        """

        if interface not in netifaces.interfaces():
            raise ValueError(f"Interface {interface} not found")

        info = {}

        hostname = socket.gethostname()
        self.hostname = hostname
        info.update({
            "hostname": hostname
        })

        addrs = netifaces.ifaddresses(interface)

        # MAC地址 (AF_LINK)
        if netifaces.AF_LINK in addrs:
            info['mac'] = addrs[netifaces.AF_LINK][0]['addr']
            self.mac = info['mac']

        # IPv4信息 (AF_INET)
        if netifaces.AF_INET in addrs:
            ipv4 = addrs[netifaces.AF_INET][0]
            info.update({
                'ipv4': ipv4.get('addr'),
                'netmask': ipv4.get('netmask'),
                'broadcast': ipv4.get('broadcast')
            })
            self.ipv4 = info['ipv4']

        # IPv6信息 (AF_INET6)
        if netifaces.AF_INET6 in addrs:
            ipv6_list = addrs[netifaces.AF_INET6]
            for ipv6 in ipv6_list:
                ipv6_addr = ipv6.get('addr')
                if is_lla(ipv6_addr):
                    info.update({
                        "ipv6_lla":  ipv6_addr,
                    })
                elif is_gua(ipv6_addr):
                    if "ipv6_gua" not in info:
                        info.update({
                            "ipv6_gua": []
                        })
                    info["ipv6_gua"].append(ipv6_addr)
            self.ipv6_lla = info['ipv6_lla']
            self.ipv6_gua = info['ipv6_gua']

        # 网关信息
        gateways = netifaces.gateways()
        info['default_gateway'] = gateways.get('default', {}).get(netifaces.AF_INET, (None, None))[0]


def async_arp_scan(ip_list):
    # 创建ARP请求包列表
    arp_packets = [Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip) for ip in ip_list]
    # 发送并接收响应，超时设为2秒
    ans, unans = srp(arp_packets, timeout=2, verbose=False)
    # 处理响应
    results = []
    for sent_packet, received_packet in ans:
        if received_packet.haslayer(ARP) and received_packet[ARP].op == 2:
            src_mac = received_packet[ARP].hwsrc
            src_ip = received_packet[ARP].psrc
            results.append((src_mac, src_ip))

    return results


def nbtstat_scan(targets):
    def create_packets(targets):
        """创建带随机事务ID的NBT-STAT查询包列表"""
        packets = []
        for dst_mac, dst_ip in targets:
            transaction_id = random.randint(0, 0xFFFF)  # 随机事务ID
            eth = Ether(dst=dst_mac)
            ip = IP(dst=dst_ip)
            udp = UDP(sport=137, dport=137)
            nbns = NBNSHeader(NAME_TRN_ID=transaction_id, NM_FLAGS=0x0000)
            query = NBNSQueryRequest(
                QUESTION_NAME=b'*\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                QUESTION_TYPE=33,
                QUESTION_CLASS=1
            )
            packets.append(eth / ip / udp / nbns / query)
        return packets
    # 创建并发送所有数据包
    packets = create_packets(targets)
    ans, _ = srp(packets, timeout=2, verbose=0, multi=True)
    results = {}
    for sent_pkt, recv_pkt in ans:
        if recv_pkt.haslayer(NBNSNodeStatusResponse):
            mac = recv_pkt[Ether].src
            response = recv_pkt[NBNSNodeStatusResponse]

            # 提取所有有效主机名
            hostnames = [
                node.NBName.decode('utf-8').split('\x00')[0].strip()
                for node in response.NodeName
                if node.NBName.decode('utf-8').strip() not in ("", "WORKGROUP")
            ]

            if hostnames:
                results[mac] = hostnames[0]  # 取第一个有效主机名

    return results


def llmnr_batch_query(interface, src_mac, src_ip, hostnames):
    def create_queries(hostnames):
        packets = []
        for host in hostnames:
            ether = Ether(src_mac, dst=LLMNR_MAC)
            ip = IP(src=src_ip, dst=LLMNR_IP)
            udp = UDP(sport=53555, dport=LLMNR_PORT)
            dns = DNS(
                id=random.randint(0, 0xFFFF),
                rd=0,
                qd=DNSQR(
                    qtype="AAAA",
                    qname=host,
                    unicastresponse=0
                )
            )
            packets.append(ether / ip / udp / dns)
        return packets

    # 发送所有查询
    packets = create_queries(hostnames)
    ans, unans = srp(packets, timeout=3, iface=interface, verbose=0, multi=True)

    results = {}
    for sent_pkt, recv_pkt in ans:
        if recv_pkt.haslayer(DNS):
            mac = recv_pkt[Ether].src
            dns = recv_pkt[DNS]
            if dns.qr == 1:
                for answer in dns.an:
                    if answer.type == 28:  # AAAA记录
                        ipv6 = answer.rdata
                        if is_lla(ipv6):
                            results[mac]["lla"] = ipv6
                        elif is_gua(ipv6):
                            results[mac]["gua"].append(ipv6)

    return results


def save_result(save_path, data):
    df = pd.DataFrame(data)
    save_file = save_path + datetime.now().strftime("%Y-%m-%d %H-%M-%S")
    df.to_csv(save_file, index=False)
    print(f"数据已保存到 {save_file}")


def run(interface="WLAN", target="172.31.99.0/24", save_path="D:/Project/Scan6/result/linkscan6/"):
    conf = Conf(INTERFACE_ID[interface])
    ip_list = [str(ip) for ip in IPY(target)]
    mac_ipv4_list = async_arp_scan(ip_list)
    hostname_dict = nbtstat_scan(mac_ipv4_list)
    hostnames = list(hostname_dict.values())
    ipv6_dict = llmnr_batch_query(interface, conf.mac, conf.ipv4, hostnames)
    info_list = []
    for mac, ipv4 in mac_ipv4_list:
        info = {
            "mac": mac,
            "ipv4": ipv4,
            "hostname": hostname_dict.get(mac),
            "ipv6_lla": ipv6_dict.get(mac, {}).get("ipv6_lla"),
            "ipv6_gua": ipv6_dict.get(mac, {}).get("ipv6_gua")
        }
        print(info)
        info_list.append(info)
    if info_list:
        save_result(save_path, info_list)


if __name__ == "__main__":
    run(target="192.168.182.0/24", save_path="D:/Project/Scan6/result/llmnr6/")
