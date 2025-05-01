import socket
from datetime import datetime

import netifaces
import pandas as pd
from scapy.layers.l2 import Ether
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.sendrecv import sendp, sniff, sr1, srp1

INTERFACE_ID = {
    "ETH": "{E9812809-EC44-4F9B-AA3F-A4EDF0835213}",
    "WLAN": "{F52FC252-BAEC-4BA6-A8CA-8706641245A6}"
}
LLA_PREFIX = ["fe80:"]
GUA_PREFIX = ["2", "3"]
LINK_LOCAL_ALL_NODES_ADDR = "ff02::1"
LINK_LOCAL_ALL_NODES_MAC = "33:33:00:00:00:01"
MDNS6_ADDR = "ff02::fb"
MDNS6_MAC = "33:33:00:00:00:fb"
SERVICE_TYPE_ENUMERATION = "_service._dns-sd._udp.local."


def is_lla(ip: str) -> bool:
    """判断是否为链路本地地址"""
    return any(ip.startswith(prefix) for prefix in LLA_PREFIX)


def is_gua(ip: str) -> bool:
    """判断是否为链路本地地址"""
    return any(ip.startswith(prefix) for prefix in GUA_PREFIX)


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


def send_icmpv6_ping(interface, mac, ipv6_lla):
    def _create_icmpv6_ping(src_mac, src_ip):
        dst_mac = LINK_LOCAL_ALL_NODES_MAC
        dst_ip = LINK_LOCAL_ALL_NODES_ADDR

        ether_layer = Ether(src=src_mac, dst=dst_mac)
        ip_layer = IPv6(src=src_ip, dst=dst_ip)
        icmpv6_ping = ICMPv6EchoRequest(id=1, seq=50, data="abcdefghijklmnopqrstuvwabcdefghi")
        packet = ether_layer/ip_layer/icmpv6_ping

        return packet

    packet = _create_icmpv6_ping(mac, ipv6_lla)
    sendp(packet, verbose=0, iface=interface)


def sniff_icmpv6_replies(interface, timeout=3):
    """通过闭包捕获结果，避免全局变量"""
    info_list = []

    def _process_packet(packet):
        """内部回调函数"""
        if packet.haslayer(ICMPv6EchoReply):
            info = {
                "mac": packet[Ether].src,
                "hostname": None,
                "ipv6_lla": packet[IPv6].src,
                "ipv6_gua": [],
                "service": [],
                "service_instance": [],
                "target": []
            }
            info_list.append(info)

    filter_str = "icmp6 and ip6[40] == 129"
    # 执行嗅探
    sniff(
        iface=interface,
        prn=_process_packet,
        filter=filter_str,
        timeout=timeout,
        store=0
    )

    return info_list  # 返回填充后的列表


def get_service(interface, dst_mac, dst_ipv6):
    eth_layer = Ether(dst=dst_mac)
    ip_layer = IPv6(dst=dst_ipv6, hlim=255)
    mdns_layer = DNS(id=0x0000, rd=0, qd=DNSQR(qtype="PTR", unicastresponse=0, qname=SERVICE_TYPE_ENUMERATION))
    trans_layer = UDP(sport=5353, dport=5353)
    packet = eth_layer/ip_layer/trans_layer/mdns_layer
    response = srp1(packet, verbose=0, timeout=1, iface=interface)
    if response:
        print(response.summary())
        if packet.haslayer(DNSRR):
            dns = packet.getlayer(DNS)
            service_list = []
            for answer in dns.an:
                if answer.type == 12:
                    if answer.rdata.decode('utf-8') not in service_list and answer.rrname.decode(
                            'utf-8') == "_services._dns-sd._udp.local.":
                        service_list.append(answer.rdata.decode('utf-8'))
            return service_list


def get_service_info(interface, dst_mac, dst_ipv6, service_list):
    eth_layer = Ether(dst=dst_mac)
    ip_layer = IPv6(dst=dst_ipv6, hlim=255)
    dns_qr_list = [DNSQR(qtype="PTR", unicastresponse=1, qname=service) for service in service_list]
    mdns_layer = DNS(id=0x0000, rd=0, qd=dns_qr_list)
    trans_layer = UDP(sport=5353, dport=5353)
    packet = eth_layer/ip_layer/trans_layer/mdns_layer
    response = srp1(packet, verbose=0, timeout=1, iface=interface)
    if response is not None:
        print(response.summary())
        if packet.haslayer(DNSRR):
            dns = packet.getlayer(DNS)
            if hasattr(dns, 'ar') and dns.ar:
                info = {
                    "hostname": None,
                    "ipv6_gua": [],
                    "service_instance": [],
                    "target": [],
                }
                for answer in dns.ar:
                    if answer.type == 33:  # SRV
                        service_instance = answer.rrname.decode('utf-8')
                        info["service_instance"].append(service_instance)
                        hostname = answer.target.decode('utf-8')
                        port = answer.port
                        target = hostname + str(port)
                        info["target"].append(target)
                    if answer.type == 28:  # AAAA
                        hostname = answer.rrname.decode('utf-8')
                        info["hostname"] = hostname
                        ip6 = answer.rdata
                        if is_gua(ip6):
                            info["ipv6_gua"].append(ip6)
                return info


def save_result(save_path, data):
    df = pd.DataFrame(data)
    save_file = save_path + datetime.now().strftime("%Y-%m-%d %H-%M-%S")
    df.to_csv(save_file, index=False)
    print(f"数据已保存到 {save_file}")


def run(interface="WLAN", save_path="D:/Project/Scan6/result/ascan6/"):
    conf = Conf(interface=INTERFACE_ID[interface])

    # 使用组播Ping获取本地链路IPv6地址
    send_icmpv6_ping(conf.interface, conf.mac, conf.ipv6_lla)
    info_list = sniff_icmpv6_replies(interface, timeout=1)

    # 使用DNS-SD协议进一步获取设备服务信息（包括IPv6地址）
    for info in info_list:
        service_list = get_service(interface, info["mac"], info["ipv6_lla"])
        if service_list:
            info.update({
                "service": service_list,
            })
            service_info = get_service_info(interface, info["mac"], info["ipv6_lla"], info["service"])
            if service_info:
                info.update({
                    "hostname": service_info["hostname"],
                    "ipv6_gua": service_info["ipv6_gua"],
                    "service_instance": service_info["service_instance"],
                    "target": service_info["target"]
                })

    print(info_list)
    if info_list:
        save_result(save_path, info_list)


if __name__ == "__main__":
    run()


