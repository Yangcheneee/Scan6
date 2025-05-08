import random
import socket
from datetime import datetime
import netifaces
import pandas as pd
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1, send, srp1, srp
from IPy import IP as IPY
from scapy.layers.l2 import ARP, Ether
import conf
# mDNS多播地址配置
MDNS_MAC = "01:00:5e:00:00:fb"  # IPv4 mDNS多播MAC
MDNS_IP = "224.0.0.251"  # IPv4 mDNS地址
LLA_PREFIX = ["fe80:"]
GUA_PREFIX = ["2", "3"]
INTERFACE_ID = {
    "ETH": "{E9812809-EC44-4F9B-AA3F-A4EDF0835213}",
    "WLAN": "{F52FC252-BAEC-4BA6-A8CA-8706641245A6}"
}
SERVICE_TYPE_ENUMERATION = "_service._dns-sd._udp.local."


# local link address
def is_lla(ip):
    return ip.startswith(("fe8", "fe9", "fea", "feb"))


# global unicast address
def is_gua(ip):
    return ip.startswith(("2", "3"))


def async_arp_scan(interface, ip_list):
    # 创建ARP请求包列表
    arp_packets = [Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip) for ip in ip_list]
    # 发送并接收响应，超时设为2秒
    ans, unans = srp(arp_packets, timeout=2, verbose=False, iface=interface)
    # 处理响应
    results = []
    for sent_packet, received_packet in ans:
        if received_packet.haslayer(ARP) and received_packet[ARP].op == 2:
            src_mac = received_packet[ARP].hwsrc
            src_ip = received_packet[ARP].psrc
            results.append((src_mac, src_ip))

    return results


def batch_service_discovery(interface, src_mac, src_ip, dst):
    packets = []
    for dst_mac, dst_ip in dst:
        packet = (
                Ether(src=src_mac, dst=dst_mac) /
                IP(src=src_ip, dst=dst_ip, ttl=255) /
                UDP(sport=5353, dport=5353) /
                DNS(
                    id=0x0000,
                    rd=0,
                    qd=DNSQR(
                        qtype="PTR",
                        qname=SERVICE_TYPE_ENUMERATION,
                        unicastresponse=1
                    )
                )
        )
        packets.append(packet)

    # 批量发送并接收响应
    ans, unans = srp(packets, timeout=2, iface=interface, verbose=0)

    # 解析结果
    results = {}
    for sent_pkt, recv_pkt in ans:
        if recv_pkt.haslayer(DNS):
            mac = recv_pkt[Ether].src
            ipv4 = recv_pkt[IP].src
            dns = recv_pkt[DNS]
            for answer in dns.an:
                if answer.type == 12:
                    service_name = answer.rdata.decode('utf-8').rstrip('.')
                    results[mac]["service"].append(service_name)
                    results[mac]["ipv4"] = ipv4
                    results[mac]["mac"] =mac

    return results


def batch_get_service_info(interface, src_mac, src_ip, dst):
    packets = []
    for dst_mac, dst_ip, services in dst:
        pkt = (
                Ether(src=src_mac, dst=dst_mac) /
                IP(src=src_ip, dst=dst_ip, ttl=255) /
                UDP(sport=5353, dport=5353) /
                DNS(
                    rd=0,
                    qd=[DNSQR(qtype="PTR", unicastresponse=1, qname=service) for service in services]
                )
        )
        packets.append(pkt)

    # 批量发送
    ans, unans = srp(packets, timeout=2, iface=interface, verbose=0)

    # 解析结果
    results = {}
    for sent, recv in ans:
        if recv.haslayer(DNS):
            dns = recv[DNS]
            # 解析附加记录 (Additional Records)
            mac = recv[Ether].src
            result = {}
            for rr in dns.ar:
                if rr.type == 33:  # SRV
                    instance = rr.rrname.decode().rstrip('.')
                    result[mac]["service_instance"].append(instance)
                    hostname = rr.target.decode().rstrip('.')
                    port = rr.port
                    result[mac]["target"].append(f"{hostname}:{port}")
                if rr.type == 1:  # A
                    result[mac] = rr.rrname.decode('utf-8').rstrip('.')
                # AAAA记录处理
                elif rr.type == 28:  # AAAA
                    ip6 = rr.rdata
                    if is_lla(ip6):
                        result[mac]["ipv6_lla"] = ip6
                    elif is_gua(ip6):
                        result[mac]["ipv6_gua"].append(ip6)
                    # 关联主机名
                    hostname = rr.rrname.decode().rstrip('.')
                    result[mac]["hostname"] = hostname

    return results


def batch_extract_info(packet):
    dns = packet[DNS]
    # 解析附加记录 (Additional Records)
    mac = packet[Ether].src
    result = {}
    for rr in dns.ar:
        if rr.type == 33:  # SRV
            instance = rr.rrname.decode().rstrip('.')
            result[mac].append(instance)

            hostname = rr.target.decode().rstrip('.')
            port = rr.port
            result[mac].append(f"{hostname}:{port}")
        if rr.type == 1:  # A
            result[mac] = rr.rrname.decode('utf-8').rstrip('.')
        # AAAA记录处理
        elif rr.type == 28:  # AAAA
            ip6 = rr.rdata
            if is_lla(ip6):
                result[mac] = ip6
            elif is_gua(ip6):
                result[mac].append(ip6)
            # 关联主机名
            hostname = rr.rrname.decode().rstrip('.')
            if not result["hostname"]:
                result["hostname"] = hostname

    # 处理回答记录 (Answer Section)
    for rr in dns.an:
        if rr.type == 12:  # PTR
            instance = rr.rdata.decode().rstrip('.')
            result[mac].append(instance)

    return result


def run(interface="WLAN", target="172.31.99.0/24", save_path="D:/Project/Scan6/result/hscan6/"):
    print("[*] (HScan6)DNS-SD协议扫描中...")
    conf_info = conf.Conf(INTERFACE_ID[interface])
    ip_list = [str(ip) for ip in IPY(target)]
    mac_ipv4_list = async_arp_scan("WLAN", ip_list)
    service_dict = batch_service_discovery(interface, conf_info.mac, conf_info.ipv4, mac_ipv4_list)
    dst = list(service_dict.values())
    service_info_dict = batch_get_service_info(interface, conf_info.mac, conf_info.ipv4, dst)
    info_list = []
    for mac, ipv4 in mac_ipv4_list:
        info = {
            "mac": mac,
            "ipv4": ipv4,
            "hostname": service_info_dict.get(mac, {}).get("hostname"),
            "service": service_dict.get(mac, {}).get("service"),
            "service_instance": service_info_dict.get(mac, {}).get("service_instance"),
            "target": service_info_dict.get(mac, {}).get("target")
        }
        print(info)
    if info_list:
        df = pd.DataFrame(info_list)
        save_file = save_path + datetime.now().strftime("%Y-%m-%d %H-%M-%S")
        df.to_csv(save_file, index=False)
        print(f"数据已保存到 {save_file}")


if __name__ == "__main__":
    run(target="10.132.169.0/24", save_path="D:/Project/Scan6/result/hscan6/")
