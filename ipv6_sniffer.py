from scapy.all import *
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether


own_mac = "48:a4:72:e6:72:bf"


# multicast mac
def is_valid_mac(mac, own_mac):
    if (not mac.startswith("33:33")) and mac != own_mac:
        return True


# link local address
def is_lla_ipv6(ip):
    if ip.startswith("fe80:"):
        return True


# unicast address
def is_gua_ipv6(ip):
    if ip.startswith("2"):
        return True


# 处理捕获的 IPv6 报文
def process_ipv6_packet(packet):
    if Ether in packet and IPv6 in packet:
        src_mac = packet[Ether].src  # 源 MAC 地址
        dst_mac = packet[Ether].dst  # 目的 MAC 地址
        src_ip = packet[IPv6].src    # 源 IPv6 地址
        dst_ip = packet[IPv6].dst    # 目的 IPv6 地址

        # 显示捕获
        # print(f"Captured IPv6 packet from {src_mac} to {dst_mac}:")
        # print(f"  Source IP: {src_ip}")
        # print(f"  Destination IP: {dst_ip}")
        # print("-" * 40)
        # 保存链路本地地址和全球单播地址
        if is_valid_mac(src_mac, own_mac):
            if src_mac not in ipv6_data:
                ipv6_data[src_mac] = {"link_local": [], "global_unicast": []}
            if is_lla_ipv6(src_ip) and src_ip not in ipv6_data[src_mac]["link_local"]:
                ipv6_data[src_mac]["link_local"].append(src_ip)
                print(ipv6_data)
            if is_gua_ipv6(src_ip) and src_ip not in ipv6_data[src_mac]["global_unicast"]:
                ipv6_data[src_mac]["global_unicast"].append(src_ip)
                print(ipv6_data)
        if is_valid_mac(dst_mac, own_mac):
            if dst_mac not in ipv6_data:
                ipv6_data[dst_mac] = {"link_local": [], "global_unicast": []}
            if is_lla_ipv6(dst_ip) and dst_ip not in ipv6_data[dst_mac]["link_local"]:
                ipv6_data[dst_mac]["link_local"].append(dst_ip)
                print(ipv6_data)
            if is_gua_ipv6(dst_ip) and dst_ip not in ipv6_data[dst_mac]["global_unicast"]:
                ipv6_data[dst_mac]["global_unicast"].append(dst_ip)
                print(ipv6_data)


# 主程序
def sniff_ipv6():
    print("Starting IPv6 sniffer...")
    # 捕获所有 IPv6 报文
    sniff(filter="ip6", prn=process_ipv6_packet, store=0, iface="WLAN")


if __name__ == "__main__":
    # 存储提取的 IPv6 地址信息
    ipv6_data = {}
    # 嗅探程序
    sniff_ipv6()
