from scapy.all import *
import re

from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.netbios import NBNSQueryResponse, NBNSHeader, NBNSNodeStatusResponse

hostnames = []


def nbns_callback_with_collection(packet):
    if packet.haslayer(NBNSHeader) and packet.getlayer(IP).src != "192.168.1.12":
        nbns_response = packet.getlayer(NBNSNodeStatusResponse)
        nbns_response.show()
        name_list = nbns_response.NODE_NAME
        for name in name_list:
            hostname = name.NETBIOS_NAME
            print(hostname)


def nbns_sniffer():
    sniff(iface="WLAN",
          filter="udp port 137",
          prn=lambda packet: nbns_callback_with_collection(packet),
          count=-1,
          store=0)


# 处理 mDNS 响应报文
def process_mdns_response(packet):
    if IPv6 in packet and UDP in packet and packet[UDP].dport == 5353:
        if DNS in packet and packet[DNS].qr == 1:  # 检查是否为响应报文
            print(f"mDNS response from {packet[IPv6].src}")

            # 遍历 DNS 资源记录
            for i in range(packet[DNS].ancount):
                rr = packet[DNS].an[i]
                if rr.type == 28:  # AAAA 记录（IPv6 地址）
                    ipv6_addr = rr.rdata
                    print(f"Found IPv6 address: {ipv6_addr}")
# 主程序


def sniff_mdns():
    print("Starting mDNS sniffing...")
    # 过滤 mDNS 报文（IPv6，UDP 端口 5353）
    sniff(filter="ip6 and udp port 5353", prn=process_mdns_response, store=0, iface="WLAN")


if __name__ == "__main__":
    sniff_mdns()
