from os import system

from scapy.all import *
from scapy.layers.dhcp6 import DHCP6_Solicit, DHCP6_Request, DHCP6_InfoRequest, DHCP6_Advertise, DHCP6_Reply, DHCP6, DHCP6OptClientFQDN, \
    VENDOR_CLASS_DATA
from scapy.layers.dhcp6 import DHCP6OptClientId, DHCP6OptServerId, DHCP6OptIA_NA
from scapy.layers.dhcp6 import DHCP6OptElapsedTime, DHCP6OptRelayMsg, DHCP6OptOptReq
from scapy.layers.dhcp6 import DHCP6OptVendorClass, DHCP6OptVendorSpecificInfo
from scapy.layers.dhcp6 import DHCP6OptDNSServers, DHCP6OptDNSDomains
import socket
import struct
import time

IANA_ENTERPRISE_NUMBERS = {
    9: "ciscoSystems",
    35: "Nortel Networks",
    43: "3Com",
    311: "Microsoft",
    2636: "Juniper Networks, Inc.",
    4526: "Netgear",
    5771: "Cisco Systems, Inc.",
    5842: "Cisco Systems",
    11129: "Google, Inc",
    16885: "Nortel Networks",
}


# 加入DHCPv6组播组
def join_dhcpv6_multicast():
    # DHCPv6组播地址是ff02::1:2
    mreq = struct.pack("16sI", socket.inet_pton(socket.AF_INET6, "ff02::1:2"), 0)
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)

    return sock


# 处理DHCPv6报文
def handle_dhcpv6_packet(packet):
    if packet.haslayer(DHCP6_Solicit) or packet.haslayer(DHCP6_InfoRequest):
        print("\n[+] Received DHCPv6 Packet")
        print(packet.summary())

        # 提取消息类型
        if DHCP6_Solicit in packet:
            print("  Message Type: Solicit")
        elif DHCP6_InfoRequest in packet:
            print("  Message Type: DHCP6_InfoRequest")

        # # 提取客户端ID
        # if DHCP6OptClientId in packet:
        #     client_id = packet[DHCP6OptClientId].duid
        #     print(f"  Client ID: {client_id.hex()}")

        # 提取域名信息
        if DHCP6OptClientFQDN in packet:
            domain_name = packet[DHCP6OptClientFQDN].fqdn
            print(f"  Domain Name: {domain_name.decode('utf-8', errors='ignore')}")

        # 提取Vendor Class信息
        if DHCP6OptVendorClass in packet:
            vendor_class = packet[DHCP6OptVendorClass]
            print(f"  Enterprise: {IANA_ENTERPRISE_NUMBERS[vendor_class.enterprisenum]}")
            for data in vendor_class.vcdata:
                print(f"  Vendor Class: {data.data.decode('utf-8')}")  # 'MSFT 5.0'


# 主函数
def main():
    print("[*] Starting DHCPv6 listener...")

    # 加入组播组
    sock = join_dhcpv6_multicast()

    # 设置过滤器只捕获DHCPv6流量 (UDP端口546和547)
    filter_str = "udp portrange 546-547"

    try:
        # 开始嗅探
        print("[*] Sniffing DHCPv6 traffic...")
        # sniff(opened_socket=sock, filter=filter_str, prn=handle_dhcpv6_packet, store=0)
        sniff(iface="WLAN", filter=filter_str, prn=handle_dhcpv6_packet, store=0)
    except KeyboardInterrupt:
        print("\n[*] Stopping DHCPv6 listener...")
    finally:
        # sock.close()
        pass


if __name__ == "__main__":
    main()
