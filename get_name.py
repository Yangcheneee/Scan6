import sys
import time
import socket
import struct
sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')
from conf import  Conf
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import Ether
from scapy.layers.netbios import NBNSQueryRequest, NBNSHeader
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1, srp1, sendp, send
from IPy import IP as IPY


def nbns_nbtstat(ip_list):
    host_name_list = []
    for ip in ip_list:
        # Create an IP packet
        ip_layer = IP(dst=str(ip))

        # Create a UDP packet
        udp_layer = UDP(dport=137)  # NetBIOS Name Service runs on UDP port 137

        # Create a NetBIOS Name Query Request packet
        nbns_request = NBNSHeader(
            NAME_TRN_ID=0x1234,  # Arbitrary transaction ID
            NM_FLAGS=0
        )
        # nbns_request.show()
        # Create the question part of the request
        question = NBNSQueryRequest(
            # QUESTION_NAME="*",  # Name to query (empty name means all names)
            QUESTION_NAME=b'*\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            QUESTION_TYPE=33,  # NBSTAT (Name Service) query type
            QUESTION_CLASS=1  # Internet class
        )

        # Combine all layers into one packet
        packet = ip_layer / udp_layer / nbns_request / question
        # packet.show()
        # Send the packet and receive the response (timeout in 1 second)
        send(packet, verbose=0,)


def mdns_ptr(ip_list):
    src_mac = "48:a4:72:e6:72:bf"
    src_ip = "192.168.3.132"
    # mdns_multicast
    dst_mac = "01:00:5E:00:00:FB"
    dst_ip = "224.0.0.251"
    # xiaomi
    # dst_mac = "4c:f2:02:e4:b7:cc"
    # dst_ip = "192.168.31.21"
    # router
    # dst_mac = "d4:da:21:6e:44:04"
    # dst_ip = "192.168.31.1"
    # query all service name
    ether_layer = Ether(src=src_mac, dst=dst_mac)
    ip_layer = IP(dst=dst_ip, src=src_ip)
    trans_layer = UDP(sport=5353, dport=5353)
    def ipv4_to_reverse_dns(ipv4):
        # 将IPv4地址分割为四个部分
        parts = str(ipv4).split('.')
        # 反转顺序
        reversed_parts = parts[::-1]
        # 将反转后的部分拼接为反向DNS格式
        reversed_dns = '.'.join(reversed_parts) + '.in-addr.arpa'
        return reversed_dns
    for ip in ip_list:
        mdns_layer = DNS(id=1234, rd=1, qd=DNSQR(qtype="PTR", unicastresponse=1, qname=ipv4_to_reverse_dns(ip)))
        packet = ether_layer/ip_layer/trans_layer/mdns_layer
        # packet.show()
        response = srp1(packet, verbose=0, timeout=2, iface="WLAN")
        if response is not None:
            # response.show()
            print("response!")
        else:
            print("no response!")


if __name__ == "__main__":
    # ipy = "192.168.1.0/24"
    # ip_list = IPY(ipy)
    # ip_list = ['192.168.3.1', '192.168.3.9', '192.168.3.11', '192.168.3.19', '192.168.3.42', '192.168.3.101', '192.168.3.107', '192.168.3.123', '192.168.3.125', '192.168.3.131']
    ip_list = ['192.168.3.13', '192.168.3.3']