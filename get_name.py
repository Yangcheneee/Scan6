import sys
import time
sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import Ether
from scapy.layers.netbios import NBNSQueryRequest, NBNSHeader
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1, srp1, sendp, send, sr
from conf import Conf
from IPy import IP as IPY


def nbns_nbtstat(ip_list):
    host_name_list = []
    for ip in ip_list:
        # Create an IP packet
        ip_layer = IP(dst=ip)

        # Create a UDP packet
        udp_layer = UDP(sport=137, dport=137)  # NetBIOS Name Service runs on UDP port 137

        # Create a NetBIOS Name Query Request packet
        nbns_request = NBNSHeader(
            NAME_TRN_ID=0x0000,  # Arbitrary transaction ID
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
        response = sr1(packet, verbose=1, timeout=3)
        if response:
            response.show()


def mdns_ptr(ip_list):
    conf = Conf()
    src_mac = conf.mac_address
    src_ip = conf.ip_address
    # mdns_multicast
    dst_mac = "01:00:5E:00:00:FB"
    dst_ip = "224.0.0.251"
    # dst_ip = '192.168.3.13'
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
        mdns_layer = DNS(id=0x0000, rd=1, qd=DNSQR(qtype="PTR", unicastresponse=0, qname=ipv4_to_reverse_dns(ip)))
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
    ip_list = ['192.168.3.9',
               '192.168.3.13',
               '192.168.3.22',
               '192.168.3.30',
               '192.168.3.71',
               '192.168.3.72',
               '192.168.3.90',
               '192.168.3.123']
    # nbns_nbtstat(ip_list)
    ip_list = ['192.168.3.59']
    while True:
        mdns_ptr(ip_list)
