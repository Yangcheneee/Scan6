import sys

sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import Ether
from scapy.layers.netbios import NBNSQueryRequest, NBNSHeader
from scapy.sendrecv import srp1
from Conf.conf import Conf


def test():
    conf = Conf
    src_mac = conf.mac
    src_ip = conf.ip
    # mdns_multicast
    dst_mac = "01:00:5E:00:00:FB"
    dst_ip = "224.0.0.251"
    # 查询 _services._dns-sd._udp.local 的 PTR 记录
    packet = Ether(src=src_mac)/IP(src=src_ip, dst="224.0.0.251") / UDP(sport=5353, dport=5353) / DNS(
        rd=1,  # 递归查询
        qd=DNSQR(unicastresponse=0, qname="CHINAMI-0BD1HT7.local", qtype="AAAA")
    )
    response = srp1(packet, timeout=5, iface="WLAN")
    if response:
        response.show()


def nbns_nbtstat(ip_list):
    conf = Conf()
    src_mac = conf.mac
    src_ip = conf.ip
    host_name_list = []
    for ip in ip_list:
        ether_layer = Ether(src=src_mac)

        # Create an IP packet
        ip_layer = IP(src=src_ip, dst=ip)

        # Create a UDP packet
        udp_layer = TCP(sport=13777, dport=137)  # NetBIOS Name Service runs on UDP port 137

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
        packet = ether_layer / ip_layer / udp_layer / nbns_request / question
        # packet.show()
        # Send the packet and receive the response (timeout in 1 second)
        response = srp1(packet, verbose=1, timeout=5, iface="WLAN")
        if response:
            response.show()


if __name__ == "__main__":
    while True:
        ip_list = ['192.168.3.9', '192.168.3.13', '192.168.3.22', '192.168.3.30', '192.168.3.123']
        nbns_nbtstat(ip_list)
