import sys
sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import Ether
from scapy.layers.netbios import NBNSQueryRequest, NBNSHeader, NBNSNodeStatusResponse
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1, srp1, sendp, send, sr


def nbns_nbtstat(ip_list):
    host_name_list = []
    for ip in ip_list:
        # Create an IP packet
        ip_layer = IP(dst=str(ip))

        # Create a UDP packet
        udp_layer = UDP(sport=137, dport=137)  # NetBIOS Name Service runs on UDP port 137

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
        send(packet, verbose=0)
        # response = sr1(packet, verbose=1, timeout=1)
        # # response.show()
        # for re in response:
        #     nbns_get_name(response)
    return host_name_list


def nbns_get_name(packet):
    if packet == None:
        print("None")
        return
    if packet.haslayer(NBNSHeader) and packet.haslayer(NBNSNodeStatusResponse):
        nbns_response = packet.getlayer(NBNSNodeStatusResponse)
        # nbns_response.show()
        name_list = nbns_response.NODE_NAME
        for name in name_list:
            hostname = name.NETBIOS_NAME
            print(hostname)


if __name__ == "__main__":
    hostname = []
    ip_list = ["192.168.233.40"]
    hostname_list = nbns_nbtstat(ip_list)
    print(hostname_list)
