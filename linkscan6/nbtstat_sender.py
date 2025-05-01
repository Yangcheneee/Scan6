import ipaddress
import sys
sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import Ether, ARP
from scapy.layers.netbios import NBNSQueryRequest, NBNSHeader, NBNSNodeStatusResponse
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1, srp1, sendp, send, sr
from IPy import IP as IPY


info_list = []


def is_alive(dst_ip):
    pkt = ARP(pdst=dst_ip)
    ans = sr1(pkt, timeout=1, verbose=False)
    if ans is not None:
        if ans.haslayer(ARP) and ans[ARP].op == 2:
            src_mac = ans[ARP].hwsrc
            src_ip = ans[ARP].psrc
            return src_mac, src_ip
        else:
            return None
    else:
        return None


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
        # if response:
        #     response.show()
    return host_name_list


def nbns_get_name(packet):
    if packet == None:
        print("None")
        return
    if packet.haslayer(NBNSHeader) and packet.haslayer(NBNSNodeStatusResponse):
        nbns_response = packet.getlayer(NBNSNodeStatusResponse)
        # nbns_response.show()
        name_list = nbns_response.NODE_NAME.decode('utf-8')
        for name in name_list:
            hostname = name.NETBIOS_NAME
            print(hostname)


if __name__ == "__main__":
    hostname = []
    # info_list = []
    dst_ip_list = IPY("172.31.99.0/24")
    # dst_ip_list = ["172.31.99.180"]
    # ip_list = []
    # for ip in dst_ip_list:
    #     # print(f"{ip} scaning...")
    #     arp_result = is_alive(str(ip))
    #     if arp_result is not None:
    #         ip_list.append(ip)
    ip_list = ["172.31.99.112", "172.31.99.198"]
    hostname_list = nbns_nbtstat(ip_list)
    print(hostname_list)
