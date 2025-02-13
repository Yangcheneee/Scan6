from scapy.all import *
import re

from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.layers.netbios import NBNSQueryResponse, NBNSHeader, NBNSNodeStatusResponse


def nbns_callback_with_collection(packet):
    if packet.haslayer(NBNSHeader) and packet.haslayer(NBNSNodeStatusResponse):
        src_mac = packet[Ether].src
        ip4 = packet[IP].src
        if src_mac not in ip4_data:
            ip4_data[src_mac] = {"hostname": [], "ip4": []}
            ip4_data[src_mac]["ip4"].append(ip4)
            nbns_response = packet.getlayer(NBNSNodeStatusResponse)
            # nbns_response.show()
            name_list = nbns_response.NODE_NAME
            for name in name_list:
                hostname = name.NETBIOS_NAME
                if hostname != b"WORKGROUP      ":
                    ip4_data[src_mac]["hostname"].append(hostname)
                    # print(hostname)
                    print(ip4_data)


def nbns_sniffer():
    print("Starting nbtstat sniffing...")
    sniff(iface="WLAN",
          filter="udp port 137",
          prn=nbns_callback_with_collection,
          count=-1,
          store=0)


hostnames = []
ip4_data = {}
if __name__ == "__main__":
    nbns_sniffer()
