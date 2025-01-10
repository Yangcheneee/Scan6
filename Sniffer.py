from scapy.all import *
import re
from scapy.layers.inet import IP
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


sniff(iface="WLAN",
      filter="udp port 137",
      prn=lambda packet: nbns_callback_with_collection(packet),
      count=-1,
      store=0)
