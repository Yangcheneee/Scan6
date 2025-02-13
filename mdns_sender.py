import sys
sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')
from scapy.layers.dns import DNS, DNSQR
import time
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.layers.l2 import Ether
from scapy.sendrecv import sr1, srp1, sendp
from scapy.layers.inet import IP, UDP


def mdns_sender(name_list):
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
    for name in name_list:
        # query all service name
        ether_layer = Ether(src=src_mac, dst=dst_mac)
        ip_layer = IP(dst=dst_ip, src=src_ip)
        trans_layer = UDP(sport=5353, dport=5353)
        mdns_layer = DNS(rd=0, qd=DNSQR(qtype="ALL", qname=name + ".local"))
        packet = ether_layer/ip_layer/trans_layer/mdns_layer
        # packet.show()
        response = srp1(packet, verbose=0, timeout=5, iface="WLAN")
        if response:
            response.show()
            print("response!")
        else:
            print("no response!")


# m_ping()
if __name__ == "__main__":
    name_list = ["Android", "CHINAMI-0BD1HT7", "PC-20201106JZIG", "LAPTOP-74UIJ3MD", "HPAEBD13", "LAPTOP-MHFMAPKM"]
    for i in range(100):
        # name_list = ["DESKTOP-8DUN5OR"]
        mdns_sender(name_list)
        time.sleep(3)


