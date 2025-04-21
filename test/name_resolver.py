import sys
import time

sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.llmnr import LLMNRQuery
from scapy.layers.inet import UDP, IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.sendrecv import srp1, sendp
from conf import Conf


def mdns(name_list):
    conf = Conf()
    src_mac = conf.mac
    src_ip = conf.ip4
    # mdns_multicast
    dst_mac = "01:00:5E:00:00:FB"
    dst_ip = "224.0.0.251"
    for name in name_list:
        # query all service name
        ether_layer = Ether(src=src_mac, dst=dst_mac)
        ip_layer = IP(dst=dst_ip, src=src_ip)
        trans_layer = UDP(sport=5353, dport=5353)
        mdns_layer = DNS(rd=1, qd=DNSQR(qtype="AAAA", unicastresponse=0, qname=name + ".local"))
        packet = ether_layer/ip_layer/trans_layer/mdns_layer
        # packet.show()
        sendp(packet, verbose=0,  iface="WLAN")
        # response = srp1(packet, verbose=0, timeout=5, iface="WLAN")
        # if response:
        #     response.show()
        #     print("response!")
        # else:
        #     print("no response!")


def mdns6(name_list):
    conf = Conf()
    src_mac = conf.mac
    src_ip = conf.lla
    # mdns_multicast
    dst_mac = "33:33:00:00:00:fb"
    dst_ip = "ff02::fb"
    for name in name_list:
        # query all service name
        ether_layer = Ether(src=src_mac, dst=dst_mac)
        ip_layer = IPv6(dst=dst_ip, src=src_ip)
        trans_layer = UDP(sport=5353, dport=5353)
        mdns_layer = DNS(rd=1, qd=DNSQR(qtype="AAAA", unicastresponse=0, qname=name + ".local"))
        packet = ether_layer/ip_layer/trans_layer/mdns_layer
        # packet.show()
        sendp(packet, verbose=0,  iface="WLAN")
        # response = srp1(packet, verbose=0, timeout=5, iface="WLAN")
        # if response:
        #     response.show()
        #     print("response!")
        # else:
        #     print("no response!")


def llmnr(name_list):
    conf = Conf()
    src_mac = conf.mac
    src_ip = conf.ip4
    dst_mac = "01:00:5e:00:00:fc"
    dst_ip = "224.0.0.252"
    for name in name_list:
        # query all service name
        ether_layer = Ether(src=src_mac, dst=dst_mac)
        ip_layer = IP(dst=dst_ip, src=src_ip)
        trans_layer = UDP(sport=53555, dport=5355)
        llmnr_layer = LLMNRQuery(id=0xb6d2, qd=DNSQR(qtype="AAAA", qname=name))
        packet = ether_layer/ip_layer/trans_layer/llmnr_layer
        # packet.show()
        sendp(packet, verbose=1, iface="WLAN")
        time.sleep(1)
        # response = srp1(packet, verbose=1, timeout=2, iface="WLAN")
        # if response:
        #     response.show()
        #     print("response!")
        # else:
        #     print("no response!")


def llmnr6(name_list):
    conf = Conf()
    src_mac = conf.mac
    src_ip = conf.lla
    dst_mac = "33:33:00:01:00:03"
    dst_ip = "ff02::1:3"
    for name in name_list:
        # query all service name
        ether_layer = Ether(src=src_mac, dst=dst_mac)
        ip_layer = IPv6(dst=dst_ip, src=src_ip)
        trans_layer = UDP(sport=53555, dport=5355)
        mdns_layer = DNS(id=0xb6d2, rd=0, qd=DNSQR(qtype="AAAA", unicastresponse=0, qname=name))
        packet = ether_layer/ip_layer/trans_layer/mdns_layer
        # packet.show()
        response = srp1(packet, verbose=1, timeout=2, iface="WLAN")
        # if response:
        #     # response.show()
        #     print("response!")
        # else:
        #     print("no response!")


if __name__ == "__main__":
    name_list = ["DESKTOP-G1AD8NT"]
    mdns(name_list)
    mdns6(name_list)
    # llmnr6(name_list)
    # llmnr(name_list)


    
