from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sr1, srp1


def mdns(name_list):
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
        mdns_layer = DNS(rd=1, qd=DNSQR(qtype="AAAA", unicastresponse=1, qname=name + ".local"))
        packet = ether_layer/ip_layer/trans_layer/mdns_layer
        # packet.show()
        response = srp1(packet, verbose=0, timeout=5, iface="WLAN")
        if response:
            # response.show()
            print("response!")
        else:
            print("no response!")


def llmnr(name_list):
    src_mac = "48:a4:72:e6:72:bf"
    src_ip = "192.168.3.132"
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
        mdns_layer = DNS(rd=1, qd=DNSQR(qtype="AAAA", unicastresponse=1, qname=name + ".local"))
        packet = ether_layer/ip_layer/trans_layer/mdns_layer
        # packet.show()
        response = srp1(packet, verbose=0, timeout=5, iface="WLAN")
        if response:
            # response.show()
            print("response!")
        else:
            print("no response!")

if __name__ == "__main__":
    name_list = ["Android", "Xiaoqiang", "艾恩奇"]
    mdns(name_list)
    
