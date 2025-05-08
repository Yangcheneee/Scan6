import conf
from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, IPv6ExtHdrDestOpt, HBHOptUnknown
from scapy.sendrecv import sendp

INTERFACE_ID = {
    "ETH": "{E9812809-EC44-4F9B-AA3F-A4EDF0835213}",
    "WLAN": "{F52FC252-BAEC-4BA6-A8CA-8706641245A6}"
}


def ieh_scan(interface="WLAN", save_path=None):
    print("[*] Sending Invalid Extension Header ICMPv6.")
    conf_info = conf.Conf(INTERFACE_ID[interface])
    src_mac = conf_info.mac
    src_ip = conf_info.ipv6_lla
    src_ip2 = conf_info.ipv6_gua[0]
    dst_mac = "33:33:00:00:00:01"
    dst_ip = "ff02::1"

    ether_layer = Ether(src=src_mac, dst=dst_mac)
    ip_layer = IPv6(src=src_ip, dst=dst_ip, nh=60, hlim=255)
    ip_layer2 = IPv6(src=src_ip2, dst=dst_ip, nh=60, hlim=255)
    doh_header = IPv6ExtHdrDestOpt(nh=58, options=HBHOptUnknown(otype=128))
    icmpv6_ping = ICMPv6EchoRequest(type=254, id=1, data="00000000")
    query = ether_layer/ip_layer/doh_header/icmpv6_ping
    query2 = ether_layer/ip_layer2/doh_header/icmpv6_ping
    sendp([query2, query], iface=interface, verbose=False)

    if save_path:
        pass


if __name__ == "__main__":
    ieh_scan(interface="WLAN", save_path="D:/Project/scan6/result/ieh/")


