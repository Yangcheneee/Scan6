import conf
from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo
from scapy.sendrecv import sendp

INTERFACE_ID = {
    "ETH": "{E9812809-EC44-4F9B-AA3F-A4EDF0835213}",
    "WLAN": "{F52FC252-BAEC-4BA6-A8CA-8706641245A6}"
}


def run(interface="WLAN", prefix_str="2409:8962:3a7:d8be::"):
    conf_info = conf.Conf(INTERFACE_ID["WLAN"])
    src_mac = conf_info.mac
    src_ipv6 = conf_info.ipv6_lla

    # 构造RA报文
    ra_packet = Ether(src=src_mac, dst="33:33:00:00:00:01") / \
        IPv6(src=src_ipv6, dst="ff02::1") / \
        ICMPv6ND_RA() / \
        ICMPv6NDOptPrefixInfo(prefix=prefix_str, prefixlen=64, validlifetime=10, preferredlifetime=10)

    # 发送RA报文
    sendp(ra_packet, iface=interface, verbose=0)


if __name__ == "__main__":
    run(interface="WLAN", prefix_str="2409:8962:3a7:d8be::")
