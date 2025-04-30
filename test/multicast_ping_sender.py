import sys

from scapy.packet import Raw

sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')
import time
from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, IPv6ExtHdrDestOpt, IPv6ExtHdrFragment
from scapy.sendrecv import srp
import conf


def m_ping():
    config = conf.get_interface_info(conf.WLAN)
    src_mac = config["ipv6_address"]
    src_ip = config["ipv6_address"]
    # 多播MAC地址和多播IP地址：本地链路所有节点
    dst_mac = "33:33:00:00:00:01"
    dst_ip = "ff02::1"

    for i in range(4):
        ether_layer = Ether(src=src_mac, dst=dst_mac)
        ip_layer = IPv6(src=src_ip, dst=dst_ip, nh=44)
        fragment1 = IPv6ExtHdrFragment(nh=60)
        doh_layer = IPv6ExtHdrDestOpt(nh=60)
        packet1 = ether_layer / ip_layer / fragment1 / doh_layer

        fragment2 = IPv6ExtHdrFragment(nh=60)
        doh_layer = IPv6ExtHdrDestOpt(nh=58)
        icmpv6_ping = ICMPv6EchoRequest(id=1, seq=i+50, data="abcdefghijklmnopqrstuvwabcdefghi")
        packet2 = ether_layer/ip_layer/fragment2/doh_layer/icmpv6_ping

        # response = srp(packet1, verbose=1, iface="WLAN", timeout=0)
        response = srp(packet2, iface="WLAN", timeout=3)
        print("ICMPv6  Message sent.")
        if response:
            for re in response:
                re.summary()
        time.sleep(2)


if __name__ == "__main__":
    m_ping()


