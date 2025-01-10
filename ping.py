import time
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.layers.l2 import Ether
from scapy.sendrecv import sr1, srp1, sendp


def ping():
    src_mac = "48:a4:72:e6:72:bf"
    dst_mac = "4c:f2:02:e4:b7:cc"
    dst_ip = "fe80::7fac:8e08:c44:b8cd"
    src_ip = "fe80::910c:e419:64df:f2f1"
    for i in range(4):
        # 创建IP层数据报
        ether_layer = Ether(src=src_mac, dst=dst_mac)
        ip_layer = IPv6(src=src_ip, dst=dst_ip, hlim=128)
        # 创建ICMPv6——ping报文
        icmpv6_ping = ICMPv6EchoRequest(id=1, seq=i+50, data="abcdefghijklmnopqrstuvwabcdefghi")
        # 将各层封装为数据包
        packet = ether_layer/ip_layer/icmpv6_ping
        # packet.show()
        ans = srp1(packet, verbose=0,timeout=2, iface="WLAN")
        if ans and ans.haslayer(ICMPv6EchoReply):
            # ans.show()
            print(f"{dst_ip} is alive!")
        else:
            print("timeout and no response!")
        time.sleep(2)
