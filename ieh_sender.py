from scapy.all import *
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, IPv6ExtHdrDestOpt
import sys
sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')
import time
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.layers.l2 import Ether
from scapy.sendrecv import sr1, srp1, sendp


def ieh_ping():
    # 多播MAC地址和多播IP地址为链路所有节点
    src_mac = "48:a4:72:e6:72:bf"
    dst_mac = "33:33:00:00:00:01"
    # dst_mac = "e2:93:9c:b3:59:56"
    src_ip = "2409:895a:d103:875b:d68e:d04d:c7:6067"
    # dst_ip = "2409:895a:d103:875b:747c:feff:fedf:6325"
    dst_ip = "ff02::1"

    for i in range(10):
        # 创建链路层帧
        ether_layer = Ether(src=src_mac, dst=dst_mac, type="IPv6")
        # 创建IP层数据报
        ip_layer = IPv6(src=src_ip, dst=dst_ip, hlim=128)
        # 构造一个包含无效扩展头的 IPv6 数据包
        # 这里使用一个无效的选项类型（0x1E）来触发 ICMPv6 参数问题
        icmpv6_ping = ICMPv6EchoRequest(id=1, seq=i+50, type=150, data="abcdefghijklmnopqrstuvwabcdefghi")
        # 将各层封装为数据包
        packet = ether_layer/ip_layer/icmpv6_ping
        # packet.show()
        ans = sendp(packet, verbose=0, iface="WLAN")
        print("ICMPv6  Message sent.")
        time.sleep(2)


# m_ping()
if __name__ == "__main__":
    ieh_ping()

