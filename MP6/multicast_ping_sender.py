import sys
sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')
import time
from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.sendrecv import srp
from Conf.conf import Conf


def m_ping():
    conf = Conf()
    src_mac = conf.mac
    src_ip = conf.lla
    # 多播MAC地址和多播IP地址：本地链路所有节点
    dst_mac = "33:33:00:00:00:01"
    dst_ip = "ff02::1"

    for i in range(4):
        # 创建链路层帧
        ether_layer = Ether(src=src_mac, dst=dst_mac)
        # 创建IP层数据报
        # ip_layer = IPv6(src=src_ip, dst=dst_ip, hlim=128)
        ip_layer = IPv6(src=src_ip, dst=dst_ip)
        # 创建ICMPv6——ping报文
        icmpv6_ping = ICMPv6EchoRequest(id=1, seq=i+50, data="abcdefghijklmnopqrstuvwabcdefghi")
        # 将各层封装为数据包
        query = ether_layer/ip_layer/icmpv6_ping
        # packet.show()
        response = srp(query, verbose=1, iface="WLAN", timeout=3)
        if response:
            for re in response:
                re.summary()
        print("ICMPv6  Message sent.")
        time.sleep(2)


if __name__ == "__main__":
    m_ping()


