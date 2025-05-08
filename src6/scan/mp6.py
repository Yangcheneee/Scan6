import sys
sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')
import time
from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.sendrecv import srp, sendp
import conf
INTERFACE_ID = {
    "ETH": "{E9812809-EC44-4F9B-AA3F-A4EDF0835213}",
    "WLAN": "{F52FC252-BAEC-4BA6-A8CA-8706641245A6}"
}


def mp6_scan(interface="WLAN", save_path=None):
    print("[*] Sending Multicast ICMPv6 Echo Request.")
    conf_info = conf.Conf(INTERFACE_ID[interface])
    src_mac = conf_info.mac
    src_ip = conf_info.ipv6_lla
    src_ip2 = conf_info.ipv6_gua[0]
    # 多播MAC地址和多播IP地址：本地链路所有节点
    dst_mac = "33:33:00:00:00:01"
    dst_ip = "ff02::1"

    # for i in range(4):
    # 创建链路层帧
    ether_layer = Ether(src=src_mac, dst=dst_mac)
    # 创建IP层数据报
    # ip_layer = IPv6(src=src_ip, dst=dst_ip, hlim=128)
    ip_layer = IPv6(src=src_ip, dst=dst_ip)
    ip_layer2 = IPv6(src=src_ip2, dst=dst_ip)
    # 创建ICMPv6——ping报文
    icmpv6_ping = ICMPv6EchoRequest(id=1, data="abcdefghijklmnopqrstuvwabcdefghi")
    # 将各层封装为数据包
    query = ether_layer/ip_layer/icmpv6_ping
    query2 = ether_layer/ip_layer2/icmpv6_ping
    # packet.show()
    sendp([query2, query], iface="WLAN", verbose=False)

    if save_path:
        pass


if __name__ == "__main__":
    mp6_scan()


