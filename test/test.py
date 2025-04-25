from scapy.all import *
from scapy.layers.inet6 import ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, IPv6
from scapy.layers.l2 import Ether

# 设置接口和参数
interface = "WLAN"  # 更改为你的网络接口
src_mac = "48:A4:72:E6:72:BF"  # 更改为你的MAC地址
src_ipv6 = "fe80::910c:e419:64df:f2f1"  # 本地链路地址

# 构造RA报文
ra_packet = Ether(src=src_mac, dst="33:33:00:00:00:01") / \
    IPv6(src=src_ipv6, dst="ff02::1") / \
    ICMPv6ND_RA() / \
    ICMPv6NDOptPrefixInfo(prefix="fe80::", prefixlen=64, validlifetime=86400, preferredlifetime=14400)

# 发送RA报文
sendp(ra_packet, iface=interface, inter=10, loop=1)
