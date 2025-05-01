from scapy.all import *
from scapy.layers.inet6 import IPv6, ICMPv6MLQuery, IPv6ExtHdrHopByHop, RouterAlert
from scapy.layers.l2 import Ether

# 多播地址定义
MLDv2_MCAST_ADDR = "ff02::1"  # 所有节点多播地址
MLDv2_MCAST_MAC = "33:33:00:00:00:01"


def create_mldv2_query(iface="WLAN"):
    """创建 MLDv2 通用查询报文"""
    # 获取接口的链路本地地址和 MAC
    lla = get_if_addr6(iface).split("%")[0]
    src_mac = get_if_hwaddr(iface)

    # 以太网层
    ether = Ether(src=src_mac, dst=MLDv2_MCAST_MAC)

    # IPv6 头部（必须包含逐跳选项头）
    ipv6 = IPv6(
        src=lla,
        dst=MLDv2_MCAST_ADDR,
        hlim=1,  # 跳数限制设为 1（本地链路）
    )

    # 逐跳选项头（包含 Router Alert 选项）
    hopbyhop = IPv6ExtHdrHopByHop(options=[RouterAlert()])

    # MLDv2 查询报文（通用查询）
    mldv2_query = ICMPv6MLQuery(
        type=130,                  # MLDv2 查询类型码
        mrd=10000,                 # 最大响应延迟（毫秒）
        maddr="::",                # 目标组播地址（:: 表示通用查询）
    )

    return ether / ipv6 / hopbyhop / mldv2_query


def send_mldv2_query(iface="WLAN"):
    """发送 MLDv2 查询报文"""
    packet = create_mldv2_query(iface)
    print("[*] Sending MLDv2 Query:")
    packet.show()
    sendp(packet, iface=iface, verbose=False)


if __name__ == "__main__":
    send_mldv2_query()
