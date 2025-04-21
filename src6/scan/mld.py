from scapy.all import *
from scapy.layers.inet6 import IPv6, ICMPv6MLQuery
from scapy.layers.l2 import Ether
from conf import Conf


# 定义MLD查询数据包
def create_mld_query():
    # Ether头部
    ether = Ether(src=conf.mac)

    # IPv6头部
    ipv6 = IPv6(src=conf.lla, dst="ff02::1", nh=0, hlim=1)  # 源地址为::，目的地址为ff02::1（所有节点多播地址）

    # 逐跳选项扩展头
    # hopbyhop = IPv6ExtHdrHopByHop(options=HBHOptUnknown(otype=0x05, optlen=0x02, optdata=0x0000))
    hopbyhop = Raw(b'\x3a\x00\x05\x02\x00\x00\x01\x00')

    # MLD查询消息
    mld_query = ICMPv6MLQuery(mrd=1)

    # 组合数据包
    packet = ether / ipv6 / hopbyhop / mld_query

    # packet.show()
    return packet


# 发送MLD查询并监听响应
def mld_scan():
    # 创建MLD查询数据包
    mld_query_packet = create_mld_query()

    # 发送数据包
    print(f"[*] Sending MLD Query...")
    sendp(mld_query_packet, verbose=0, iface=conf.iface)


# 主函数
if __name__ == "__main__":
    conf = Conf()
    while True:
        # 执行MLD扫描
        mld_scan()
        time.sleep(2)
