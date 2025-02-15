from scapy.all import *
from scapy.layers.inet6 import IPv6, ICMPv6MLQuery
from scapy.layers.l2 import Ether
from conf import Conf


# 定义MLD查询数据包
def create_mld_query():
    # IPv6头部
    ipv6 = IPv6(src=conf.ip6_adress, dst="ff02::1")  # 源地址为::，目的地址为ff02::1（所有节点多播地址）

    # MLD查询消息
    mld_query = ICMPv6MLQuery()

    # 组合数据包
    packet = ipv6 / mld_query
    return packet


# 发送MLD查询并监听响应
def mld_scan(iface):
    # 创建MLD查询数据包
    mld_query_packet = create_mld_query()

    # 发送数据包并监听响应
    print(f"[*] Sending MLD Query on interface {iface}...")
    responses = srp1(Ether(src=conf.mac_address) / mld_query_packet, iface=iface, timeout=2, verbose=0)

    # 处理响应
    if responses:
        print("[*] Received MLD Report:")
        responses.show()
    else:
        print("[*] No MLD Reports received.")


conf = Conf()
# 主函数
if __name__ == "__main__":
    # 设置网络接口
    interface = "WLAN"  # 替换为你的网络接口名称

    # 执行MLD扫描
    mld_scan(interface)
