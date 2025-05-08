from scapy.all import *
from scapy.layers.inet6 import IPv6, ICMPv6MLQuery, IPv6ExtHdrHopByHop, RouterAlert
from scapy.layers.l2 import Ether
import conf
INTERFACE_ID = {
    "ETH": "{E9812809-EC44-4F9B-AA3F-A4EDF0835213}",
    "WLAN": "{F52FC252-BAEC-4BA6-A8CA-8706641245A6}"
}
# 多播地址定义
MLDv2_MCAST_ADDR = "ff02::1"  # 所有节点多播地址
MLDv2_MCAST_MAC = "33:33:00:00:00:01"


def send_mldv2_query(interface="WLAN", save_path=None):
    """发送 MLDv2 查询报文"""
    def create_mldv2_query():
        """创建 MLDv2 通用查询报文"""
        # 获取接口的链路本地地址和 MAC
        conf_info = conf.Conf(INTERFACE_ID[interface])
        src_mac = conf_info.mac
        src_ip = conf_info.ipv6_lla

        ether = Ether(src=src_mac, dst=MLDv2_MCAST_MAC)
        ipv6 = IPv6(src=src_ip, dst=MLDv2_MCAST_ADDR, hlim=1)
        hopbyhop = IPv6ExtHdrHopByHop(options=[RouterAlert()])

        # MLDv2 查询报文（通用查询）
        mldv2_query = ICMPv6MLQuery(
            type=130,  # MLDv2 查询类型码
            mrd=1,  # 最大响应延迟（毫秒）
            mladdr="::",  # 目标组播地址（:: 表示通用查询）
        )

        return ether / ipv6 / hopbyhop / mldv2_query
    packet = create_mldv2_query()
    print("[*] Sending MLDv2 Query.")
    # packet.show()
    sendp(packet, iface=interface, verbose=False)

    if save_path:
        pass


# 主函数
if __name__ == "__main__":
    # 执行MLD扫描
    send_mldv2_query(interface="WLAN", save_path="D:/Project/scan6/result/mld/")
