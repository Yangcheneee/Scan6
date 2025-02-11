import sys

from scapy.layers.l2 import Ether

sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')
from scapy.all import sniff
from scapy.layers.inet6 import IPv6, ICMPv6EchoReply
import logging


def icmpv6_reply_sniffer(interface="WLAN"):
    """
    捕获指定接口上的 ICMPv6 Echo Reply 报文。

    参数:
    interface (str): 要监听的网络接口名称，默认为 "WALN"。
    """
    try:
        # 使用 scapy 的 sniff 函数捕获数据包
        sniff(
            iface=interface,  # 指定网络接口
            prn=process_packet,  # 回调函数处理捕获的数据包
            filter="ip6 proto 58 and icmp6[icmp6type] == 129",  # BPF 过滤器，只捕获 ICMPv6 Echo Reply
            store=0  # 不存储捕获的数据包，节省内存
        )
    except PermissionError:
        print("没有足够的权限来捕获数据包，请尝试以管理员权限运行脚本。")
    except Exception as e:
        print(f"捕获数据包时发生错误: {e}")


def process_packet(packet):
    """
    处理捕获的数据包，如果是 ICMPv6 Echo Reply，则记录信息。

    参数:
    packet: 捕获的数据包。
    """
    try:
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
        src_mac = packet[Ether].src
        # print(f"捕获到源地址为{src_ip}的 ICMPv6 Echo Reply 报文")
        if src_mac not in ipv6_data:
            ipv6_data[src_mac] = {"link_local": src_ip}
            # print(f"捕获到源地址为{src_ip}的 ICMPv6 Echo Reply 报文")
            print(ipv6_data)
    except Exception as e:
        print(f"捕获数据包时发生错误: {e}")


# icmpv6_reply_sniffer()
if __name__ == "__main__":
    # 存储提取的 IPv6 地址信息
    ipv6_data = {}
    # 运行 sniffer 函数
    icmpv6_reply_sniffer()
