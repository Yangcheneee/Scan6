import sys
sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.llmnr import LLMNRResponse
from scapy.layers.l2 import Ether
from scapy.all import sniff
from scapy.layers.inet6 import IPv6, ICMPv6EchoReply
import logging


# link local address
def is_lla_ipv6(ip):
    if ip.startswith("fe80:"):
        return True


# unicast address
def is_gua_ipv6(ip):
    if ip.startswith("2"):
        return True


def llmnr_response_sniffer(interface="WLAN"):
    """
    捕获指定接口上的 LLMNR response 报文。

    参数:
    interface (str): 要监听的网络接口名称，默认为 "WALN"。
    """
    print("Starting LLMNR sniffing...")
    try:
        # 使用 scapy 的 sniff 函数捕获数据包
        sniff(
            iface=interface,  # 指定网络接口
            prn=process_packet,  # 回调函数处理捕获的数据包
            filter="udp port 5355 and udp[10] & 0x80 == 0x80 and ip",  # BPF 过滤器，只捕获 LLMNR
            store=0  # 不存储捕获的数据包，节省内存
        )
    except PermissionError:
        print("没有足够的权限来捕获数据包，请尝试以管理员权限运行脚本。")
    except Exception as e:
        print(f"捕获数据包时发生错误: {e}")


# 定义回调函数来处理捕获的LLMNR报文
def process_packet(packet):
    """
    处理捕获的数据包，如果是 LLMNR response，则记录信息。

    参数:
    packet: 捕获的数据包。
    """
    try:
        # packet.show()
        if LLMNRResponse in packet:
            dns = packet.getlayer(LLMNRResponse)
            # dns.show()
            # 检查是否有响应记录
            if dns.qr == 1:  # QR=1表示响应
                # print("response!")
                for answer in dns.an:
                    # answer.show()
                    if isinstance(answer, DNSRR) and answer.type == 28:
                        hostname = answer.rrname.decode('utf-8')
                        ip = answer.rdata
                        if hostname not in ipv6_data:
                            ipv6_data[hostname] = {"link_local": [], "global_unicast": []}
                        if is_lla_ipv6(ip) and ip not in ipv6_data[hostname]["link_local"]:
                            ipv6_data[hostname]["link_local"].append(ip)
                            print(ipv6_data)
                        if is_gua_ipv6(ip) and ip not in ipv6_data[hostname]["global_unicast"]:
                            ipv6_data[hostname]["global_unicast"].append(ip)
                            print(ipv6_data)
    except Exception as e:
        print(f"捕获数据包时发生错误: {e}")


# 存储提取的 IPv6 地址信息
ipv6_data = {}
# icmpv6_reply_sniffer()
if __name__ == "__main__":
    # 运行 sniffer 函数
    llmnr_response_sniffer()
