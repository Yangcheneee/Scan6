import sys
sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.l2 import Ether
from scapy.all import sniff
from scapy.layers.inet6 import IPv6, ICMPv6EchoReply
import logging


def dns_sd_sniffer(interface="WLAN"):
    """
    捕获指定接口上的 DNS-SD response 报文。

    参数:
    interface (str): 要监听的网络接口名称，默认为 "WALN"。
    """
    print("Starting DNS-SD sniffing...")
    try:
        # 使用 scapy 的 sniff 函数捕获数据包
        sniff(
            iface=interface,  # 指定网络接口
            prn=process_packet,  # 回调函数处理捕获的数据包
            filter="udp port 5353 and udp[10] & 0x80 == 0x80",  # BPF 过滤器，只捕获DNS-SD
            store=0  # 不存储捕获的数据包，节省内存
        )
    except PermissionError:
        print("没有足够的权限来捕获数据包，请尝试以管理员权限运行脚本。")
    except Exception as e:
        print(f"捕获数据包时发生错误: {e}")


# 定义回调函数来处理捕获的DNS-SD报文
def process_packet(packet):
    """
    处理捕获的数据包，如果是 DNS-SD response，则记录信息。

    参数:
    packet: 捕获的数据包。
    """
    try:
        # packet.show()
        if packet.haslayer(DNSRR):
            # packet.show()
            dns = packet.getlayer(DNS)
            for answer in dns.an:
                # answer.show()
                if answer.type == 12:
                    #  == "_services._dns-sd._udp.local"
                    # print(answer.rrname.decode('utf-8'))
                    if answer.rdata.decode('utf-8') not in service_list and answer.rrname.decode('utf-8') == "_services._dns-sd._udp.local.":
                        service_list.append(answer.rdata.decode('utf-8'))
                        print(service_list)
    except Exception as e:
        print(f"捕获数据包时发生错误: {e}")


service_list = []
if __name__ == "__main__":
    dns_sd_sniffer()
