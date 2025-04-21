import sys

from scapy.layers.dns import DNS, DNSRR

sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')
from scapy.all import sniff
import conf


# link local address
def is_lla_ipv6(ip):
    if ip.startswith("fe80:"):
        return True


# unicast address
def is_gua_ipv6(ip):
    if ip.startswith("2"):
        return True


def mdns_response_sniffer(interface="WLAN"):
    """
    捕获指定接口上的 MDNS response 报文。

    参数:
    interface (str): 要监听的网络接口名称，默认为 "WALN"。
    """
    print("Starting mDNS sniffing...")
    try:
        # 使用 scapy 的 sniff 函数捕获数据包
        sniff(
            iface=interface,  # 指定网络接口
            prn=process_packet,  # 回调函数处理捕获的数据包
            filter="udp port 5353",  # BPF 过滤器，只捕获 ICMPv6 Echo Reply
            store=0  # 不存储捕获的数据包，节省内存
        )
    except PermissionError:
        print("没有足够的权限来捕获数据包，请尝试以管理员权限运行脚本。")
    except Exception as e:
        print(f"捕获数据包时发生错误: {e}")


# 定义回调函数来处理捕获的mDNS报文
def process_packet(packet):
    """
    处理捕获的数据包，如果是 MDNS response，则记录信息。

    参数:
    packet: 捕获的数据包。
    """
    try:
        if packet.haslayer(DNSRR):
            dns = packet.getlayer(DNS)
            for answer in dns.ar:
                if answer.type == 12:
                    if answer.rrname.decode('utf-8') != "_services._dns-sd._udp.local.":
                        if hasattr(dns, 'ar') and dns.ar:
                                service_instance_list = []
                                target_list = []
                                hostname_list = []
                                lla_list = []
                                gua_list = []
                                if answer.type == 33:  # SRV
                                    service_instance = answer.rrname.decode('utf-8')
                                    service_instance_list.append(service_instance)
                                    hostname = answer.target.decode('utf-8')
                                    port = answer.port
                                    target = hostname + str(port)
                                    target_list.append(target)
                                if answer.type == 1:  # A
                                    # answer.show()
                                    hostname = answer.rrname.decode('utf-8')
                                    # ip4 = answer.rdata
                                    # info["ip4"].append(ip4)
                                    hostname_list.append(hostname)
                                if answer.type == 28:  # AAAA
                                    # answer.show()
                                    ip6 = answer.rdata
                                    if is_lla_ipv6(ip6):
                                        lla_list.append(ip6)
                                    if is_gua_ipv6(ip6):
                                        gua_list.append(ip6)
    except Exception as e:
        print(f"捕获数据包时发生错误: {e}")


info_list = []
if __name__ == "__main__":
    interface = conf.Conf.iface

    # 存储提取的 IPv6 地址信息
    # 运行 sniffer 函数
    mdns_response_sniffer()
