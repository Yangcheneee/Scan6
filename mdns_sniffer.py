import sys

from scapy.layers.dns import DNS, DNSRR
from scapy.layers.l2 import Ether

sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')
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
        # packet.show()
        src_mac = packet[Ether].src
        if packet.haslayer(DNS):
            dns = packet.getlayer(DNS)
            # dns.show()
            # 检查是否有响应记录
            if dns.qr == 1:  # QR=1表示响应
                # print("response!")
                for answer in dns.an:
                    # answer.show()
                    if answer.type == 33:  # SRV
                        # answer.show()
                        hostname = answer.target.decode('utf-8')
                        service = answer.rrname.decode('utf-8')
                        if hostname not in host_data:
                            host_data[hostname] = {"link_local": [], "global_unicast": [], "ip4": [], "service": []}
                        if service not in host_data[hostname]["service"]:
                            host_data[hostname]["service"].append(service)
                            print(host_data)
                    if answer.type == 1:   # A
                        # answer.show()
                        hostname = answer.rrname.decode('utf-8')
                        ip4 = answer.rdata
                        if hostname not in host_data:
                            host_data[hostname] = {"link_local": [], "global_unicast": [], "ip4": [], "service": []}
                        if ip4 not in host_data[hostname]["ip4"]:
                            host_data[hostname]["ip4"].append(ip4)
                        print(host_data)
                    if isinstance(answer, DNSRR) and answer.type == 28:    # AAAA
                        # answer.show()
                        hostname = answer.rrname.decode('utf-8')
                        ip = answer.rdata
                        if hostname not in host_data:
                            host_data[hostname] = {"link_local": [], "global_unicast": [], "ip4": [], "services": []}
                        if is_lla_ipv6(ip) and ip not in host_data[hostname]["link_local"]:
                            host_data[hostname]["link_local"].append(ip)
                            # print(ipv6_data)
                        if is_gua_ipv6(ip) and ip not in host_data[hostname]["global_unicast"]:
                            host_data[hostname]["global_unicast"].append(ip)
                            # print(ipv6_data)
                        print(host_data)
            if hasattr(dns, 'ar') and dns.ar:
                for answer in dns.ar:
                    if answer.type == 33:  # SRV
                        # answer.show()
                        hostname = answer.target.decode('utf-8')
                        service = answer.rrname.decode('utf-8')
                        if hostname not in host_data:
                            host_data[hostname] = {"link_local": [], "global_unicast": [], "ip4": [], "service": []}
                        if service not in host_data[hostname]["service"]:
                            host_data[hostname]["service"].append(service)
                            print(host_data)
                    if answer.type == 1:   # A
                        # answer.show()
                        hostname = answer.rrname.decode('utf-8')
                        ip4 = answer.rdata
                        if hostname not in host_data:
                            host_data[hostname] = {"link_local": [], "global_unicast": [], "ip4": [], "service": []}
                        if ip4 not in host_data[hostname]["ip4"]:
                            host_data[hostname]["ip4"].append(ip4)
                        print(host_data)
                    if answer.type == 28:  # AAAA
                        # answer.show()
                        hostname = answer.rrname.decode('utf-8')
                        ip = answer.rdata
                        if hostname not in host_data:
                            host_data[hostname] = {"link_local": [], "global_unicast": [], "ip4": [], "services": []}
                        if is_lla_ipv6(ip) and ip not in host_data[hostname]["link_local"]:
                            host_data[hostname]["link_local"].append(ip)
                            # print(ipv6_data)
                        if is_gua_ipv6(ip) and ip not in host_data[hostname]["global_unicast"]:
                            host_data[hostname]["global_unicast"].append(ip)
                            # print(ipv6_data)
                        print(host_data)

    except Exception as e:
        print(f"捕获数据包时发生错误: {e}")


host_data = {}
if __name__ == "__main__":
    # 存储提取的 IPv6 地址信息
    # 运行 sniffer 函数
    mdns_response_sniffer()
