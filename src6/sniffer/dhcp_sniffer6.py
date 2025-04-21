import sys
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.l2 import Ether
import pandas as pd
from scapy.sendrecv import sniff

sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')


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
            filter="ip6 dst ff02::fb and udp dst port 5353",  # BPF 过滤器，只捕获 ICMPv6 Echo Reply
            store=0  # 不存储捕获的数据包，节省内存
        )
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
        if packet.haslayer(DNS):
            dns = packet.getlayer(DNS)
            # 检查是否有响应记录
            if dns.qr == 1:
                info = {
                    "mac": packet[Ether].src,
                    "hostname": None,
                    "lla": None,
                    "gua": []
                }
                for answer in dns.an:
                    if answer.type == 28:    # AAAA
                        info["hostname"] = answer.rrname.decode('utf-8')
                        ip6 = answer.rdata
                        if is_lla_ipv6(ip6):
                            info["lla"] = ip6
                        if is_gua_ipv6(ip6):
                            if info["gua"] is None:
                                info["gua"].append(ip6)
                            else:
                                info["gua"].append(ip6)
                print(info)
                info_list.append(info)
    except Exception as e:
        print(f"捕获数据包时发生错误: {e}")
    finally:
        if info_list:
            df = pd.DataFrame(info_list)
            # 去除完全重复的行（所有列值相同）
            df = df.drop_duplicates()
            df.to_csv(save_file, index=False, header=not os.path.exists(save_file), mode='a')
            print(f"数据已保存到 {save_file}")
        else:
            print("未捕获到数据，未生成文件。")


if __name__ == "__main__":
    info_list = []
    # 存储提取的 IPv6 地址信息
    # 运行 sniffer 函数
    mdns_response_sniffer()
