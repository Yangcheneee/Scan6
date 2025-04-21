import os
import sys
from datetime import datetime

sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')
import pandas as pd
from scapy.all import sniff
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.l2 import Ether

info_list = []


# link local address
def is_lla_ipv6(ip):
    if ip.startswith("fe80:"):
        return True


# unicast address
def is_gua_ipv6(ip):
    if ip.startswith("2"):
        return True


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
            if dns.qr == 1:  # QR=1表示响应
                info = {
                    "mac": None,
                    "ip4": None,
                    "hostname": None,
                    "lla": None,
                    "gua": [],
                    # "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                # print("response!")
                for answer in dns.an:
                    if answer.type == 1:   # A
                        hostname = answer.rrname.decode('utf-8')
                        info["hostname"] = hostname
                        ip4 = answer.rdata
                        info["ip4"] = ip4
                    if answer.type == 28:    # AAAA
                        hostname = answer.rrname.decode('utf-8')
                        info["hostname"] = hostname
                        ip = answer.rdata
                        if is_lla_ipv6(ip):
                            info["lla"] = ip
                        if is_gua_ipv6(ip):
                            info["gua"].append(ip)
                info["mac"] = packet[Ether].src
                for answer in dns.ar:
                    if answer.type == 1:   # A
                        hostname = answer.rrname.decode('utf-8')
                        info["hostname"] = hostname
                        ip4 = answer.rdata
                        info["ip4"] = ip4
                    if answer.type == 28:    # AAAA
                        hostname = answer.rrname.decode('utf-8')
                        info["hostname"] = hostname
                        ip = answer.rdata
                        if is_lla_ipv6(ip):
                            info["lla"] = ip
                        if is_gua_ipv6(ip):
                            info["gua"].append(ip)
                print(info)
                info_list.append(info)
    except Exception as e:
        print(f"解析数据包时发生错误: {e}")


def run(interface="WLAN", duration=10*60, save_file="../result/mdns_sniffer.csv"):
    """
    捕获指定接口上的 MDNS response 报文。

    参数:
    interface (str): 要监听的网络接口名称，默认为 "WALN"。
    """
    print("捕获mDNS Response报文中...")
    try:
        # 使用 scapy 的 sniff 函数捕获数据包
        sniff(
            iface=interface,  # 指定网络接口
            prn=process_packet,  # 回调函数处理捕获的数据包
            filter="udp port 5353",  # BPF 过滤器，只捕获 ICMPv6 Echo Reply
            timeout=duration,
            store=0  # 不存储捕获的数据包，节省内存
        )
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
    run()
