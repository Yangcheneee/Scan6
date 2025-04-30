import os
from scapy.utils import rdpcap
import pandas as pd
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.l2 import Ether
import ipaddress


def ip_to_int(ip):
    return int(ipaddress.IPv4Address(ip))


# link local address
def is_lla_ipv6(ip):
    if ip.startswith("fe80:"):
        return True


# unicast address
def is_gua_ipv6(ip):
    if ip.startswith("2"):
        return True


def handle_mdns_packet(packet):
    try:
        if packet.haslayer(DNS):
            dns = packet.getlayer(DNS)
            if dns.qr == 1:  # QR=1表示响应
                info = {
                    "mac": None,
                    "ip4": None,
                    "hostname": None,
                    "lla": None,
                    "gua": None,
                    "tua": None
                }
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
                            if hostname != "Android.local.":
                                if info["gua"] is None:
                                    info["gua"] = ip
                                else:
                                    info["tua"] = ip
                            else:
                                if info["tua"] is None:
                                    info["tua"] = ip
                                else:
                                    info["gua"] = ip
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
                            if info["gua"] is None:
                                info["gua"] = ip
                            else:
                                info["tua"] = ip
                # if info["hostname"] and info["lla"] and info["gua"] and info["ip4"]:
                if True:
                    info["mac"] = packet[Ether].src
                    # print(info)
                    return info
    except Exception as e:
        print(f"解析数据包时发生错误: {e}")


def run(pcap_path='data/mdns.pcapng', save_file="result/mdns_pcap.csv"):
    mdns_info_list = []
    packets = rdpcap(pcap_path)
    for pkt in packets:
        mdns_info = handle_mdns_packet(pkt)
        if mdns_info:
            mdns_info_list.append(mdns_info)
    if mdns_info_list:
        df = pd.DataFrame(mdns_info_list)
        # 去除完全重复的行（所有列值相同）
        df = df.drop_duplicates()
        # df = df.drop_duplicates(subset=['mac', 'ip4', 'hostname', 'lla', 'gua'], keep='last')
        # 按转换后的整数值排序
        # df['ip_int'] = df['ip4'].apply(ip_to_int)
        # df = df.sort_values('ip_int')
        # 删除临时列（可选）
        # df = df.drop('ip_int', axis=1)
        df.to_csv(save_file, index=False, header=not os.path.exists(save_file), mode='a')
        print(f"数据已保存到 {save_file}")
    else:
        print("未捕获到数据，未生成文件。")


if __name__ == "__main__":
    run("data/school_mdns.pcapng", "result/shool_mdns_pcap.csv")

