import os
from datetime import datetime

import pandas as pd
from scapy.layers.inet6 import ICMPv6ND_NA
from scapy.layers.l2 import Ether
from scapy.utils import rdpcap

GLOBAL_DEVICES = {}  # 核心数据结构: {mac: device_info}
LLA_PREFIX = ("fe80::", "fe80:")  # 链路本地地址前缀
GUA_PREFIX = ("2", "3")  # 全局单播地址前缀 (按需扩展)


def is_lla(ip: str) -> bool:
    """判断是否为链路本地地址"""
    return any(ip.startswith(prefix) for prefix in LLA_PREFIX)


def is_gua(ip: str) -> bool:
    """判断是否为全局单播地址"""
    return any(ip.startswith(prefix) for prefix in GUA_PREFIX)


def update_device_info(mac: str, new_data: dict):
    """合并新旧设备信息（基于 MAC 地址）"""
    if mac not in GLOBAL_DEVICES:
        GLOBAL_DEVICES[mac] = {
            "mac": mac,
            "ipv6_lla": None,
            "ipv6_gua": [],
        }

    device = GLOBAL_DEVICES[mac]

    # 合并策略

    # IPv6 地址处理
    if new_data.get("ipv6_lla"):
        device["ipv6_lla"] = new_data["ipv6_lla"]
    if new_data.get("ipv6_gua"):
        device["ipv6_gua"] = list(set(device["ipv6_gua"] + new_data["ipv6_gua"]))


def process_icmpv6_na(packet):
    """处理 ICMPv6 邻居通告（携带 MAC 和 IPv6 地址）"""
    try:
        na = packet[ICMPv6ND_NA]
        mac = packet[Ether].src
        target_ip = na.tgt

        # 构建数据
        if is_lla(target_ip):
            new_data = {"ipv6_lla": target_ip}
        elif is_gua(target_ip):
            new_data = {"ipv6_gua": [target_ip]}
        else:
            new_data = {}
        update_device_info(mac, new_data)

    except Exception as e:
        print(f"[ICMPv6 NA 解析错误] {e}")


def process_pcap(pcap_file):
    """处理单个pcap文件，提取NBNS register查询的主机名"""
    print(f"\n[*] 正在分析文件: {pcap_file}")
    packets = rdpcap(pcap_file)
    results = set()  # 用集合去重

    for packet in packets:
        if packet.haslayer(ICMPv6ND_NA):
            process_icmpv6_na(packet)
    return results


def analyze_icmpv6_dir(dir_path, output_file=None):
    """分析目录下所有pcap文件"""

    # 遍历目录中的pcap文件
    for filename in os.listdir(dir_path):
        if filename.lower().endswith(('.pcap', '.pcapng')):
            full_path = os.path.join(dir_path, filename)
            process_pcap(full_path)

    # 输出结果
    print("\n[+] 所有文件分析完成，去重后结果:")
    df = pd.DataFrame(GLOBAL_DEVICES.values())
    print(df)
    df = df[["mac",  "ipv6_lla", "ipv6_gua",
             ]]

    df.to_csv(output_file, index=False)


if __name__ == "__main__":
    analyze_icmpv6_dir(dir_path="data/icmpv6", output_file="result/icmpv6.csv")



