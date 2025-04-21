from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
import pandas as pd
from scapy.layers.l2 import Ether

import name_resolver


# 提取标准BOOTP chaddr（客户端MAC）
def handle_dhcp_packet(packet):
    if DHCP in packet and packet[DHCP].options:
        # 检查报文类型是否为Discover (1) 或 Request (3)
        is_discover_or_request = False
        for opt in packet[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 'message-type':
                if opt[1] in [3]:  # 1=Discover, 3=Request
                    is_discover_or_request = True
                break
        if not is_discover_or_request:
            return None
        info = {
            "mac": None,
            "ip4": None,
            "hostname": None,
            "vendor": None
        }
        for option in packet[DHCP].options:
            if isinstance(option, tuple):
                if option[0] == 'hostname':  # Option 12
                    info["hostname"] = option[1].decode('utf-8', errors='ignore')
                if option[0] == 'vendor_class_id':  # Option 60
                    info["vendor"] = option[1].decode()
                if option[0] == 'client_id':  # Option 61
                    info["mac"] = ":".join(f"{b:02x}" for b in packet[BOOTP].chaddr[:6])
                if option[0] == 'requested_addr':  # Option 50
                    info["ip4"] = option[1]
        if info["mac"] is None:
            info["mac"] = packet[Ether].src
        # print(f"{info}")
        return info


if __name__ == "__main__":
    # 读取PCAP文件
    packets = rdpcap('../pacp/dhcp.pcapng')

    info_list = []
    # 遍历数据包
    for pkt in packets:
        info = handle_dhcp_packet(pkt)
        if info:
            info_list.append(info)

    # 方法3：使用Pandas去重
    df = pd.DataFrame(info_list)
    # print(df)
    df_unique = df.drop_duplicates()  # 完全相同的行
    print(df_unique)
    # 或者按MAC列去重
    df_unique_mac = df_unique.drop_duplicates(subset=['mac'], keep='last')
    print(df_unique_mac)

    hostname_list = df_unique_mac['hostname']
    ip6_info_list = []
    for hostname in hostname_list:
        if hostname:
            ip6_info = name_resolver.mdns(hostname)
            if ip6_info:
                ip6_info_list.append(ip6_info)
    df2 = pd.DataFrame(ip6_info_list)
    df_merged = pd.merge(df_unique_mac, df2, on="hostname", how="outer")
    df_merged.to_csv("../test/dhcp_merge.csv")
    print(df_merged)
    # print(df_unique_mac.to_dict('records'))
    # 读取CSV文件
    #
    # # 假设MAC地址列名为'mac_address'，根据实际列名调整
    # df_unique = df.drop_duplicates(subset=['mac'], keep='first')
    #
    # # 保存结果（可选）
