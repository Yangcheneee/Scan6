import ipaddress

from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
import pandas as pd
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether


def ip_to_int(ip):
    return int(ipaddress.IPv4Address(ip))


def handle_dhcp_packet(packet):
    if DHCP in packet and packet[DHCP].options:
        # 检查报文类型是否为Discover (1) 或 Request (3)
        is_discover_or_request = False
        for opt in packet[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 'message-type':
                if opt[1] in [1, 3]:  # 1=Discover, 3=Request
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
        if info["ip4"] is None and packet[IP].src != "0.0.0.0":
            info["ip4"] = packet[IP].src
        if info["ip4"]:
            return info


def run(save_file="result/dhcp_pcap_all.csv"):
    info_list = []
    packets = rdpcap('data/dhcp.pcapng')
    for pkt in packets:
        info = handle_dhcp_packet(pkt)
        if info:
            info_list.append(info)

    df = pd.DataFrame(info_list)
    df = df.drop_duplicates()
    # df_unique_mac = df_unique.drop_duplicates(subset=['mac'], keep='last')
    # 按转换后的整数值排序
    df['ip_int'] = df['ip4'].apply(ip_to_int)
    df = df.sort_values('ip_int')
    # 删除临时列（可选）
    df = df.drop('ip_int', axis=1)
    df.to_csv(save_file, index=False, header=not os.path.exists(save_file), mode='a')


if __name__ == "__main__":
    run()
