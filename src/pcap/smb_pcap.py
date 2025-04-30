import ipaddress
import os

from scapy.utils import rdpcap
from scapy.layers.l2 import Ether
from scapy.layers.inet import UDP, IP
from scapy.layers.smb import BRWS_HostAnnouncement, SMB_Header, SMBTransaction_Request
import pandas as pd


def ip_to_int(ip):
    return int(ipaddress.IPv4Address(ip))


def handle_smb_packet(packet):
    if packet.haslayer(UDP) and packet.dport == 138:  # NetBIOS Datagram Service
        # 检查是否是SMB协议
        if packet.haslayer(SMB_Header):
            info = {"mac": None, "ip4": None, "hostname": None, "os": None, "server": None}
            smb_com = packet.getlayer(5)
            data = smb_com.Buffer[0]
            if data[1].haslayer(BRWS_HostAnnouncement):
                info["mac"] = packet[Ether].src
                info["ip4"] = packet[IP].src
                browser = data[1].getlayer(BRWS_HostAnnouncement)
                info["hostname"] = browser.ServerName.decode()[:15]
                info["os"] = str(browser.OSVersionMajor) + "." + str(browser.OSVersionMinor)
                info["server"] = browser.ServerType
                # print(info)
                return info


def run(save_file="result/smb_pcap.csv"):
    # 读取PCAP文件
    packets = rdpcap('data/smb.pcapng')

    # 遍历数据包
    smb_info_list = []
    for pkt in packets:
        smb_info = handle_smb_packet(pkt)
        if smb_info:
            smb_info_list.append(smb_info)

    # 去除完全相同的行
    df = pd.DataFrame(smb_info_list)
    df = df.drop_duplicates()
    # 按MAC列去重
    df = df.drop_duplicates(subset=['mac'], keep='last')
    # 按转换后的整数值排序
    df['ip_int'] = df['ip4'].apply(ip_to_int)
    df = df.sort_values('ip_int')
    # 删除临时列（可选）
    df = df.drop('ip_int', axis=1)
    df.to_csv(save_file, index=False, header=not os.path.exists(save_file), mode='a')


if __name__ == "__main__":
    run()
