from scapy.layers.dhcp import DHCP, BOOTP
import pandas as pd
from scapy import *
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
from scapy.layers.netbios import NBTSession, NetBIOS_DS, NBNSHeader
from scapy.layers.smb import BRWS_HostAnnouncement, SMB_Header, SMBTransaction_Request
from scapy.utils import rdpcap


def handle_smb_packet(packet):
    """
    处理Browser协议的Host Announcement数据包，提取主机名
    """
    if packet.haslayer(UDP) and packet.dport == 138:  # NetBIOS Datagram Service
        # 检查是否是SMB协议
        # packet.show()
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


if __name__ == "__main__":
    # 读取PCAP文件
    packets = rdpcap('../data/smb.pcapng')

    info_list = []
    # 遍历数据包
    for pkt in packets:
        info = handle_smb_packet(pkt)
        if info:
            info_list.append(info)
    # 去除完全相同的行
    df = pd.DataFrame(info_list)
    df_unique = df.drop_duplicates()
    # print(df_unique)
    # 或者按MAC列去重
    df_unique_mac = df_unique.drop_duplicates(subset=['mac'], keep='last')
    print(df_unique_mac)
    # # 保存结果（可选）
    df_unique_mac.to_csv('../data/smb.csv', index=False)
