from scapy.utils import rdpcap
from scapy.layers.l2 import Ether
from scapy.layers.inet import UDP, IP
from scapy.layers.smb import BRWS_HostAnnouncement, SMB_Header, SMBTransaction_Request
import pandas as pd
import name_resolver


def handle_smb_packet(packet):
    """
    处理Browser协议的Host Announcement数据包，提取主机名
    """
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


def run():
    # 读取PCAP文件
    packets = rdpcap('../pacp/smb.pcapng')

    # 遍历数据包
    smb_info_list = []
    for pkt in packets:
        smb_info = handle_smb_packet(pkt)
        if smb_info:
            smb_info_list.append(smb_info)

    # 去除完全相同的行
    df = pd.DataFrame(smb_info_list)
    df_unique = df.drop_duplicates()
    # 按MAC列去重
    df_unique_mac = df_unique.drop_duplicates(subset=['mac'], keep='last')

    # 主机名解析
    ip6_info_list = []
    hostname_list = df_unique_mac['hostname']
    for hostname in hostname_list:
        if hostname:
            ip6_info = name_resolver.mdns(hostname)
            if ip6_info:
                ip6_info_list.append(ip6_info)
    df2 = pd.DataFrame(ip6_info_list)
    if not df2.empty:
        df_merged = pd.merge(df_unique_mac, df2, on="hostname", how="outer")
        df.sort_values("IP_int").drop("IP_int", axis=1)
        sorted_df = df_merged.sort_values("ip4")
        sorted_df.to_csv("../test/smb_pcap.csv", index=False)
        print(sorted_df)
    else:
        sorted_df = df_unique_mac.sort_values("ip4")
        sorted_df.to_csv("../test/smb_pcap.csv", index=False)
        print(sorted_df)


if __name__ == "__main__":
    run()
