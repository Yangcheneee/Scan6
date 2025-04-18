from scapy.all import *
import pandas as pd
from scapy import *
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
from scapy.layers.netbios import NBTSession, NetBIOS_DS, NBNSHeader, NBTDatagram
from scapy.layers.smb import BRWS, BRWS_HostAnnouncement, SMB_Header, SMBTransaction_Request, SMBMailslot_Write
from scapy.utils import rdpcap
from SRC import name_resolver


def generate_smb_packet():
    ip_layer = IP(dst="172.31.99.255")
    udp_layer = UDP(sport=138, dport=138)
    nbds_layer = NBTDatagram(Type=17, Flags=0x0a, SourceIP="172.31.99.79", SourcePort=138, SourceName="DESKTOP-8DUN5OR<00>", DestinationName="WORKGROUP")
    smb_header = SMB_Header(Command=0x25, Flags=0x00)
    trans_request = SMBTransaction_Request(DataLen=11, Timeout=0, WordCount=17, TotalDataCount=11, DataBufferOffset=86,
                                           Data=b'\x02\x01\x00\x48\x50\x41\x45\x42\x44\x31\x33', ByteCount=28)
    trans_request = Raw(bytes.fromhex("1100000b000000000000000000000000000000000000000b00560003000100010002001c005c4d41494c534c4f545c42524f575345000201004850414542443133"))
    # mailslot = Raw(b'\x01\x00\x01\x00\x02\x00\x1c\x00\x5c\x4d\x41\x49\x4c\x53\x4c\x4f\x54\x5c\x42\x52\x4f\x57\x53\x45\x00')
    # browser = Raw(b'\x02\x01\x00\x48\x50\x41\x45\x42\x44\x31\x33')
    # smb_mailslot = SMBMailslot_Write()
    # nbds_layer.show()
    # smb_header.show()
    # trans_request.show()
    # browser.show()
    packet = ip_layer / udp_layer / nbds_layer / smb_header/trans_request
    # smb_mailslot.show()
    send(packet, verbose=0)


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
                print(info)
            info_list.append(info)


if __name__ == "__main__":
    generate_smb_packet()
    wait_time = 60
    info_list = []
    # 捕获DHCP流量(端口67和68)
    try:
        print("捕获SMB报文中...")
        sniff(filter="udp and port 138", timeout=wait_time, prn=handle_smb_packet, store=0, iface="WLAN")
    except KeyboardInterrupt:
        print("\n停止捕获，正在保存数据...")

    # 去除完全相同的行
    df = pd.DataFrame(info_list)
    df_unique = df.drop_duplicates()
    # print(df_unique)
    # 或者按MAC列去重
    df_unique_mac = df_unique.drop_duplicates(subset=['mac'], keep='last')
    # print(df_unique_mac)
    hostname_list = df['hostname']
    ip6_info_list =
    for hostname in hostname_list:
        ip6_info = name_resolver.mdns(hostname_list)
    # print(hostname_list)
