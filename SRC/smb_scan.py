from scapy.all import *
import pandas as pd
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
from scapy.layers.netbios import NBTDatagram
from scapy.layers.smb import BRWS_HostAnnouncement, SMB_Header, SMBTransaction_Request
import name_resolver
import conf

info_list = []


def generate_smb_packet(broadcast):
    conf_info = conf.get_interface_info(conf.WLAN)
    ip_layer = IP(dst=broadcast)
    udp_layer = UDP(sport=138, dport=138)
    nbds_layer = NBTDatagram(Type=17, Flags=0x0a, SourceIP=conf_info["ipv4_address"], SourcePort=138, SourceName=socket.gethostname() + "<00>", DestinationName="WORKGROUP")
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
    send(packet, verbose=0)


def handle_smb_packet(packet):
    """
    处理Browser协议的Host Announcement数据包，提取主机名
    """
    if packet.haslayer(UDP) and packet.dport == 138:  # NetBIOS Datagram Service
        # 检查是否是SMB协议
        if packet.haslayer(SMB_Header):
            smb_com = packet.getlayer(5)
            data = smb_com.Buffer[0]
            if data[1].haslayer(BRWS_HostAnnouncement):
                info = {
                    "mac": packet[Ether].src,
                    "ip4": packet[IP].src,
                    "hostname": None,
                    "lla": None,
                    "gua": [],
                    "os": None,
                    "server": None
                }
                browser = data[1].getlayer(BRWS_HostAnnouncement)
                info["hostname"] = browser.ServerName.decode()[:15]
                info["os"] = str(browser.OSVersionMajor) + "." + str(browser.OSVersionMinor)
                info["server"] = browser.ServerType
                ip6_info = name_resolver.mdns(info["hostname"])
                if ip6_info is not None:
                    info["lla"] = ip6_info["lla"]
                    info["gua"] = ip6_info["gua"]
                info["gua"] = tuple(info["gua"])
                print(info)
                info_list.append(info)


def run(target="172.31.99.255", interface="WLAN", save_path="../result/smb_scan/"):
    print("MS-BRWS协议扫描中...")
    generate_smb_packet(target)
    wait_time = 30
    # 捕获DHCP流量(端口67和68)
    try:
        sniff(filter="udp and port 138", timeout=wait_time, prn=handle_smb_packet, store=0, iface=interface)
    except KeyboardInterrupt:
        print("\n停止捕获，正在保存数据...")
    finally:
        if info_list:
            df = pd.DataFrame(info_list)
            # 去除完全重复的行（所有列值相同）
            # df = df.drop_duplicates()
            # 或者按MAC列去重
            # df_unique_mac = df_unique.drop_duplicates(subset=['hostname'], keep='last')
            save_file = save_path + datetime.now().strftime("%Y-%m-%d %H-%M-%S")
            df.to_csv(save_file, index=False, mode='a')
            print(f"数据已保存到 {save_file}")
        else:
            print("未捕获到数据，未生成文件。")


if __name__ == "__main__":
    run()
