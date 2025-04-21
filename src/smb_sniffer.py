from scapy.all import *
import pandas as pd
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
from scapy.layers.netbios import NBTSession, NetBIOS_DS, NBNSHeader
from scapy.layers.smb import BRWS_HostAnnouncement, SMB_Header, SMBTransaction_Request
import name_resolver

info_list = []


def handle_smb_packet(packet):
    """
    处理Browser协议的Host Announcement数据包，提取主机名
    """
    try:
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
                        "server": None,
                        # "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
    except Exception as e:
        print(f"解析数据包时发生错误: {e}")


def run(interface="WLAN", duration=12*60, save_file="../result6/smb_sniffer.csv"):
    update_periodicity_minutes = 12
    try:
        print("捕获SMB报文中...")
        sniff(filter="udp and port 138", timeout=duration, prn=handle_smb_packet, store=0, iface=interface)
    except KeyboardInterrupt:
        print("\n停止捕获，正在保存数据...")
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
    run(duration=30)
