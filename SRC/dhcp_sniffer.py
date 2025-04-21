from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.l2 import Ether
import pandas as pd
from datetime import datetime
import name_resolver

info_list = []


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
            "lla": None,
            "gua": [],
            "vendor": None,
            # "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
        if info["hostname"] is not None:
            ip6_info = name_resolver.mdns(info["hostname"])
            if ip6_info is not None:
                info["lla"] = ip6_info["lla"]
                info["gua"] = ip6_info["gua"]
        print(info)
        info_list.append(info)


def run(duration=10*60, interface="WLAN", save_file="../result/dhcp_sniffer.csv"):
    # 捕获DHCP流量(端口67和68)
    try:
        print("捕获DHCP Discover/Request报文中...")
        sniff(iface=interface, filter="udp and (port 67 or port 68)", timeout=duration, prn=handle_dhcp_packet, store=0)
    except KeyboardInterrupt:
        print("\n停止捕获，正在保存数据...")
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
    run()
