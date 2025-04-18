from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether


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
        print(f"{info}")
        info_list.append(info)


if __name__ == "__main__":
    info_list = []
    # 捕获DHCP流量(端口67和68)
    try:
        print("捕获DHCP Discover/Request报文中...")
        sniff(filter="udp and (port 67 or port 68)", timeout=10, prn=handle_dhcp_packet, store=0)
    except KeyboardInterrupt:
        print("\n停止捕获，正在保存数据...")
