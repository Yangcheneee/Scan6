import os
import sys
from datetime import datetime
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dhcp6 import DHCP6_Solicit, DHCP6_InfoRequest, DHCP6OptClientFQDN, DHCP6OptVendorClass
from scapy.layers.inet6 import IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, ICMPv6EchoReply
from scapy.layers.inet6 import ICMPv6MLReport, ICMPv6MLQuery  # MLDv1/v2 协议层
from scapy.layers.l2 import Ether, ARP
import pandas as pd
from scapy.all import sniff
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.netbios import NBNSQueryRequest, NBNSRegistrationRequest
from scapy.layers.netbios import NBTDatagram
from scapy.layers.smb import BRWS_HostAnnouncement, SMB_Header
from scapy.utils import rdpcap

sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')

# ========================== 全局配置 ==========================
GLOBAL_DEVICES = {}  # 核心数据结构: {mac: device_info}
LLA_PREFIX = ("fe80::", "fe80:")  # 链路本地地址前缀
GUA_PREFIX = ("2", "3")  # 全局单播地址前缀 (按需扩展)
IANA_ENTERPRISE_NUMBERS = {
    9: "ciscoSystems",
    35: "Nortel Networks",
    43: "3Com",
    311: "Microsoft",
    2636: "Juniper Networks, Inc.",
    4526: "Netgear",
    5771: "Cisco Systems, Inc.",
    5842: "Cisco Systems",
    11129: "Google, Inc",
    16885: "Nortel Networks",
}


# ========================== 工具函数 ==========================
def is_lla(ip: str) -> bool:
    """判断是否为链路本地地址"""
    return any(ip.startswith(prefix) for prefix in LLA_PREFIX)


def is_gua(ip: str) -> bool:
    """判断是否为全局单播地址"""
    return any(ip.startswith(prefix) for prefix in GUA_PREFIX)


def update_device_info(mac: str, new_data: dict):
    """合并新旧设备信息（基于 MAC 地址）"""
    if mac not in GLOBAL_DEVICES:
        GLOBAL_DEVICES[mac] = {
            "mac": mac,
            "hostname": None,
            "nbns_name": None,
            "llmnr_name": None,
            "mdns_name": None,
            "dhcp_name": None,
            "ipv4": None,
            "ipv6_lla": None,
            "ipv6_gua": [],
            "nbns_info": [],
            "os_version": None,
            "enterprise": None,
            "vendor_class": None,
            "first_seen": datetime.now(),
            "last_seen": datetime.now()
        }

    device = GLOBAL_DEVICES[mac]

    # 合并策略
    device["hostname"] = new_data.get("hostname") or device["hostname"]
    device["ipv4"] = new_data.get("ipv4") or device["ipv4"]
    device["nbns_name"] = new_data.get("nbns_name") or device["nbns_name"]
    device["dhcp_name"] = new_data.get("dhcp_name") or device["dhcp_name"]
    device["os_version"] = new_data.get("os_version") or device["os_version"]
    device["enterprise"] = new_data.get("enterprise") or device["enterprise"]
    device["vendor_class"] = new_data.get("vendor_class") or device["vendor_class"]

    # IPv6 地址处理
    if new_data.get("ipv6_lla"):
        device["ipv6_lla"] = new_data["ipv6_lla"]
    if new_data.get("ipv6_gua"):
        device["ipv6_gua"] = list(set(device["ipv6_gua"] + new_data["ipv6_gua"]))

    device["last_seen"] = datetime.now()


# ========================== 协议解析 ==========================
def process_icmpv6_na(packet):
    """处理 ICMPv6 邻居通告（携带 MAC 和 IPv6 地址）"""
    try:
        na = packet[ICMPv6ND_NA]
        mac = packet[Ether].src
        target_ip = na.tgt

        # 构建数据
        if is_lla(target_ip):
            new_data = {"ipv6_lla": target_ip}
        elif is_lla(target_ip):
            new_data = {"ipv6_gua": [target_ip]}
        else:
            new_data = {}
        update_device_info(mac, new_data)

    except Exception as e:
        print(f"[ICMPv6 NA 解析错误] {e}")


def process_icmpv6_mld(packet):
    """处理 MLD 报告（Membership Report）"""
    try:
        # 检查是否为 MLD 报告（ICMPv6 Type=143）
        if packet.haslayer(ICMPv6MLReport):
            # 提取源 MAC 地址
            mac = packet[Ether].src

            ipv6_lla = packet[IPv6].src
            # # 提取组播地址列表
            # mld = packet[ICMPv6MLReport]
            # multicast_groups = set()
            #
            # # 遍历组记录（MLDv2 支持多组）
            # for record in mld.mldaddrrecords:
            #     multicast_groups.add(record.mcastaddr)

            # 更新设备信息
            update_device_info(mac, {"ipv6_lla": ipv6_lla})
    except Exception as e:
        print(f"[MLD 解析错误] {e}")


def process_icmpv6_echo_reply(packet):
    """处理 ICMPv6 Echo Reply（Ping 回复）"""
    try:
        # 检查是否为 Echo Reply（Type=129）
        if packet.haslayer(ICMPv6EchoReply):
            # 提取源 IPv6 地址和目标 IPv6 地址
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst

            # 提取 MAC 地址（需从以太网层获取，适用于本地网络）
            mac = packet[Ether].src

            # 更新设备信息（关联 MAC 和 IPv6 地址）
            update_device_info(mac, {
                "ipv6_lla": src_ip if is_lla(src_ip) else None,
                "ipv6_gua": [src_ip] if is_gua(src_ip) else [],
            })
    except Exception as e:
        print(f"[ICMPv6 Echo Reply 解析错误] {e}")


def process_netbios_browser(packet):
    """处理 NetBIOS Browser 协议 Announcement 报文"""
    try:
        # 检查是否为 Announcement 报文（Browser Election 或 Host Announcement）
        if packet.haslayer(SMB_Header):
            smb_com = packet.getlayer(5)
            data = smb_com.Buffer[0]
            if data[1].haslayer(BRWS_HostAnnouncement):
                browser = data[1].getlayer(BRWS_HostAnnouncement)
                # 提取源 MAC 地址
                mac = packet[Ether].src

                # 提取服务器名称和域名
                server_name = browser.ServerName.decode('utf-8', errors='ignore').strip('\x00 ')
                os_version = "Windows " + str(browser.OSVersionMajor) + "." + str(browser.OSVersionMinor)

                # 更新设备信息
                update_device_info(mac, {
                    "hostname": server_name,
                    "os_version": os_version
                })
    except Exception as e:
        print(f"[NetBIOS Browser 解析错误] {e}")


def process_nbns_packet(packet):
    """处理 NBNS 协议（NetBIOS 名称服务）"""
    try:
        # 仅处理 NBNS 注册请求（Opcode=5 为注册请求）
        nbns_name = packet[NBNSRegistrationRequest].QUESTION_NAME.decode('utf-8').strip(' ')
        if nbns_name == "WORKGROUP":
            return

        # 获取 MAC 地址（NBNS 在 IPv4 层，需从以太网层取 MAC）
        mac = packet[Ether].src

        # 更新设备信息
        if nbns_name:
            update_device_info(mac, {"nbns_name": nbns_name})
    except Exception as e:
        print(f"[NBNS 解析错误] {e}")


def process_mdns_packet(packet):
    """处理 mDNS 响应（携带主机名、IPv4、IPv6）"""
    try:
        dns = packet[DNS]
        if dns.qr != 1:  # 仅处理响应包
            return

        mac = packet[Ether].src
        new_data = {"hostname": None, "ipv4": None, "ipv6_lla": None, "ipv6_gua": []}

        # 解析 Answer 和 Additional 记录
        for section in [dns.an, dns.ar]:
            for answer in section:
                if answer.type == 1:  # A 记录 (IPv4)
                    new_data["hostname"] = answer.rrname.decode().rstrip('.')
                    new_data["ipv4"] = answer.rdata
                elif answer.type == 28:  # AAAA 记录 (IPv6)
                    ip = answer.rdata
                    if is_lla(ip):
                        new_data["ipv6_lla"] = ip
                    elif is_gua(ip):
                        new_data["ipv6_gua"].append(ip)

        update_device_info(mac, new_data)

    except Exception as e:
        print(f"[mDNS 解析错误] {e}")


def process_dhcp_packet(packet):
    """处理 DHCP 请求（携带主机名、IPv4）"""
    try:
        mac = packet[Ether].src

        new_data = {"dhcp_name": None, "vendor_class": None, "ipv4": None}
        for option in packet[DHCP].options:
            if isinstance(option, tuple):
                if option[0] == 'hostname':  # Option 12
                    new_data["hostname"] = option[1].decode('utf-8', errors='ignore')
                if option[0] == 'vendor_class_id':  # Option 60
                    new_data["vendor_class"] = option[1].decode()
                if option[0] == 'requested_addr':  # Option 50
                    new_data["ipv4"] = option[1]

        update_device_info(mac, new_data)

    except Exception as e:
        print(f"[DHCP 解析错误] {e}")


def process_dhcpv6_packet(packet):
    """处理 DHCPv6 请求（携带主机名、IPv6）"""
    try:
        mac = packet[Ether].src

        new_data = {"dhcp_name": None, "enterprise": None, "vendor_class": None}
        # 提取域名信息
        if DHCP6OptClientFQDN in packet:
            domain_name = packet[DHCP6OptClientFQDN].fqdn
            new_data["dhcp_name"] = domain_name.decode('utf-8')

        # 提取Vendor Class信息
        if DHCP6OptVendorClass in packet:
            vendor_class = packet[DHCP6OptVendorClass]
            new_data["enterprise"] = IANA_ENTERPRISE_NUMBERS[vendor_class.enterprisenum]
            for data in vendor_class.vcdata:
                new_data["vendor_class"] = data.data.decode('utf-8')

        update_device_info(mac, new_data)

    except Exception as e:
        print(f"[DHCPv6 解析错误] {e}")


def process_arp_reply(packet):
    pass


# ========================== 主流程 ==========================


def process_packet(packet):
    """统一处理数据包分发"""
    try:
        if packet.haslayer(ICMPv6ND_NA):
            process_icmpv6_na(packet)
        elif packet.haslayer(DNS):
            process_mdns_packet(packet)
        elif packet.haslayer(NBNSRegistrationRequest):
            process_nbns_packet(packet)
        elif packet.haslayer(ICMPv6MLReport):
            process_icmpv6_mld(packet)
        elif packet.haslayer(ICMPv6EchoReply):
            process_icmpv6_echo_reply(packet)
        elif packet.haslayer(DHCP6_Solicit) or packet.haslayer(DHCP6_InfoRequest):
            process_dhcpv6_packet(packet)
        elif packet.haslayer(DHCP):
            process_dhcp_packet(packet)
        elif packet.haslayer(SMB_Header):
            process_netbios_browser(packet)
        elif packet.haslayer(ARP):
            process_arp_reply(packet)
    except Exception as e:
        print(f"[数据包处理异常] {e}")


def run(dir_path="data/all/", save_file="D:/Project/Scan6/src/pcap/result/com_pcap.csv"):
    # 遍历目录中的pcap文件
    file_list = []
    for filename in os.listdir(dir_path):
        if filename.lower().endswith(('.pcap', '.pcapng')):
            full_path = os.path.join(dir_path, filename)
            file_list.append(full_path)
    for file in file_list:
        print(f"\n[*] 正在分析文件: {file}")
        packets = rdpcap(file)
        for pkt in packets:
            process_packet(pkt)
    if GLOBAL_DEVICES:
        df = pd.DataFrame(GLOBAL_DEVICES.values())
        df = df[["mac", "ipv4", "hostname", "ipv6_lla", "ipv6_gua",
                 "nbns_name", "dhcp_name", "enterprise", "vendor_class",
                 "first_seen", "last_seen"]]
        # 生成文件名
        df.to_csv(save_file, index=False)
        print(f"[+] 数据已保存至: {save_file}")
    else:
        print("[!] 未捕获到有效数据")


if __name__ == "__main__":
    run()
