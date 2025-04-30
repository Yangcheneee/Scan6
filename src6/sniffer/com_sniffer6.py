import os
import sys
from datetime import datetime
from scapy.layers.inet6 import IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr
from scapy.layers.l2 import Ether
import pandas as pd
from scapy.all import sniff
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.netbios import NBNSQueryRequest, NBNSRegistrationRequest

sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')

# ========================== 全局配置 ==========================
GLOBAL_DEVICES = {}  # 核心数据结构: {mac: device_info}
LLA_PREFIX = ("fe80::", "fe80:")  # 链路本地地址前缀
GUA_PREFIX = ("2001:", "2000:")  # 全局单播地址前缀 (按需扩展)


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
            "nbns_name": None,
            "llmnr_name": None,
            "hostname": None,
            "ipv4": None,
            "ipv6_lla": None,
            "ipv6_gua": [],
            "nbns_info": [],
            "first_seen": datetime.now(),
            "last_seen": datetime.now()
        }

    device = GLOBAL_DEVICES[mac]

    # 合并策略
    device["hostname"] = new_data.get("hostname") or device["hostname"]
    device["ipv4"] = new_data.get("ipv4") or device["ipv4"]

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
        new_data = {"ipv6_lla": target_ip} if is_lla(target_ip) else {"ipv6_gua": [target_ip]}
        update_device_info(mac, new_data)

    except Exception as e:
        print(f"[ICMPv6 NA 解析错误] {e}")


def process_nbns_packet(packet):
    """处理 NBNS 协议（NetBIOS 名称服务）"""
    try:
        # 仅处理 NBNS 注册请求（Opcode=5 为注册请求）
        nbns_name = packet[NBNSRegistrationRequest].QUESTION_NAME
        hostname = nbns_name
        print(nbns_name)
        # hostname = decode_netbios_name(nbns_name)

        # 获取 MAC 地址（NBNS 在 IPv4 层，需从以太网层取 MAC）
        mac = packet[Ether].src

        # 更新设备信息
        if hostname:
            update_device_info(mac, {"nbns_info": hostname})
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
    except Exception as e:
        print(f"[数据包处理异常] {e}")


def run(interface="WLAN", duration=600, save_path="result"):
    """主捕获循环"""
    try:
        print(f"[*] 开始捕获 {duration} 秒...")
        sniff(
            iface=interface,
            prn=process_packet,
            filter="icmp6 or udp port 5353 or 137",  # mDNS 和 ICMPv6
            timeout=duration,
            store=0
        )
    except KeyboardInterrupt:
        print("\n[!] 用户中断捕获")
    finally:
        # 保存结果
        if GLOBAL_DEVICES:
            df = pd.DataFrame(GLOBAL_DEVICES.values())
            print(df)
            df = df[["mac", "hostname", "ipv4", "ipv6_lla", "ipv6_gua", "first_seen", "last_seen"]]

            # 生成文件名
            os.makedirs(save_path, exist_ok=True)
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            csv_file = os.path.join(save_path, f"devices_{timestamp}.csv")

            df.to_csv(csv_file, index=False)
            print(f"[+] 数据已保存至: {csv_file}")
        else:
            print("[!] 未捕获到有效数据")


if __name__ == "__main__":
    run(duration=10)  # 测试运行10秒