from scapy.all import *
import time

from scapy.layers.l2 import Ether


# 定义SSDP发现请求报文
def create_ssdp_discovery_request():
    # SSDP发现请求的固定格式
    ssdp_request = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        # "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 10\r\n"  # 最大等待时间（秒）
        "ST: ssdp:all\r\n"  # 搜索目标（ssdp:all 表示所有设备）
        "\r\n"
    )
    return ssdp_request

# 发送SSDP发现请求
def send_ssdp_discovery():
    # 构造IP和UDP层
    ether = Ether(src="48:a4:72:e6:72:bf",dst="01:00:5e:7f:ff:fa")
    ip = IP(src="192.168.3.89",dst="239.255.255.250")  # SSDP多播地址
    udp = UDP(dport=1900, sport=RandShort())  # 目标端口1900，源端口随机
    # 构造SSDP请求报文
    ssdp_request = create_ssdp_discovery_request()
    # 发送报文
    p = srp1(ether/ip/udp/ssdp_request, verbose=False,timeout=3,iface="WLAN")
    if p:
        p.show()

# 监听SSDP响应
def listen_ssdp_responses(timeout=5):
    print("[*] Listening for SSDP responses...")
    # 使用sniff函数捕获响应报文
    responses = sniff(filter="udp and port 1900", timeout=timeout)
    # 解析响应
    for packet in responses:
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load.decode("utf-8", errors="ignore")
            if "HTTP/1.1 200 OK" in raw_data:  # 检查是否为SSDP响应
                print(f"[+] Found device: {packet[IP].src}")
                print(raw_data)  # 打印完整的响应内容
                print("-" * 50)


# 主函数
def main():
    print("[*] Sending SSDP discovery request...")
    send_ssdp_discovery()  # 发送SSDP发现请求
    # time.sleep(1)  # 等待1秒，确保请求发送完成
    listen_ssdp_responses()  # 监听并解析响应


if __name__ == "__main__":
    main()