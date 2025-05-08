import sys

sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
from scapy.sendrecv import srp1
import src6.scan.conf
INTERFACE_ID = {
    "ETH": "{E9812809-EC44-4F9B-AA3F-A4EDF0835213}",
    "WLAN": "{F52FC252-BAEC-4BA6-A8CA-8706641245A6}"
}
mdns_mac = "01:00:5E:00:00:FB"
mdns_ip = "224.0.0.251"
# link local address


def is_lla_ipv6(ip):
    if ip.startswith("fe80"):
        return True


# unicast address
def is_gua_ipv6(ip):
    if ip.startswith("2"):
        return True


def process_packet(packet, name):
    try:
        if packet.haslayer(DNS):
            dns = packet.getlayer(DNS)
            # 检查是否有响应记录,QR=1表示响应
            if dns.qr == 1:
                info = {
                    "lla": None,
                    "gua": []
                }
                for answer in dns.an:
                    if isinstance(answer, DNSRR) and answer.type == 28:    # AAAA
                        if name == answer.rrname.decode('utf-8').split(".")[0]:
                            ip = answer.rdata
                            if is_lla_ipv6(ip):
                                info["lla"] = ip
                            if is_gua_ipv6(ip):
                                info["gua"].append(ip)
                return info
    except Exception as e:
        print(f"捕获数据包时发生错误: {e}")


def mdns(name):
    conf_info = src6.scan.conf.Conf(INTERFACE_ID["WLAN"])
    src_mac = conf_info.mac
    src_ip = conf_info.ipv4
    ether_layer = Ether(src=src_mac, dst=mdns_mac)
    ip_layer = IP(dst=mdns_ip, src=src_ip)
    trans_layer = UDP(sport=5353, dport=5353)
    mdns_layer = DNS(rd=1, qd=DNSQR(qtype="AAAA", unicastresponse=0, qname=name + ".local"))
    packet = ether_layer/ip_layer/trans_layer/mdns_layer
    response = srp1(packet, verbose=0, timeout=1, iface="WLAN")
    if response:
        info = process_packet(response, name)
        return info
    else:
        return None


if __name__ == "__main__":
    name = "DESKTOP-G1AD8NT"
    info = mdns(name)
    print(info)


    
