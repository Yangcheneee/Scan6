import sys
import time

sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.llmnr import LLMNRQuery
from scapy.layers.inet import UDP, IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.sendrecv import srp1, sendp
from Conf.conf import Conf

# link local address
def is_lla_ipv6(ip):
    if ip.startswith("fe80:"):
        return True


# unicast address
def is_gua_ipv6(ip):
    if ip.startswith("2"):
        return True


def process_packet(packet, target_hostname):
    try:
        if packet.haslayer(DNS):
            dns = packet.getlayer(DNS)
            # 检查是否有响应记录
            if dns.qr == 1:  # QR=1表示响应
                info = {
                    "lla": None,
                    "gua": None
                }
                for answer in dns.an:
                    if isinstance(answer, DNSRR) and answer.type == 28:    # AAAA
                        ip = answer.rdata
                        if is_lla_ipv6(ip):
                            info["lla"] = ip
                        if is_gua_ipv6(ip):
                            if info["gua"] is None:
                                info["gua"] = []
                                info["gua"].append(ip)
                            else:
                                info["gua"].append(ip)
                return info
    except Exception as e:
        print(f"捕获数据包时发生错误: {e}")


def mdns(name):
    conf = Conf()
    src_mac = conf.mac
    src_ip = conf.ip4
    # mdns_multicast
    dst_mac = "01:00:5E:00:00:FB"
    dst_ip = "224.0.0.251"
    info_list = []
    # query all service name
    ether_layer = Ether(src=src_mac, dst=dst_mac)
    ip_layer = IP(dst=dst_ip, src=src_ip)
    trans_layer = UDP(sport=5353, dport=5353)
    mdns_layer = DNS(rd=1, qd=DNSQR(qtype="AAAA", unicastresponse=0, qname=name + ".local"))
    packet = ether_layer/ip_layer/trans_layer/mdns_layer
    # packet.show()
    sendp(packet, verbose=0,  iface="WLAN")
    response = srp1(packet, verbose=0, timeout=5, iface="WLAN")
    if response:
        # response.show()
        # print("response!")
        # response.summary()
        info = process_packet(response, name + ".local")
        # print("response!")
        return info
    else:
        # print("no response!")
        return None


def mdns6(name_list):
    conf = Conf()
    src_mac = conf.mac
    src_ip = conf.lla
    # mdns_multicast
    dst_mac = "33:33:00:00:00:fb"
    dst_ip = "ff02::fb"
    for name in name_list:
        # query all service name
        ether_layer = Ether(src=src_mac, dst=dst_mac)
        ip_layer = IPv6(dst=dst_ip, src=src_ip)
        trans_layer = UDP(sport=5353, dport=5353)
        mdns_layer = DNS(rd=1, qd=DNSQR(qtype="AAAA", unicastresponse=0, qname=name + ".local"))
        packet = ether_layer/ip_layer/trans_layer/mdns_layer
        # packet.show()
        sendp(packet, verbose=0,  iface="WLAN")
        # response = srp1(packet, verbose=0, timeout=5, iface="WLAN")
        # if response:
        #     response.show()
        #     print("response!")
        # else:
        #     print("no response!")


def llmnr(name_list):
    conf = Conf()
    src_mac = conf.mac
    src_ip = conf.ip4
    dst_mac = "01:00:5e:00:00:fc"
    dst_ip = "224.0.0.252"
    for name in name_list:
        # query all service name
        ether_layer = Ether(src=src_mac, dst=dst_mac)
        ip_layer = IP(dst=dst_ip, src=src_ip)
        trans_layer = UDP(sport=53555, dport=5355)
        llmnr_layer = LLMNRQuery(id=0xb6d2, qd=DNSQR(qtype="AAAA", qname=name))
        packet = ether_layer/ip_layer/trans_layer/llmnr_layer
        # packet.show()
        sendp(packet, verbose=1, iface="WLAN")
        time.sleep(1)
        # response = srp1(packet, verbose=1, timeout=2, iface="WLAN")
        # if response:
        #     response.show()
        #     print("response!")
        # else:
        #     print("no response!")


def llmnr6(name_list):
    conf = Conf()
    src_mac = conf.mac
    src_ip = conf.lla
    dst_mac = "33:33:00:01:00:03"
    dst_ip = "ff02::1:3"
    for name in name_list:
        # query all service name
        ether_layer = Ether(src=src_mac, dst=dst_mac)
        ip_layer = IPv6(dst=dst_ip, src=src_ip)
        trans_layer = UDP(sport=53555, dport=5355)
        mdns_layer = DNS(id=0xb6d2, rd=0, qd=DNSQR(qtype="AAAA", unicastresponse=0, qname=name))
        packet = ether_layer/ip_layer/trans_layer/mdns_layer
        # packet.show()
        response = srp1(packet, verbose=1, timeout=2, iface="WLAN")
        # if response:
        #     # response.show()
        #     print("response!")
        # else:
        #     print("no response!")


if __name__ == "__main__":
    info_list = []
    name_list = ["DESKTOP-G1AD8NT"]
    mdns(name_list)
    for info in info_list:
        print(info)
    # mdns6(name_list)
    # llmnr6(name_list)
    # llmnr(name_list)


    
