import sys
from datetime import datetime

from scapy.layers.l2 import Ether
import pandas as pd
sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import srp, sr
import conf
# 目标mDNS组播地址和端口


# local link address
def is_lla_ipv6(ip):
    return ip.startswith(("fe8", "fe9", "fea", "feb"))


# global unicast address
def is_gua_ipv6(ip):
    return ip.startswith(("2", "3"))


def create_service_type_enumeration_message():
    conf_info = conf.get_interface_info(conf.WLAN)
    src_mac = conf_info["mac"]
    src_ip = conf_info["ipv4_address"]
    dst_mac = "01:00:5e:00:00:fb"
    dst_ip = "224.0.0.251"
    eth_layer = Ether(src=src_mac, dst=dst_mac)
    ip_layer = IP(src=src_ip, dst=dst_ip, ttl=255)
    trans_layer = UDP(sport=5353, dport=5353)
    mdns_layer = DNS(id=0x0000, rd=1, qd=DNSQR(qtype="PTR", unicastresponse=0, qname='_services._dns-sd._udp.local'))
    packet = eth_layer/ip_layer/trans_layer/mdns_layer
    return packet


def create_service_query(service_list):
    conf_info = conf.get_interface_info(conf.WLAN)
    src_mac = conf_info["mac"]
    src_ip = conf_info["ipv4_address"]
    dst_mac = "01:00:5e:00:00:fb"
    dst_ip = "224.0.0.251"
    eth_layer = Ether(src=src_mac, dst=dst_mac)
    ip_layer = IP(src=src_ip, dst=dst_ip, ttl=255)
    trans_layer = UDP(sport=5353, dport=5353)
    dns_qr_list = [DNSQR(qtype="PTR", unicastresponse=0, qname=service) for service in service_list]
    mdns_layer = DNS(id=0x0000, rd=0, qd=dns_qr_list)
    packet = eth_layer/ip_layer/trans_layer/mdns_layer
    return packet


def extract_service_info(packet):
    if packet.haslayer(DNSRR):
        dns = packet.getlayer(DNS)
        if hasattr(dns, 'ar') and dns.ar:
            service_info = {
                "mac": None,
                "ip4": None,
                "hostname": None,
                "lla": None,
                "gua": None,
                "tua": None,
                "service": None,
                "service_instance": None,
                "target": None
            }
            for answer in dns.ar:
                if answer.type == 33:  # SRV
                    service_instance = answer.rrname.decode('utf-8')
                    service_info["service_instance"] = service_instance
                    hostname = answer.target.decode('utf-8')
                    port = answer.port
                    target = hostname + str(port)
                    service_info["target"] = target
                if answer.type == 1:  # A
                    hostname = answer.rrname.decode('utf-8')
                    service_info["hostname"] = hostname
                    service_info["ip4"] = answer.rdata
                if answer.type == 28:  # AAAA
                    hostname = answer.rrname.decode('utf-8')
                    service_info["hostname"] = hostname
                    ip6 = answer.rdata
                    if is_lla_ipv6(ip6):
                        lla = ip6
                        service_info["lla"] = lla
                    if is_gua_ipv6(ip6):
                        if service_info["gua"] is None:
                            service_info["gua"] = ip6
                        else:
                            service_info["tua"] = ip6
            return service_info
    else:
        return None


def extract_service_type(packet):
    service_list = []
    if packet.haslayer(DNSRR):
        dns = packet.getlayer(DNS)
        for answer in dns.an:
            if answer.type == 12:
                if answer.rdata.decode('utf-8') not in service_list and answer.rrname.decode(
                        'utf-8') == "_services._dns-sd._udp.local.":
                    service_list.append(answer.rdata.decode('utf-8'))
        return service_list
    else:
        return None


def run(interface="WLAN", save_path="D://Project/Scan6/result"):
    print("DNS-SD协议组播扫描中...")

    # 服务类型枚举模块
    packet = create_service_type_enumeration_message()
    response_answered_list, response_unanswered_list = srp(packet, verbose=0, timeout=1, iface=interface)
    service_list = []
    if response_answered_list:
        for response in response_answered_list:
            service_list += extract_service_type(response[1])
    if service_list:
        print(f"可用服务列表: {service_list}")
    else:
        print(f"未查询到任何服务")

    service_list = ['_companion-link._tcp.local.',
                    '_androidtvremote._tcp.local.',
                    '_dosvc._tcp.local.',
                    '_raop._tcp.local.',
                    '_rdlink._tcp.local.',
                    ]
    # 服务信息获取模块
    if service_list:
        packet = create_service_query(service_list)
        response_answered_list, response_unanswered_list = srp(packet, verbose=0, timeout=1, iface=interface)
    service_info_list = []
    if response_answered_list:
        for response in response_answered_list:
            service_info_list += extract_service_info(response[1])

    # 结果保存模块
    if service_info_list:
        print(service_info_list)
        df = pd.DataFrame(service_info_list)
        save_file = save_path + datetime.now().strftime("%Y-%m-%d %H-%M-%S") + ".csv"
        df.to_csv(save_file, index=False)
        print(f"数据已保存到 {save_file}")
    else:
        print(f"未扫描到任何数据")


if __name__ == "__main__":
    run()
