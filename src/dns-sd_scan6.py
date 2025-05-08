import sys

from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1, srp1
import src.conf
# 目标mDNS组播地址和端口


# local link address
def is_lla_ipv6(ip):
    return ip.startswith(("fe8", "fe9", "fea", "feb"))


# global unicast address
def is_gua_ipv6(ip):
    return ip.startswith(("2", "3"))


def extract_info(packet):
    info = {
        "mac": packet[Ether].src,
        "ip4": None,
        "hostname": None,
        "lla": None,
        "gua": None,
        "service": None,
        "service_instance": None,
        "target": None,
    }
    if packet.haslayer(DNSRR):
        dns = packet.getlayer(DNS)
        if hasattr(dns, 'ar') and dns.ar:
            for answer in dns.ar:
                if answer.type == 33:  # SRV
                    service_instance = answer.rrname.decode('utf-8')
                    info["service_instance"] = service_instance
                    hostname = answer.target.decode('utf-8')
                    port = answer.port
                    target = hostname + str(port)
                    info["target"] = target
                if answer.type == 1:  # A
                    info["ip4"] = answer.rdata
                    hostname = answer.rrname.decode('utf-8')
                    info["hostname"] = hostname
                if answer.type == 28:  # AAAA
                    hostname = answer.rrname.decode('utf-8')
                    info["hostname"] = hostname
                    ip6 = answer.rdata
                    if is_lla_ipv6(ip6):
                        info["lla"] = ip6
                    if is_gua_ipv6(ip6):
                        info["gua"] = ip6
        return info
    else:
        return None


def extract_service(packet):
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


def get_service_list():
    dst_ip = "ff02::fb"
    dst_mac = "33:33:00:00:00:fb"
    conf_info = src.conf.get_interface_info(src.conf.WLAN)
    src_ip = conf_info["ipv6_address"]
    src_ip = "fe80::910c:e419:64df:f2f1"
    src_mac = conf_info["mac"]
    eth_layer = Ether(src=src_mac, dst=dst_mac)
    ip_layer = IPv6(src=src_ip, dst=dst_ip, hlim=255)
    mdns_layer = DNS(id=0x0000, qd=DNSQR(qtype="PTR", unicastresponse=0, qname='_service._dns-sd._udp.local.'))
    trans_layer = UDP(sport=5353, dport=5353)
    packet = eth_layer/ip_layer/trans_layer/mdns_layer
    response = srp1(packet, verbose=0, timeout=3, iface="WLAN")
    if response is not None:
        print(response.summary())
        return extract_service(response)
    else:
        return None


def get_service_info(service='_dosvc._tcp.local.'):
    dst_ip = "ff02::fb"
    dst_mac = "33:33:00:00:00:fb"
    conf_info = src.conf.get_interface_info(src.conf.WLAN)
    src_ip = conf_info["ipv6_address"]
    src_ip = "fe80::910c:e419:64df:f2f1"
    src_mac = conf_info["mac"]
    eth_layer = Ether(src=src_mac, dst=dst_mac)
    ip_layer = IPv6(src=src_ip, dst=dst_ip, hlim=255)
    mdns_layer = DNS(id=0x0000, rd=0, qd=DNSQR(qtype="PTR", unicastresponse=0, qname=service))
    trans_layer = UDP(sport=5353, dport=5353)
    packet = eth_layer/ip_layer/trans_layer/mdns_layer
    response = srp1(packet, verbose=0, timeout=3, iface="WLAN")
    if response is not None:
        print(response.summary())
        info = extract_info(response)
        print(info)
        return info
    else:
        return None


def get_info(service_list, dst_ip):
    dns_qr_list = [DNSQR(qtype="PTR", unicastresponse=1, qname=service) for service in service_list]
    mdns_layer = DNS(id=0x0000, rd=1, qd=dns_qr_list)
    trans_layer = UDP(sport=5353, dport=5353)
    ip_layer = IP(dst=dst_ip, ttl=255)
    packet = ip_layer/trans_layer/mdns_layer
    response = sr1(packet, verbose=0, timeout=1)
    if response:
        return extract_info(response)
    else:
        return None


def run(save_path="../result6/mdns_scan/"):
    info_list = []
    info = {
        "mac": None,
        "ip4": None,
        "hostname": None,
        "lla": None,
        "gua": [],
        "service": [],
        "service_instance": [],
        "target": [],
    }
    print("DNS-SD协议扫描中...")
    service_list = get_service_list()
    for service in service_list:
        service_info = get_service_info(service)

    # if service_list:
    #             info["service"] = service_list
    #             ar_info = get_info(service_list, str(ip))
    #             if ar_info is not None:
    #                 hostname, lla, gua_list, service_instance_list, target_list = ar_info
    #                 info["hostname"] = hostname
    #                 info["lla"] = lla
    #                 info["gua"] = gua_list
    #                 info["service_instance"] = service_instance_list
    #                 info["target"] = target_list
    #         info["gua"] = tuple(info["gua"])
    #         info["service"] = tuple(info["service"])
    #         info["service_instance"] = tuple(info["service_instance"])
    #         info["target"] = tuple(info["target"])
    #         print(info)
    #         info_list.append(info)
    # if info_list:
    #     df = pd.DataFrame(info_list)
    #     save_file = save_path + datetime.now().strftime("%Y-%m-%d %H-%M-%S")
    #     df.to_csv(save_file, index=False, mode='a')
    #     print(f"数据已保存到 {save_file}")


if __name__ == "__main__":
    run()
