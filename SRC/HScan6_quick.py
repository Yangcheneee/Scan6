import sys
from scapy.layers.l2 import Ether, ARP
sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1
from IPy import IP as IPY
from tqdm import tqdm


# local link address
def is_lla_ipv6(ip):
    return ip.startswith(("fe8", "fe9", "fea", "feb"))


# global unicast address
def is_gua_ipv6(ip):
    return ip.startswith(("2", "3"))


def extract_info(packet):
    service_instance_list = []
    target_list = []
    hostname_list = []
    lla_list = []
    gua_list = []
    if packet.haslayer(DNSRR):
        dns = packet.getlayer(DNS)
        if hasattr(dns, 'ar') and dns.ar:
            for answer in dns.ar:
                if answer.type == 33:  # SRV
                    service_instance = answer.rrname.decode('utf-8')
                    service_instance_list.append(service_instance)
                    hostname = answer.target.decode('utf-8')
                    port = answer.port
                    target = hostname + str(port)
                    target_list.append(target)
                if answer.type == 1:  # A
                    # answer.show()
                    hostname = answer.rrname.decode('utf-8')
                    # ip4 = answer.rdata
                    # info["ip4"].append(ip4)
                    hostname_list.append(hostname)
                if answer.type == 28:  # AAAA
                    # answer.show()
                    ip6 = answer.rdata
                    if is_lla_ipv6(ip6):
                        lla_list.append(ip6)
                    if is_gua_ipv6(ip6):
                        gua_list.append(ip6)
        return hostname_list, lla_list, gua_list, service_instance_list, target_list
    else:
        return None


def extract_service(packet):
    service_list = []
    # packet.show()
    if packet.haslayer(DNSRR):
        # packet.show()
        dns = packet.getlayer(DNS)
        for answer in dns.an:
            # answer.show()
            if answer.type == 12:
                #  == "_services._dns-sd._udp.local"
                # print(answer.rrname.decode('utf-8'))
                if answer.rdata.decode('utf-8') not in service_list and answer.rrname.decode(
                        'utf-8') == "_services._dns-sd._udp.local.":
                    service_list.append(answer.rdata.decode('utf-8'))
                    # print(service_list)
        return service_list
    else:
        return None


def get_service_list(dst_ip):
    # DNS Services Discovery: _services._dns-sd._udp.local
    mdns_layer = DNS(id=0x0000, rd=1, qd=DNSQR(qtype="PTR", unicastresponse=1, qname='_services._dns-sd._udp.local'))
    trans_layer = UDP(sport=5353, dport=5353)
    # 注意这个地方源端口不能为5353
    ip_layer = IP(dst=dst_ip)
    # 注意这个地方dst_ip必须是mDNS组播IP
    packet = ip_layer/trans_layer/mdns_layer
    # packet.show()
    response = sr1(packet, verbose=0, timeout=1)
    if response:
        return extract_service(response)
    else:
        return None


def get_info(service_list, dst_ip):
    # 创建DNS查询记录列表
    dns_qr_list = [DNSQR(qtype="PTR", unicastresponse=1, qname=service) for service in service_list]
    # 创建mDNS层
    mdns_layer = DNS(id=0x0000, rd=1, qd=dns_qr_list)
    # DNS Services Discovery: _services._dns-sd._udp.local
    trans_layer = UDP(sport=5353, dport=5353)
    # 注意这个地方源端口不能为5353
    ip_layer = IP(dst=dst_ip, ttl=255)
    packet = ip_layer/trans_layer/mdns_layer
    # packet.show()
    response = sr1(packet, verbose=0, timeout=1)
    if response:
        # response.show()
        return extract_info(response)
    else:
        return None


def is_alive(dst_ip):
    pkt = ARP(pdst=dst_ip)
    ans = sr1(pkt, timeout=1, verbose=False)
    if ans is not None:
        if ans.haslayer(ARP) and ans[ARP].op == 2:
            src_mac = ans[ARP].hwsrc
            src_ip = ans[ARP].psrc
            return src_mac, src_ip
        else:
            return None
    else:
        return None


if __name__ == "__main__":
    # info_list = []
    dst_ip_list = IPY("172.31.99.0/24")
    # dst_ip_list = ["172.31.99.180"]
    for ip in dst_ip_list:
        # print(f"{ip} scaning...")
        arp_result = is_alive(str(ip))
        if arp_result is not None:
            info = {
                "mac": [],
                "ip4": [],
                "hostname": [],
                "lla": [],
                "gua": [],
                "service": [],
                "service_instance": [],
                "target": [],
            }
            mac, ip4 = arp_result
            info["mac"].append(mac)
            info["ip4"].append(ip4)
            service_list = get_service_list(str(ip))
            if service_list is not None:
                info["service"] = service_list
                ar_info = get_info(service_list, str(ip))
                if ar_info:
                    hostname_list, lla_list, gua_list, service_instance_list, target_list = ar_info
                    info["hostname"] = hostname_list
                    info["lla"] = lla_list
                    info["gua"] = gua_list
                    info["service_instance"] = service_instance_list
                    info["target"] = target_list
            print(info)
