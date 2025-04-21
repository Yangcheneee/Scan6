import sys

from scapy.layers.l2 import ARP

sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1
from IPy import IP as IPY
from tqdm import tqdm


def is_lla_ipv6(ip):
    if ip.startswith("fe80:"):
        return True


# unicast address
def is_gua_ipv6(ip):
    if ip.startswith("2"):
        return True


def extract_ip6(packet):
    lla_list = []
    gua_list = []
    if packet.haslayer(DNSRR):
        dns = packet.getlayer(DNS)
        # dns.show()
        # 检查是否有响应记录
        if dns.qr == 1:  # QR=1表示响应
            # print("response!")
            for answer in dns.an:
                if isinstance(answer, DNSRR) and answer.type == 28:  # AAAA
                    # answer.show()
                    ip6 = answer.rdata
                    if is_lla_ipv6(ip6):
                        lla_list.append(ip6)
                    if is_gua_ipv6(ip6):
                        gua_list.append(ip6)
    return lla_list, gua_list


def extract_target(packet):
    target_list = []
    if packet.haslayer(DNSRR):
        dns = packet.getlayer(DNS)
        # dns.show()
        # 检查是否有响应记录
        if dns.qr == 1:  # QR=1表示响应
            # print("response!")
            for answer in dns.an:
                # answer.show()
                if answer.type == 33:  # SRV
                    # answer.show()
                    hostname = answer.target.decode('utf-8')
                    port = answer.port
                    target = hostname + str(port)
                    target_list.append(target)
    return target_list


def extract_service_instance(packet):
    service_instance_list = []
    # packet.show()
    if packet.haslayer(DNSRR):
        # packet.show()
        dns = packet.getlayer(DNS)
        for answer in dns.an:
            # answer.show()
            if answer.type == 12:
                if answer.rdata.decode('utf-8') not in service_instance_list and answer.rrname.decode(
                        'utf-8') != "_services._dns-sd._udp.local.":
                    service_instance_list.append(answer.rdata.decode('utf-8'))
    return service_instance_list


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
        service_list = extract_service(response)
        return service_list
    else:
        return None


def get_service_instance_list(service_list, dst_ip):
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
    response = sr1(packet, verbose=0, timeout=0.5)
    if response:
        # response.show()
        service_instance_list = extract_service_instance(response)
        return service_instance_list
    else:
        return None


def get_target(service_instance_list, dst_ip):
    # 创建DNS查询记录列表，查询类型为SRV
    dns_qr_list = [DNSQR(qtype="SRV", unicastresponse=1, qname=service_instance) for service_instance in service_instance_list]
    # 创建mDNS层
    mdns_layer = DNS(id=0x0000, rd=1, qd=dns_qr_list)
    # 创建UDP层，源端口不为5353，目标端口为5353
    trans_layer = UDP(sport=5353, dport=5353)  # 源端口设置为5354，确保不为5353
    # 创建IP层
    ip_layer = IP(dst=dst_ip, ttl=255)
    # 组装报文
    packet = ip_layer / trans_layer / mdns_layer
    # 发送报文并接收响应
    response = sr1(packet, verbose=0, timeout=0.5)
    if response:
        # 解析响应中的服务实例
        target_list = extract_target(response)
        return target_list
    else:
        return None


def mdns(name, dst_ip):
    # query all service name
    ip_layer = IP(dst=dst_ip)
    trans_layer = UDP(sport=5353, dport=5353)
    mdns_layer = DNS(rd=1, qd=DNSQR(qtype="AAAA", unicastresponse=1, qname=name))
    packet = ip_layer/trans_layer/mdns_layer
    response = sr1(packet, verbose=0,  timeout=0.5)
    if response:
        ipv6_list = extract_ip6(response)
        return ipv6_list
    else:
        return None


def is_alive(dst_ip):
    pkt = ARP(pdst=dst_ip)
    ans = sr1(pkt, timeout=0.5, verbose=False)
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
    info_list = []
    dst_ip_list = IPY("172.31.99.0/24")
    # dst_ip_list = ["172.31.99.130"]
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
            if service_list:
                # print(service_list)
                info["service"] = service_list
                service_instance_list = get_service_instance_list(service_list, str(ip))
                if service_instance_list:
                    info["service_instance"] = service_instance_list
                    # print(service_instance_list)
                    target_list = get_target(service_instance_list, str(ip))
                    if target_list:
                        # print(target_list)
                        info["target"] = target_list
                        hostname = (target_list[0]).rsplit(".", 1)[0]
                        info["hostname"] = hostname
                        # print(hostname)
                        ipv6_list = mdns(hostname, str(ip))
                        if ipv6_list:
                            # print(ipv6_list)
                            info["lla"].append(ipv6_list[0])
                            info["gua"].append(ipv6_list[1])
            print(info)
