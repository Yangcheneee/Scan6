from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.l2 import ARP
from scapy.layers.netbios import NBNSQueryRequest, NBNSHeader, NBNSNodeStatusResponse
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1, send, srp1
from IPy import IP as IPY


def is_lla_ipv6(ip):
    if ip.startswith("fe80:"):
        return True


# unicast address
def is_gua_ipv6(ip):
    if ip.startswith("2"):
        return True


import scapy.all as scapy

from scapy.layers.l2 import ARP, Ether


def async_arp_scan(ip_list):
    # 创建ARP请求包列表
    arp_packets = [Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip) for ip in ip_list]
    # 发送并接收响应，超时设为2秒
    ans, unans = scapy.srp(arp_packets, timeout=2, verbose=False)
    # 处理响应
    results = []
    for sent_packet, received_packet in ans:
        if received_packet.haslayer(ARP) and received_packet[ARP].op == 2:
            src_mac = received_packet[ARP].hwsrc
            src_ip = received_packet[ARP].psrc
            results.append((src_mac, src_ip))

    return results


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


def nbtstat_scan(target_list):
    def create_nbtstat_query(dst_mac, dst_ip):
        eth_layer = Ether(dst=dst_mac)
        ip_layer = IP(dst=dst_ip)
        udp_layer = UDP(sport=137, dport=137)
        nbns_request = NBNSHeader(
            NAME_TRN_ID=0x1234,
            NM_FLAGS=0
        )
        question = NBNSQueryRequest(
            QUESTION_NAME=b'*\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            QUESTION_TYPE=33,
            QUESTION_CLASS=1
        )
        packet = ip_layer / udp_layer / nbns_request / question
        return packet

    response = sr1(packet, verbose=0, timeout=1)
    if response:
        if response.haslayer(NBNSHeader) and response.haslayer(NBNSNodeStatusResponse):
            name_list = response[NBNSNodeStatusResponse].NODE_NAME.decode('utf-8')
            for name in name_list:
                hostname = name.NETBIOS_NAME
                if hostname != "WORKGOUP":
                    return hostname


def mdns(hostname):
    ether_layer = Ether(src=src_mac, dst=mdns_mac)
    ip_layer = IP(dst=mdns_ip, src=src_ip)
    trans_layer = UDP(sport=5353, dport=5353)
    mdns_layer = DNS(rd=0, qd=DNSQR(qtype="AAAA", unicastresponse=0, qname=hostname + ".local"))
    packet = ether_layer/ip_layer/trans_layer/mdns_layer
    response = srp1(packet, verbose=0, timeout=2, iface=interface)
    if response:
        if packet.haslayer(DNS):
            dns = packet.getlayer(DNS)
            if dns.qr == 1:
                info = {
                    "lla": None,
                    "gua": []
                }
                for answer in dns.an:
                    if isinstance(answer, DNSRR) and answer.type == 28:  # AAAA
                        if hostname == answer.rrname.decode('utf-8').split(".")[0]:
                            ip = answer.rdata
                            if is_lla_ipv6(ip):
                                info["lla"] = ip
                            if is_gua_ipv6(ip):
                                info["gua"].append(ip)
                return info


def run(target="172.31.99.0/24", save_path="D:/Project/Scan6/result/linkscan6/"):
    ip_list = [str(ip) for ip in IPY(target)]
    arp_result_list = async_arp_scan(ip_list)
    for arp_result in arp_result_list:
        print(arp_result)
        print(type(arp_result))




if __name__ == "__main__":
    run(target="192.168.182.0/24", save_path="D:/Project/Scan6/result/linkscan6/")
