import sys
import time
sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')
from conf import Conf
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1, srp1, sendp, send


def get_service_list():
    conf = Conf
    src_mac = Conf.mac_address
    src_ip = Conf.ip_address
    # mdns_multicast
    dst_mac = "01:00:5E:00:00:FB"
    dst_ip = "224.0.0.251"
    # DNS Services Discovery: _services._dns-sd._udp.local
    ether_layer = Ether(src=src_mac, dst=dst_mac)
    mdns_layer = DNS(id=0x0000, rd=1, qd=DNSQR(qtype="PTR", unicastresponse=0, qname='_services._dns-sd._udp.local'))
    trans_layer = UDP(sport=53535, dport=5353)
    # 注意这个地方源端口不能为5353
    ip_layer = IP(dst=dst_ip, src=src_ip)
    # 注意这个地方dst_ip必须是mDNS组播IP
    packet = ether_layer/ip_layer/trans_layer/mdns_layer
    # packet.show()
    sendp(packet, verbose=1, iface="WLAN")


def get_service_instance_list(service_list):
    for service in service_list:
        conf = Conf
        src_mac = Conf.mac_address
        src_ip = Conf.ip_address
        # mdns_multicast
        dst_mac = "01:00:5E:00:00:FB"
        dst_ip = "224.0.0.251"
        # DNS Services Discovery: _services._dns-sd._udp.local
        ether_layer = Ether(src=src_mac, dst=dst_mac)
        mdns_layer = DNS(id=0x0000, rd=1, qd=DNSQR(qtype="PTR", unicastresponse=0, qname=service))
        trans_layer = UDP(sport=53535, dport=5353)
        # 注意这个地方源端口不能为5353
        ip_layer = IP(dst=dst_ip, src=src_ip)
        packet = ether_layer/ip_layer/trans_layer/mdns_layer
        # packet.show()
        sendp(packet, verbose=1, iface="WLAN")
        time.sleep(1)


if __name__ == "__main__":
    service_list = ['_airplay._tcp.local.',
                    '_companion-link._tcp.local.',
                    '_dosvc._tcp.local.',
                    '_http-alt._tcp.local.',
                    '_http._tcp.local.',
                    '_ipp._tcp.local.',
                    '_ipps._tcp.local.',
                    '_printer._tcp.local.',
                    '_pdl-datastream._tcp.local.',
                    '_privet._tcp.local.',
                    '_raop._tcp.local.',
                    '_rdlink._tcp.local.'
                    '_scanner._tcp.local.',
                    '_uscan._tcp.local.',
                    '_uscans._tcp.local.']
    get_service_instance_list(service_list)
