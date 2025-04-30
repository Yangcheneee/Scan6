import sys
import time
sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sendp


def get_service_list_m():
    interface = "WLAN"
    src_mac = "48:A4:72:E6:72:BF"
    src_ip = "172.31.99.79"
    dst_mac = "01:00:5E:00:00:FB"
    dst_ip = "224.0.0.251"
    ether_layer = Ether(src=src_mac, dst=dst_mac)
    ip_layer = IP(dst=dst_ip, src=src_ip, ttl=255)
    trans_layer = UDP(sport=5353, dport=5353)
    mdns_layer1 = DNS(id=0x0000, rd=0, qd=DNSQR(qtype="PTR", unicastresponse=0, qname='_services._dns-sd._udp.local'))
    mdns_layer2 = DNS(id=0x0000, rd=0, qd=DNSQR(qtype="PTR", unicastresponse=0, qname='_services._dns-sd._udp.local'))
    packet1 = ether_layer / ip_layer / trans_layer / mdns_layer1
    packet2 = ether_layer / ip_layer / trans_layer / mdns_layer2
    sendp([packet1, packet2], verbose=1, iface=interface)
    time.sleep(0.2)


def get_service_instance_list_m(service_list):
    for service in service_list:
        interface = "WLAN"
        src_mac = "48:A4:72:E6:72:BF"
        src_ip = "172.31.99.79"
        dst_mac = "01:00:5E:00:00:FB"
        dst_ip = "224.0.0.251"
        # DNS Services Discovery: _services._dns-sd._udp.local
        ether_layer = Ether(src=src_mac, dst=dst_mac)
        mdns_layer1 = DNS(id=0x0000, qd=DNSQR(qtype="PTR", unicastresponse=1, qname=service))
        mdns_layer2 = DNS(id=0x0000, qd=DNSQR(qtype="PTR", unicastresponse=0, qname=service))
        trans_layer = UDP(sport=5353, dport=5353)
        # 注意这个地方源端口不能为5353
        ip_layer = IP(dst=dst_ip, src=src_ip, ttl=255)
        packet1 = ether_layer/ip_layer/trans_layer/mdns_layer1
        packet2 = ether_layer/ip_layer/trans_layer/mdns_layer2
        # packet.show()
        sendp([packet2, packet1], verbose=1, iface=interface)
        time.sleep(1)


if __name__ == "__main__":
    get_service_list_m()
    service_list = ['_airplay._tcp.local.',
                    '_androidtvremote._tcp.local.',
                    '_companion-link._tcp.local.',
                    '_dosvc._tcp.local.',
                    '_http-alt._tcp.local.',
                    '_http._tcp.local.',
                    '_ipp._tcp.local.',
                    '_ipps._tcp.local.',
                    '_lyra-mdns._udp.local',
                    '_mi-connect._udp.local',
                    '_nvstream_dbd._tcp.local',
                    '_printer._tcp.local.',
                    '_pdl-datastream._tcp.local.',
                    '_privet._tcp.local.',
                    '_raop._tcp.local.',
                    '_rdlink._tcp.local.',
                    '_scanner._tcp.local.',
                    '_sleep-proxy._udp.local',
                    '_ssh._tcp.local.',
                    '_sftp-ssh._tcp.local.',
                    '_uscan._tcp.local.',
                    '_uscans._tcp.local.']
    # service_list = ['_companion-link._tcp.local.', '_androidtvremote._tcp.local.', '_dosvc._tcp.local.', '_mi-connect._udp.local', '_nvstream_dbd._tcp.local']
    get_service_instance_list_m(service_list)
