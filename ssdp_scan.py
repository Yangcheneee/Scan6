import sys
import time
import socket
import struct
sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import Ether
from scapy.layers.netbios import NBNSQueryRequest, NBNSHeader
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1, srp1, sendp, send
from IPy import IP as IPY


address = ("239.255.255.250", 1900)
result = {}


def get_serv_ua(resp):
    lines = resp.split("\r\n")
    for i in lines:
        array = i.split(":")
        if array[0].upper() == "SERVER" or array[0].upper() == "USER-AGENT":
            return array[1]
    # end-for
# end get_serv_ua()


def ssdp_scan():
    print("[scan mode]")
    req = b'M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nST:ssdp:all\r\nMan: "ssdp:discover"\r\nMX:1\r\n\r\n'

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    # send "ssdp:all" query request
    sock.sendto(req, address)

    # receive and print
    while True:
        try:
            resp, raddr = sock.recvfrom(1024)
        except:
            break
        if raddr[0] not in result:
            data = get_serv_ua(resp.decode())
            result[raddr[0]] = data
            print(raddr[0], data)
    # end-while
