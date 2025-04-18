from IPy import IP as IPY
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, ICMP, TCP
from scapy.sendrecv import sr1


def arp_scan(dst_ip_list):
    alive_ip_list = []
    print("ARP scan script is running...")
    for dst_ip in dst_ip_list:
        pkt = ARP(pdst=str(dst_ip))
        # pkt.show()
        ans = sr1(pkt, timeout=0.5, verbose=False)
        if ans is not None:
            # ans.summary()
            # ans.show()
            alive_ip_list.append(dst_ip)
            print(dst_ip, 'is up')
        # else:
            # print(dst_ip, 'is closed')

    return alive_ip_list


if __name__ == "__main__":
    # dst_ip_list = ["192.168.150.67"]
    dst_ip_list = IPY("192.168.3.0/24")
    alive_ip_list = arp_scan(dst_ip_list)
    print(f"alive_ip_list: {alive_ip_list}")