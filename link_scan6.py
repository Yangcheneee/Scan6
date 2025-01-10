import scan4
import get_name
import name_resolver
from IPy import IP as IPY


def link_scan6():
    ipy = "192.168.1.0/24"
    ip_list = IPY(ipy)
    alive_ip_list = scan4.arp_scan(dst_ip_list=ip_list)
    name_list = get_name.nbns_nbtstat(ip_list=alive_ip_list)
    alive_ip6_list = name_resolver.mdns(name_list=name_list)


if __name__ == "__main__":
    link_scan6()