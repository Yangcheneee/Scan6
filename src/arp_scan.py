import os
from datetime import datetime
from scapy.layers.l2 import ARP
from scapy.sendrecv import sr1
from IPy import IP as IPY
import pandas as pd


def arp_probe(dst_ip):
    pkt = ARP(pdst=dst_ip)
    ans = sr1(pkt, timeout=0.5, verbose=False)
    if ans is not None:
        if ans.haslayer(ARP) and ans[ARP].op == 2:
            arp_info = {
                "mac": ans[ARP].hwsrc,
                "ip": ans[ARP].psrc,
            }
            return arp_info
        else:
            return None
    else:
        return None


def arp_scan(target, save_path="result/arp_scan/"):
    print("ARP协议扫描中...")
    dst_ip_list = IPY(target)
    arp_info_list = []
    for ip in dst_ip_list:
        arp_info = arp_probe(str(ip))
        if arp_info:
            print(arp_info)
            arp_info_list.append(arp_info)
    if arp_info_list:
        df = pd.DataFrame(arp_info_list)
        save_file = save_path + datetime.now().strftime("%Y-%m-%d %H-%M-%S") + ".csv"
        df.to_csv(save_file, index=False)
        print(f"数据已保存到 {save_file}")
    return arp_info_list


if __name__ == "__main__":
    target = "172.31.99.0/24"
    arp_scan(target)
