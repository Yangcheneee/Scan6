from scapy.all import *
import os

from scapy.layers.dns import DNS
from scapy.layers.llmnr import LLMNRQuery
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6


def process_pcap(pcap_file):
    """处理单个pcap文件，提取LLMNR ANY查询的主机名"""
    print(f"\n[*] 正在分析文件: {pcap_file}")
    packets = rdpcap(pcap_file)
    results = set()  # 用集合去重

    for pkt in packets:
        if pkt.haslayer(LLMNRQuery) and pkt.haslayer(IP):
            dns = pkt[LLMNRQuery]
            if dns.qr == 0 and dns.qdcount > 0 and dns.qd[0].qtype == 255:
                hostname = dns.qd[0].qname.decode('utf-8').rstrip('.')
                results.add(hostname)
                print(f"  [+] 发现查询: {hostname} (来自 {pkt[IP].src})")
        if pkt.haslayer(UDP) and pkt[UDP].dport == 5355 and pkt.haslayer(DNS) and pkt.haslayer(IPv6):
            dns = pkt[DNS]
            if dns.qr == 0 and dns.qdcount > 0 and dns.qd[0].qtype == 255:
                hostname = dns.qd[0].qname.decode('utf-8').rstrip('.')
                results.add(hostname)
                print(f"  [+] 发现查询: {hostname} (来自 {pkt[IP].src})")
    return results


def analyze_llmnr_dir(dir_path, output_file=None):
    """分析目录下所有pcap文件"""
    all_hostnames = set()

    # 遍历目录中的pcap文件
    for filename in os.listdir(dir_path):
        if filename.lower().endswith(('.pcap', '.pcapng')):
            full_path = os.path.join(dir_path, filename)
            hostnames = process_pcap(full_path)
            all_hostnames.update(hostnames)

    # 输出结果
    print("\n[+] 所有文件分析完成，去重后结果:")
    for idx, name in enumerate(all_hostnames, 1):
        print(f"  {idx:2d}. {name}")

    # 可选：保存到文件
    if output_file:
        with open(output_file, "w") as f:
            f.write("\n".join(all_hostnames))
        print(f"\n[+] 结果已保存至: {output_file}")


if __name__ == "__main__":
    # import argparse
    #
    # parser = argparse.ArgumentParser(description="LLMNR ANY查询主机名提取工具")
    # parser.add_argument("-d", "--dir", required=True, help="包含pcap文件的目录路径")
    # parser.add_argument("-o", "--output", help="结果输出文件路径")
    # args = parser.parse_args()
    #
    # analyze_llmnr_dir(args.dir, args.output)
    analyze_llmnr_dir("data/llmnr/", "result/llmnr")