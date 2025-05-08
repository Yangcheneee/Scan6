import os
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.netbios import NBNSRegistrationRequest
from scapy.utils import rdpcap


def process_pcap(pcap_file):
    """处理单个pcap文件，提取NBNS register查询的主机名"""
    print(f"\n[*] 正在分析文件: {pcap_file}")
    packets = rdpcap(pcap_file)
    results = set()  # 用集合去重

    for packet in packets:
        """处理 NBNS 协议（NetBIOS 名称服务）"""
        try:
            if packet.haslayer(NBNSRegistrationRequest):
                # 仅处理 NBNS 注册请求（Opcode=5 为注册请求）
                hostname = packet[NBNSRegistrationRequest].QUESTION_NAME.decode('utf-8').strip(' ')
                if hostname != "WORKGROUP":
                    print(f"  [+] 发现查询: {hostname} (来自 {packet[IP].src})")
                    # 获取 MAC 地址（NBNS 在 IPv4 层，需从以太网层取 MAC）
                    mac = packet[Ether].src
                    results.add(hostname)
        except Exception as e:
            print(f"[NBNS 解析错误] {e}")
    return results


def analyze_nbns_dir(dir_path, output_file=None):
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
    analyze_nbns_dir("data/nbns/", "result/nbns")