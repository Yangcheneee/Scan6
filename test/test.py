from scapy.all import sniff

try:
    sniff(prn=lambda x: x.summary(), timeout=60)  # 设置超时或无限嗅探
except KeyboardInterrupt:
    print("\n[+] 手动停止捕获")