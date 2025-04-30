from scapy.all import *
from scapy.layers.inet6 import *

# 目标地址（示例）
target = "fe80::320d:9eff:fe80:cf44"

# 构造ICMPv6 Echo Request负载（需分片）
icmp_payload = ICMPv6EchoRequest(data="A"*2000)  # 生成大负载触发分片

# 手动分片（1440和剩余部分，长度需为8的倍数）
fragment1 = raw(icmp_payload)[:1440]   # 第一段数据（不包含完整ICMPv6头）
fragment2 = raw(icmp_payload)[1440:]   # 第二段数据（包含ICMPv6头）

# -----------------------------------------------
# 构造第一个分片包
# -----------------------------------------------
# IPv6头部：下一头部指向目标选项头（60）
ipv6_frag1 = IPv6(dst=target, nh=60)  # nh=60表示DOH

# 目标选项头（DOH）：填充PadN选项，下一头部指向分片头（44）
doh_header = IPv6ExtHdrDestOpt(
    nh=44,  # 下一头部为分片头
    options=[PadN(optdata=b"\x00"*6)]  # 6字节PadN填充
)

# 分片头配置（第一片）
frag_header1 = IPv6ExtHdrFragment(
    nh=58,        # 最终上层协议为ICMPv6（58），但当前分片未包含
    offset=0,     # 偏移量0（单位：8字节）
    m=1,          # 更多分片标志
    id=0x12345    # 分片标识符（需一致）
)

# 组合第一个分片包
packet_frag1 = ipv6_frag1 / doh_header / frag_header1 / fragment1

# -----------------------------------------------
# 构造第二个分片包
# -----------------------------------------------
# IPv6头部（配置与第一片相同）
ipv6_frag2 = IPv6(dst=target, nh=60)

# 目标选项头（与第一片相同）
doh_header = IPv6ExtHdrDestOpt(
    nh=44,
    options=[PadN(optdata=b"\x00"*6)]
)

# 分片头配置（第二片）
frag_header2 = IPv6ExtHdrFragment(
    nh=58,
    offset=1440 // 8,  # 计算偏移量（1440字节 ÷ 8 = 180）
    m=0,               # 无后续分片
    id=0x12345
)

# 组合第二个分片包
packet_frag2 = ipv6_frag2 / doh_header / frag_header2 / fragment2

# -----------------------------------------------
# 验证数据包结构
# -----------------------------------------------
packet_frag1.show()
print("\n--- Second Fragment ---")
packet_frag2.show()

# -----------------------------------------------
# 发送数据包（需root权限）
# -----------------------------------------------
# send(packet_frag1)
# send(packet_frag2)