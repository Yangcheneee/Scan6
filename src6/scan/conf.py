import socket
import netifaces

LLA_PREFIX = ["fe80:"]
GUA_PREFIX = ["2", "3"]
LINK_LOCAL_ALL_NODES_ADDR = "ff02::1"
LINK_LOCAL_ALL_NODES_MAC = "33:33:00:00:00:01"
MDNS6_ADDR = "ff02::fb"
MDNS6_MAC = "33:33:00:00:00:fb"
SERVICE_TYPE_ENUMERATION = "_service._dns-sd._udp.local."


def is_lla(ip: str) -> bool:
    """判断是否为链路本地地址"""
    return any(ip.startswith(prefix) for prefix in LLA_PREFIX)


def is_gua(ip: str) -> bool:
    """判断是否为链路本地地址"""
    return any(ip.startswith(prefix) for prefix in GUA_PREFIX)


class Conf:
    hostname = "DESKTOP-8DUN5OR"
    interface = "WLAN"
    mac = "48:a4:72:e6:72:bf"
    ipv4 = "172.31.99.79"
    ipv6_lla = "fe80::910c:e419:64df:f2f1"
    ipv6_gua = ["2001:250:2003:8890:e4ba:2bc9:db45:472e"]

    def __init__(self, interface):
        """
        获取指定网卡的网络配置信息
        :param interface: 网卡名称，如'eth0'、'ens33'、'wlan0'等
        :return: 包含网络配置的字典
        """

        if interface not in netifaces.interfaces():
            raise ValueError(f"Interface {interface} not found")

        info = {}

        hostname = socket.gethostname()
        self.hostname = hostname
        info.update({
            "hostname": hostname
        })

        addrs = netifaces.ifaddresses(interface)

        # MAC地址 (AF_LINK)
        if netifaces.AF_LINK in addrs:
            info['mac'] = addrs[netifaces.AF_LINK][0]['addr']
            self.mac = info['mac']

        # IPv4信息 (AF_INET)
        if netifaces.AF_INET in addrs:
            ipv4 = addrs[netifaces.AF_INET][0]
            info.update({
                'ipv4': ipv4.get('addr'),
                'netmask': ipv4.get('netmask'),
                'broadcast': ipv4.get('broadcast')
            })
            self.ipv4 = info['ipv4']

        # IPv6信息 (AF_INET6)
        if netifaces.AF_INET6 in addrs:
            ipv6_list = addrs[netifaces.AF_INET6]
            for ipv6 in ipv6_list:
                ipv6_addr = ipv6.get('addr')
                if is_lla(ipv6_addr):
                    info.update({
                        "ipv6_lla":  ipv6_addr,
                    })
                    self.ipv6_lla = info['ipv6_lla']
                elif is_gua(ipv6_addr):
                    if "ipv6_gua" not in info:
                        info.update({
                            "ipv6_gua": []
                        })
                    info["ipv6_gua"].append(ipv6_addr)
                    self.ipv6_gua = info.get("ipv6_gua")


        # 网关信息
        gateways = netifaces.gateways()
        info['default_gateway'] = gateways.get('default', {}).get(netifaces.AF_INET, (None, None))[0]