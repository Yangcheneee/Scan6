import netifaces
ETH = "{E9812809-EC44-4F9B-AA3F-A4EDF0835213}"
WLAN = "{F52FC252-BAEC-4BA6-A8CA-8706641245A6}"


def get_interface_info(interface_name):
    """
    获取指定网卡的网络配置信息
    :param interface_name: 网卡名称，如'eth0'、'ens33'、'wlan0'等
    :return: 包含网络配置的字典
    """
    if interface_name not in netifaces.interfaces():
        raise ValueError(f"Interface {interface_name} not found")

    info = {}
    addrs = netifaces.ifaddresses(interface_name)

    # MAC地址 (AF_LINK)
    if netifaces.AF_LINK in addrs:
        info['mac'] = addrs[netifaces.AF_LINK][0]['addr']

    # IPv4信息 (AF_INET)
    if netifaces.AF_INET in addrs:
        ipv4 = addrs[netifaces.AF_INET][0]
        info.update({
            'ipv4_address': ipv4.get('addr'),
            'netmask': ipv4.get('netmask'),
            'broadcast': ipv4.get('broadcast')
        })

    # IPv6信息 (AF_INET6)
    if netifaces.AF_INET6 in addrs:
        ipv6 = addrs[netifaces.AF_INET6][0]
        info['ipv6_address'] = ipv6.get('addr')

    # 网关信息
    gateways = netifaces.gateways()
    info['default_gateway'] = gateways.get('default', {}).get(netifaces.AF_INET, (None, None))[0]

    return info


# 使用示例
if __name__ == '__main__':
    interface = WLAN  # 替换为你的网卡名称
    try:
        config = get_interface_info(interface)
        print(f"{interface} 网络配置:")
        for key, value in config.items():
            print(f"{key:>15}: {value}")
    except ValueError as e:
        print(e)
