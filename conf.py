import socket
import psutil


class Conf:
    interface = "WLAN"
    hostname = "DESKTOP-8DUN5OR"
    mac_address = "48:A4:72:E6:72:BF"
    ip_address = "192.168.3.89"
    # 这台电脑的链路本地地址不会随着时间和接入网络发生变化，可以看看其他设备的情况。
    ip6_adress = "fe80::910c:e419:64df:f2f1"

    def __init__(self):
        # 获取所有网络接口信息
        # net_if_addrs = psutil.net_if_addrs()
        # net_status = psutil.net_if_stats()
        # print(net_status)
        # interfaces = []
        # for interface, info in net_status.items():
        #     if info.isup:
        #         interfaces.append(interface)
        pass

    def get_hostname(self):
        return socket.gethostname()

    def info(self):
        return f"interface: {self.interface}\n" \
               f"hostname: {self.hostname}\n" \
               f"mac_address: {self.mac_address}\n" \
               f"ip_address: {self.ip_address}\n" \
               f"ip6_address: {self.ip6_adress}\n"


if __name__ == "__main__":
    conf = Conf()
    print(conf.info())


