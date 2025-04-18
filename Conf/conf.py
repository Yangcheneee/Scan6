import socket


class Conf:
    iface = "WLAN"
    hostname = "DESKTOP-8DUN5OR"
    mac = "48:A4:72:E6:72:BF"
    ip4 = "172.31.99.79"
    lla = "fe80::910c:e419:64df:f2f1"
    gua = "2001:250:2003:8890:78bf:e756:ba57:b63a"

    def info(self):
        return f"interface: {self.iface}\n" \
               f"hostname: {self.hostname}\n" \
               f"mac_address: {self.mac}\n" \
               f"ip4_address: {self.ip4}\n" \
               f"ip6_address: {self.lla}; {self.gua}\n"


if __name__ == "__main__":
    conf = Conf()
    print(conf.info())


