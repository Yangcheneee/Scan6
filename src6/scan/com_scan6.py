import mp6
import ieh
import mld
import linkscan6
import browserscan6
import hscan6
import llmnr6
import ascan6


def run(interface="WLAN"):
    # mld.send_mldv2_query(interface=interface)
    # ieh.ieh_scan(interface=interface)
    # mp6.mp6_scan(interface=interface)
    # linkscan6.run(interface=interface, target="192.168.242.0/24", save_path="D:/Project/Scan6/result/linkscan6/")
    # browserscan6.run(interface=interface, target="192.168.242.255", save_path="D:/Project/scan6/result/smb_scan/")
    hscan6.run(interface=interface, target="192.168.242.0/24", save_path="D:/Project/Scan6/result/hscan6/")


if __name__ == "__main__":
    run()
