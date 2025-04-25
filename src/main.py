import multiprocessing
import HScan6_quick
import smb_scan
import dhcp_sniffer
import smb_sniffer
import mdns_sniffer


def quick_scan():
    # 创建两个进程
    p1 = multiprocessing.Process(target=HScan6_quick.run())
    p2 = multiprocessing.Process(target=smb_scan.run())

    # 启动进程
    p1.start()
    p2.start()

    # 等待进程结束
    p1.join()
    p2.join()

    print("所有进程执行完毕")


if __name__ == "__main__":
    """
    save_path参数是保存的路径，程序将会根据当前时间生成文件名
    """
    HScan6_quick.run(target="172.31.99.0/24", save_path="../result/mdns_scan/")
    smb_scan.run(target="172.31.99.255", save_path="../result/smb_scan/")

    """
    save_file参数是保存的文件，程序将会以追加的方式写入文件
    duration监听时间，单位为秒
    """
    # dhcp_sniffer.run(interface="WLAN", duration=60, save_file="../result/dhcp_sniffer.csv")
    # mdns_sniffer.run(interface="WLAN", duration=60, save_file="../result/mdns_sniffer.csv")
    # smb_sniffer.run(interface="WLAN", duration=60, save_file="../result/smb_sniffer.csv")



