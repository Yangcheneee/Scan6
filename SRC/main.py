import multiprocessing

import HScan6_quick
import smb_scan
import conf
import dhcp_sniffer


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
    conf_info = conf.get_interface_info("{F52FC252-BAEC-4BA6-A8CA-8706641245A6}")
    quick_scan()
    """"
    Function: dhcp_sniffer.run
    : Param
        duration: sniffer函数监听时间
        save_file: 结果保存的位置
    """
    dhcp_sniffer.run(duration=10 * 60, save_file="../result/dhcp_sniffer.csv")
