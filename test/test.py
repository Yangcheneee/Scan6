import multiprocessing
import time
from scapy.all import *

def worker1():
    print("进程1开始工作")
    for i in range(10):
        print("123")
        time.sleep(2)
    print("进程1结束")

def pr():
    print("111")
def worker2():
    print("进程2开始工作")
    sniff(filter="udp and (port 67 or port 68)", timeout=10, prn=pr, store=0)
    print("进程2结束")


if __name__ == '__main__':
    # 创建两个进程
    p1 = multiprocessing.Process(target=worker1)
    p2 = multiprocessing.Process(target=worker2)

    # 启动进程
    p1.start()
    p2.start()

    # 等待进程结束
    p1.join()
    p2.join()

    print("所有进程执行完毕")