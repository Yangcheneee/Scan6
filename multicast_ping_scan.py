import threading
import multicast_ping_sender
import multicast_ping_sniffer
import ping
from multiprocessing import Process
import time


def func1():
    for i in range(1000):
        # time.sleep(0.1)
        print(i)


def func2():
    for i in range(1000):
        # time.sleep(0.1)
        print(i*10)


def mp_run():
    # 创建两个进程，分别运行func1和func2
    process1 = Process(target=multicast_ping_sender.m_ping())
    process2 = Process(target=multicast_ping_sniffer.icmpv6_reply_sniffer())
    # process2 = Process(target=ping.ping())
    # 启动进程
    process1.start()
    process2.start()

    # 等待进程完成
    process1.join()
    process2.join()

    print("Both functions have finished execution.")


def mt_run():
    # 创建线程
    thread2 = threading.Thread(target=multicast_ping_sniffer.icmpv6_reply_sniffer())
    thread1 = threading.Thread(target=multicast_ping_sender.m_ping())

    # 启动线程
    thread1.start()
    thread2.start()

    # 等待线程结束
    thread1.join()
    thread2.join()


if __name__ == "__main__":
    # mt_run()
    # mp_run()
    # 创建线程
    # thread2 = Process(target=func1())
    # thread1 = Process(target=func2())
    thread2 = threading.Thread(target=func1())
    thread1 = threading.Thread(target=func2())

    # 启动线程
    thread1.start()
    thread2.start()

    # 等待线程结束
    thread1.join()
    thread2.join()

