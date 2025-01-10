# import muiticast_ping_sender
# import multicast_ping_sniffer
# import ping
# from multiprocessing import Process
# import time
#
# if __name__ == "__main__":
#     # 创建两个进程，分别运行func1和func2
#     process1 = Process(target=muiticast_ping_sender.m_ping(), args=('Python',))
#     # process2 = Process(target=multicast_ping_sniffer.icmpv6_reply_sniffer(), args=('Python',))
#     process2 = Process(target=ping.ping())
#     # 启动进程
#     process2.start()
#     process1.start()
#
#     # 等待进程完成
#     process2.join()
#     process1.join()
#
#     print("Both functions have finished execution.")

import subprocess
import sys
sys.path.append('D:/Project/Scan6/venv/Lib/site-packages')

if __name__ == "__main__":
    # 运行第一个Python脚本
    try:
        subprocess.run(["python", "multicast_ping_sender.py"])
    except Exception as e:
        print(f"捕获数据包时发生错误: {e}")
    try:
        # 运行第二个Python脚本
        subprocess.run(["python", "multicast_ping_sniffer.py"])
    except Exception as e:
        print(f"捕获数据包时发生错误: {e}")
