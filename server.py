#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import Ether, IP, UDP, BOOTP, DHCP
from scapy.all import *
import subprocess
import sys

PacketCount = 0


def printCount(mac):
    global PacketCount
    PacketCount += 1
    seq = f"[{PacketCount}]"
    print(f"{seq:<8} Assigned IP:192.168.0.11 MAC:{mac}")


opOffer = [
    ("message-type", 2),
    ("subnet_mask", "255.255.255.0"),
    ("router", "192.168.0.1"),
    ("NetBIOS_node_type", 8),
    ("lease_time", 86400),
    ("server_id", "192.168.0.1"),
    "end",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
]
opAck = [
    ("message-type", 5),
    ("subnet_mask", "255.255.255.0"),
    ("router", "192.168.0.1"),
    ("NetBIOS_node_type", 8),
    ("lease_time", 86400),
    ("server_id", "192.168.0.1"),
    "end",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
]
offerPack = (
    Ether()
    / IP(src="192.168.0.1", dst="255.255.255.255")
    / UDP(sport=67, dport=68)
    / BOOTP(
        op=2,
        htype=1,
        hlen=6,
        yiaddr="192.168.0.11",
        siaddr="192.168.0.1",
        options=b"c\x82Sc",
    )
    / DHCP(options=opOffer)
)
ackPack = (
    Ether()
    / IP(src="192.168.0.1", dst="255.255.255.255")
    / UDP(sport=67, dport=68)
    / BOOTP(
        op=2,
        htype=1,
        hlen=6,
        yiaddr="192.168.0.11",
        siaddr="192.168.0.1",
        options=b"c\x82Sc",
    )
    / DHCP(options=opAck)
)


def f(x, interface):
    # x.show()
    # print(x.summary())
    # print(x[0].src)
    if x[4].options[0][1] == 1:
        # print("discover")
        # print(x[3].xid)
        # print(offerPack[3].xid)
        offerPack[0].dst = x[0].src
        offerPack[3].xid = x[3].xid
        offerPack[3].chaddr = x[3].chaddr
        # offerPack.show2()
        sendp(offerPack, iface=interface, verbose=False)
    elif x[4].options[0][1] == 3:
        mac = x[0].src
        # print(x[3].xid)
        # print(offerPack[3].xid)
        ackPack[0].dst = x[0].src
        ackPack[3].xid = x[3].xid
        ackPack[3].chaddr = x[3].chaddr
        # x.show()
        # ackPack.show2()
        sendp(ackPack, iface=interface, verbose=False)
        printCount(mac)


def startDhcpServer(iface):
    sniff(filter="udp portrange 67-68", prn=lambda x: f(x, iface), iface=iface)


def printTips():
    print("")
    print(">>> 请关闭本机使用的其他DHCP服务\n")
    print(">>> 请将有线网卡设置为 静态IP:192.168.0.1 子网掩码:255.255.255.0\n")
    print(">>> 用网线连接电脑和被测设备 并且网卡指示灯闪烁\n")
    print(">>> 如长时间未见分配IP 请插拔一下网线\n")


def selectIfaceLinux():
    cmd = subprocess.run("ifconfig", shell=True, capture_output=True)
    rt = (cmd.stdout).decode("utf8")
    err = (cmd.stderr).decode("utf8")
    ifaces = rt.split("\n\n")
    if err:
        print("*" * 10 + "\n" + rt + "\n" + "*" * 10 + "\n")
        print("*" * 10 + "\n" + err + "\n" + "*" * 10 + "\n")
        print(">>> " + "执行ifconfig命令失败" + "\n")
        return None
    else:
        for i in ifaces:
            if "inet 192.168.0.1" in i:
                iface = i.split(":")[0].strip()
                print(">>> " + f"iface is {iface}" + "\n")
                return iface
        print(">>> " + "找不到 IP 192.168.0.1 的有线网卡 请检查网络配置后重试" + "\n")
        return None


def selectIfaceWindows():
    cmd = subprocess.run("ipconfig /all", shell=True, capture_output=True)
    rt = (cmd.stdout).decode("gbk")
    err = (cmd.stderr).decode("gbk")
    ifaces = rt.split("\r\n\r\n")
    if err:
        print("*" * 10 + "\n" + rt + "\n" + "*" * 10 + "\n")
        print("*" * 10 + "\n" + err + "\n" + "*" * 10 + "\n")
        print(">>> " + "执行ifconfig命令失败" + "\n")
        return None
    else:
        for i in range(len(ifaces)):
            if "192.168.0.1" in ifaces[i] and "Ethernet adapter" in ifaces[i - 1]:
                iface = ifaces[i - 1]
                iface = iface.replace("Ethernet adapter", "").replace(":", "").strip()
                print(">>> " + f"iface is {iface}" + "\n")
                return iface
        print(">>> " + "找不到 IP 192.168.0.1 的有线网卡 请检查网络配置后重试" + "\n")
        return None


def printLogo():
    a = """
'########::'##::::'##::'######::'########::
 ##.... ##: ##:::: ##:'##... ##: ##.... ##:
 ##:::: ##: ##:::: ##: ##:::..:: ##:::: ##:
 ##:::: ##: #########: ##::::::: ########::
 ##:::: ##: ##.... ##: ##::::::: ##.....:::
 ##:::: ##: ##:::: ##: ##::: ##: ##::::::::
 ########:: ##:::: ##:. ######:: ##::::::::
........:::..:::::..:::......:::..:::::::::"""
    print(a)


if __name__ == "__main__":
    printLogo()
    args = sys.argv
    if len(args) > 1:
        printTips()
        if args[1] == "linux":
            iface = selectIfaceLinux()
        elif args[1] == "windows":
            iface = selectIfaceWindows()
        else:
            print(">>> " + "平台参数错误" + "\n")
        if iface:
            startDhcpServer(iface)
        else:
            time.sleep(5)
    else:
        print(">>> " + "未提供平台参数" + "\n")
        time.sleep(5)
