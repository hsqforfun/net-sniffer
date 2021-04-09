import socket
import struct
from ctypes import *
import time


class ARP(Structure):  #  28 bytes
    _pack_ = 2
    _fields_ = [
        ("hardware_type", c_ushort),  # 2 bytes 0001
        ("protocol_num", c_ushort),  # 2 bytes 0800
        ("mac_length", c_ubyte),  # 1 bytes 06
        ("ip_length", c_ubyte),  # 1 bytes 04
        ("op_num", c_ushort),  # 2 bytes
        ("src_mac", c_ubyte * 6),  # 6 bytes
        ("src_ip", c_uint),  # 4 bytes
        ("dst_mac", c_ubyte * 6),  # 6 bytes
        ("dst_ip", c_uint),  # 4 bytes
    ]

    def __new__(self, arp_buffer=None):
        return self.from_buffer_copy(arp_buffer)

    def __init__(self, arp_buffer=None):
        self.protocol_map = {
            0x0800: "IP",
            0x0806: "ARP",
            0x86DD: "IPv6",
            0x8864: "PPPoE",
            0x9999: "Not support",
        }

        self.op_map = {1: "request", 2: "reply", 3: "rarp request", 4: "rarp reply"}

        self.hardware_map = {1: "Ethernet"}

        self.src_ip_str = socket.inet_ntoa(struct.pack("<I", self.src_ip))
        self.dst_ip_str = socket.inet_ntoa(struct.pack("<I", self.dst_ip))

        self.op_num = socket.ntohs(self.op_num)
        self.protocol_num = socket.ntohs(self.protocol_num)
        try:
            self.op = self.op_map[self.op_num]
        except:
            print("oh on")
            print("hardware:%x" % (self.hardware_type))
            print("protocol_num:%x" % (self.protocol_num))
            print("mac_length:%x" % (self.mac_length))
            print("ip_length:%x" % (self.ip_length))
            print(bin(self.op_num))
            time.sleep(5)

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = "NOT SUPPORT"
            print("warning by hsq !!!")
            print("protocol is: %x" % self.protocol_num)
            time.sleep(1)
