import socket
import struct
from ctypes import *
import time


class myByte(Structure):
    _fields_ = [("mac", c_ubyte)]


class Frame(Structure):  # 14 bytes
    _fields_ = [
        ("dst_mac", c_ubyte * 6),
        ("src_mac", c_ubyte * 6),
        ("protocol_num", c_ushort),  # 16bit
    ]

    def __new__(self, mac_head=None):
        return self.from_buffer_copy(mac_head)

    def __init__(self, mac_head=None):
        self.protocol_map = {
            0x0800: "IP",
            0x0806: "ARP",
            0x86DD: "IPv6",
            0x8864: "PPPoE",
            0x9999: "Not support",
        }
        self.protocol_hex = socket.ntohs(self.protocol_num)
        print(hex(self.protocol_hex))

        for i in reversed(self.dst_mac):
            print(i, end=".")
        print()

        try:
            self.protocol = self.protocol_map[self.protocol_hex]
        except:
            self.protocol = self.protocol_map[0x9999]
            print("warning  !!!")
            print("protocol is: 0x%x" % self.protocol_hex)
            time.sleep(1)
