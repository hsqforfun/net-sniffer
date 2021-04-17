import socket
import struct
from ctypes import *


class IP(Structure):  # 20 bytes
    _fields_ = [
        ("ihl", c_ubyte, 4),  # 4bit
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),  # 8bit
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),  # 16bit
        ("src", c_uint),  # 32bit
        ("dst", c_uint),  # 32bit
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        self.src_address = socket.inet_ntoa(struct.pack("<I", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<I", self.dst))
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)
            print("warning by hsq !!!")
