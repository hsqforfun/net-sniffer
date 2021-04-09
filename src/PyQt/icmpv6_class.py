import socket
import struct
from ctypes import *

# ("ihl", c_ubyte, 4),  # 4bit
# ("ttl", c_ubyte),  # 8bit
# ("sum", c_ushort),  # 16bit
# ("src", c_uint),  # 32bit


class ICMPv6(Structure):  # 20 bytes
    _pack_ = 2
    _fields_ = [
        ("type", c_ubyte),
        ("code", c_ubyte),
        ("checksum", c_ushort),
        ("messageBody", c_uint),
    ]

    def __new__(self, icmp_buffer=None):
        return self.from_buffer_copy(icmp_buffer)

    def __init__(self, icmp_buffer=None):
        self.srcPort = self.src_port
        self.dstPort = self.dst_port
        # try:
        #     self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        #     self.protocol = self.protocol_map[self.protocol_num]
        # except:
        #     self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        #     self.protocol = str(self.protocol_num)
        #     print("warning by hsq !!!")
