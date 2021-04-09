import socket
import struct
from ctypes import *
import time


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
        self.protocol_map = {
            0: "IP",
            1: "ICMP",
            2: "IGMP",
            3: "GGP",
            4: "IP-ENCAP",
            5: "ST",
            6: "TCP",
            8: "EGP",
            9: "IGP",
            12: "PUP",
            17: "UDP",
            41: "IPv6",
            43: "IPv6-Route",
            44: "IPv6-Frag",
            58: "IPv6-ICMP ",  # ICMP for IPv6
            59: "IPv6-NoNxt ",  # No Next Header for IPv6
            60: "IPv6-Opts ",
            88: "IGRP",
            89: "OSPF",
        }
        self.src_address = socket.inet_ntoa(struct.pack("<I", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<I", self.dst))
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)
            print("warning by hsq !!!")
            print("protocol is: " + self.protocol)
            time.sleep(1)
