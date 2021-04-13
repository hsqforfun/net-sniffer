import socket
import struct
from ctypes import *

# ("ihl", c_ubyte, 4),  # 4bit
# ("ttl", c_ubyte),  # 8bit
# ("sum", c_ushort),  # 16bit
# ("src", c_uint),  # 32bit


class IPv6(Structure):  # 20 bytes
    _pack_ = 2
    _fields_ = [
        ("version", c_ubyte, 4),
        ("trafficClass", c_ubyte),
        ("flowLabel", c_ushort),
        ("flowLabel_remain", c_ubyte, 4),
        ("payloadLength", c_ubyte),
        ("NextHeader", c_ubyte, 4),
        ("hopLimit", c_ubyte, 4),
        ("source", c_ubyte * 16),
        ("destination", c_ubyte * 16),
    ]

    def __new__(self, buffer=None):
        return self.from_buffer_copy(buffer)

    def __init__(self, buffer=None):
        self.src = self.dst = ""
        flag = 0
        for i in reversed(self.source):
            i = hex(i)
            if flag == 0:
                self.src += "%s" % str(i[2:])
                flag = 1
            else:
                flag = 0
                self.src += "%s:" % str(i[2:])
        flag = 0
        for i in reversed(self.destination):
            i = hex(i)
            if flag == 0:
                self.dst += "%s" % str(i[2:])
                flag = 1
            else:
                flag = 0
                self.dst += "%s:" % str(i[2:])

        self.src = self.src[:-1]
        self.dst = self.dst[:-1]
        self.protocol = "IPv6"
        protocol_map = {
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
        try:
            self.nxt = protocol_map[self.NextHeader]
        except:
            pass
        # try:
        #     self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        #     self.protocol = self.protocol_map[self.protocol_num]
        # except:
        #     self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        #     self.protocol = str(self.protocol_num)
        #     print("warning by hsq !!!")
