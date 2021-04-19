import socket
import struct
from ctypes import *

# ("ihl", c_ubyte, 4),  # 4bit
# ("ttl", c_ubyte),  # 8bit
# ("sum", c_ushort),  # 16bit
# ("src", c_uint),  # 32bit


class IPv6(Structure):  # 40 bytes
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
        zero = False

        for i in self.source:
            i = hex(i)
            if flag == 0:
                if i == "0x0":
                    zero = True
                else:
                    self.src += "%s" % str(i[2:])
                flag = 1
            else:
                if i == "0x0":
                    if zero:
                        self.src += ":"
                    else:
                        self.src += "%s:" % str(i[2:])
                else:
                    self.src += "%s:" % str(i[2:])
                zero = False
                flag = 0

        flag = 0
        zero = False

        for i in self.destination:
            i = hex(i)
            if flag == 0:
                if i == "0x0":
                    zero = True
                else:
                    self.dst += "%s" % str(i[2:])
                flag = 1
            else:
                if i == "0x0":
                    if zero:
                        self.dst += ":"
                    else:
                        self.dst += "%s:" % str(i[2:])
                else:
                    self.dst += "%s:" % str(i[2:])
                zero = False
                flag = 0

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
            self.next = protocol_map[self.NextHeader]
        except:
            self.next = self.NextHeader

        self.detailInfo = "IPv6:\nsrc:%s\ndst:%s\nNext Protocol:%s\n\n" % (
            self.src,
            self.dst,
            self.next,
        )

        # self.info = "Port: %s -> %s Len=%s" % (
        #     self.srcPort,
        #     self.dstPort,
        #     self.udpLength,
        # )
