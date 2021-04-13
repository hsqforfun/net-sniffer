import socket
import struct
from ctypes import *
import time


class IP(Structure):  # 20 bytes
    _pack_ = 2
    _fields_ = [
        ("version", c_ubyte, 4),  # In IPv4 is set to 0100, which indicates 4 in binary
        ("headerLength", c_ubyte, 4),  # how many 32-bit words are present in the header
        ("tos", c_ubyte),
        ("totalLength", c_ushort),  # The total length is measured in bytes
        ("id", c_ushort),
        ("flags", c_ubyte, 3),
        ("offset", c_ushort, 13),
        # ("offset", c_ushort),
        ("ttl", c_ubyte),  # 8bit
        ("protocol_num", c_ubyte),
        ("checksum", c_ushort),  # 16bit
        ("srcIP", c_uint),  # 32bit
        ("dstIP", c_uint),  # 32bit
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
        self.src = socket.inet_ntoa(struct.pack("<I", self.srcIP))
        self.dst = socket.inet_ntoa(struct.pack("<I", self.dstIP))

        self.info = "version: %s ttl: %s head: %s total: %s" % (
            self.version,
            self.ttl,
            self.headerLength,
            self.totalLength,
        )
        self.errorFlag = False
        self.errorInfo = ""

        try:
            self.protocol = self.protocol_map[self.protocol_num]
            self.errorFlag = False
            self.errorInfo = ""
        except:
            self.protocol = str(self.protocol_num)
            self.errorFlag = True
            self.errorInfo = "warning by hsq !!! Protocol is: %s " % self.protocol
            # time.sleep(1)

        self.detailInfo = "IP:\nversion:%d\nheader length:%d\ntotal length:%d\nttl:%d\nprotocol:%s\nchecksum:%d\nsrc:%s\ndst:%s\n\n" % (
            self.version,
            self.headerLength,
            self.totalLength,
            self.ttl,
            self.protocol,
            self.checksum,
            self.src,
            self.dst,
        )
