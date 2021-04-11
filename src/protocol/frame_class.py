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

        self.src = ""
        self.dst = ""
        self.info = ""

        for i in reversed(self.src_mac):
            self.src += "%s." % str(i)
        self.src = self.src[:-1]

        for i in reversed(self.dst_mac):
            self.dst += "%s." % str(i)
        self.dst = self.dst[:-1]

        try:
            self.protocol = self.protocol_map[self.protocol_hex]
        except:
            self.protocol = self.protocol_map[0x9999]
            self.info = "Unknown protocol is: 0x%x" % self.protocol_hex

        self.detailInfo = "dst mac:%s\nsrc mac:%s\nprotocol:%s\n" % (
            self.dst,
            self.src,
            self.protocol,
        )
