import socket
import struct
from ctypes import *


class EthernetII(Structure):  # 14 bytes
    _fields_ = [
        ("dst_mac", c_ubyte * 6),
        ("src_mac", c_ubyte * 6),
        ("protocol_num", c_ushort),  # 16bit
    ]

    def __new__(self, mac_head=None):
        return self.from_buffer_copy(mac_head)

    def __init__(self, mac_head=None):
        self.protocol_map = {  # 目前支持的协议内容
            0x0800: "IP",
            0x0806: "ARP",
            0x86DD: "IPv6",
            0x8864: "PPPoE",
            0x9999: "Not support",
        }
        protocol_hex = socket.ntohs(self.protocol_num)

        self.src = ""
        self.dst = ""
        self.info = ""
        self.detailInfo = ""

        for i in self.src_mac:
            i = hex(i)
            self.src += "%s:" % str(i[2:])
        self.src = self.src[:-1]

        flag = False
        for i in self.dst_mac:
            if i == 255:
                flag = True
            else:
                flag = False
                break

        if flag:
            self.dst = "Broadcast"
        else:
            for i in self.dst_mac:
                i = hex(i)
                self.dst += "%s:" % str(i[2:])
            self.dst = self.dst[:-1]

        try:
            self.protocol = self.protocol_map[protocol_hex]
        except:
            self.protocol = self.protocol_map[0x9999]
            self.info = "Unknown protocol type is: 0x%x" % protocol_hex

        self.detailInfo = "Ethernet-II:\ndst mac:%s\nsrc mac:%s\nprotocol:%s\n\n" % (
            self.dst,
            self.src,
            self.protocol,
        )
