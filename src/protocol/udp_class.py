import socket
import struct
from ctypes import *


class UDP(Structure):  # 20 bytes
    _fields_ = [
        ("src_port", c_ushort),
        ("dst_port", c_ushort),
        ("length", c_ushort),
        ("checksum", c_uint),
    ]

    def __new__(self, buffer=None):
        return self.from_buffer_copy(buffer)

    def __init__(self, buffer=None):
        self.srcPort = self.src_port
        self.dstPort = self.dst_port
        self.udpLength = self.length
        self.udpdata = buffer[8:]

        self.protocol = "UDP"

        self.detailInfo = "UDP:\nPort:%s -> :%s\Length:%s\nCheckSum:%s\n\n" % (
            self.srcPort,
            self.dstPort,
            self.udpLength,
            self.checksum,
        )

        self.info = "Port: %s -> %s Len=%s" % (
            self.srcPort,
            self.dstPort,
            self.udpLength,
        )
