import socket
import struct
from ctypes import *

# ("ihl", c_ubyte, 4),  # 4bit
# ("ttl", c_ubyte),  # 8bit
# ("sum", c_ushort),  # 16bit
# ("src", c_uint),  # 32bit

Nonce = 0x100
CWR = 0x080
ECNEcho = 0x040
Urgent = 0x020
Acknowledgement = 0x010
Push = 0x008
Reset = 0x004
Syn = 0x002
Fin = 0x001


class UDP(Structure):  # 20 bytes
    _fields_ = [
        ("src_port", c_ushort),
        ("dst_port", c_ushort),
        ("length", c_ushort),
        ("checksum", c_uint),
    ]

    def __new__(self, buffer=None):
        return self.buffer(socket_buffer)

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
