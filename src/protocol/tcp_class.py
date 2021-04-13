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


class TCP(Structure):  # 20 bytes
    _fields_ = [
        ("src_port", c_ushort),
        ("dst_port", c_ushort),
        ("seq", c_uint),
        ("ack", c_uint),
        ("lenres", c_ubyte),
        ("flags", c_ubyte),
        ("win_size", c_ushort),
        ("checksum", c_ubyte),
        ("urg_point", c_ubyte),
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.srcPort = self.src_port
        self.dstPort = self.dst_port
        self.flagInfo = ""
        self.protocol = "TCP"

        if self.flags & Nonce:
            self.flagInfo += "Non "
        elif self.flags & CWR:
            self.flagInfo += "CWR "
        elif self.flags & ECNEcho:
            self.flagInfo += "ECN"
        elif self.flags & Urgent:
            self.flagInfo += "URG "
        elif self.flags & Acknowledgement:
            self.flagInfo += "ACK "
        elif self.flags & Push:
            self.flagInfo += "PSH"
        elif self.flags & Reset:
            self.flagInfo += "RST "
        elif self.flags & Syn:
            self.flagInfo += "SYN "
        elif self.flags & Fin:
            self.flagInfo += "FIN "
        self.flagInfo = "[%s]" % self.flagInfo[:-1]

        self.detailInfo = (
            "TCP:\nsrc Port:%s -> Dst Port:%s\nSeq:%s Ack:%s\nFlags:%s\n\n"
            % (
                self.srcPort,
                self.dstPort,
                self.seq,
                self.ack,
                self.flagInfo,
            )
        )

        self.info = "Port: %s -> %s %s Win=%s" % (
            self.srcPort,
            self.dstPort,
            self.flagInfo,
            self.win_size,
        )
