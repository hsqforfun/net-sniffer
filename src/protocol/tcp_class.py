import socket
import struct
from ctypes import *

# ("ihl", c_ubyte, 4),  # 4bit
# ("ttl", c_ubyte),  # 8bit
# ("sum", c_ushort),  # 16bit
# ("src", c_uint),  # 32bit

CWR = 0x80
ECNEcho = 0x40
Urgent = 0x20
Acknowledgement = 0x10
Push = 0x08
Reset = 0x04
Syn = 0x02
Fin = 0x01


class TCPOption:
    def __init__(self, optionbuffer):
        self.options = optionbuffer


class TCP(Structure):  # 20 bytes
    _pack_ = 2
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
        self.srcPort = socket.ntohs(self.src_port)
        self.dstPort = socket.ntohs(self.dst_port)
        self.flagInfo = ""
        self.protocol = "TCP"
        self.len = int((self.lenres & 0xF0) / 4)
        self.seq = socket.ntohl(self.seq)
        self.ack = socket.ntohl(self.ack)

        if self.flags & CWR:
            self.flagInfo += "CWR "
        if self.flags & ECNEcho:
            self.flagInfo += "ECN "
        if self.flags & Urgent:
            self.flagInfo += "URG "
        if self.flags & Acknowledgement:
            self.flagInfo += "ACK "
        if self.flags & Push:
            self.flagInfo += "PSH "
        if self.flags & Reset:
            self.flagInfo += "RST "
        if self.flags & Syn:
            self.flagInfo += "SYN "
        if self.flags & Fin:
            self.flagInfo += "FIN "
        self.flagInfo = "[%s]" % self.flagInfo[:-1]

        self.detailInfo = (
            "TCP:\nPort:%s -> %s\nSeq:%s Ack:%s\nFlags:%s\nHeader Length:%s\n\n"
            % (self.srcPort, self.dstPort, self.seq, self.ack, self.flagInfo, self.len)
        )

        self.info = "Port: %s -> %s %s Win=%s" % (
            self.srcPort,
            self.dstPort,
            self.flagInfo,
            self.win_size,
        )
