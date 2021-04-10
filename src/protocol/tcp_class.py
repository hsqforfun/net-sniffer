import socket
import struct
from ctypes import *

# ("ihl", c_ubyte, 4),  # 4bit
# ("ttl", c_ubyte),  # 8bit
# ("sum", c_ushort),  # 16bit
# ("src", c_uint),  # 32bit


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
        self.src = ""
        self.dst = ""
        self.protocol = ""
        self.info = "Port: %s -> %s . Seq: %s Ack: %s" % (
            self.srcPort,
            self.dstPort,
            self.seq,
            self.ack,
        )

        # self
        # try:
        #     self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        #     self.protocol = self.protocol_map[self.protocol_num]
        # except:
        #     self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        #     self.protocol = str(self.protocol_num)
        #     print("warning by hsq !!!")
