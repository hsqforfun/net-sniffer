import socket
import struct
from ctypes import *

typemap = {
    128: "ping",
    129: "回ping",
    133: "路由器请求",
    134: "路由器通告",
    135: "邻节点请求",
    136: "邻节点通告",
    137: "重定向",
}


class ICMPv6(Structure):  # 20 bytes
    _fields_ = [
        ("type", c_ubyte),
        ("code", c_ubyte),
        ("checksum", c_ushort),
        ("reserved", c_uint),
        ("targetAddress", c_ubyte * 16),
    ]

    def __new__(self, buffer=None):
        return self.buffer(socket_buffer)

    def __init__(self, buffer=None):
        self.icmpOption = buffer[24:]
        self.protocol = "ICMPv6"
        self.target = ""

        flag = 0
        zero = False
        for i in self.targetAddress:
            i = hex(i)
            if flag == 0:
                if i == "0x0":
                    zero = True
                else:
                    self.target += "%s" % str(i[2:])
                flag = 1
            else:
                if i == "0x0":
                    if zero:
                        self.target += ":"
                    else:
                        self.dst += "%s:" % str(i[2:])
                else:
                    self.target += "%s:" % str(i[2:])
                zero = False
                flag = 0
        self.target = self.target[:-1]

        try:
            self.typeInfo = typemap[self.type]
        except:
            self.typeInfo = self.type

        self.detailInfo = "ICMPv6:\n%s -> :%s\n\n" % (
            self.typeInfo,
            self.target,
        )

        self.info = "%s -> :%s" % (
            self.typeInfo,
            self.target,
        )
