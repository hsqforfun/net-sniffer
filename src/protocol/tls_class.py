from ctypes import *
import socket

contentMap = {
    20: "change cipher spec",
    21: "alert",
    22: "handshake",
    23: "application data",
    24: "heartbeat",
    25: "tls12 cid",
}

versionMap = {
    0x301: "TLS 1.0",
    0x302: "TLS 1.1",
    0x303: "TLS 1.2",
    0x304: "TLS 1.4",
}


class recordLayerHeader(Structure):

    _pack_ = 1
    _fields_ = [
        ("contentTypeNum", c_ubyte),
        ("versionNum", c_ushort),
        ("layerlength", c_ushort),
    ]

    def __new__(self, buffer=None):
        return self.from_buffer_copy(buffer)

    def __init__(self, buffer=None):
        self.versionNum = socket.ntohs(self.versionNum)
        self.layerlength = socket.ntohs(self.layerlength)

        try:
            self.version = versionMap[self.versionNum]
        except:
            self.version = str(hex(self.versionNum))

        try:
            self.contentType = contentMap[self.contentTypeNum]
        except:
            self.contentType = str(hex(self.contentTypeNum))

        self.detailInfo = "content type:%s\n version:%s\n layer length:%d\n" % (
            self.contentType,
            self.version,
            self.layerlength,
        )


class TLS:
    def __init__(self, data):
        self.data = data
        self.length = len(data)
        self.LayerHead = []
        self.LayerMessage = []
        self.tail = 0
        self.cnt = 0
        self.protocol = "TLS"
        self.detailInfo = "TLS:\n"
        self.info = ""

        while self.tail < self.length:
            self.LayerHead.append(
                recordLayerHeader(self.data[self.tail : self.tail + 5])
            )
            thisLength = int(self.LayerHead[self.cnt].layerlength)
            self.LayerMessage.append(data[self.tail + 5 : self.tail + thisLength])
            self.tail += 5 + thisLength
            self.cnt += 1

        self.protocol = self.LayerHead[0].version

        for i in range(self.cnt):
            self.detailInfo += "TLS Report Layer %d:\n %s" % (
                i + 1,
                self.LayerHead[i].detailInfo,
            )
            self.info += str("[%s] " % self.LayerHead[i].contentType)
