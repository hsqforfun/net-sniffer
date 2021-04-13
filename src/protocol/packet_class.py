import socket
import struct
from ctypes import *
import time
from . import *


class Packet(Structure):
    def updateMe(self, header):
        if hasattr(header, "src"):
            self.src = header.src
        if hasattr(header, "dst"):
            self.dst = header.dst
        if hasattr(header, "protocol"):
            self.protocol = header.protocol
        if hasattr(header, "info"):
            self.info = header.info
        if hasattr(header, "detailInfo"):
            self.detailInfo += header.detailInfo

    def __init__(self, data, address):
        self.data = data
        self.length = len(self.data)
        self.addres = address
        self.detailInfo = ""
        self.info = ""
        self.protocol = ""
        self.src = ""
        self.dst = ""

        # 定义报头
        self.frame = Frame(self.length, self.addres)
        self.updateMe(self.frame)

        self.ethernetHead = EthernetII(self.data[:14])
        self.updateMe(self.ethernetHead)

        if self.ethernetHead.protocol == "IP":
            self.ipHead = IP(self.data[14:34])
            self.updateMe(self.ipHead)

            if self.ipHead.protocol == "TCP":
                self.tcpHead = TCP(self.data[34:54])
                self.updateMe(self.tcpHead)
                if self.tcpHead.srcPort == 80 | self.tcpHead.dstPort == 80:
                    self.httpHead = Http(self.data[54:])
            elif self.ipHead.protocol == "UDP":
                self.udpHead = TCP(self.data[34:])
                self.updateMe(self.udpHead)
            else:
                pass

        elif self.ethernetHead.protocol == "IPv6":
            self.ipv6Head = IPv6(self.data[14:54])
            self.updateMe(self.ipv6Head)
            if self.ipv6Head.protocol == "TCP":
                self.tcpHead = TCP(self.data[54:74])
                self.updateMe(self.tcpHead)
                if self.tcpHead.srcPort == 80 | self.tcpHead.dstPort == 80:
                    self.httpHead = Http(self.data[54:])
            elif self.ipHead.protocol == "UDP":
                self.udpHead = TCP(self.data[54:])
                self.updateMe(self.udpHead)
            else:
                pass

        elif self.ethernetHead.protocol == "ARP":
            self.arpHead = ARP(self.data[14:42])
            self.updateMe(self.arpHead)

        else:
            self.detailInfo += "Unfinished Ethernet-II protocol"