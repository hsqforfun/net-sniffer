import socket
import struct
from ctypes import *
import time

from .tcp_class import TCP, TCPOption
from .ip_class import IP
from .ethernet_class import EthernetII
from .arp_class import ARP
from .frame_class import Frame
from .void_class import VoidHeader
from .http_class import Http
from .ipv6_class import IPv6
from .udp_class import UDP
from .icmpv6_class import ICMPv6
from .tls_class import TLS


httpPort = [443, 80]
tlsPort = [443]
httpString = ["GET", "POST", "HTTP"]


def hasString(StringItem, Target):
    for i in StringItem:
        if i in Target:
            return True
    return False


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
        self.row = None
        self.dirt = False
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
                self.tcpOptionLen = self.tcpHead.len - 20
                if self.tcpOptionLen != 0:
                    self.tcpOption = TCPOption(self.data[54 : self.tcpOptionLen])
                if self.length - 54 - self.tcpOptionLen > 10:
                    pieceStr = str(
                        self.data[54 + self.tcpOptionLen : 74 + self.tcpOptionLen]
                    )
                    if (
                        (self.tcpHead.srcPort in httpPort)
                        or (self.tcpHead.dstPort in httpPort)
                    ) and (hasString(httpString, pieceStr)):
                        self.httpHead = Http(self.data[54 + self.tcpOptionLen :])
                        self.updateMe(self.httpHead)
                    elif (
                        (self.tcpHead.srcPort in tlsPort)
                        or (self.tcpHead.dstPort in tlsPort)
                    ) and (not hasString(httpString, pieceStr)):
                        self.tlsHead = TLS(self.data[54 + self.tcpOptionLen :])
                        self.updateMe(self.tlsHead)

            elif self.ipHead.protocol == "UDP":
                self.udpHead = UDP(self.data[34:])
                self.updateMe(self.udpHead)
            else:
                pass

        elif self.ethernetHead.protocol == "IPv6":
            self.ipv6Head = IPv6(self.data[14:54])
            self.updateMe(self.ipv6Head)
            if self.ipv6Head.protocol == "TCP":
                self.tcpHead = TCP(self.data[34:54])
                self.updateMe(self.tcpHead)
                self.tcpOptionLen = self.tcpHead.len - 20
                if self.tcpOptionLen != 0:
                    self.tcpOption = TCPOption(self.data[54 : self.tcpOptionLen])
                if self.length - 54 - self.tcpOptionLen > 10:
                    pieceStr = str(
                        self.data[54 + self.tcpOptionLen : 74 + self.tcpOptionLen]
                    )
                    if (
                        (self.tcpHead.srcPort in httpPort)
                        or (self.tcpHead.dstPort in httpPort)
                    ) and (hasString(httpString, pieceStr)):
                        self.httpHead = Http(self.data[54 + self.tcpOptionLen :])
                        self.updateMe(self.httpHead)
                    elif (
                        (self.tcpHead.srcPort in tlsPort)
                        or (self.tcpHead.dstPort in tlsPort)
                    ) and (not hasString(httpString, pieceStr)):
                        self.tlsHead = TLS(self.data[54 + self.tcpOptionLen :])
                        self.updateMe(self.tlsHead)

            elif self.ipv6Head.protocol == "UDP":
                self.udpHead = TCP(self.data[54:])
                self.updateMe(self.udpHead)

            elif self.ipv6Head.protocol == "IPv6-ICMP":
                self.icmpv6Head = ICMPv6(self.data[54:])
                self.updateMe(self.icmpv6Head)
            else:
                pass

        elif self.ethernetHead.protocol == "ARP":
            self.arpHead = ARP(self.data[14:42])
            self.updateMe(self.arpHead)

        else:
            self.detailInfo += "Unfinished Ethernet-II protocol"

    def hasHttpString(self, https=0):
        ret = "HTTP" in str(self.data[54 + self.tcpOptionLen : 74 + self.tcpOptionLen])
        if https == 0:
            print(ret)
            ret
        else:
            not ret
