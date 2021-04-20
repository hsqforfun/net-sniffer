import socket
import struct
from ctypes import *
import time
import sys

from .tcp_class import TCP, TCPOption
from .ip_class import IP
from .ethernet_class import EthernetII
from .arp_class import ARP
from .frame_class import Frame
from .void_class import VoidHeader
from .packet_class import Packet
from .http_class import Http
from .ipv6_class import IPv6
from .udp_class import UDP
from .icmpv6_class import ICMPv6
from .tls_class import TLS

CWR = 0x80
ECNEcho = 0x40
URG = 0x20
ACK = 0x10
PSH = 0x08
RST = 0x04
SYN = 0x02
FIN = 0x01


class Tracing:
    def __init__(self, tcpDict=None):
        self.dict = tcpDict
        self.clientSeqBase = 0
        self.ServerSeqBase = 0
        self.clientBye = 0
        self.serverBye = 0
        self.clientIP = None
        self.serverIP = None
        self.finishFlag = False

    def shake1(self):
        for (Num, pkt) in self.dict.items():
            if pkt.tcpHead.flags == SYN and pkt.tcpHead.ack == 0:
                self.clientSeqBase = pkt.tcpHead.seq
                self.clientIP = pkt.src
                self.serverIP = pkt.dst
                break
        if self.clientSeqBase == 0:
            print("No first handshake of TCP connection included!")
        else:
            print("SYN: clientSeqBase:%d " % (self.clientSeqBase))
            self.shake2()

    def shake2(self):
        for (Num, pkt) in self.dict.items():
            if (pkt.tcpHead.flags == (SYN | ACK)) and (
                pkt.tcpHead.ack == self.clientSeqBase + 1
            ):
                self.ServerSeqBase = pkt.tcpHead.seq
                break
        if self.ServerSeqBase == 0:
            print("No second handshake of TCP connection included!")
        else:
            print("SYN ACK: ServerSeqBase:%d" % (self.ServerSeqBase))
            self.shake3()

    def shake3(self):
        for (Num, pkt) in self.dict.items():
            if (
                (pkt.tcpHead.flags == ACK)
                and (pkt.tcpHead.seq == (self.clientSeqBase + 1))
                and (pkt.tcpHead.ack == (self.ServerSeqBase + 1))
            ):
                print("Connecting Ok...")
                self.bye1()

    def bye1(self):
        flg = False
        for (Num, pkt) in self.dict.items():
            if (pkt.tcpHead.flags & FIN) and pkt.src == self.clientIP:
                self.clientBye = pkt.tcpHead.seq
                self.bye2()
                flg = True
        if flg == False:
            print("Not finishing.")

    def bye2(self):
        flg = False
        for (Num, pkt) in self.dict.items():
            if (
                pkt.tcpHead.flags & ACK
                and pkt.src == self.serverIP
                and pkt.tcpHead.ack == (self.clientBye + 1)
            ):
                flg = True
                self.bye3()
        if flg == False:
            print("No bye2.")

    def bye3(self):
        flg = False
        for (Num, pkt) in self.dict.items():
            if (
                pkt.tcpHead.flags == (FIN | ACK)
                and pkt.src == self.serverIP
                and pkt.tcpHead.ack == (self.clientBye + 1)
            ):
                self.serverBye = pkt.tcpHead.seq
                flg = True
                self.bye4()

        if flg == False:
            print("Not bye3.")

    def bye4(self):
        flg = False
        for (Num, pkt) in self.dict.items():
            if (
                pkt.tcpHead.flags == ACK
                and pkt.src == self.clientIP
                and pkt.tcpHead.seq == (self.clientBye + 1)
                and pkt.tcpHead.ack == (self.serverBye + 1)
            ):
                print("finish this stream.")
                flg = True
                self.dirtIt(Num)

        if flg == False:
            print("Not bye4.")

    def dirtIt(self, lastRowNum):
        for (Num, pkt) in self.dict.items():
            if Num > lastRowNum:
                pkt.dirt = True
