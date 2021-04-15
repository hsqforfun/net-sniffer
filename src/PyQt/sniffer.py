import socket
import os
import sys
import netifaces
import time
import struct

sys.path.append(os.path.join(os.path.dirname(__file__), "../"))
from protocol import *

SelectListString = 1
SelectDetailString = 2
SelectBinaryString = 3

SIOCGIFHWADDR = 0x8927  # Get hardware address
SIOCGIFADDR = 0x8915  # get PA address
SIOCGIFNETMASK = 0x891B  # get network PA mask
SIOCGIFNAME = 0x8910  # get iface name
SIOCSIFLINK = 0x8911  # set iface channel
SIOCGIFCONF = 0x8912  # get iface list
SIOCGIFFLAGS = 0x8913  # get flags
SIOCSIFFLAGS = 0x8914  # set flags
SIOCGIFINDEX = 0x8933  # name -> if_index mapping
SIOCGIFCOUNT = 0x8938  # get number of devices
SIOCGSTAMP = 0x8906  # get packet timestamp (as a timeval)
IFF_PROMISC = 0x100
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_DROP_MEMBERSHIP = 2
PACKET_RECV_OUTPUT = 3
PACKET_RX_RING = 5
PACKET_STATISTICS = 6
PACKET_MR_MULTICAST = 0
PACKET_MR_PROMISC = 1
PACKET_MR_ALLMULTI = 2
PACKET_MR_PROMISC = 1
ETH_P_ALL = 3
ETH_P_IP = 0x800

hostName = netifaces.gateways()["default"][netifaces.AF_INET][1]
mr_ifindex = socket.if_nametoindex(hostName)  # c_type is int
mr_type = PACKET_MR_PROMISC  # c_type is unsigned short
mr_alen = 0  # c_type is unsigned short
mr_address = b"\0"  # c_type is unsigned char[8]
packet_mreq = struct.pack("iHH8s", mr_ifindex, mr_type, mr_alen, mr_address)


def get_something():
    routingGateway = netifaces.gateways()["default"][netifaces.AF_INET][0]
    routingNicName = netifaces.gateways()["default"][netifaces.AF_INET][1]
    for interface in netifaces.interfaces():
        if interface == routingNicName:
            routingNicMacAddr = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0][
                "addr"
            ]
            try:
                routingIPAddr = netifaces.ifaddresses(interface)[netifaces.AF_INET][0][
                    "addr"
                ]
                routingIPNetmask = netifaces.ifaddresses(interface)[netifaces.AF_INET][
                    0
                ]["netmask"]
            except KeyError:
                pass
    return routingIPAddr, routingNicName


class MySniffer:
    def __init__(self):
        super(MySniffer, self).__init__()
        self.ipAddr, self.hostName = get_something()

        self.port = 0
        self.data = bytes()
        self.address = bytes()

        self.snifferSocket = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)
        )
        self.snifferSocket.bind((self.hostName, self.port))
        self.snifferSocket.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, packet_mreq)

        # if os.name == "nt":
        #     snifferSocket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    def sniffing(self):
        try:
            self.data, self.address = self.snifferSocket.recvfrom(65565)
        except BlockingIOError as e:
            print("Blocking! Not happened!")
            time.sleep(1)

    def myClear(self):
        self.data = bytes()
        self.address = bytes()


if __name__ == "__main__":
    tcp = TCPSniffer()
    tcp.sniffing()

# class TCPSniffer:
#     def __init__(self):
#         self.ipAddr, self.hostName = get_something()
#         self.socket_proto = socket.IPPROTO_TCP
#         self.sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, self.socket_proto)
#         port = 0
#         self.sniffer.bind((self.ipAddr, port))
#         self.sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

#     def sniffing(self):
#         while 1:
#             print("Listening ...")
#             data, address = self.sniffer.recvfrom(65565)
#             cnt = 0
#             for i in data:
#                 cnt += 1
#                 # print(chr(i), end=" ")
#                 print(hex(i)[2:], end=" ")
#                 if cnt % 16 == 0:
#                     cnt = 0
#                     print()
#             break
