import socket
import netifaces
import os
import sys

import time
import struct

sys.path.append(os.path.join(os.path.dirname(__file__), "./"))
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

# nicName = netifaces.gateways()["default"][netifaces.AF_INET][1]
# mr_ifindex = socket.if_nametoindex(nicName)  # c_type is int


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
    mr_ifindex = socket.if_nametoindex(routingNicName)
    return routingIPAddr, routingNicName, mr_ifindex


class MySniffer:
    def __init__(self, InputNicName=None):
        super(MySniffer, self).__init__()
        self.ipAddr, self.nicName, self.mr_ifindex = get_something()
        self.packet_mreq = struct.pack(
            "iHH8s", self.mr_ifindex, PACKET_MR_PROMISC, 0, b"\0"
        )

        if InputNicName and (InputNicName in netifaces.interfaces()):
            self.nic = str(InputNicName)
        else:
            self.nic = self.nicName

        self.port = 0
        self.data = bytes()
        self.address = bytes()

        self.snifferSocket = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)
        )
        try:
            self.snifferSocket.bind((self.nic, self.port))
        except:
            print(self.nic)
        self.snifferSocket.setsockopt(
            SOL_PACKET, PACKET_ADD_MEMBERSHIP, self.packet_mreq
        )

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

    def closeMe(self):
        self.snifferSocket.close()


if __name__ == "__main__":
    tcp = TCPSniffer()
    tcp.sniffing()
