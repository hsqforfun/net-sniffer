from socket import AF_NETLINK, SOCK_DGRAM
import socket
import os
import sys
import netifaces
import time
import struct

import ctypes
import fcntl

from ip_class import IP
from tcp_class import TCP
from frame_class import Frame
from arp_class import ARP

hostName = "enx000ec6c14487"
port = 0


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


# For packet_mreq structure
mr_ifindex = socket.if_nametoindex(hostName)  # c_type is int
mr_type = PACKET_MR_PROMISC  # c_type is unsigned short
mr_alen = 0  # c_type is unsigned short
mr_address = b"\0"  # c_type is unsigned char[8]
packet_mreq = struct.pack("iHH8s", mr_ifindex, mr_type, mr_alen, mr_address)

routingNicName = ""


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
                # TODO(Guodong Ding) Note: On Windows, netmask maybe give a wrong result in 'netifaces' module.
                routingIPNetmask = netifaces.ifaddresses(interface)[netifaces.AF_INET][
                    0
                ]["netmask"]
            except KeyError:
                pass

    display_format = "%-30s %-20s"
    print(display_format % ("Routing Gateway:", routingGateway))
    print(display_format % ("Routing NIC Name:", routingNicName))
    print(display_format % ("Routing NIC MAC Address:", routingNicMacAddr))
    print(display_format % ("Routing IP Address:", routingIPAddr))
    print(display_format % ("Routing IP Netmask:", routingIPNetmask))
    return routingIPAddr


def print_ip(ipHead):
    print(
        "IP head: Protocol: %s %s -> %s"
        % (ipHead.protocol, ipHead.src_address, ipHead.dst_address)
    )
    print("ttl: %s" % (ipHead.ttl))


def print_tcp(tcpHead):
    print("TCP head:")
    print("Port: %s -> %s" % (tcpHead.srcPort, tcpHead.dstPort))
    print("Seq: %s Ack: %s" % (tcpHead.seq, tcpHead.ack))


def print_arp(arpHead):
    print("ARP")
    print("type: %s %s -> %s" % (arpHead.op, arpHead.src_ip_str, arpHead.dst_ip_str))


def sniffing(hostIP):
    print("Listening ...")
    while 1:

        sniffer = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)
        )

        sniffer.bind((hostName, port))
        sniffer.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, packet_mreq)

        try:
            data, address = sniffer.recvfrom(65565)
            # data, address = sniffer.recvfrom(65565, 0x40)  # 0x40 MSG_NONBLOCK
        except BlockingIOError as e:
            data = None
            address = None
            print("Blocking!")
            time.sleep(1)
            continue

        mac_head = Frame(data[:14])

        if mac_head.protocol == "ARP":
            print("Frame head: Protocol: %s" % (mac_head.protocol))
            arp_head = ARP(data[14:42])
            print_arp(arp_head)

        elif mac_head.protocol == "IP":
            ip_header = IP(data[14:34])
            print_ip(ip_header)

            if ip_header.protocol == "TCP":
                tcp_header = TCP(data[34:54])
                print_tcp(tcp_header)
            else:
                print("Unfinished IP protocol")

        elif mac_head.protocol == "IPv6":
            print("Frame head: Protocol: %s" % (mac_head.protocol))

        else:
            print("Unfinished Frame protocol")
        # for item in address:
        #     if item != 0:
        #         print("address: " + str(item))
        print()


if __name__ == "__main__":

    ipAddr = get_something()

    sniffing(ipAddr)  # 17