import socket
import os
import sys
import netifaces

from ip_class import IP
from tcp_class import TCP


class Sniffers:
    def __init__(self):
        super(Sniffers, self).__init__()
        hostname = socket.gethostname()
        HOST = socket.gethostbyname(hostname)
        self.ipAddr = self.get_something()
        self.returnString = ""

    def addString(self, str):
        self.returnString += str + "\n"

    def clearString(self):
        self.returnString = ""

    def get_something(self):
        routingGateway = netifaces.gateways()["default"][netifaces.AF_INET][0]
        routingNicName = netifaces.gateways()["default"][netifaces.AF_INET][1]

        for interface in netifaces.interfaces():
            if interface == routingNicName:
                # self.addString netifaces.ifaddresses(interface)
                routingNicMacAddr = netifaces.ifaddresses(interface)[netifaces.AF_LINK][
                    0
                ]["addr"]
                try:
                    routingIPAddr = netifaces.ifaddresses(interface)[netifaces.AF_INET][
                        0
                    ]["addr"]
                    # TODO(Guodong Ding) Note: On Windows, netmask maybe give a wrong result in 'netifaces' module.
                    routingIPNetmask = netifaces.ifaddresses(interface)[
                        netifaces.AF_INET
                    ][0]["netmask"]
                except KeyError:
                    pass

        # display_format = "%-30s %-20s"
        # self.addString(display_format % ("Routing Gateway:", routingGateway))
        # self.addString(display_format % ("Routing NIC Name:", routingNicName))
        # self.addString(display_format % ("Routing NIC MAC Address:", routingNicMacAddr))
        # self.addString(display_format % ("Routing IP Address:", routingIPAddr))
        # self.addString(display_format % ("Routing IP Netmask:", routingIPNetmask))
        return routingIPAddr

    def sniffing(self, hostIP, winORlinux, socket_proto):
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_proto)
        port = 0
        sniffer.bind((hostIP, port))

        # include the IP headers in the captured packets
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if winORlinux == 1:
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        # read in a single packet
        self.addString("Listening ...")

        try:
            data, address = sniffer.recvfrom(65565)
            # data, address = sniffer.recvfrom(65565, 0x40)  # 0x40 MSG_NONBLOCK
        except BlockingIOError as e:
            data = None
            address = None
            self.addString("Blocking!")
            return

        ip_header = IP(data[:20])
        self.addString("IP head:")
        self.addString(
            "Protocol: %s %s -> %s"
            % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)
        )
        self.addString("ttl: %s" % (ip_header.ttl))

        self.addString("TCP head:")
        tcp_header = TCP(data[20:40])
        self.addString("Port: %s -> %s" % (tcp_header.srcPort, tcp_header.dstPort))
        self.addString("Seq: %s Ack: %s" % (tcp_header.seq, tcp_header.ack))

        for item in address:
            if item != 0:
                self.addString("address: " + str(item))

    def call_from_others(self):
        if os.name == "nt":  # windows
            self.sniffing(self.ipAddr, 1, socket.IPPROTO_IP)
            # sniffing(self.ipAddr, 1, socket.IPPROTO_IP)  # 0
        else:  # Linux
            self.addString("Linux : " + self.ipAddr)
            # self.sniffing(self.ipAddr, 0, socket.IPPROTO_ICMP)  # 1
            # self.sniffing(self.ipAddr, 0, socket.IPPROTO_TCP)  # 6
            self.sniffing(self.ipAddr, 0, socket.IPPROTO_UDP)  # 17

    def myPrint(self):
        self.addString("Hello there.")


if __name__ == "__main__":
    try:
        import netifaces
    except ImportError:
        try:
            command_to_execute = "pip install netifaces || easy_install netifaces"
            os.system(command_to_execute)
        except OSError:
            print("Can NOT install netifaces, Aborted!")
            sys.exit(1)
        import netifaces
    # hostIP to listen
    hostname = socket.gethostname()
    HOST = socket.gethostbyname(hostname)

    snf = Sniffers()

    snf.ipAddr = snf.get_something()

    if os.name == "nt":  # windows
        snf.sniffing(ipAddr, 1, socket.IPPROTO_IP)  # 0
    else:  # Linux
        print("Linux : " + HOST)
        # snf.sniffing(ipAddr, 0, socket.IPPROTO_ICMP)  # 1
        # snf.sniffing(ipAddr, 0, socket.IPPROTO_TCP)  # 6
        snf.sniffing(ipAddr, 0, socket.IPPROTO_UDP)  # 17
