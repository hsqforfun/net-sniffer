import socket
import os
import sys
from ip_class import IP
from tcp_class import TCP
import netifaces


class Sniffers:
    def __init__(self):
        super(Sniffers, self).__init__()

    def get_something(self):
        routingGateway = netifaces.gateways()["default"][netifaces.AF_INET][0]
        routingNicName = netifaces.gateways()["default"][netifaces.AF_INET][1]

        for interface in netifaces.interfaces():
            if interface == routingNicName:
                # print netifaces.ifaddresses(interface)
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

        display_format = "%-30s %-20s"
        print(display_format % ("Routing Gateway:", routingGateway))
        print(display_format % ("Routing NIC Name:", routingNicName))
        print(display_format % ("Routing NIC MAC Address:", routingNicMacAddr))
        print(display_format % ("Routing IP Address:", routingIPAddr))
        print(display_format % ("Routing IP Netmask:", routingIPNetmask))
        return routingIPAddr

    def sniffing(self, host, winORlinux, socket_proto):
        while 1:
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_proto)
            port = 0
            sniffer.bind((host, port))

            # include the IP headers in the captured packets
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            if winORlinux == 1:
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            # read in a single packet
            print("Listening ...")

            try:
                data, address = sniffer.recvfrom(65565)
                # data, address = sniffer.recvfrom(65565, 0x40) # 0x40 MSG_NONBLOCK
            except BlockingIOError as e:
                data = None
                address = None
                print("Blocking!")
                return

            ip_header = IP(data[:20])
            print("IP head:")
            print(
                "Protocol: %s %s -> %s"
                % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)
            )
            print("ttl: %s" % (ip_header.ttl))

            print("TCP head:")
            tcp_header = TCP(data[20:40])
            print("Port: %s -> %s" % (tcp_header.srcPort, tcp_header.dstPort))
            print("Seq: %s Ack: %s" % (tcp_header.seq, tcp_header.ack))
            print(".")

            for item in address:
                if item != 0:
                    print("address: " + str(item))
            print("")

    def call_from_others(self):
        hostname = socket.gethostname()
        HOST = socket.gethostbyname(hostname)

        ipAddr = self.get_something()

        if os.name == "nt":  # windows
            self.sniffing(ipAddr, 1, socket.IPPROTO_IP)
            # sniffing(ipAddr, 1, socket.IPPROTO_IP)  # 0
        else:  # Linux
            print("Linux : " + HOST)
            self.sniffing(ipAddr, 0, socket.IPPROTO_ICMP)  # 1
            # self.sniffing(ipAddr, 0, socket.IPPROTO_TCP)  # 6
            # self.sniffing(ipAddr, 0, socket.IPPROTO_UDP)  # 17

    def myPrint(self):
        print("Hello there.")


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
    # host to listen
    hostname = socket.gethostname()
    HOST = socket.gethostbyname(hostname)

    snf = Sniffers()

    ipAddr = snf.get_something()

    if os.name == "nt":  # windows
        snf.sniffing(ipAddr, 1, socket.IPPROTO_IP)  # 0
    else:  # Linux
        print("Linux : " + HOST)
        # snf.sniffing(ipAddr, 0, socket.IPPROTO_ICMP)  # 1
        # snf.sniffing(ipAddr, 0, socket.IPPROTO_TCP)  # 6
        snf.sniffing(ipAddr, 0, socket.IPPROTO_UDP)  # 17
