from Ui_qtLearn import Ui_MainWindow
from PyQt5 import QtWidgets
from PyQt5.QtCore import *
from PyQt5.QtGui import QTextCursor

import sys
import time

sys.path.append("..")
from protocol import *
from sniffer import MySniffer


class MyWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        super(MyWindow, self).__init__()
        self.setupUi(self)
        self.sniffer = MySniffer()
        self.count = 0
        self.length = 0
        self.snipFlag = True
        self.snipTimes = 1
        self.DetailInfo = ""

    # def outputText(self, text):
    #     cursor = self.ListText.textCursor()
    #     cursor.movePosition(QTextCursor.atEnd)
    #     cursor.insertText(text)
    #     self.ListText.setTextCursor(cursor)
    #     self.ListText.ensureCursorVisible()

    def print_list(self, head):
        self.ListNumber.append(str(self.count))  # self.count
        self.ListSrc.append(head.src)
        self.ListDst.append(head.dst)
        self.ListProtocol.append(head.protocol)
        self.ListLength.append(str(self.length))
        self.ListInfo.append(head.info)

    def print_detail(self, str):
        self.DetailText.append(str)

    def print_binary(self, bytesData):
        c = bytesData.hex()
        c = " ".join(c[i : i + 2] for i in range(0, len(c), 2))
        # c = "| ".join(c[i : i + 24] for i in range(0, len(c), 48))
        c = "\n".join(c[i : i + 48] for i in range(0, len(c), 48))
        self.Binarytext.append(c)

    def stop(self):
        self.snipFlag = False

    def conti(self):
        self.snipFlag = True

    def snip(self):
        # while self.snipFlag:
        for _ in range(self.snipTimes):
            self.sniffer.sniffing()
            data = self.sniffer.data
            self.count += 1
            self.length = len(data)

            mac_head = Frame(data[:14])
            self.DetailInfo += str("Frame: \n")
            self.DetailInfo += str(mac_head.detailInfo)
            # print(self.DetailInfo)
            # print(mac_head.info)

            if mac_head.protocol == "IP":
                ip_head = IP(data[14:34])

                if ip_head.protocol == "TCP":
                    tcp_header = TCP(data[34:54])
                    tcp_header.src = ip_head.src
                    tcp_header.dst = ip_head.dst
                    tcp_header.protocol = ip_head.protocol
                    self.print_list(tcp_header)
                    self.DetailInfo += "TCP: \n"
                    self.DetailInfo += tcp_header.detailInfo

                else:
                    self.print_list(ip_head)
                    self.print_detail("Unfinished IP protocol")

            elif mac_head.protocol == "ARP":
                arp_head = ARP(data[14:42])
                self.print_list(arp_head)
                self.DetailInfo += "ARP: \n"
                self.DetailInfo += arp_head.detailInfo

            elif mac_head.protocol == "IPv6":
                self.print_list(mac_head)
                self.print_detail("Frame head: Protocol: %s" % (mac_head.protocol))

            else:
                self.print_detail("Unfinished Frame protocol")

            self.DetailText.clear()
            self.print_detail(self.DetailInfo)

            self.DetailInfo = ""
            self.Binarytext.clear()
            self.print_binary(data)
            # time.sleep(1)

            # address = self.sniffer.address
            # print(address)
            # for it in address:
            #     if type(it) == bytes:
            #         print(it.hex())
            #     else:
            #         print(it)


# self.ListButton.clicked.connect(MainWindow.snip)

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    ui = MyWindow()
    ui.show()
    # sys.stdout = ui
    sys.exit(app.exec_())
