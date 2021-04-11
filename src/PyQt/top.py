from Ui_qtLearn import Ui_MainWindow
from PyQt5 import QtWidgets
from PyQt5.QtCore import *
from PyQt5.QtGui import QTextCursor
from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem

import sys
import time

sys.path.append("..")
from protocol import *
from sniffer import MySniffer

# self.ListButton.clicked.connect(MainWindow.snip)
# self.stopBtn.clicked.connect(MainWindow.stop)
# self.continueBtn.clicked.connect(MainWindow.conti)
# self.Btnclear.clicked.connect(MainWindow.clearTable)


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
        self.dataDict = {}

    def printThis(self, id):
        self.DetailText.clear()
        self.Binarytext.clear()
        data = self.dataDict[id]
        DetailInfo = "pass"
        self.print_detail(DetailInfo)
        self.print_binary(data)

    def print_list(self, header):
        row = self.tableList.rowCount()
        tmp_cnt = self.count
        self.tableList.setRowCount(row + 1)
        self.tableList.setItem(row, 0, QTableWidgetItem(str(self.count)))
        self.tableList.setItem(row, 1, QTableWidgetItem(header.src))
        self.tableList.setItem(row, 2, QTableWidgetItem(header.dst))
        self.tableList.setItem(row, 3, QTableWidgetItem(header.protocol))
        self.tableList.setItem(row, 4, QTableWidgetItem(str(self.length)))
        self.tableList.setItem(row, 5, QTableWidgetItem(header.info))
        enablePacket = QtWidgets.QPushButton(self.centralwidget)
        self.tableList.setCellWidget(row, 6, enablePacket)
        enablePacket.clicked.connect(lambda: self.printThis(tmp_cnt))

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

    def clearTable(self):
        row = self.tableList.rowCount()
        for _ in range(row):
            self.tableList.removeRow(0)
        self.tableList.setRowCount(0)
        self.dataDict.clear()

    def detectTCP(self):
        cnt = 0
        self.snipFlag = True
        while self.snipFlag:
            cnt += 1
            self.sniffer.sniffing()
            data = self.sniffer.data
            mac_head = Frame(data[:14])
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
                    self.count += 1
                    self.length = len(data)
                    self.dataDict[self.count] = data
                    self.DetailText.clear()
                    self.print_detail(self.DetailInfo)
                    self.DetailInfo = ""
                    self.Binarytext.clear()
                    self.print_binary(data)
                    self.snipFlag = False
                    cnt = 0
            print(cnt)
            if cnt == 100:
                print("sleep")
                self.snipFlag = False

    def snip(self):
        # self.detectTCP()
        for _ in range(self.snipTimes):
            self.sniffer.sniffing()
            data = self.sniffer.data
            self.count += 1
            self.length = len(data)
            self.dataDict[self.count] = data

            mac_head = Frame(data[:14])
            self.DetailInfo += str("Frame: \n")
            self.DetailInfo += str(mac_head.detailInfo)

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


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    ui = MyWindow()
    ui.show()
    # sys.stdout = ui
    sys.exit(app.exec_())
