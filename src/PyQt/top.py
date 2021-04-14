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


class data_cache:
    def __init__(self, packet):
        self.data = packet.data
        self.detailInfo = packet.detailInfo


class MyWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        super(MyWindow, self).__init__()
        self.setupUi(self)
        self.sniffer = MySniffer()
        self.count = 0
        self.length = 0
        self.snipFlag = True
        self.snipTimes = 1
        self.detailInfo = ""
        self.dataDict = {}

    def clearTable(self):
        row = self.tableList.rowCount()
        for _ in range(row):
            self.tableList.removeRow(0)
        self.tableList.setRowCount(0)
        self.dataDict.clear()
        self.ASCIItext.clear()

    def clearText(self):
        self.ASCIItext.clear()
        self.DetailText.clear()
        self.Binarytext.clear()

    def printThis(self, id):
        self.clearText()
        dataCache = self.dataDict[id]
        self.print_detail(dataCache.detailInfo)
        self.print_binary(dataCache.data)

    def print_list(self, packet):
        row = self.tableList.rowCount()
        tmp_cnt = self.count
        self.tableList.setRowCount(row + 1)
        enablePacket = QtWidgets.QPushButton(self.centralwidget)
        enablePacket.setText(str(tmp_cnt))
        self.tableList.setCellWidget(row, 0, enablePacket)
        enablePacket.clicked.connect(lambda: self.printThis(tmp_cnt))
        # self.tableList.setItem(row, 0, QTableWidgetItem(str(self.count)))
        if self.sniffer.ipAddr == packet.src:
            self.tableList.setItem(row, 1, QTableWidgetItem("localhost"))
        else:
            self.tableList.setItem(row, 1, QTableWidgetItem(packet.src))

        if self.sniffer.ipAddr == packet.dst:
            self.tableList.setItem(row, 2, QTableWidgetItem("localhost"))
        else:
            self.tableList.setItem(row, 2, QTableWidgetItem(packet.dst))

        self.tableList.setItem(row, 3, QTableWidgetItem(packet.protocol))
        self.tableList.setItem(row, 4, QTableWidgetItem(str(packet.length)))
        self.tableList.setItem(row, 5, QTableWidgetItem(packet.info))

    def print_detail(self, str):
        self.DetailText.append(str)

    def print_ascii(self, bytesData):
        cnt = 0
        s = ""
        for i in bytesData:
            cnt += 1
            if (i < 0x80) & (i > 0x1F):
                s += "%s " % chr(i)
            else:
                s += "."
            if cnt == 16:
                cnt = 0
                s += "\n"
        self.ASCIItext.append(s)

    def print_binary(self, bytesData):
        c = bytesData.hex()
        c = " ".join(c[i : i + 2] for i in range(0, len(c), 2))
        c = "\n".join(c[i : i + 48] for i in range(0, len(c), 48))
        self.Binarytext.append(c)
        self.print_ascii(bytesData)

    def stop(self):
        self.snipFlag = False

    def conti(self):
        self.snipFlag = True

    def detect(self, proto="tcpHead"):
        while 1:
            self.sniffer.sniffing()
            myPacket = Packet(self.sniffer.data, self.sniffer.address)
            if hasattr(myPacket, proto):
                self.count += 1
                self.print_list(myPacket)
                self.clearText()
                self.print_detail(myPacket.detailInfo)
                self.print_binary(myPacket.data)

                tmpCache = data_cache(myPacket)
                self.dataDict[self.count] = tmpCache
                break
            time.sleep(0.01)

    def detectTCP(self):
        self.detect("tcpHead")

    def detectHTTP(self):
        self.detect("httpHead")

    def detectTLS(self):
        self.detect("tlsHead")

    def snip(self):
        for _ in range(self.snipTimes):
            # print("sniffing")
            self.sniffer.sniffing()
            myPacket = Packet(self.sniffer.data, self.sniffer.address)
            self.count += 1

            self.print_list(myPacket)
            self.clearText()
            self.print_detail(myPacket.detailInfo)
            self.print_binary(myPacket.data)

            tmpCache = data_cache(myPacket)
            self.dataDict[self.count] = tmpCache


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    ui = MyWindow()
    ui.show()
    # sys.stdout = ui
    sys.exit(app.exec_())
