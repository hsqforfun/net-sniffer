import sys
import time
import netifaces
import os

from Ui_qtLearn import Ui_MainWindow
from PyQt5 import QtWidgets
from PyQt5.QtCore import *
from PyQt5.QtGui import QTextCursor, QCursor
from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem
from sniffer import MySniffer

# path1 = os.path.abspath("./src")
# sys.path.append(path1)
sys.path.append(os.path.join(os.path.dirname(__file__), "../"))
from protocol import *


CWR = 0x80
ECNEcho = 0x40
URG = 0x20
ACK = 0x10
PSH = 0x08
RST = 0x04
SYN = 0x02
Fin = 0x01


def noNeedIt(packet1, packet2):
    if not hasattr(packet1, "tcpHead"):
        return True
    if not hasattr(packet2, "tcpHead"):
        return True
    if (
        (packet1.src == packet2.dst)
        and (packet1.tcpHead.srcPort == packet2.tcpHead.dstPort)
        and (packet1.dst == packet2.src)
        and (packet1.tcpHead.dstPort == packet2.tcpHead.srcPort)
    ):
        return False
    elif (
        (packet1.dst == packet2.dst)
        and (packet1.tcpHead.dstPort == packet2.tcpHead.dstPort)
        and (packet1.src == packet2.src)
        and (packet1.tcpHead.srcPort == packet2.tcpHead.srcPort)
    ):
        return False
    else:
        return True


class tcpThread(QThread):  # 建立一个任务线程类
    signal = pyqtSignal(str)  # 设置触发信号传递的参数数据类型,这里是字符串

    def __init__(self):
        super(tcpThread, self).__init__()
        self.flag = True

    def run(self):  # 在启动线程后任务从这个函数里面开始执行
        self.flag = True
        for _ in range(200):
            if self.flag:
                self.signal.emit(str("hsq"))
                # time.sleep(0.01)
            else:
                break


class MyThread(QThread):  # 建立一个任务线程类
    signal = pyqtSignal(str)  # 设置触发信号传递的参数数据类型,这里是字符串

    def __init__(self):
        super(MyThread, self).__init__()
        self.flag = True

    def run(self):  # 在启动线程后任务从这个函数里面开始执行
        self.flag = True
        while self.flag:
            self.signal.emit(str("hsq"))
            time.sleep(0.5)


class MyWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        super(MyWindow, self).__init__()
        self.setupUi(self)
        self.count = 0
        self.length = 0
        self.snipFlag = True
        self.snipTimes = 1
        self.detailInfo = ""
        self.dataDict = {}
        self.listDict = {}

        self.mythread = MyThread()
        self.tcpthread = tcpThread()
        self.comboBoxInit()
        self.socketInit()

        self.mythread.signal.connect(self.contiSnip)
        self.tcpthread.signal.connect(self.TcpContinue)
        self.nicBox.currentTextChanged.connect(self.setNIC)

    def setNIC(self):
        # print("Before:%s") % self.sniffer.nic
        self.sniffer.closeMe()
        self.sniffer = MySniffer(self.nicBox.currentText())
        # print("after:%s" % self.sniffer.nic)

    def comboBoxInit(self):
        self.nicList = netifaces.interfaces()
        self.nicBox.addItem("default")
        for i in self.nicList:
            self.nicBox.addItem(i)

    def socketInit(self):
        self.sniffer = MySniffer()

    def stop(self):
        self.mythread.flag = False
        self.tcpthread.flag = False

    def contiSnip(self, i):
        self.snip()

    def continuous(self):
        self.mythread.start()

    def TcpContinue(self, i):
        self.detectTCP()

    def continuousTCP(self):
        self.tcpthread.start()

    def updataRow(self):
        cnt = 0
        tmpDict = {}
        for (c, p) in self.listDict.items():
            tmpDict[cnt] = p
            cnt += 1
        self.listDict = tmpDict

        self.outsideTracingJudge()

    def outsideTracingJudge(self):
        self.traceClass = Tracing(self.listDict)
        self.traceClass.shake1()
        if self.traceClass.clientSeqBase != 0:
            for (c, p) in self.listDict.items():
                if p.dirt == True:
                    self.tableList.removeRow(c)
            self.printTracingInfo()

    def printTracingInfo(self):
        clientBase = self.traceClass.clientSeqBase
        client = self.traceClass.clientIP
        serverBase = self.traceClass.ServerSeqBase
        server = self.traceClass.serverIP
        for (row, p) in self.listDict.items():
            tmpInfo = p.tcpHead.flagInfo
            if p.src == client:
                if p.tcpHead.flags == SYN:
                    tmpInfo += " Seq=%d Ack=%d" % (
                        p.tcpHead.seq - clientBase,
                        p.tcpHead.ack,
                    )
                else:
                    tmpInfo += " Seq=%d Ack=%d" % (
                        p.tcpHead.seq - clientBase,
                        p.tcpHead.ack - serverBase,
                    )
            else:
                tmpInfo += " Seq=%d Ack=%d" % (
                    p.tcpHead.seq - serverBase,
                    p.tcpHead.ack - clientBase,
                )

            if hasattr(p, "tlsHead"):
                tmpInfo += "  Payload:%d" % (p.length - 54 - p.tcpOptionLen)

            self.tableList.setItem(row, 6, QTableWidgetItem(tmpInfo))

    def traceTCP(self, id):
        packet = self.dataDict[id]
        self.clearText()
        self.print_detail(packet.detailInfo)
        self.print_binary(packet.data)
        deleteList = []

        for (rowNum, p) in self.listDict.items():
            if noNeedIt(p, packet):
                deleteList.append(rowNum)

        deleteList.sort(reverse=True)
        for i in deleteList:
            self.tableList.removeRow(i)
            del self.listDict[i]

        self.updataRow()

    def print_list(self, packet):
        row = self.tableList.rowCount()
        packet.row = row
        self.listDict[row] = packet
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

        if hasattr(packet, "tcpHead"):
            tcpPacket = QtWidgets.QPushButton(self.centralwidget)
            tcpPacket.setText(packet.protocol)
            self.tableList.setCellWidget(row, 3, tcpPacket)
            tcpPacket.clicked.connect(lambda: self.traceTCP(tmp_cnt))
        else:
            self.tableList.setItem(row, 3, QTableWidgetItem(packet.protocol))

        self.tableList.setItem(row, 4, QTableWidgetItem(str(packet.length)))
        self.tableList.setItem(row, 5, QTableWidgetItem(packet.info))
        self.tableList.verticalScrollBar().setValue(row)

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
        packet = self.dataDict[id]
        self.print_detail(packet.detailInfo)
        self.print_binary(packet.data)

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

                self.dataDict[self.count] = myPacket
                break
            # time.sleep(0.01)

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

            self.dataDict[self.count] = myPacket


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    ui = MyWindow()
    ui.show()
    sys.exit(app.exec_())
