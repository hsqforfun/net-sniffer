from Ui_qtLearn import Ui_MainWindow
from PyQt5 import QtWidgets
from PyQt5.QtCore import *
from PyQt5.QtGui import QTextCursor

from sniffer import Sniffers

import sys


# class Stream(QObject):
#     newText = pyqtSignal(str)

#     def write(self, text):
#         self.newText.emit(str(text))


class MyWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        super(MyWindow, self).__init__()
        self.setupUi(self)
        self.snif = Sniffers()
        # self.stdout = Stream(newText=self.outputText)
        # self.stdout = self

    # def outputText(self, text):
    #     cursor = self.ListText.textCursor()
    #     cursor.movePosition(QTextCursor.atEnd)
    #     cursor.insertText(text)
    #     self.ListText.setTextCursor(cursor)
    #     self.ListText.ensureCursorVisible()

    def snip(self):
        # while 1:
        self.snif.call_from_others()
        # self.ListText.append(self.snif.returnString)
        print(self.snif.returnString)
        self.ListText.append(self.snif.returnString)
        self.snif.clearString()

    # def write(self, inputstr):
    #     self.ListText.append(inputstr)
    #     self.cursot = self.ListText.textCursor()
    #     self.ListText.moveCursor(QTextCursor.atEnd, QTextCursor.keepPositionOnInsert)


# self.ListButton.clicked.connect(MainWindow.tcp)

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    ui = MyWindow()
    ui.show()
    # sys.stdout = ui
    sys.exit(app.exec_())
