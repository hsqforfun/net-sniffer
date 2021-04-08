import sys
from PyQt5.QtWidgets import QWidget, QLabel, QApplication, QMainWindow
from Ui_qtLearn import Ui_MainWindow


# class Example(QWidget):
#     def __init__(self):
#         super().__init__()
#         self.initUI()

#     def initUI(self):
#         lbl1 = QLabel("sniffer list", self)
#         lbl1.move(15, 10)

#         lbl2 = QLabel("sniffer detail", self)
#         lbl2.move(15, 40)

#         lbl1 = QLabel("sniffer binary", self)
#         lbl1.move(15, 70)

#         self.setGeometry(300, 300, 750, 750)
#         self.setWindowTitle("Rukawa")
#         self.show()


class myUI(QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        super(myUI, self).__init__(parent)
        self.setupUi(self)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    ui = myUI()
    ui.show()
    sys.exit(app.exec_())
