import socket
import struct
from ctypes import *
import time


class Frame(Structure):
    def __init__(self, data_len=None, address=None):
        self.length = data_len
        self.Interface = address[0]  # nic name
        self.detailInfo = "Frame:\n%s captured by Interface:%s\n\n" % (
            self.length,
            self.Interface,
        )
