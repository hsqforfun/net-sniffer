import socket
import struct
from ctypes import *
import time


class VoidHeader:
    def __init__(self):
        self.src = ""
        self.dst = ""
        self.protocol = ""
        self.length = ""
        self.info = ""