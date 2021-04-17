#!/usr/bin/python
import os
import netifaces

# nicList = netifaces.interfaces()
NICList = [i for i in netifaces.interfaces() if i != "lo"]

for i in NICList:
    os.system("sudo ifconfig " + i + " promisc")

os.system("sudo python ./src/top.py")
