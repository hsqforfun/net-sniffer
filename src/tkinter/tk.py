import tkinter as tk
from PIL import Image, ImageTk
import sys
from sock import call_from_others
import netifaces
import socket
import os
from ip_class import IP
from tcp_class import TCP

root = tk.Tk()
root.title("Rukawa的嗅探器")
# root.geometry("720x720")

titleLabel = tk.Label(root, text="hello", bg="yellow", fg="black", relief="raised")
titleLabel.grid(row=0)
# titleLabel.pack()

sniffer_list = tk.Text(root, bg="green", relief="sunken")
sniffer_list.grid(row=1)


def init():
    list_item = ["one", "two", "three"]
    for item in list_item:
        Lst.insert("end", item)


def clear1():
    Lst.delete(0, "end")


def clear2():
    sniffer_detail.delete(0, "end")


def tcp():
    sniffer_detail.insert("end", "hsq")
    print("hi")
    call_from_others()


def restdout(inputstr):
    sniffer_list.insert("end", inputstr)


sys.stdout.write = restdout

# frame1 = tk.Frame(root, relief="groove")
# frame1.grid(column=1, row=1)
# btn1 = tk.Button(frame1, text="初始化", command=init)
# btn1.grid(column=2, row=1)
# btn2 = tk.Button(frame1, text="clear", command=clear1)
# btn2.grid(column=3, row=1)
# Lst = tk.Listbox(frame1)
# Lst.grid(column=4, row=1)

frame2 = tk.Frame(root, bg="red", relief="groove")
frame2.grid(row=2)
btn3 = tk.Button(frame2, text="tcp", command=tcp)
btn3.grid(column=2, row=2)
btn4 = tk.Button(frame2, text="clear", command=clear2)
btn4.grid(column=3, row=2)
sniffer_detail = tk.Listbox(frame2)
sniffer_detail.grid(column=4, row=2)


root.mainloop()