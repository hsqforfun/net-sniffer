Report：网络嗅探器

姓名：黄树琦

学号：202028013229056



# EX01- A： net sniffer

语言：python3

相关库：pyqt5 neticfaces socket ctypes struct

github：https://github.com/hsqforfun/net-sniffer.git



## 实验要求

![要求](./pic/要求.png)





## 设计思想：

​	本次实验设计中，在抓包方面选择了python的socket库来协助实现。python的socket库是基于C++的socket库实现的，使用方式大致相同。socket库对于抓包类型方面可以让用户直接抓取高层级的报文，如TCP、UDP。但为了本次实验，对于多层级的要求，选择使用SOCK_RAW的类型，从而获取完整的包信息。

​	参考TCP/IP的五层协议，其中物理层由路由器、网卡等硬件实现，不在本次实验的代码实现范畴内。利用SOCK_RAW抓到的数据，是在数据链路层的数据帧构成。

​	对于抓取到的数据帧信息，通过手写包含了IP报头、TCP报头、UDP报头等报头的类，来手动解析。根据抓包获得的数据，与py写的报头类进行匹配、判断，来实现报文的解析。

​	在GUI方面，选择python的PyQt5库来协助实现。PyQt5是python下的Qt5库，能够结合PyDesigner等图形化界面进行操作，能够通过拖拽的方式基本构建出UI框架。Designer工具操作一个.ui的文件，并且能够编译为一个.py文件。部分UI模块的具体参数，以及一些槽函数等不能直接在PyDesigner中实现，因此我们需要进一步丰富ui文件编译生成的py文件，来得到最终的图形界面。

​	对于TCP流追踪，目前的支持需要在嗅探的TCP流含有完整的三次握手，且报文不间断，否则不能确定Seq的相对值。四次挥手的部分可以没有。目前TCP流追踪的设计思想是，根据用户点击的TCP报文，来在报文列表中遍历有相同地址和端口的报文，通过TCP报头的标志位、seq、ack以及payload大小，来输出TCP流的相对Seq、相对Ack值。

​	