# not working yet


class FLAGS(object):
    # linux/if_ether.h
    ETH_P_ALL = 0x0003  # 所有协议
    ETH_P_IP = 0x0800  # 只处理IP层
    # linux/if.h，混杂模式
    IFF_PROMISC = 0x100
    # linux/sockios.h
    SIOCGIFFLAGS = 0x8913  # 获取标记值
    SIOCSIFFLAGS = 0x8914  # 设置标记值


def capture_packet():
    # 设置过滤条件
    filters = fitler_entry.get()
    print("抓包条件：" + filters)
    # 设置停止抓包的条件stop_filter
    stop_sending.clear()
    global packet_list
    # 清空列表
    packet_list.clear()
    # 抓取数据包并将抓到的包存在列表中
    sniff(
        prn=(lambda x: process_packet(x)),
        filter=filters,
        stop_filter=(lambda x: stop_sending.is_set()),
    )


def process_packet(packet):
    if pause_flag == False:
        global packet_list
        # 将抓到的包存在列表中
        packet_list.append(packet)
        # packet.show()
        # 抓包的时间
        packet_time = timestamp2time(packet.time)
        src = packet[Ether].src
        dst = packet[Ether].dst
        type = packet[Ether].type
        types = {
            0x0800: "IPv4",
            0x0806: "ARP",
            0x86DD: "IPv6",
            0x88CC: "LLDP",
            0x891D: "TTE",
        }
        if type in types:
            proto = types[type]
        else:
            proto = "LOOP"  # 协议
        # IP
        if proto == "IPv4":
            # 建立协议查询字典
            protos = {
                1: "ICMP",
                2: "IGMP",
                4: "IP",
                6: "TCP",
                8: "EGP",
                9: "IGP",
                17: "UDP",
                41: "IPv6",
                50: "ESP",
                89: "OSPF",
            }
            src = packet[IP].src
            dst = packet[IP].dst
            proto = packet[IP].proto
            if proto in protos:
                proto = protos[proto]
        # tcp
        if TCP in packet:
            protos_tcp = {
                80: "Http",
                443: "Https",
                23: "Telnet",
                21: "Ftp",
                20: "ftp_data",
                22: "SSH",
                25: "SMTP",
            }
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            if sport in protos_tcp:
                proto = protos_tcp[sport]
            elif dport in protos_tcp:
                proto = protos_tcp[dport]
        elif UDP in packet:
            if packet[UDP].sport == 53 or packet[UDP].dport == 53:
                proto = "DNS"
        length = len(packet)  # 长度
        info = packet.summary()  # 信息
        global packet_id  # 数据包的编号
        packet_list_tree.insert(
            "",
            "end",
            packet_id,
            text=packet_id,
            values=(packet_id, packet_time, src, dst, proto, length, info),
        )
        packet_list_tree.update_idletasks()  # 更新列表，不需要修改
        packet_id = packet_id + 1
