class Http:
    def __init__(self, data):
        self.data = data
        self.statusLine = ""
        self.headerLine = ""
        self.entityBody = ""
        self.protocol = "HTTP"
        flag1 = False
        flag2 = False
        cnt = 0

        for it in data:
            cnt += 1
            self.statusLine += chr(it)
            if flag1 == True:
                if it == 0x0A:
                    break
                else:
                    flag1 = False
            if it == 0x0D:
                flag1 = True
        print(self.statusLine)
        for it in data[cnt:]:
            self.statusLine += chr(it)
            if flag1 == True:
                if it == 0x0A:
                    break
                else:
                    flag1 = False
            if it == 0x0D:
                flag1 = True
