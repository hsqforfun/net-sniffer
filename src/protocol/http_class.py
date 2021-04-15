class Http:
    def __init__(self, data):
        self.data = data
        self.statusLine = ""
        self.headerLine = ""
        self.entityBody = ""
        self.protocol = "HTTP"
        try:
            self.httpInfo = str(self.data, encoding="utf-8")  # , encoding="utf-8"
        except:
            try:
                self.httpInfo = self.data.decode("utf-8", "ignore")
            except:
                self.httpInfo = str(self.data)  # , encoding="utf-8"
        self.detailInfo = "%s\n" % self.httpInfo

        # self.detailInfo += "HTTP headerLine: %s\n" % self.headerLine

        # self.entityBody += "HTTP entityBody: %s\n" % self.entityBody