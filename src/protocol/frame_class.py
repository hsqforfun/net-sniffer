class Frame:
    def __init__(self, data_len=None, address=None):
        self.length = data_len
        self.nicName = address[0]  # nic name
        self.detailInfo = "Frame:\n%s captured by Interface:%s\n\n" % (
            self.length,
            self.nicName,
        )
