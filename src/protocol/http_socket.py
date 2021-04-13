import time

import socket
from urllib.parse import urlparse


def get_url(url):
    url = urlparse(url)
    host = url.netloc
    path = url.path
    if path == "":
        path = "/"

    # 模拟http协议
    while 1:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((host, 80))
        client.send(
            "GET {} HTTP/1.1\r\nHost:{}\r\nConnection:close\r\n\r\n".format(
                path, host
            ).encode("utf8")
        )
        data = b""
        while True:
            d = client.recv(1024)
            if d:
                data += d
            else:
                break
        data = data.decode("utf8")
        # html_data = data.split("\r\n\r\n")[1]  # 去掉请求头
        print(data)
        time.sleep(1)
        client.close()


if __name__ == "__main__":
    get_url("http://www.alibaba.com")
