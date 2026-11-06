from contextlib import closing
import http.client
import os
import socket


class UnixHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect("/run/safevault/gunicorn.sock")


with closing(UnixHTTPConnection(os.environ["DJANGO_ALLOWED_HOSTS"], timeout=4)) as connection:
    connection.request("GET", "/api/ready/", headers={"X-Forwarded-Proto": "https"})
    raise SystemExit(0 if connection.getresponse().status == 200 else 1)
