#!/usr/bin/env python3
"""A small HTTP upstream for decoy-conformance-test.sh (stdlib only).

Behind both nginx's proxy_pass and a tinc node's HttpsDecoyUpstream, it
answers by path with the shapes a reverse proxy has to relay differently --
a Content-Length body with headers nginx hides, a body without a length, a
chunked body, a 404 with its own reason phrase -- and appends every request
head it receives to a log, so the test can compare what each proxy forwards.

Usage: decoy_upstream.py <log file>   (listens on TCP 80)
"""
import email.utils
import socket
import sys
import threading

LOG = sys.argv[1]
lock = threading.Lock()


def answer(path):
    date = email.utils.formatdate(usegmt=True)
    if path.startswith('/nolen'):
        return ("HTTP/1.1 200 OK\r\nServer: upstream/1\r\nDate: %s\r\nContent-Type: text/plain\r\n"
                "X-Up: 1\r\n\r\nhello-nolen" % date).encode()
    if path.startswith('/chunked'):
        return ("HTTP/1.1 200 OK\r\nServer: upstream/1\r\nDate: %s\r\nContent-Type: text/plain\r\n"
                "Transfer-Encoding: chunked\r\nX-Up: 1\r\n\r\n5\r\nhello\r\n0\r\n\r\n" % date).encode()
    if path.startswith('/missing'):
        body = "not here"
        return ("HTTP/1.1 404 Nope\r\nServer: upstream/1\r\nDate: %s\r\nContent-Type: text/html\r\n"
                "Content-Length: %d\r\n\r\n%s" % (date, len(body), body)).encode()
    if path.startswith('/moved'):
        return ("HTTP/1.1 302 Found\r\nServer: upstream/1\r\nDate: %s\r\nLocation: /elsewhere\r\n"
                "Content-Length: 0\r\n\r\n" % date).encode()
    body = "<html>upstream page, long enough to be compressed</html>\n"
    return ("HTTP/1.1 200 OK\r\nServer: upstream/1\r\nDate: %s\r\nContent-Type: text/html; charset=utf-8\r\n"
            "Content-Length: %d\r\nLast-Modified: Wed, 05 Feb 2025 11:07:30 GMT\r\nETag: \"up-1\"\r\nX-Up: 1\r\n"
            "Set-Cookie: a=b\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\n\r\n%s"
            % (date, len(body), body)).encode()


def serve(c):
    data = b''
    c.settimeout(5)
    try:
        while b'\r\n\r\n' not in data:
            d = c.recv(4096)
            if not d:
                break
            data += d
        with lock, open(LOG, 'ab') as f:
            f.write(b'=====\n' + data.split(b'\r\n\r\n')[0] + b'\n')
        parts = data.split(b' ')
        path = parts[1].decode(errors='replace') if len(parts) > 1 else '/'
        c.sendall(answer(path))
    except OSError:
        pass
    c.close()


s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 80))
s.listen(64)
while True:
    conn, _ = s.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
