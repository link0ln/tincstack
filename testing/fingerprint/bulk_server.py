#!/usr/bin/env python3
"""A plain HTTP server for traffic inside the tunnel (carrier-traffic-audit.sh):
GET /big streams SIZE bytes of incompressible data, POST anything is read and
discarded. Standard library only. Usage: bulk_server.py <bind ip> [port] [size]
"""
import http.server
import os
import sys

BIND = sys.argv[1]
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
SIZE = int(sys.argv[3]) if len(sys.argv) > 3 else 20 * 1024 * 1024
CHUNK = os.urandom(65536)


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(SIZE))
        self.end_headers()
        left = SIZE
        while left:
            n = min(left, len(CHUNK))
            self.wfile.write(CHUNK[:n])
            left -= n

    def do_POST(self):
        left = int(self.headers.get("Content-Length", "0"))
        while left:
            b = self.rfile.read(min(left, 65536))
            if not b:
                break
            left -= len(b)
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


http.server.ThreadingHTTPServer((BIND, PORT), H).serve_forever()
