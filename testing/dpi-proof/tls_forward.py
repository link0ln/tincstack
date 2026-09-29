#!/usr/bin/env python3
"""A per-connection TLS tunnel, the positive control of the TLS-in-TLS oracle.

Every TCP connection accepted by the client side is carried in its own fresh
TLS connection to the server side, which forwards it in the clear to a
target. That is how trojan, VLESS-over-TLS and the like carry a browser's
HTTPS: the inner TLS handshake is the first thing inside the outer one, the
case the burst model was built to catch. If the oracle does not catch this,
the oracle (or the inner workload) is broken, not our carrier clean.

Usage:
  tls_forward.py server PORT CERT KEY TARGET_HOST TARGET_PORT [TICKETS [GROUP]]
  tls_forward.py client PORT SERVER_HOST SERVER_PORT [GROUP]   (listens on 127.0.0.1)

TICKETS is how many TLS 1.3 session tickets the server sends after the
handshake (OpenSSL's default, 2, when absent); GROUP limits the key exchange
to one named curve (e.g. prime256v1) instead of the library's default list.
nDPI 6.0 gives up on a flow whose server writes again after the packet with
its ServerHello -- tickets, or a first flight longer than one segment, which
any post-quantum ServerHello (~1.1 KB alone) or a web-sized chain is. The
positive control is therefore a small certificate, a classic curve and no
tickets: what nDPI's own sample captures look like.

Standard library only.
"""
import select
import socket
import ssl
import sys
import threading


def pump(a, b):
    """Copy both ways until either side closes. One thread per connection:
    an SSL socket must not be read and written from two threads at once."""
    peer = {a: b, b: a}
    try:
        while True:
            ready = [s for s in (a, b) if isinstance(s, ssl.SSLSocket) and s.pending()]
            if not ready:
                ready = select.select([a, b], [], [])[0]
            for s in ready:
                data = s.recv(65536)
                if not data:
                    return
                peer[s].sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.close()
            except OSError:
                pass


def serve(port, host, handle):
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((host, port))
    ls.listen(64)
    while True:
        conn, _ = ls.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def main():
    mode = sys.argv[1]
    if mode == "server":
        port, cert, key, thost, tport = int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], int(sys.argv[6])
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        if len(sys.argv) > 7:
            ctx.num_tickets = int(sys.argv[7])
        if len(sys.argv) > 8:
            ctx.set_ecdh_curve(sys.argv[8])

        def handle(conn):
            try:
                tls = ctx.wrap_socket(conn, server_side=True)
                up = socket.create_connection((thost, tport))
            except OSError:
                conn.close()
                return
            pump(tls, up)
        serve(port, "0.0.0.0", handle)
    elif mode == "client":
        port, shost, sport = int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if len(sys.argv) > 5:
            ctx.set_ecdh_curve(sys.argv[5])

        def handle(conn):
            try:
                tls = ctx.wrap_socket(socket.create_connection((shost, sport)), server_hostname="www.example.com")
            except OSError:
                conn.close()
                return
            pump(conn, tls)
        serve(port, "127.0.0.1", handle)
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
