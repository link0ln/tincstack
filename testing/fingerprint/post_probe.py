#!/usr/bin/env python3
"""Time a web server's answer to a POST whose body comes late.

A tinc listener must read a POST's body (the authenticator) before it can
answer it; nginx answers a POST to a static file with 405 as soon as the
request head is whole. This prober splits the request in two -- the head,
then after a pause the body -- and records when the answer arrives relative
to each half. One probe = one fresh connection.

  h3   HTTP/3 over QUIC (aioquic): HEADERS, pause, DATA + FIN
  h1   HTTP/1.1 over TLS over TCP (stdlib ssl): head, pause, body

Modes:
  get          GET /, the round-trip baseline
  post-now     POST / with an 8-byte body in the same flight
  post-pause   POST / head, PAUSE ms, then the 8-byte body (+ FIN)
  post-nobody  POST / head only, no body, no FIN; wait up to WAIT ms
  post-authver POST / head, then the first 10 body bytes shaped like the
               start of a tinc authenticator (version 2, name length 32),
               PAUSE ms, then the rest of an 8+... byte body (+ FIN)

Prints one tab-separated line per probe:
  proto mode status t_head t_body
    t_head  ms from sending the head to the answer's first byte/HEADERS
    t_body  ms from sending the (last part of the) body to the answer,
            "-" when the answer came before it was sent or no body was sent
    status  the HTTP status, or "none" when nothing came within WAIT ms

Usage: post_probe.py <proto> <host> <mode> <count> [PAUSE_ms] [WAIT_ms]
"""
import asyncio
import socket
import ssl
import sys
import time

PROTO, HOST, MODE, COUNT = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
PAUSE = float(sys.argv[5]) / 1000 if len(sys.argv) > 5 else 1.0
WAIT = float(sys.argv[6]) / 1000 if len(sys.argv) > 6 else 5.0
BODY = b"x=1&y=22"                                   # 8 bytes, like a form post
AUTHV_HEAD = bytes([2, 32]) + b"nodeabcd"            # ver 2, namelen 32, ...
AUTHV_REST = b"efghijklmnopqrstuvwxyz0123456789" + bytes(88)


def ms(t):
    return "%.1f" % (t * 1000)


def body_parts():
    """(first part sent with the head, part sent after the pause)"""
    if MODE == "post-now":
        return BODY, None
    if MODE == "post-pause":
        return None, BODY
    if MODE == "post-authver":
        return AUTHV_HEAD, AUTHV_REST
    return None, None


# ---- HTTP/1.1 over TLS ---------------------------------------------------------------------------
def h1_once():
    first, later = body_parts()
    total = (len(first or b"") + len(later or b"")) if MODE.startswith("post") else 0
    if MODE == "post-nobody":
        total = 8                                       # announced, never sent
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])
    raw = socket.create_connection((HOST, 443), timeout=10)
    s = ctx.wrap_socket(raw, server_hostname=None)
    if MODE == "get":
        head = b"GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/8.14.1\r\nAccept: */*\r\n\r\n" % HOST.encode()
    else:
        head = (b"POST / HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/8.14.1\r\nAccept: */*\r\n"
                b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n") % (HOST.encode(), total)
    t0 = time.monotonic()
    s.sendall(head + (first or b""))
    t_body = None
    s.settimeout(PAUSE if later is not None else WAIT)
    got = b""
    try:
        got = s.recv(4096)
    except (socket.timeout, TimeoutError):
        pass
    if not got and later is not None:
        t_body = time.monotonic()
        s.sendall(later)
        s.settimeout(WAIT)
        try:
            got = s.recv(4096)
        except (socket.timeout, TimeoutError):
            pass
    t1 = time.monotonic()
    s.close()
    if not got:
        return "none", "-", "-"
    status = got.split(b" ", 2)[1].decode() if got.startswith(b"HTTP/") else "junk"
    return status, ms(t1 - t0), (ms(t1 - t_body) if t_body else "-")


# ---- HTTP/3 --------------------------------------------------------------------------------------
async def h3_once():
    from aioquic.asyncio.client import connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3_ALPN, H3Connection
    from aioquic.h3.events import HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration

    class Proto(QuicConnectionProtocol):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.h3 = H3Connection(self._quic)
            self.answer = asyncio.get_running_loop().create_future()

        def quic_event_received(self, event):
            for e in self.h3.handle_event(event):
                if isinstance(e, HeadersReceived) and not self.answer.done():
                    st = dict(e.headers).get(b":status", b"?").decode()
                    self.answer.set_result((time.monotonic(), st))

    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, verify_mode=ssl.CERT_NONE)
    first, later = body_parts()
    async with connect(HOST, 443, configuration=cfg, create_protocol=Proto, wait_connected=True) as p:
        sid = p._quic.get_next_available_stream_id()
        hdrs = [(b":method", b"GET" if MODE == "get" else b"POST"), (b":scheme", b"https"),
                (b":authority", HOST.encode()), (b":path", b"/"),
                (b"user-agent", b"curl/8.14.1"), (b"accept", b"*/*")]
        if MODE.startswith("post"):
            n = len(first or b"") + len(later or b"") if MODE != "post-nobody" else 8
            hdrs += [(b"content-type", b"application/x-www-form-urlencoded"), (b"content-length", str(n).encode())]
        end_now = MODE == "get" or (MODE == "post-now")
        p.h3.send_headers(sid, hdrs, end_stream=(MODE == "get"))
        if first is not None:
            p.h3.send_data(sid, first, end_stream=end_now)
        p.transmit()
        t0 = time.monotonic()
        t_body = None
        try:
            t1, st = await asyncio.wait_for(asyncio.shield(p.answer), PAUSE if later is not None else WAIT)
        except asyncio.TimeoutError:
            if later is None:
                return "none", "-", "-"
            t_body = time.monotonic()
            p.h3.send_data(sid, later, end_stream=True)
            p.transmit()
            try:
                t1, st = await asyncio.wait_for(asyncio.shield(p.answer), WAIT)
            except asyncio.TimeoutError:
                return "none", "-", "-"
        return st, ms(t1 - t0), (ms(t1 - t_body) if t_body else "-")


def main():
    for _ in range(COUNT):
        try:
            r = asyncio.run(h3_once()) if PROTO == "h3" else h1_once()
        except Exception as e:  # a failed connection is a result, not a crash
            r = ("error:" + type(e).__name__, "-", "-")
        print("%s\t%s\t%s\t%s\t%s" % (PROTO, MODE, *r), flush=True)
        time.sleep(0.1)


main()
