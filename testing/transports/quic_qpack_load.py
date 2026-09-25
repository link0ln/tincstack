#!/usr/bin/env python3
"""Make a quic listener's QPACK decoder stream grow, as any HTTP/3 client can.

Each connection (aioquic, whose encoder uses the dynamic table the listener's
SETTINGS offer) sends REQS GET requests in bursts, with header values that
repeat across requests so the encoder inserts them. The listener answers
with decoder stream instructions -- Insert Count Increment, Section
Acknowledgment, and Stream Cancellation for the requests past its eighth --
so its decoder stream keeps growing while earlier bytes of it are in flight.
Run under packet loss, lost decoder-stream bytes are retransmitted from
wherever the listener left them (testing/transports/quic-loss-test.sh).

Prints one line per connection: "conn <n> answered <k>/<REQS>".

Usage: quic_qpack_load.py <host> <port> <conns> <reqs>
"""
import asyncio
import ssl
import sys

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration

HOST, PORT, CONNS, REQS = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])


class Proto(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.h3 = H3Connection(self._quic)
        self.answered = 0

    def quic_event_received(self, event):
        for e in self.h3.handle_event(event):
            if isinstance(e, HeadersReceived):
                self.answered += 1


async def one(n):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, verify_mode=ssl.CERT_NONE,
                            idle_timeout=20)
    async with connect(HOST, PORT, configuration=cfg, create_protocol=Proto, wait_connected=True) as p:
        for r in range(REQS):
            sid = p._quic.get_next_available_stream_id()
            p.h3.send_headers(sid, [
                (b":method", b"GET"), (b":scheme", b"https"), (b":authority", HOST.encode()),
                (b":path", b"/page-%d" % (r % 5)),
                (b"user-agent", b"Mozilla/5.0 (X11; Linux x86_64) load/%d" % (r % 7)),
                (b"accept-language", b"en-US,en;q=0.%d" % (r % 9 + 1)),
                (b"cookie", b"session=%032d" % (r % 11)),
            ], end_stream=True)
            p.transmit()
            await asyncio.sleep(0.02 if r % 10 else 0.2)
        await asyncio.sleep(3)
        print("conn %d answered %d/%d" % (n, p.answered, REQS), flush=True)


async def main():
    for n in range(CONNS):
        try:
            await asyncio.wait_for(one(n), 60)
        except Exception as e:  # a lost connection under loss is a result, not a crash
            print("conn %d error %s" % (n, type(e).__name__), flush=True)


asyncio.run(main())
