#!/usr/bin/env python3
"""Probe a QUIC server with single UDP datagrams, as a scanner does, and
print what comes back -- one line per probe, stable across runs (random
fields such as a stateless reset's length are reduced to their class).

  vn-*      a long header with a version the server does not speak: an RFC
            9000 server answers Version Negotiation (6.1), listing its
            versions and echoing both connection ids;
  v1-*      a v1 Initial nobody can decrypt: dropped;
  short-*   a short header for a connection the server does not have: a
            server that sends stateless resets answers one (10.3) unless the
            datagram is too small to be answered safely;
  zeros, http-get: not QUIC at all.

Standard library only. Usage: quic_probe.py <server ip> [port]
"""
import os
import socket
import struct
import sys

host = sys.argv[1]
port = int(sys.argv[2]) if len(sys.argv) > 2 else 443


def long_hdr(version, dcid, scid, first=0xC0):
    return bytes([first]) + struct.pack(">I", version) + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid


def pad(b, n):
    return b + os.urandom(max(0, n - len(b)))


def describe(d, dcid, scid):
    if d[0] & 0x80:
        ver = struct.unpack(">I", d[1:5])[0]
        i = 5
        dl = d[i]
        rd = d[i + 1:i + 1 + dl]
        i += 1 + dl
        sl = d[i]
        rs = d[i + 1:i + 1 + sl]
        i += 1 + sl
        if ver == 0:
            vs = [d[j:j + 4].hex() for j in range(i, len(d), 4)]
            echo = "ids echoed" if (rd, rs) == (scid, dcid) else "ids NOT echoed"
            return "version negotiation %d B, %s, versions %s" % (len(d), echo, ",".join(vs))
        return "long header v%08x type %d, %d B" % (ver, (d[0] >> 4) & 3, len(d))
    return "short header (stateless reset?), %s B" % ("< 43" if len(d) < 43 else ">= 43")


def probe(name, payload, dcid=b"", scid=b"", wait=1.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(wait)
    s.sendto(payload, (host, port))
    got = []
    try:
        while True:
            d, _ = s.recvfrom(65535)
            got.append(describe(d, dcid, scid))
    except socket.timeout:
        pass
    s.close()
    print("%s\t%s" % (name, "; ".join(got) or "silence"))


def vn(name, version, n, idlen=8):
    d, s = os.urandom(idlen), os.urandom(idlen)
    probe(name, pad(long_hdr(version, d, s), n), d, s)


vn("vn-1200", 0x1A2A3A4A, 1200)
vn("vn-1200-ids20", 0x1A2A3A4A, 1200, 20)
vn("vn-1199", 0x1A2A3A4A, 1199)
vn("vn-draft29", 0xFF00001D, 1200)
vn("vn-v2", 0x6B3343CF, 1200)
probe("v1-initial-junk-1200", pad(long_hdr(1, os.urandom(8), os.urandom(8)) + b"\x00\x44\xb0", 1200))
probe("v1-initial-junk-600", pad(long_hdr(1, os.urandom(8), os.urandom(8)) + b"\x00\x44\xb0", 600))
probe("short-unknown-1200", pad(bytes([0x40]), 1200))
probe("short-unknown-100", pad(bytes([0x40]), 100))
probe("short-unknown-40", pad(bytes([0x40]), 40))
probe("zeros-1200", bytes(1200))
probe("http-get", b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
