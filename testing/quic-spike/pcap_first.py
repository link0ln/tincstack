#!/usr/bin/env python3
"""Print the UDP payload head of every packet in a pcap (stdlib only).

Used by test.sh to show, from the wire rather than from the client's own
buffer, what the first bytes of a QUIC session look like: the bytes the M4
UDP classifier keys on. Handles the loopback/Ethernet link type (1) and
Linux cooked capture (113), IPv4 and IPv6 without extension headers.
"""
import struct
import sys


def main(path):
    with open(path, "rb") as f:
        data = f.read()

    magic = data[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    else:
        sys.exit("not a pcap file")

    linktype = struct.unpack(endian + "I", data[20:24])[0]
    off = 24
    n = 0
    longhdr = shorthdr = 0
    while off + 16 <= len(data):
        _, _, incl, _ = struct.unpack(endian + "IIII", data[off:off + 16])
        pkt = data[off + 16:off + 16 + incl]
        off += 16 + incl
        if linktype == 1:
            ethertype = struct.unpack(">H", pkt[12:14])[0]
            ip = pkt[14:]
        elif linktype == 113:
            ethertype = struct.unpack(">H", pkt[14:16])[0]
            ip = pkt[16:]
        else:
            sys.exit("unsupported link type %d" % linktype)
        if ethertype == 0x0800:
            ihl = (ip[0] & 0x0F) * 4
            udp = ip[ihl:]
            src, dst = ip[12:16], ip[16:20]
            src_s = ".".join(map(str, src))
            dst_s = ".".join(map(str, dst))
        elif ethertype == 0x86DD:
            udp = ip[40:]
            src_s, dst_s = ip[8:24].hex(), ip[24:40].hex()
        else:
            continue
        sport, dport, ulen = struct.unpack(">HHH", udp[:6])
        payload = udp[8:ulen]
        n += 1
        form = "long" if payload[0] & 0x80 else "short"
        if form == "long":
            longhdr += 1
            version = struct.unpack(">I", payload[1:5])[0]
            ptype = (payload[0] >> 4) & 3
            tname = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}[ptype] if version else "VersionNegotiation"
            desc = "form=long fixed=%d type=%s version=0x%08x dcidlen=%d" % (
                (payload[0] >> 6) & 1, tname, version, payload[5])
        else:
            shorthdr += 1
            desc = "form=short fixed=%d" % ((payload[0] >> 6) & 1)
        if n <= 6 or form == "long":
            print("pkt %3d %s:%d -> %s:%d len=%d bytes[0..7]=%s %s" % (
                n, src_s, sport, dst_s, dport, len(payload), payload[:8].hex(" "), desc))
    print("packets=%d long_header=%d short_header=%d" % (n, longhdr, shorthdr))


if __name__ == "__main__":
    main(sys.argv[1])
