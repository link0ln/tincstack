#!/usr/bin/env python3
"""Print the clients' QUIC datagrams from a pcap as an observer sees them.

Initial packets are protected with keys anyone derives from the Destination
Connection ID of the client's first Initial (RFC 9001 5.2), so an observer
reads their frames. tshark finds those keys by tracking connections by id;
once a client moves to a connection ID the server issued inside a 1-RTT
packet, tshark cannot follow without the TLS secrets and stops decrypting.
This script keys every Initial of a client by the first DCID that client
used, which is what an observer on the path does.

Standard library only. One line per client datagram that carries a long
header packet:

  <src ip>  <udp length>  <packet types>  <Length fields>  <Initial frames>  <DCID>  <src port>

packet types: I (Initial), H (Handshake), 0 (0-RTT), S (short header, rest
of the datagram). Initial frames: ACK, PING, CRYPTO<offset>+<length>,
PADDING<n>, in order, "." between packets.

Usage: quic_initial.py <pcap> [server port, default 443]
"""
import hashlib
import hmac
import struct
import sys

# ---- AES-128 (encryption only: header protection and GCM's counter mode) ----

SBOX = [0] * 256


def _init_sbox():
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ (q << 1 | q >> 7) ^ (q << 2 | q >> 6) ^ (q << 3 | q >> 5) ^ (q << 4 | q >> 4)
        SBOX[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    SBOX[0] = 0x63


_init_sbox()


def _xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def _expand(key):
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return [sum(w[r * 4:r * 4 + 4], []) for r in range(11)]


def _encrypt_block(rk, block):
    s = [a ^ b for a, b in zip(block, rk[0])]
    for r in range(1, 11):
        s = [SBOX[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]  # ShiftRows, column-major state
        if r != 10:
            m = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                t = a[0] ^ a[1] ^ a[2] ^ a[3]
                m += [a[i] ^ t ^ _xtime(a[i] ^ a[(i + 1) % 4]) for i in range(4)]
            s = m
        s = [a ^ b for a, b in zip(s, rk[r])]
    return bytes(s)


def _ctr(rk, nonce, data):
    out = bytearray()
    for i in range(0, len(data), 16):
        ks = _encrypt_block(rk, nonce + struct.pack(">I", 2 + i // 16))
        out += bytes(a ^ b for a, b in zip(data[i:i + 16], ks))
    return bytes(out)


# ---- QUIC v1 Initial keys (RFC 9001 5.2) --------------------------------------------------

SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")


def _expand_label(secret, label, length):
    full = b"tls13 " + label
    info = struct.pack(">HB", length, len(full)) + full + b"\x00"
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(secret, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def client_keys(dcid):
    initial = hmac.new(SALT, dcid, hashlib.sha256).digest()
    secret = _expand_label(initial, b"client in", 32)
    return (_expand(_expand_label(secret, b"quic key", 16)),
            _expand_label(secret, b"quic iv", 12),
            _expand(_expand_label(secret, b"quic hp", 16)))


# ---- parsing -------------------------------------------------------------------------------

def varint(b, i):
    n = 1 << (b[i] >> 6)
    v = b[i] & 0x3F
    for k in range(1, n):
        v = v << 8 | b[i + k]
    return v, i + n


def frames(p):
    out, i = [], 0
    while i < len(p):
        t = p[i]
        if t == 0:
            j = i
            while j < len(p) and p[j] == 0:
                j += 1
            out.append("PADDING%d" % (j - i))
            i = j
        elif t == 1:
            out.append("PING")
            i += 1
        elif t in (2, 3):
            _, i = varint(p, i + 1)
            _, i = varint(p, i)
            n, i = varint(p, i)
            _, i = varint(p, i)
            for _ in range(2 * n + (3 if t == 3 else 0)):
                _, i = varint(p, i)
            out.append("ACK")
        elif t == 6:
            off, i = varint(p, i + 1)
            ln, i = varint(p, i)
            i += ln
            out.append("CRYPTO%d+%d" % (off, ln))
        else:
            out.append("0x%02x" % t)
            break
    return out


def decrypt_initial(dgram, start, hdr_end, length, keys):
    key, iv, hp = keys
    sample = dgram[hdr_end + 4:hdr_end + 20]
    mask = _encrypt_block(hp, sample)
    first = dgram[start] ^ (mask[0] & 0x0F)
    pnlen = (first & 3) + 1
    pn = 0
    for k in range(pnlen):
        pn = pn << 8 | (dgram[hdr_end + k] ^ mask[1 + k])
    nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big")))
    ct = dgram[hdr_end + pnlen:hdr_end + length - 16]
    return _ctr(key, nonce, ct)


def datagrams(path, port):
    with open(path, "rb") as f:
        data = f.read()
    magic = data[:4]
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    link = struct.unpack(endian + "I", data[20:24])[0]
    i = 24
    while i + 16 <= len(data):
        incl = struct.unpack(endian + "I", data[i + 8:i + 12])[0]
        pkt = data[i + 16:i + 16 + incl]
        i += 16 + incl
        off = {1: 14, 113: 16, 276: 20}.get(link)
        if off is None or len(pkt) < off + 28 or pkt[off] >> 4 != 4:
            continue
        ihl = (pkt[off] & 0x0F) * 4
        if pkt[off + 9] != 17:
            continue
        src = ".".join(str(b) for b in pkt[off + 12:off + 16])
        u = off + ihl
        sport, dport, ulen = struct.unpack(">HHH", pkt[u:u + 6])
        if dport == port:
            yield src, sport, ulen, pkt[u + 8:u + ulen]


def main():
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    origin = {}
    for src, sport, ulen, d in datagrams(sys.argv[1], port):
        if not d or not d[0] & 0x80:
            continue
        types, lengths, fr, dcids = [], [], [], []
        i = 0
        while i < len(d):
            if not d[i] & 0x80:
                types.append("S")
                break
            ptype = (d[i] >> 4) & 3
            j = i + 5
            dcid = d[j + 1:j + 1 + d[j]]
            j += 1 + d[j]
            j += 1 + d[j]
            if ptype == 0:
                tl, j = varint(d, j)
                j += tl
            length, j = varint(d, j)
            types.append("I0HR"[ptype])
            lengths.append(str(length))
            dcids.append(dcid.hex())
            if ptype == 0:
                keys = origin.setdefault((src, sport), client_keys(dcid))
                fr.append(",".join(frames(decrypt_initial(d, i, j, length, keys))))
            i = j + length
        print("\t".join([src, str(ulen), "".join(types), ",".join(lengths), ".".join(fr), dcids[0], str(sport)]))


if __name__ == "__main__":
    main()
