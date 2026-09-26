#!/usr/bin/env python3
"""Byte and size statistics of the UDP datagrams in a capture of the direct
peer-to-peer path (natlab `--capture`), stdlib only.

dpi-fingerprint answers "is this tinc?" with thresholds; this answers "how many
datagrams still carry a tinc marker at all, and do the first bytes and the
sizes look like random bytes?" -- the question the sealed direct path
(DirectSeal) has to answer with 0, not with "below the threshold".

Counted per capture (QUIC long/short-header packets of a direct QUIC meta link
are reported separately and left out of the byte statistics: they are
supposed to look like QUIC):

  zero6        datagrams whose first 6 bytes are zero (tinc's null
               destination id: a direct SPTPS datagram)
  sfmagic      datagrams opening with the single-flow magic 9f 74 73 66 6c 77
               (a cleartext `sf' meta frame)
  size51       datagrams of exactly 51 bytes (tinc's minimum UDP probe)
  const_srcid  senders whose bytes 6..11 are the same in every datagram
  counter      senders whose bytes 12..15 count up (SPTPS seqno in the clear)
  eq6_consec   consecutive datagrams of one sender with equal bytes 0..5
  sizes        distinct sizes, the most common size and its share
  chi2         per byte position 0..15: chi-square of the byte histogram
               against uniform (p via Wilson-Hilferty); positions with
               p < 1e-6 are flagged. Needs a few hundred datagrams to mean much.

Usage: wirestats FILE.pcap [--json OUT.json] [--label TEXT]
"""
import argparse
import collections
import json
import math
import struct
import sys

SF_MAGIC = bytes([0x9F, 0x74, 0x73, 0x66, 0x6C, 0x77])


def read_pcap(path):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 24:
        return []
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        sys.exit("not a pcap file (pcapng is not supported: use tcpdump -w)")
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    pos, out = 24, []
    while pos + 16 <= len(data):
        _s, _u, incl, _o = struct.unpack(endian + "IIII", data[pos:pos + 16])
        pos += 16
        out.append((data[pos:pos + incl], linktype))
        pos += incl
    return out


def udp_payload(frame, linktype):
    if linktype == 1:
        if len(frame) < 14 or struct.unpack("!H", frame[12:14])[0] != 0x0800:
            return None
        ip = frame[14:]
    elif linktype == 101:
        ip = frame
    elif linktype == 113:
        if len(frame) < 16 or struct.unpack("!H", frame[14:16])[0] != 0x0800:
            return None
        ip = frame[16:]
    elif linktype == 276:  # LINUX_SLL2 (tcpdump -i any on current libpcap)
        if len(frame) < 20 or struct.unpack("!H", frame[0:2])[0] != 0x0800:
            return None
        ip = frame[20:]
    else:
        return None
    if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 17:
        return None
    ihl = (ip[0] & 0xF) * 4
    total = struct.unpack("!H", ip[2:4])[0]
    l4 = ip[ihl:total]
    if len(l4) < 8:
        return None
    sport = struct.unpack("!H", l4[:2])[0]
    src = ".".join(str(b) for b in ip[12:16])
    return (src, sport), l4[8:]


def looks_quic(pl):
    if len(pl) >= 5 and (pl[0] & 0xC0) == 0xC0:
        return struct.unpack("!I", pl[1:5])[0] in (1, 0x6B3343CF)
    return False


def chi2_p(counts, n):
    k = 255
    exp = n / 256.0
    x = sum((c - exp) ** 2 / exp for c in counts)
    # Wilson-Hilferty: (x/k)^(1/3) is ~normal
    z = ((x / k) ** (1.0 / 3) - (1 - 2.0 / (9 * k))) / math.sqrt(2.0 / (9 * k))
    return 0.5 * math.erfc(z / math.sqrt(2))


def analyse(pkts):
    dgrams = []
    for frame, lt in pkts:
        p = udp_payload(frame, lt)
        if p:
            dgrams.append(p)
    quic = [d for d in dgrams if looks_quic(d[1])]
    rest = [d for d in dgrams if not looks_quic(d[1])]
    res = {"datagrams": len(dgrams), "quic_long_header": len(quic), "analysed": len(rest)}
    res["zero6"] = sum(1 for _s, pl in rest if len(pl) >= 6 and pl[:6] == b"\0" * 6)
    res["sfmagic"] = sum(1 for _s, pl in rest if pl[:6] == SF_MAGIC)
    res["size51"] = sum(1 for _s, pl in rest if len(pl) == 51)
    by = collections.defaultdict(list)
    for s, pl in rest:
        by[s].append(pl)
    const, counters, eq6, pairs = {}, {}, 0, 0
    for s, pls in by.items():
        big = [pl for pl in pls if len(pl) >= 16]
        if len(big) >= 5:
            ids = {pl[6:12] for pl in big}
            if len(ids) == 1:
                const["%s:%d" % s] = next(iter(ids)).hex()
            seq = [struct.unpack("!I", pl[12:16])[0] for pl in big]
            d = [b - a for a, b in zip(seq, seq[1:])]
            if d and sum(1 for x in d if 0 < x <= 64) / len(d) > 0.9:
                counters["%s:%d" % s] = [seq[0], seq[-1]]
        for a, b in zip(pls, pls[1:]):
            if len(a) >= 6 and len(b) >= 6:
                pairs += 1
                eq6 += a[:6] == b[:6]
    res["const_srcid"] = const
    res["counter"] = counters
    res["eq6_consec"] = "%d/%d" % (eq6, pairs)
    sizes = collections.Counter(len(pl) for _s, pl in rest)
    res["distinct_sizes"] = len(sizes)
    if sizes:
        top, cnt = sizes.most_common(1)[0]
        res["top_size"] = "%d B x%d (%.1f %%)" % (top, cnt, 100.0 * cnt / len(rest))
    res["size_histogram_top10"] = dict(sizes.most_common(10))
    flagged, pvals = [], []
    for pos in range(16):
        col = [pl[pos] for _s, pl in rest if len(pl) > pos]
        if len(col) < 64:
            pvals.append(None)
            continue
        c = collections.Counter(col)
        p = chi2_p([c.get(v, 0) for v in range(256)], len(col))
        pvals.append(p)
        if p < 1e-6:
            flagged.append(pos)
    res["chi2_flagged_positions"] = flagged
    res["chi2_min_p"] = min((p for p in pvals if p is not None), default=None)
    pooled = collections.Counter(b for _s, pl in rest for b in pl[:16])
    tot = sum(pooled.values())
    res["entropy_bytes_0_15"] = round(-sum(v / tot * math.log2(v / tot) for v in pooled.values()), 4) if tot else None
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--json", default="")
    ap.add_argument("--label", default="")
    a = ap.parse_args()
    res = analyse(read_pcap(a.pcap))
    if a.label:
        res = {"label": a.label, **res}
    if a.json:
        with open(a.json, "w") as f:
            json.dump(res, f, indent=1)
    for k, v in res.items():
        print("%-24s %s" % (k, json.dumps(v) if isinstance(v, (dict, list)) else v))


if __name__ == "__main__":
    main()
