#!/usr/bin/env python3
"""Report the byte patterns that fingerprint a tinc 1.1 session on the wire.

Reads a libpcap file (Ethernet link type, as written by `tcpdump -w`) with the
standard library only and evaluates these detectors:

  tcp_id_line            cleartext protocol banner "0 <name> 17.x\\n" at the start
                         of a TCP payload (tinc's ID request, both directions)
  tcp_sptps_handshake    plaintext SPTPS handshake record on TCP right after the
                         banner: [len:2][type 0x80 = SPTPS_HANDSHAKE] + KEX body
  udp_null_dstid         UDP datagrams beginning with 6 zero bytes (the "direct
                         path" null destination node id of tinc >= 17.4)
  udp_constant_srcid     bytes 6..11 of every datagram from one sender are the
                         same 6 bytes (sender node id in the clear)
  udp_seqno_counter      bytes 12..15 are a big-endian counter that increases by
                         small steps per sender (SPTPS datagram seqno in the clear)
  udp_probe_size         fixed-size datagrams matching tinc's minimum UDP probe
                         (18 B payload + 21 B SPTPS + 12 B ids = 51 B)
  udp_size_histogram     (informative) datagram sizes

Usage: dpi-fingerprint FILE.pcap [--port 655] [--json OUT.json]
Prints a text report; exit 0 always (the verdict is dpi-compare's job).
"""
import argparse
import collections
import json
import re
import struct
import sys

ID_LINE = re.compile(rb"^0 [A-Za-z0-9_]+ 17(\.[0-9]+)?\n")


def read_pcap(path):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 24:
        return []
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    elif magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        endian = "<" if magic[0] == 0x4D else ">"
    else:
        sys.exit("not a pcap file (pcapng is not supported: use tcpdump -w)")
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    pos = 24
    pkts = []
    while pos + 16 <= len(data):
        ts_sec, ts_usec, incl, _orig = struct.unpack(endian + "IIII", data[pos:pos + 16])
        pos += 16
        frame = data[pos:pos + incl]
        pos += incl
        pkts.append((ts_sec + ts_usec / 1e6, frame, linktype))
    return pkts


def parse(frame, linktype):
    """Return (proto, src, sport, dst, dport, payload) for IPv4 TCP/UDP or None."""
    if linktype == 1:  # Ethernet
        if len(frame) < 14:
            return None
        eth = struct.unpack("!H", frame[12:14])[0]
        if eth != 0x0800:
            return None
        ip = frame[14:]
    elif linktype == 101:  # raw IP
        ip = frame
    elif linktype == 113:  # Linux cooked
        if len(frame) < 16 or struct.unpack("!H", frame[14:16])[0] != 0x0800:
            return None
        ip = frame[16:]
    else:
        return None
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    ihl = (ip[0] & 0xF) * 4
    total = struct.unpack("!H", ip[2:4])[0]
    proto = ip[9]
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    l4 = ip[ihl:total]
    if proto == 17 and len(l4) >= 8:
        sport, dport = struct.unpack("!HH", l4[:4])
        return ("udp", src, sport, dst, dport, l4[8:])
    if proto == 6 and len(l4) >= 20:
        sport, dport = struct.unpack("!HH", l4[:4])
        off = (l4[12] >> 4) * 4
        return ("tcp", src, sport, dst, dport, l4[off:])
    return None


def analyse(pkts, port):
    tcp_payloads = []  # (flow, payload) in capture order
    udp = []           # (sender, payload)
    for _ts, frame, lt in pkts:
        p = parse(frame, lt)
        if not p:
            continue
        proto, src, sport, dst, dport, payload = p
        if port and port not in (sport, dport):
            continue
        if proto == "tcp" and payload:
            tcp_payloads.append(((src, sport, dst, dport), payload))
        elif proto == "udp":
            udp.append(((src, sport), payload))

    fp = {}
    # --- TCP: ID line
    id_hits = [pl for _f, pl in tcp_payloads if ID_LINE.match(pl)]
    fp["tcp_id_line"] = {
        "present": bool(id_hits),
        "count": len(id_hits),
        "evidence": [h.split(b"\n", 1)[0].decode(errors="replace") for h in id_hits[:4]],
    }
    # --- TCP: plaintext SPTPS handshake record ([len16][0x80]...) either as its
    # own segment or immediately after the ID line in the same segment.
    hs = []
    for _f, pl in tcp_payloads:
        m = ID_LINE.match(pl)
        rest = pl[m.end():] if m else pl
        if len(rest) >= 3 and rest[2] == 0x80:
            rlen = struct.unpack("!H", rest[:2])[0]
            if rlen + 3 <= len(rest):
                hs.append(rlen)
    fp["tcp_sptps_handshake"] = {
        "present": bool(hs),
        "count": len(hs),
        "evidence": [f"record len={n} type=0x80" for n in hs[:4]],
    }
    # --- UDP
    sizes = collections.Counter(len(pl) for _s, pl in udp)
    fp["udp_size_histogram"] = {"present": None, "count": len(udp),
                                "evidence": dict(sorted(sizes.items())[:40])}
    nulldst = [pl for _s, pl in udp if len(pl) >= 33 and pl[:6] == b"\0" * 6]
    fp["udp_null_dstid"] = {
        "present": len(udp) >= 5 and len(nulldst) / len(udp) > 0.5,
        "count": len(nulldst),
        "evidence": f"{len(nulldst)}/{len(udp)} datagrams start with 6 zero bytes",
    }
    by_sender = collections.defaultdict(list)
    for s, pl in udp:
        if len(pl) >= 33:
            by_sender[s].append(pl)
    const_ids = {}
    counters = {}
    for s, pls in by_sender.items():
        if len(pls) < 5:
            continue
        ids = {pl[6:12] for pl in pls}
        if len(ids) == 1:
            const_ids[f"{s[0]}:{s[1]}"] = next(iter(ids)).hex()
        seq = [struct.unpack("!I", pl[12:16])[0] for pl in pls]
        deltas = [b - a for a, b in zip(seq, seq[1:])]
        if deltas:
            inc = sum(1 for d in deltas if 0 < d <= 64) / len(deltas)
            if inc > 0.9 and seq[0] < 100000:
                counters[f"{s[0]}:{s[1]}"] = {"first": seq[0], "last": seq[-1], "monotone_ratio": round(inc, 3)}
    fp["udp_constant_srcid"] = {"present": bool(const_ids), "count": len(const_ids), "evidence": const_ids}
    fp["udp_seqno_counter"] = {"present": bool(counters), "count": len(counters), "evidence": counters}
    probes = sizes.get(51, 0)
    fp["udp_probe_size"] = {"present": probes >= 3, "count": probes,
                            "evidence": f"{probes} datagrams of exactly 51 bytes (tinc MIN_PROBE_SIZE)"}
    summary = {
        "tcp_payload_segments": len(tcp_payloads),
        "udp_datagrams": len(udp),
        "fingerprints_present": sorted(k for k, v in fp.items() if v["present"]),
    }
    return {"port": port, "summary": summary, "fingerprints": fp}


def report(res):
    out = [f"dpi-fingerprint: port={res['port']} tcp_segments={res['summary']['tcp_payload_segments']} udp_datagrams={res['summary']['udp_datagrams']}"]
    for k, v in res["fingerprints"].items():
        state = {True: "PRESENT", False: "absent", None: "info"}[v["present"]]
        ev = v["evidence"]
        if isinstance(ev, (dict, list)):
            ev = json.dumps(ev)
        out.append(f"  {k:24s} {state:8s} n={v['count']:<5d} {ev}")
    out.append(f"present: {', '.join(res['summary']['fingerprints_present']) or 'none'}")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--port", type=int, default=655)
    ap.add_argument("--json", default="")
    a = ap.parse_args()
    res = analyse(read_pcap(a.pcap), a.port)
    if a.json:
        with open(a.json, "w") as f:
            json.dump(res, f, indent=1)
    print(report(res))


if __name__ == "__main__":
    main()
