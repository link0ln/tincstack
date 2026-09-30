#!/usr/bin/env python3
"""TLS-in-TLS burst-model oracle: score every flow of a capture against the
encapsulated-TLS-handshake model that nDPI uses, and say by how much it
passes or fails.

The model (Xue et al., "Fingerprinting Obfuscated Proxy Traffic with
Encapsulated TLS Handshakes", USENIX Security 2024, as implemented in nDPI's
src/lib/protocols/tls.c, release 6.0): a flow is cut into bursts -- runs of
payload-carrying packets in one direction -- and every 4 consecutive bursts
that start client -> server form a 4-gram of byte counts. A 4-gram is
"a TLS handshake inside" when its Mahalanobis distance to one of three
centroids (Firefox TLS 1.2, Firefox TLS 1.3, Chrome with PQ/ECH) is below that
centroid's threshold. Before summing, a fixed overhead is taken off every
packet (24 B inside TLS, 0 elsewhere). A 4-gram whose first burst has more
than 3 packets is not scored.

This is a reimplementation from the nDPI source and the paper; the centroids
and inverse covariance matrices below are nDPI's model parameters (nDPI is
LGPL-3.0; only its numbers are used here).

Margin of a 4-gram = the smallest (distance - threshold) over the centroids
that apply (the TLS 1.3 one only when burst 1 >= 517 B, as in nDPI). Below 0
is caught; the plan's bar for "safe" is >= 0.9, because a live Chrome session
sat 0.038 above the 3.0 threshold.

Three scorings per flow:

  ndpi<N>  what nDPI 6.0 itself does with dpi.heuristics.max_packets_extra_
           dissection = N (and every other packet budget at least as large --
           a stock nDPI stops after 32 packets of a flow, ndpiReader after 24
           UDP ones, so the stock window is smaller than 25; the arbiter's
           run is the authority there): inside TLS it starts after the packet with the
           ServerHello, skips each direction until that direction's
           ChangeCipherSpec, gives up on a packet smaller than the overhead,
           on a server-first start, or after N+1 counted packets, and stops at
           the first match. Other TCP/UDP flows get the "plain" variant: from
           the first packet, overhead 0 (nDPI only runs it on flows it could
           not classify; QUIC is classified, so for QUIC it is not run -- the
           analyser says "n/a").
  fix<N>   nDPI with its one self-inflicted blind spot removed: it gives up on
           a TLS flow whose server writes first after the handshake, which
           every OpenSSL/nginx server does (TLS 1.3 session tickets), so as
           shipped it scores almost no real TLS. Here leading server packets
           are skipped instead -- the obvious next nDPI release.
  flow     the same model over the whole connection: a stronger observer who
           keeps scoring after packet N. Packets not larger than the overhead
           are ignored instead of ending the search. Over thousands of
           4-grams some fall under any threshold, legitimate TLS included, so
           the number to read is the rate of caught 4-grams next to a
           long-lived plain HTTPS control, and in which phase they fall.
  tuned    `flow` with the tunnel's measured per-packet overhead instead of
           nDPI's 24 B, and packets not larger than overhead + an inner pure
           TCP ACK ignored (an observer who knows it is looking at an L3
           tunnel and drops the tunnelled ACKs that would split bursts).

A verdict at nDPI's thresholds says little on its own: plain HTTPS falls under
them too. What decides whether a detector of this family can exist is
separability: per centroid, the smallest distance any scored 4-gram of the
flow reaches. If for some centroid our flow gets closer than the reference
(plain HTTPS) does, a threshold between the two flags us and not it; if for
every centroid the reference gets at least as close, any setting that flags
us flags it as well. `report --reference NAME` prints that comparison.

Usage:
  tls_in_tls.py score [--limits 25,255] [--overhead TCP:UDP] [--ack 52]
                      [--phases phases.tsv] [--json OUT] FILE.pcap[ng]...
  tls_in_tls.py calibrate FILE.pcap T0 T1 INNER_IP_LEN
      prints the per-packet overhead of pings of INNER_IP_LEN sent between
      epochs T0 and T1: the most common payload length minus INNER_IP_LEN when
      one length carries a third of them, else the smallest (a lower bound)
  tls_in_tls.py report [--reference NAME] [--json OUT] RUNDIR NAME:PROTO/PORT...
      one table from RUNDIR/NAME.json (score --json) and RUNDIR/NAME.ndpi<N>.txt
      (ndpiReader -v 2), for the flows of each NAME whose server port is PORT;
      with --reference A,B,.., each other NAME's per-centroid minimum distance
      against the smallest any of the reference flows reaches

Standard library only. Exit 0 always; verdicts are in the report.
"""
import argparse
import collections
import json
import math
import re
import struct
import sys

# ---- nDPI 6.0 model parameters (src/lib/protocols/tls.c, check_set) ----------------------------------
MODELS = [
    # name, threshold, centroid (bytes of bursts 1..4), inverse covariance (row-major 4x4), min burst 1
    ("tls12", 3.5,
     (212.883690341977, 4514.71195039459, 107.770762871101, 307.580232995115),
     (0.000292421113167604, 4.43677617831228E-07, -5.69966093492813E-05, -2.18124698406311E-06,
      4.43677617831228E-07, 5.98954952745268E-07, -3.59798436724817E-07, 5.71638172955893E-07,
      -5.69966093492813E-05, -3.59798436724817E-07, 0.00076893788148309, 2.22278496185964E-05,
      -2.18124698406311E-06, 5.71638172955893E-07, 2.22278496185964E-05, 5.72770077086287E-05), 0),
    ("tls13", 3.0,
     (640.657378447541, 4649.30338356554, 448.408302530566, 1094.2013079329),
     (3.08030337925007E-05, 1.16179172096944E-07, 1.05356744968627E-07, 3.8862884355278E-08,
      1.16179172096944E-07, 6.93179117519316E-07, 2.77413220880937E-08, -3.63723200682445E-09,
      1.05356744968627E-07, 2.77413220880937E-08, 1.0260950589675E-06, -1.08769813590053E-08,
      3.88628843552779E-08, -3.63723200682445E-09, -1.08769813590053E-08, 8.63307792288604E-08), 517),
    ("chrome", 3.0,
     (1850.43045387994, 4903.07735480722, 785.25280624695, 1051.22303562714),
     (6.72374390966642E-06, -2.32109583941723E-08, 6.67140014394388E-08, 1.2526322628285E-08,
      -2.32109583941723E-08, 5.64668947932086E-07, 4.58963631972597E-08, 6.41254684791958E-09,
      6.67140014394388E-08, 4.58963631972597E-08, 6.04057768431344E-07, -9.1507432597718E-10,
      1.2526322628285E-08, 6.41254684791958E-09, -9.1507432597718E-10, 1.01184796635481E-07), 0),
]
NDPI_TLS_OVERHEAD = 24
SAFE_MARGIN = 0.9


THRESHOLD = {m[0]: m[1] for m in MODELS}


def mahalanobis(x, mean, inv):
    d = [x[i] - mean[i] for i in range(4)]
    t = [sum(d[j] * inv[4 * j + i] for j in range(4)) for i in range(4)]
    return math.sqrt(max(0.0, sum(t[i] * d[i] for i in range(4))))


def score(byts, pkts):
    """(margin, model, distances) of one 4-gram, or None when nDPI would not score it.
    distances holds only the centroids that apply to this 4-gram."""
    if pkts[0] > 3:
        return None
    best, dists = None, {}
    for name, thr, mean, inv, min_b0 in MODELS:
        if byts[0] < min_b0:
            continue
        dist = mahalanobis(byts, mean, inv)
        dists[name] = round(dist, 3)
        m = dist - thr
        if best is None or m < best[0]:
            best = (m, name)
    return best[0], best[1], dists


# ---- capture reading -----------------------------------------------------------------------------------
def read_capture(path):
    """Yield (epoch, linktype, frame bytes) from a pcap or pcapng file."""
    with open(path, "rb") as f:
        data = f.read()
    magic = data[:4]
    if magic == b"\x0a\x0d\x0d\x0a":
        yield from _pcapng(data)
        return
    order = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
             b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}.get(magic)
    if not order:
        raise SystemExit("%s: not a pcap/pcapng file" % path)
    e, scale = order
    linktype = struct.unpack(e + "I", data[20:24])[0]
    off = 24
    while off + 16 <= len(data):
        sec, frac, incl, _ = struct.unpack(e + "IIII", data[off:off + 16])
        yield sec + frac * scale, linktype, data[off + 16:off + 16 + incl]
        off += 16 + incl


def _pcapng(data):
    off, e, ifaces = 0, "<", []
    while off + 12 <= len(data):
        btype = struct.unpack(e + "I", data[off:off + 4])[0]
        if btype == 0x0A0D0D0A:
            e = "<" if data[off + 8:off + 12] == b"\x4d\x3c\x2b\x1a" else ">"
            ifaces = []
        blen = struct.unpack(e + "I", data[off + 4:off + 8])[0]
        body = data[off + 8:off + blen - 4]
        if btype == 1:  # interface description: link type, then options (if_tsresol)
            lt = struct.unpack(e + "H", body[:2])[0]
            res, o = 1e-6, 8
            while o + 4 <= len(body):
                code, ln = struct.unpack(e + "HH", body[o:o + 4])
                if code == 0:
                    break
                if code == 9 and ln >= 1:
                    v = body[o + 4]
                    res = 2.0 ** -(v & 0x7f) if v & 0x80 else 10.0 ** -v
                o += 4 + ((ln + 3) & ~3)
            ifaces.append((lt, res))
        elif btype == 6:  # enhanced packet
            iface, hi, lo, incl = struct.unpack(e + "IIII", body[:16])
            lt, res = ifaces[iface]
            yield ((hi << 32) | lo) * res, lt, body[20:20 + incl]
        elif btype == 3:  # simple packet
            lt, res = ifaces[0]
            yield 0.0, lt, body[4:]
        off += blen


def l3(linktype, frame):
    """The IP packet inside a frame, or None."""
    if linktype == 1:  # Ethernet, with VLAN tags
        off, et = 14, struct.unpack("!H", frame[12:14])[0]
        while et in (0x8100, 0x88a8) and len(frame) >= off + 4:
            et = struct.unpack("!H", frame[off + 2:off + 4])[0]
            off += 4
        return frame[off:] if et in (0x0800, 0x86dd) else None
    if linktype == 113:  # Linux cooked
        return frame[16:] if struct.unpack("!H", frame[14:16])[0] in (0x0800, 0x86dd) else None
    if linktype == 276:  # Linux cooked v2
        return frame[20:] if struct.unpack("!H", frame[0:2])[0] in (0x0800, 0x86dd) else None
    if linktype == 0:  # BSD loopback
        return frame[4:]
    if linktype in (12, 101, 228, 229):
        return frame
    return None


def parse(ip):
    """(src, dst, proto, sport, dport, payload length, payload head, tcp flags, seq) or None."""
    if len(ip) < 20:
        return None
    v = ip[0] >> 4
    if v == 4:
        ihl = (ip[0] & 15) * 4
        total = struct.unpack("!H", ip[2:4])[0]
        if struct.unpack("!H", ip[6:8])[0] & 0x1fff:
            return None  # a non-first fragment
        proto, src, dst, l4 = ip[9], ".".join(map(str, ip[12:16])), ".".join(map(str, ip[16:20])), ihl
        l4len = total - ihl
    elif v == 6 and len(ip) >= 40:
        proto, l4 = ip[6], 40
        l4len = struct.unpack("!H", ip[4:6])[0]
        src = ":".join("%x" % x for x in struct.unpack("!8H", ip[8:24]))
        dst = ":".join("%x" % x for x in struct.unpack("!8H", ip[24:40]))
    else:
        return None
    seg = ip[l4:]
    if proto == 6 and len(seg) >= 20:
        sport, dport, seq = struct.unpack("!HHI", seg[:8])
        doff = (seg[12] >> 4) * 4
        return src, dst, 6, sport, dport, max(0, l4len - doff), seg[doff:], seg[13], seq
    if proto == 17 and len(seg) >= 8:
        sport, dport, ulen = struct.unpack("!HHH", seg[:6])
        return src, dst, 17, sport, dport, max(0, ulen - 8), seg[8:], 0, 0
    return None


# ---- flows ---------------------------------------------------------------------------------------------
class Flow:
    def __init__(self, key, proto, client, server, first_syn):
        self.key, self.proto, self.client, self.server = key, proto, client, server
        self.seen_syn = first_syn
        self.pkts = []            # (t, dir 0=C>S 1=S>C, payload length, first byte)
        self.next_end = [None, None]
        self.walk = [TlsWalk(), TlsWalk()]
        self.kind = None

    def add(self, t, d, plen, head, flags, seq):
        if self.proto == 6:
            if plen == 0:
                return
            end = (seq + plen) & 0xffffffff
            ne = self.next_end[d]
            if ne is not None and (end == ne or ((end - ne) & 0xffffffff) > 0x7fffffff):
                return  # nothing new: a retransmission, which nDPI skips
            self.next_end[d] = end
        elif plen == 0:
            return
        idx = len(self.pkts)
        self.pkts.append((t, d, plen, head[0] if head else -1))
        if self.proto == 6 and idx < 400:
            self.walk[d].feed(idx, head, plen)
        if self.kind is None:
            self.kind = classify(self.proto, d, head)


def classify(proto, d, head):
    if proto == 6:
        if d == 0 and len(head) >= 6 and head[0] == 0x16 and head[1] == 3 and head[5] == 1:
            return "tls"
        return "tcp"
    if len(head) >= 5 and head[0] & 0xc0 == 0xc0 and head[1:5] in (b"\x00\x00\x00\x01", b"\x6b\x33\x43\xcf"):
        return "quic"
    return "udp"


class TlsWalk:
    """Follows TLS record boundaries through one direction's segments (in order,
    captured in full) and remembers the packet of the first ServerHello and
    of the first ChangeCipherSpec."""

    def __init__(self):
        self.pending = b""      # a partial record header
        self.skip = 0           # bytes of the current record still to come
        self.first_sh = None
        self.first_ccs = None
        self.broken = False

    def feed(self, idx, head, plen):
        if self.broken:
            return
        if len(head) < plen:
            self.broken = True  # truncated capture: boundaries are lost
            return
        buf, o = self.pending + head[:plen], 0
        self.pending = b""
        if self.skip:
            take = min(self.skip, len(buf))
            self.skip -= take
            o = take
        while o < len(buf):
            if len(buf) - o < 6:
                self.pending = buf[o:]
                return
            ctype, ver, rlen = buf[o], buf[o + 1], struct.unpack("!H", buf[o + 3:o + 5])[0]
            if ver != 3 or not 20 <= ctype <= 26:
                self.broken = True
                return
            if ctype == 0x16 and buf[o + 5] == 2 and self.first_sh is None:
                self.first_sh = idx
            if ctype == 0x14 and rlen == 1 and self.first_ccs is None:
                self.first_ccs = idx
            end = o + 5 + rlen
            if end > len(buf):
                self.skip = end - len(buf)
                return
            o = end


def load_flows(path):
    flows = {}
    for t, lt, frame in read_capture(path):
        ip = l3(lt, frame)
        p = ip and parse(ip)
        if not p:
            continue
        src, dst, proto, sport, dport, plen, head, flags, seq = p
        a, b = (src, sport), (dst, dport)
        key = (proto,) + tuple(sorted([a, b]))
        f = flows.get(key)
        if f is None:
            syn = proto == 6 and flags & 0x12 == 0x02
            if proto == 6 and flags & 0x12 == 0x12:
                a, b = b, a  # first packet seen is the SYN-ACK: the client is its destination
            f = flows[key] = Flow(key, proto, a, b, syn)
        d = 0 if (src, sport) == f.client else 1
        f.add(t, d, plen, head, flags, seq)
    return [f for f in flows.values() if f.pkts]


# ---- scoring -------------------------------------------------------------------------------------------
def fourgrams(seq):
    """seq: (t, dir, bytes) of the counted packets. Yields (t, bytes[4], pkts[4]) for
    every 4 bursts that start client -> server, as nDPI's two interleaved sets do,
    each completed by the first packet of the burst after it."""
    bursts = []
    for t, d, b in seq:
        if bursts and bursts[-1][0] == d:
            bursts[-1][2] += b
            bursts[-1][3] += 1
        else:
            bursts.append([d, t, b, 1])
    for i, bu in enumerate(bursts):
        if bu[0] != 0 or i + 4 >= len(bursts):
            continue
        g = bursts[i:i + 4]
        yield g[0][1], [x[2] for x in g], [x[3] for x in g]


def counted(f, overhead, limit=None, ignore_upto=None, server_first_ok=False):
    """The packets the heuristic sums, as (t, dir, bytes - overhead), and why it stopped.

    limit=None, ignore_upto=None reproduces nDPI: a packet below the overhead ends
    the search, so does a server-first start and packet limit+2. With ignore_upto
    set, packets up to that size are dropped instead and nothing ends the search.
    Inside TLS each direction is skipped until its ChangeCipherSpec, as nDPI does."""
    if f.kind == "tls":
        sh = f.walk[1].first_sh
        if sh is None:
            return None, "no ServerHello seen"
        ccs = [f.walk[0].first_ccs is not None and f.walk[0].first_ccs <= sh,
               f.walk[1].first_ccs is not None and f.walk[1].first_ccs <= sh]
        pkts = f.pkts[sh + 1:]
    else:
        if f.proto == 6 and not f.seen_syn and ignore_upto is None:
            return None, "flow start not captured"
        ccs, pkts = [True, True], f.pkts
    seq, opened = [], False
    for t, d, plen, first in pkts:
        if not ccs[d]:
            if first == 0x14:
                ccs[d] = True
            continue
        if ignore_upto is not None:
            if plen > ignore_upto:
                seq.append((t, d, plen - overhead))
            continue
        if plen < overhead:
            return seq, "stopped at a %d-B packet (below the %d-B overhead)" % (plen, overhead)
        if not opened:
            if d != 0:
                if server_first_ok:
                    continue
                return None, "server sent first after the handshake"
            opened = True
        if len(seq) > limit:
            return seq, "stopped after %d packets" % (limit + 1)
        seq.append((t, d, plen - overhead))
    return seq, "flow ended"


def closest(mind, dists):
    """Fold one 4-gram's per-centroid distances into the running minimum."""
    for k, v in dists.items():
        if k not in mind or v < mind[k]:
            mind[k] = v


def score_ndpi(f, limit, fixed=False):
    """nDPI 6.0's own run of the heuristic on this flow (fixed: without the
    server-first exclusion): (verdict, detail, t of the hit, margin, the
    per-centroid minimum distance over every 4-gram of the window)."""
    if f.kind == "quic":
        return "n/a", "nDPI classifies QUIC; the heuristic is not run on it", None, None, {}
    seq, why = counted(f, NDPI_TLS_OVERHEAD if f.kind == "tls" else 0, limit=limit, server_first_ok=fixed)
    if seq is None:
        return "excluded", why, None, None, {}
    best, hit, mind = None, None, {}
    for t, byts, pk in fourgrams(seq):
        s = score(byts, pk)
        if s is None:
            continue
        closest(mind, s[2])
        if s[0] < 0 and hit is None:  # nDPI stops at the first match
            hit = ("CAUGHT", "margin %.3f (%s) on %s pkts %s" % (s[0], s[1], "/".join(map(str, byts)), pk), t, s[0])
        if best is None or s[0] < best[0]:
            best = (s[0], s[1], byts, pk, t)
    if hit:
        return hit + (mind,)
    if best is None:
        return "not scored", "no 4-gram completed; %s" % why, None, None, mind
    verdict = "clean" if best[0] >= SAFE_MARGIN else "below-bar"
    return verdict, "min margin %.3f (%s) on %s pkts %s; %s" % (
        best[0], best[1], "/".join(map(str, best[2])), best[3], why), best[4], best[0], mind


def score_flow(f, overhead, ignore_upto):
    """Whole-connection scoring: counts and the worst 4-gram."""
    seq, why = counted(f, overhead, ignore_upto=ignore_upto)
    res = dict(scored=0, unscored=0, caught=0, below_safe=0, worst=None, caught_t=[], mind={})
    for t, byts, pk in fourgrams(seq or []):
        s = score(byts, pk)
        if s is None:
            res["unscored"] += 1
            continue
        res["scored"] += 1
        closest(res["mind"], s[2])
        res["caught"] += s[0] < 0
        res["below_safe"] += s[0] < SAFE_MARGIN
        if s[0] < 0:
            res["caught_t"].append(t)
        if res["worst"] is None or s[0] < res["worst"]["margin"]:
            res["worst"] = dict(margin=round(s[0], 3), model=s[1], t=t, bytes=byts, pkts=pk, dist=s[2])
    return res


def phase_of(marks, t):
    cur = "pre"
    for name, mt in marks:
        if t >= mt:
            cur = name
    return cur


def fmt_flow(res, marks):
    if res["scored"] == 0:
        return "no 4-gram scored (%d unscored)" % res["unscored"]
    w = res["worst"]
    where = (" in %s" % phase_of(marks, w["t"])) if marks else ""
    by_phase = collections.Counter(phase_of(marks, t) for t in res["caught_t"]) if marks else {}
    return "min margin %.3f (%s) %s pkts %s%s; %d scored, %d caught (%.1f/1000%s), %d below %.1f, %d unscored" % (
        w["margin"], w["model"], "/".join(map(str, w["bytes"])), w["pkts"], where,
        res["scored"], res["caught"], 1000.0 * res["caught"] / res["scored"],
        (": " + ", ".join("%s %d" % kv for kv in sorted(by_phase.items()))) if by_phase else "",
        res["below_safe"], SAFE_MARGIN, res["unscored"])


def cmd_score(args):
    limits = [int(x) for x in args.limits.split(",") if x]
    ov_tcp, ov_udp = (int(x) for x in args.overhead.split(":")) if args.overhead else (None, None)
    marks = []
    if args.phases:
        marks = sorted(((l.split("\t")[0], float(l.split("\t")[-1])) for l in open(args.phases) if l.strip()),
                       key=lambda x: x[1])
    out = []
    for path in args.files:
        print("== %s" % path)
        for f in sorted(load_flows(path), key=lambda f: f.pkts[0][0]):
            if len(f.pkts) < args.min_pkts:
                continue
            name = "%s %s:%d > %s:%d" % (f.kind, f.client[0], f.client[1], f.server[0], f.server[1])
            rec = dict(file=path, id=name, kind=f.kind, client="%s:%d" % f.client, server="%s:%d" % f.server,
                       packets=len(f.pkts), start=f.pkts[0][0])
            print("  %s  (%d payload packets)" % (name, len(f.pkts)))
            for mode, fixed in (("ndpi", False), ("fix", True)):
                for n in limits:
                    v, detail, t, m, mind = score_ndpi(f, n, fixed)
                    rec["%s%d" % (mode, n)] = [v, detail, m, mind]
                    where = (" [%s]" % phase_of(marks, t)) if marks and t else ""
                    print("    %-8s %-10s %s%s" % ("%s%d" % (mode, n), v, detail, where))
            ov = NDPI_TLS_OVERHEAD if f.kind == "tls" else 0
            r = score_flow(f, ov, ov)
            rec["flow"] = r
            print("    flow     %s" % fmt_flow(r, marks))
            tov = ov_tcp if f.proto == 6 else ov_udp
            if tov is not None:
                r = score_flow(f, tov, tov + args.ack)
                rec["tuned"] = dict(r, overhead=tov, ignore_upto=tov + args.ack)
                print("    tuned    %s (overhead %d, ignore <= %d)" % (fmt_flow(r, marks), tov, tov + args.ack))
            out.append(rec)
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(out, fh, indent=1)


def cmd_calibrate(args):
    t0, t1, inner = float(args.t0), float(args.t1), int(args.inner)
    hist = collections.Counter()
    for f in load_flows(args.file):
        for t, d, plen, _ in f.pkts:
            if t0 <= t <= t1 and plen >= inner:
                hist[plen] += 1
    if not hist:
        print("none")
        return
    # A constant overhead shows as one size carrying most of the pings; a
    # random tail (obfs) as a spread, whose floor is the overhead -- unless a
    # packet that is not a ping (a probe, a key exchange) falls in the window,
    # so a floor is only a lower bound and is said to be one.
    size = min(hist)
    mode, n = hist.most_common(1)[0]
    total = sum(hist.values())
    constant = 3 * n >= total
    print((mode if constant else size) - inner)
    print("calibrate: %s; floor %d B, mode %d B (x%d) of %d packets >= %d B (the ping's inner IP length)" % (
        "constant overhead (the mode)" if constant else "spread, the floor (a lower bound)",
        size, mode, n, total, inner), file=sys.stderr)


ARBITER_FLOW = re.compile(r"^\s+\d+\s+(TCP|UDP) ([0-9.]+):(\d+) <-> ([0-9.]+):(\d+) \[proto: ([^\]]*)\]")


def load_arbiter(path):
    """{frozenset of two 'ip:port'}: (proto label, risk info or '') from ndpiReader -v 2."""
    out = {}
    try:
        lines = open(path).read().splitlines()
    except OSError:
        return None
    for line in lines:
        m = ARBITER_FLOW.match(line)
        if not m:
            continue
        key = frozenset(("%s:%s" % (m.group(2), m.group(3)), "%s:%s" % (m.group(4), m.group(5))))
        risk = re.search(r"\[Risk Info: ([^\]]*)\]", line)
        out[key] = (m.group(6), risk.group(1) if risk and "Obfuscated" in risk.group(1) else "")
    return out


def min_dist(recs, key):
    """Per-centroid minimum distance over the flows' 4-grams in one scoring
    (fix<N>, flow or tuned), or None when no flow has that scoring."""
    mind, seen = {}, False
    for r in recs:
        if key not in r:
            continue
        seen = True
        closest(mind, r[key][3] if isinstance(r[key], list) else r[key]["mind"])
    return mind if seen else None


def separation(ours, ref):
    """(verdict, text): can a threshold on some centroid flag ours and not ref?"""
    if not ours:
        return "nothing scored", "-"
    parts, best = [], None
    for m in THRESHOLD:
        a, b = ours.get(m), ref.get(m)
        if a is None:
            continue
        parts.append("%s %.2f/%s" % (m, a, "%.2f" % b if b is not None else "-"))
        gap = (b if b is not None else float("inf")) - a
        if gap > 0 and (best is None or gap > best[1]):
            best = (m, gap)
    if best is None:
        return "not separable", ", ".join(parts)
    return "separable by %s (gap %s)" % (best[0], "%.2f" % best[1] if best[1] != float("inf") else "inf"), ", ".join(parts)


def cmd_report(args):
    status, loaded = {}, {}
    for spec in args.specs:
        name, sel = spec.split(":")
        proto, port = sel.split("/")
        recs = json.load(open("%s/%s.json" % (args.rundir, name)))
        recs = [r for r in recs if r["server"].endswith(":" + port) and r["kind"] in
                (("tls", "tcp") if proto == "tcp" else ("udp", "quic"))]
        loaded[name] = recs
        limits = sorted(int(k[4:]) for k in (recs[0] if recs else {}) if k.startswith("ndpi"))
        st = status[name] = dict(flows=len(recs))
        arbs = {n: load_arbiter("%s/%s.ndpi%d.txt" % (args.rundir, name, n)) for n in limits}
        called = []
        for n in limits:
            labels = collections.Counter(
                (arbs[n] or {}).get(frozenset((r["client"], r["server"])), ("not in arbiter output", ""))[0] for r in recs)
            called.append("%d: %s" % (n, ", ".join("%s x%d" % kv for kv in labels.items()) or "-"))
        print("[%s] %d flow(s) %s/%s; nDPI calls them  %s" % (name, len(recs), proto, port, "   ".join(called)))
        line, agree = [], True
        for n in limits:
            a = arbs[n]
            hits = [bool(a and a.get(frozenset((r["client"], r["server"])), ("", ""))[1]) for r in recs]
            st["arbiter%d" % n] = sum(hits)
            line.append("%d: %d/%d flagged" % (n, sum(hits), len(recs)) if a is not None else "%d: no output" % n)
            for r, hit in zip(recs, hits):
                if r["kind"] == "tls" and hit != (r["ndpi%d" % n][0] == "CAUGHT"):
                    agree = False
        st["agree"] = agree
        print("  %-24s %s" % ("arbiter, nDPI 6.0", "   ".join(line)))
        for mode, title in (("ndpi", "analyser as nDPI"), ("fix", "analyser, nDPI fixed")):
            line = []
            for n in limits:
                c = collections.Counter(r["%s%d" % (mode, n)][0] for r in recs)
                margins = [r["%s%d" % (mode, n)][2] for r in recs if r["%s%d" % (mode, n)][2] is not None]
                st["%s%d" % (mode, n)] = dict(c, min_margin=min(margins) if margins else None)
                line.append("%d: %s%s" % (n, ", ".join("%s %d" % kv for kv in sorted(c.items())),
                                          " (min %.3f)" % min(margins) if margins else ""))
            extra = ("   [agrees with the arbiter on TLS flows: %s]" % ("yes" if agree else "NO")) if mode == "ndpi" else ""
            print("  %-24s %s%s" % (title, "   ".join(line), extra))
        for key, title in (("flow", "whole flow"), ("tuned", "whole flow, tuned")):
            rs = [r[key] for r in recs if key in r]
            if not rs:
                continue
            sc, ca = sum(x["scored"] for x in rs), sum(x["caught"] for x in rs)
            ws = [x["worst"] for x in rs if x["worst"]]
            w = min(ws, key=lambda x: x["margin"]) if ws else None
            st[key] = dict(scored=sc, caught=ca, per_mille=round(1000.0 * ca / sc, 2) if sc else None,
                           worst=w["margin"] if w else None)
            print("  %-24s %d 4-grams scored, %d caught (%s/1000)%s%s" % (
                title, sc, ca, "%.1f" % (1000.0 * ca / sc) if sc else "-",
                ", worst %.3f %s %s" % (w["margin"], w["model"], "/".join(map(str, w["bytes"]))) if w else "",
                " (overhead %d)" % rs[0]["overhead"] if "overhead" in rs[0] else ""))
    if args.reference:
        names = args.reference.split(",")
        missing = [n for n in names if n not in loaded]
        if missing:
            raise SystemExit("reference %s is not among the specs" % ", ".join(missing))
        ref = [r for n in names for r in loaded[n]]
        keys = [k for k in (ref[0] if ref else {}) if k.startswith("fix")] + ["flow", "tuned"]
        thr = ", ".join("%s %.1f" % kv for kv in THRESHOLD.items())
        print()
        print("--- the plain-HTTPS reference: per-centroid minimum distance (thresholds %s) ---" % thr)
        for n in names:
            for key in keys:
                mind = min_dist(loaded[n], key)
                if mind is not None:
                    print("  %-10s %-7s %s" % (n, key, ", ".join("%s %.2f" % (m, mind[m]) for m in THRESHOLD if m in mind)
                                                or "nothing scored"))
        status["reference"] = dict(names=names, mind={k: min_dist(ref, k) for k in keys})
        print()
        print("--- which of nDPI's own centroids, at nDPI's own thresholds, flag the reference ---")
        for key in keys:
            mind = status["reference"]["mind"][key]
            if not mind:
                continue
            print("  %-7s %s" % (key, ", ".join("%s %s (%.2f %s %.1f)" % (
                m, "FLAGS it" if mind[m] < THRESHOLD[m] else "does not", mind[m],
                "<" if mind[m] < THRESHOLD[m] else ">=", THRESHOLD[m]) for m in THRESHOLD if m in mind)))
        print()
        print("--- separability from the reference (%s): per-centroid minimum distance, ours/reference ---" %
              " + ".join(names))
        for name, recs in loaded.items():
            if name in names:
                continue
            for key in keys:
                ours, theirs = min_dist(recs, key), min_dist(ref, key)
                if ours is None:
                    continue
                if key == "tuned":  # like for like only: the reference tuned at the same overhead
                    ov = {r["tuned"]["overhead"] for r in recs + ref if "tuned" in r}
                    if theirs is None or len(ov) != 1:
                        print("  %-10s %-7s %-32s %s" % (name, key, "n/a", "reference not tuned at this overhead"))
                        continue
                verdict, text = separation(ours, theirs)
                status[name].setdefault("separation", {})[key] = dict(verdict=verdict, ours=ours, reference=theirs)
                print("  %-10s %-7s %-32s %s" % (name, key, verdict, text))
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(status, fh, indent=1)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("score")
    s.add_argument("--limits", default="25,255")
    s.add_argument("--overhead", help="TCP:UDP per-packet overhead for the tuned scoring")
    s.add_argument("--ack", type=int, default=52, help="inner pure-ACK IP length ignored by the tuned scoring")
    s.add_argument("--phases")
    s.add_argument("--min-pkts", type=int, default=4)
    s.add_argument("--json")
    s.add_argument("files", nargs="+")
    c = sub.add_parser("calibrate")
    c.add_argument("file")
    c.add_argument("t0")
    c.add_argument("t1")
    c.add_argument("inner")
    r = sub.add_parser("report")
    r.add_argument("--json")
    r.add_argument("--reference", help="comma-separated spec NAMEs of plain-HTTPS controls; every other NAME "
                   "is compared with the closest of them, per centroid")
    r.add_argument("rundir")
    r.add_argument("specs", nargs="+")
    args = ap.parse_args()
    dict(score=cmd_score, calibrate=cmd_calibrate, report=cmd_report)[args.cmd](args)


if __name__ == "__main__":
    main()
