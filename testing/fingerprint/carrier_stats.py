#!/usr/bin/env python3
"""Reduce carrier-traffic-audit.sh's captures: TLS record sizes, QUIC datagram
sizes and idle timing per phase, ours next to curl/nginx.

Inputs: phases.tsv (name, epoch), the founder's and nginx's tshark field dumps
(time, src, dst, ip proto, udp length, tcp len, TLS content types, TLS record
lengths, QUIC header forms, FIN, RST; multi-valued fields comma-joined).
Direction is "S>C" (server/founder to client/leaf) or "C>S".

Standard library only. Usage: carrier_stats.py phases.tsv f.tsv n.tsv <F> <L> <N>
"""
import collections
import statistics
import sys

phases_tsv, f_tsv, n_tsv, F, L, N = sys.argv[1:7]
marks = sorted(((l.split("\t")[0], float(l.split("\t")[1])) for l in open(phases_tsv)), key=lambda x: x[1])


def phase_of(t):
    cur = "pre"
    for name, mt in marks:
        if t >= mt:
            cur = name
    return cur


def load(path, server):
    out = []
    for line in open(path):
        f = line.rstrip("\n").split("\t")
        f += [""] * (13 - len(f))
        t, src, dst, proto, ulen, tlen, ctypes, rlens, forms, fin, rst, tports, uports = f[:13]
        ports = {int(x) for x in (tports + "," + uports).split(",") if x}
        if server not in (src, dst):
            continue
        d = "S>C" if src == server else "C>S"
        recs = []
        if rlens:
            # TLS 1.3 hides the content type (every protected record says 23 in
            # tls.record.opaque_type, and tls.record.content_type lists only the
            # clear ones), so every record length counts; the handshake's few
            # records fall in the handshake phase, not in the ones reported.
            recs = [(23, int(r)) for r in rlens.split(",")]
        out.append(dict(t=float(t), d=d, peer=dst if d == "S>C" else src, proto=int(proto or 0),
                        udp=int(ulen) - 8 if ulen else None, tcp=int(tlen) if tlen else 0, recs=recs,
                        long=("1" in forms.split(",")) if forms else False, fin=fin == "1", rst=rst == "1",
                        ph=phase_of(float(t)), p655=655 in ports))
    return out


allours = [p for p in load(f_tsv, F) if p["peer"] == L]
ours = [p for p in allours if not p["p655"]]
ref = load(n_tsv, N)


def q(v, p):
    v = sorted(v)
    return v[min(len(v) - 1, int(p * (len(v) - 1) + 0.5))] if v else 0


def dist(v, top=6):
    if not v:
        return "n=0"
    c = collections.Counter(v)
    return "n=%d median %d p10 %d p90 %d max %d distinct %d; top %s" % (
        len(v), statistics.median(v), q(v, 0.1), q(v, 0.9), max(v), len(c),
        ", ".join("%d x%d" % kv for kv in c.most_common(top)))


def buckets(v, edges=(100, 300, 600, 1000, 1200, 1500, 4096, 16000, 16500)):
    if not v:
        return ""
    out, lo = [], 0
    for e in edges:
        k = sum(1 for x in v if lo <= x < e)
        out.append("<%d:%.0f%%" % (e, 100.0 * k / len(v)))
        lo = e
    return " ".join(out)


def report(label, pk, phase):
    sel = [p for p in pk if p["ph"] == phase]
    if not sel:
        print("%-22s (no packets)" % label)
        return
    dur = sel[-1]["t"] - sel[0]["t"]
    for d in ("S>C", "C>S"):
        s = [p for p in sel if p["d"] == d]
        tls = [r for p in s for c, r in p["recs"] if c == 23]
        udp = [p["udp"] for p in s if p["proto"] == 17 and p["udp"] is not None]
        byts = sum((p["udp"] or 0) + p["tcp"] for p in s)
        print("%-22s %s %6d pkts %9d B in %6.1f s" % (label, d, len(s), byts, dur))
        if tls:
            print("    TLS records: %s" % dist(tls))
            print("    buckets: %s" % buckets(tls))
        if udp:
            print("    UDP payloads: %s" % dist(udp))
            print("    buckets: %s" % buckets(udp))


print("== bulk transfers: our tunnel vs curl <-> nginx ==")
for carrier, rname in (("https", "h1"), ("quic", "h3")):
    for what in ("down", "up"):
        report("ours %s %s" % (carrier, what), ours, "%s-%s" % (carrier, what))
        report("ref %s %s" % (rname, what), ref, "ref-%s-%s" % (rname, what))
    print()

print("== 20 pings at 1 s through the tunnel ==")
for carrier in ("https", "quic"):
    report("ours %s ping" % carrier, ours, "%s-ping" % carrier)
print()


def idle(label, pk, phase):
    sel = [p for p in pk if p["ph"] == phase and (p["udp"] or p["tcp"] or p["fin"] or p["rst"])]
    a = [t for n, t in marks if n == phase]
    if not a:
        return
    a = a[0]
    print("%s: %d packets with payload/FIN/RST" % (label, len(sel)))
    print("  " + " ".join("%.1f%s%s%s" % (p["t"] - a, "<" if p["d"] == "S>C" else ">",
                                          (p["udp"] if p["proto"] == 17 else p["tcp"]),
                                          "F" if p["fin"] else "R" if p["rst"] else "") for p in sel[:60]))
    bursts = []
    for p in sel:
        if not bursts or p["t"] - bursts[-1][-1]["t"] > 0.5:
            bursts.append([p])
        else:
            bursts[-1].append(p)
    st = [b[0]["t"] - a for b in bursts]
    gaps = [y - x for x, y in zip(st, st[1:])]
    print("  %d bursts at %s s" % (len(bursts), ", ".join("%.1f" % s for s in st)))
    if gaps:
        print("  gaps: %s (median %.1f s)" % (", ".join("%.1f" % g for g in gaps), statistics.median(gaps)))
    pat = collections.Counter(tuple((p["d"], p["udp"] if p["proto"] == 17 else p["tcp"]) for p in b) for b in bursts)
    print("  burst patterns: %s" % "; ".join("%s x%d" % (" ".join("%s%d" % x for x in k), c) for k, c in pat.most_common(5)))


print("== idle: after the pings, nothing in the tunnel ==")
for carrier in ("https", "quic"):
    idle("ours %s idle" % carrier, ours, "%s-idle" % carrier)
print()
print("== reference idle: one GET, then nothing (what nginx sends, when it closes) ==")
idle("ref h1 idle (openssl s_client)", ref, "ref-h1-idle")
idle("ref h3 idle (aioquic)", ref, "ref-h3-idle")
print()

print("== anything on tinc's port 655 between the nodes while the carrier ran ==")
for carrier in ("https", "quic"):
    ph = {"%s-%s" % (carrier, x) for x in ("handshake", "down", "up", "ping", "idle")}
    s = [p for p in allours if p["ph"] in ph and p["p655"]]
    print("  %s: %d packets on port 655 (%s)" % (carrier, len(s), dist([(p["udp"] or p["tcp"]) for p in s])))
