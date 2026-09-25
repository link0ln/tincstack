#!/usr/bin/env python3
"""Reduce an obfs capture (obfs-audit.sh) to the numbers that decide whether
it looks like uniformly random UDP.

Input: tshark fields (time, src, sport, dst, dport, udp length, payload hex)
and the phase marks (config, phase, epoch). Output, per phase and direction:
sizes; per handshake: the size sequence; over every tunnel datagram: the
structural rules a stateless or per-flow classifier could use (the plaintext
length field, the whitened counter's constant prefix), per-position byte
chi-square against uniform, and the idle timing.

Standard library only. Usage: obfs_stats.py udp.tsv phases.tsv <founder ip> <leaf ip>
"""
import collections
import math
import statistics
import sys

udp_tsv, phases_tsv, F, L = sys.argv[1:5]

pk = []  # (t, dir, payload bytes, src, dst)
for line in open(udp_tsv):
    f = line.rstrip("\n").split("\t")
    if len(f) < 7:
        continue
    t, src, sport, dst, dport, ulen, hx = f[:7]
    if not hx:
        continue
    d = "L>F" if (src, dst) == (L, F) else "F>L" if (src, dst) == (F, L) else "%s>%s" % (src, dst)
    pk.append((float(t), d, bytes.fromhex(hx.replace(":", "")), src, dst))
pk.sort(key=lambda x: x[0])

marks = []
for line in open(phases_tsv):
    cfg, name, t = line.rstrip("\n").split("\t")
    marks.append((name, float(t)))
marks.sort(key=lambda x: x[1])


def phase_of(t):
    cur = "pre"
    for name, mt in marks:
        if t >= mt:
            cur = name
    return cur


tunnel = [p for p in pk if p[1] in ("L>F", "F>L")]
print("obfs capture: %d UDP datagrams, %d between founder and leaf" % (len(pk), len(tunnel)))
print()

# ---- sizes per phase -----------------------------------------------------------------------------
print("== sizes per phase (payload bytes; top sizes with counts) ==")
by = collections.defaultdict(list)
for t, d, b, _, _ in pk:
    ph = phase_of(t)
    ph = "restarts" if ph.startswith("restart") else ph
    by[(ph, d)].append(len(b))
order = ["handshake", "ping", "bulk", "idle", "restarts", "probes", "replay", "end"]
for ph in order:
    for d in sorted({k[1] for k in by if k[0] == ph}):
        v = by[(ph, d)]
        c = collections.Counter(v)
        print("%-9s %-24s n=%-5d distinct=%-4d top: %s" % (
            ph, d, len(v), len(c), ", ".join("%d x%d" % kv for kv in c.most_common(6))))
print()

# ---- handshakes ----------------------------------------------------------------------------------
print("== handshakes: the first 14 datagrams after each dial (dir size +ms) ==")
starts = [(n, t) for n, t in marks if n == "handshake" or n.startswith("restart")]
seqs = []
for i, (name, t0) in enumerate(starts):
    t_end = starts[i + 1][1] if i + 1 < len(starts) else min([t for n, t in marks if t > t0] + [float("inf")])
    hs = [p for p in tunnel if t0 <= p[0] < t_end][:14]
    if not hs:
        print("%-10s (nothing captured)" % name)
        continue
    base = hs[0][0]
    seq = tuple((p[1], len(p[2])) for p in hs)
    seqs.append(seq)
    print("%-10s %s" % (name, " ".join("%s%d+%.0f" % ("<" if p[1] == "F>L" else ">", len(p[2]), 1000 * (p[0] - base)) for p in hs)))
if seqs:
    c = collections.Counter(tuple(s[:10]) for s in seqs)
    print("identical first-10 size sequences: %d of %d handshakes share the most common one" % (c.most_common(1)[0][1], len(seqs)))
    pos = collections.defaultdict(collections.Counter)
    for s in seqs:
        for i, x in enumerate(s[:10]):
            pos[i][x] += 1
    fixed = [i for i in range(10) if pos[i] and pos[i].most_common(1)[0][1] == len(seqs)]
    print("handshake positions whose (direction, size) never varied: %s" % (fixed or "none"))
print()

# ---- structural rules ----------------------------------------------------------------------------
print("== structural rules over the %d tunnel datagrams ==" % len(tunnel))
exact = at_least = 0
exact4 = 0
for _, _, b, _, _ in tunnel:
    if len(b) >= 10:
        clen = (b[8] << 8) | b[9]
        exact += clen == len(b) - 10
        at_least += 16 <= clen <= len(b) - 10
    if len(b) >= 14:
        exact4 += ((b[12] << 8) | b[13]) == len(b) - 14
n = max(1, len(tunnel))
print("bytes 8-9 (big-endian) == payload length - 10  : %d/%d = %.4f  (uniform random: %.6f)" % (exact, len(tunnel), exact / n, 2 ** -16))
print("16 <= bytes 8-9 <= payload length - 10          : %d/%d = %.4f  (uniform random, 1000 B: %.4f)" % (at_least, len(tunnel), at_least / n, 975 / 65536))
print("bytes 12-13 == payload length - 14 (magic form) : %d/%d = %.4f" % (exact4, len(tunnel), exact4 / n))
tails = collections.Counter(len(b) - 10 - ((b[8] << 8) | b[9]) for _, _, b, _, _ in tunnel if len(b) >= 10)
print("payload length - 10 - bytes 8-9 (the tail junk, if bytes 8-9 are the length): %s" % (
    ", ".join("%d x%d" % kv for kv in tails.most_common(6))))
big = [(phase_of(t), d, len(b)) for t, d, b, _, _ in tunnel
       if len(b) >= 400 and phase_of(t) not in ("ping", "bulk")]
print("datagrams >= 400 B outside the ping/bulk phases (PMTU probes?): %d: %s" % (
    len(big), ", ".join("%s %s %d" % x for x in big[:30])))
for d in ("L>F", "F>L"):
    v = [p[2] for p in tunnel if p[1] == d and len(p[2]) >= 8]
    if len(v) < 2:
        continue
    same6 = sum(1 for a, b in zip(v, v[1:]) if a[:6] == b[:6])
    same2 = sum(1 for a, b in zip(v, v[1:]) if a[:2] == b[:2])
    pref2 = collections.Counter(x[:2].hex() for x in v)
    pref6 = collections.Counter(x[:6].hex() for x in v)
    print("%s: consecutive datagrams with equal bytes 0-5: %d/%d; equal bytes 0-1: %d/%d; distinct 0-1 prefixes: %d, distinct 0-5 prefixes: %d (random: every pair differs)" % (
        d, same6, len(v) - 1, same2, len(v) - 1, len(pref2), len(pref6)))
    print("    most common bytes 0-5: %s" % ", ".join("%s x%d" % kv for kv in pref6.most_common(4)))
print()


# ---- byte statistics -----------------------------------------------------------------------------
def chi2_p(x, k):
    """upper tail of chi-square with k dof (Wilson-Hilferty)"""
    z = ((x / k) ** (1 / 3) - (1 - 2 / (9 * k))) / math.sqrt(2 / (9 * k))
    return 0.5 * math.erfc(z / math.sqrt(2))


def chi2(counts, total):
    e = total / 256
    return sum((counts.get(v, 0) - e) ** 2 / e for v in range(256))


print("== per-position byte chi-square vs uniform (255 dof; p < 1e-6 is a tell) ==")
v = [p[2] for p in tunnel if len(p[2]) >= 32]
print("sample: %d tunnel datagrams of >= 32 bytes (expected %.1f per byte value)" % (len(v), len(v) / 256))
for i in range(16):
    c = collections.Counter(x[i] for x in v)
    x2 = chi2(c, len(v))
    top = ", ".join("%02x x%d" % kv for kv in c.most_common(3))
    print("  byte %2d: chi2 %10.1f  p %.2e  %s  top %s" % (i, x2, chi2_p(x2, 255), "TELL" if chi2_p(x2, 255) < 1e-6 else "ok  ", top))
rest = collections.Counter()
tot = 0
for x in v:
    rest.update(x[16:])
    tot += len(x) - 16
x2 = chi2(rest, tot)
print("  bytes 16..end pooled (%d bytes): chi2 %.1f p %.2e" % (tot, x2, chi2_p(x2, 255)))
ent = -sum((c / tot) * math.log2(c / tot) for c in rest.values()) if tot else 0
print("  their Shannon entropy: %.4f bits/byte" % ent)
print()

# ---- timing --------------------------------------------------------------------------------------
print("== idle phase: every datagram (offset s, dir, size) and the gaps between them ==")
t_idle = [t for n, t in marks if n == "idle"]
t_next = [t for n, t in marks if n.startswith("restart") or n == "probes"]
if t_idle:
    a = t_idle[0]
    b = min([t for t in t_next if t > a] + [float("inf")])
    idle = [p for p in tunnel if a <= p[0] < b]
    print("  %d datagrams in %.0f s" % (len(idle), (b - a) if b != float("inf") else 0))
    print("  " + " ".join("%.1f%s%d" % (p[0] - a, "<" if p[1] == "F>L" else ">", len(p[2])) for p in idle[:80]))
    bursts = []
    for p in idle:
        if not bursts or p[0] - bursts[-1][-1][0] > 0.5:
            bursts.append([p])
        else:
            bursts[-1].append(p)
    starts_ = [bu[0][0] - a for bu in bursts]
    gaps = [y - x for x, y in zip(starts_, starts_[1:])]
    print("  %d bursts (datagrams < 0.5 s apart), starting at %s s" % (len(bursts), ", ".join("%.1f" % s for s in starts_)))
    if gaps:
        print("  gaps between bursts: %s s (median %.1f)" % (", ".join("%.1f" % g for g in gaps), statistics.median(gaps)))
    sizes = collections.Counter(tuple(sorted(len(p[2]) for p in bu)) for bu in bursts)
    print("  burst size patterns: %s" % "; ".join("%s x%d" % (list(k), c) for k, c in sizes.most_common(6)))
print()

print("== answers to strangers (datagrams from the founder to anyone but the leaf) ==")
other = [p for p in pk if p[3] == F and p[4] != L]
print("  %d datagrams: %s" % (len(other), ", ".join("%s %d B at %s" % (p[4], len(p[2]), phase_of(p[0])) for p in other[:20]) or "none"))
