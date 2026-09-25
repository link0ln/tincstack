#!/usr/bin/env python3
"""Summarise post405-timing.sh's raw.tsv.

Per netem condition, protocol and mode: each server's statuses and the
median / p10 / p90 of the time to the answer, measured from the head. Then
how well a prober tells the two apart:

  per-probe   the best single threshold on t_head (chosen on the pooled
              sample, so optimistic for the prober), its accuracy over both
              servers' probes; for post-pause/-authver/-nobody also the
              structural rule "answered before the body was sent / at all"
  statistical AUC = P(listener's t_head > nginx's t_head) (Mann-Whitney):
              0.5 = indistinguishable, 1.0 = every listener probe is slower

Standard library only. Usage: post405_summary.py raw.tsv
"""
import collections
import statistics
import sys

rows = collections.defaultdict(list)
with open(sys.argv[1]) as f:
    next(f)
    for line in f:
        rtt, jit, srv, proto, mode, status, th, tb = line.rstrip("\n").split("\t")
        rows[(int(rtt), int(jit), proto, mode, srv)].append((status, None if th == "-" else float(th), tb != "-"))


def q(v, p):
    v = sorted(v)
    return v[min(len(v) - 1, int(p * (len(v) - 1) + 0.5))]


def auc(a, b):
    """P(x > y) for x in a, y in b, ties count half"""
    if not a or not b:
        return float("nan")
    s = sum(1.0 if x > y else 0.5 if x == y else 0.0 for x in a for y in b)
    return s / (len(a) * len(b))


def best_threshold(a, b):
    """accuracy of the best rule 't > thr => listener' over both samples"""
    best = 0.0
    for thr in sorted(set(a + b)) + [float("-inf")]:
        ok = sum(1 for x in a if x > thr) + sum(1 for y in b if y <= thr)
        best = max(best, ok / (len(a) + len(b)))
    return best


def fmt(v):
    if not v:
        return "-"
    return "%7.1f [%6.1f..%7.1f]" % (statistics.median(v), q(v, 0.1), q(v, 0.9))


conds = sorted({k[:2] for k in rows})
print("POST-405 timing: time from the request head to the answer, ms (median [p10..p90])")
print("per-probe = best single-threshold accuracy (optimistic); structural = answered before the body / at all")
print()
for rtt, jit in conds:
    print("=== RTT %d ms, jitter %d ms ===" % (rtt, jit))
    print("%-3s %-13s %-8s %-26s %-8s %-26s %6s %6s  %s" % (
        "", "mode", "listener", "t_head", "nginx", "t_head", "AUC", "thr", "structural"))
    for proto in ("h3", "h1"):
        for mode in ("get", "post-now", "post-pause", "post-authver", "post-nobody"):
            L = rows.get((rtt, jit, proto, mode, "listener"), [])
            G = rows.get((rtt, jit, proto, mode, "nginx"), [])
            if not L and not G:
                continue
            lt = [t for s, t, _ in L if t is not None]
            gt = [t for s, t, _ in G if t is not None]
            ls = ",".join("%s:%d" % kv for kv in sorted(collections.Counter(s for s, _, _ in L).items()))
            gs = ",".join("%s:%d" % kv for kv in sorted(collections.Counter(s for s, _, _ in G).items()))
            struct = "-"
            if mode in ("post-pause", "post-authver", "post-nobody"):
                # a listener probe is "caught" if it waited for the body (or never
                # answered); an nginx probe is "caught" if it answered on the head
                lw = sum(1 for s, t, b in L if b or t is None)
                ge = sum(1 for s, t, b in G if t is not None and not b)
                struct = "listener waited %d/%d, nginx early %d/%d -> %.0f%%" % (
                    lw, len(L), ge, len(G), 100.0 * (lw + ge) / max(1, len(L) + len(G)))
            a = auc(lt, gt)
            thr = best_threshold(lt, gt) if lt and gt else float("nan")
            print("%-3s %-13s %-8s %-26s %-8s %-26s %6.2f %5.0f%%  %s" % (
                proto, mode, ls, fmt(lt), gs, fmt(gt), a, 100 * thr, struct))
    print()
