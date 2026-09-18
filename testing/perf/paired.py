#!/usr/bin/env python3
"""Paired comparison of bench.sh arms against the first arm.

Arms are interleaved inside each repeat, so repeat number pairs them: arm X and
the reference in round 7 met the same host conditions. Pairing on it removes the
run-to-run variation that swamps an unpaired comparison -- on the measurement
this was written for, the unpaired spread was 34 % while the paired difference
resolved to -13 % with a 95 % CI of 9 points.

Reported per arm: the median paired relative difference, a bootstrap 95 % CI for
it, and an exact two-sided sign test (distribution-free -- with 14 repeats there
is no basis for assuming normality).
"""
import csv
import random
import statistics
import sys
from math import comb


def main(path: str) -> int:
    rows = list(csv.DictReader(open(path)))
    arms: list[str] = []
    for r in rows:
        if r["arm"] not in arms:
            arms.append(r["arm"])

    per: dict[str, list[float]] = {a: [] for a in arms}
    rss: dict[str, list[float]] = {a: [] for a in arms}
    for r in rows:
        per[r["arm"]].append((float(r["norm_a"]) + float(r["norm_b"])) / 2)
        rss[r["arm"]].append((float(r["hwm_kb_a"]) + float(r["hwm_kb_b"])) / 2 / 1024)

    n = min(len(v) for v in per.values())
    ref = arms[0]
    print(f"{n} paired repeats, reference arm: {ref}\n")
    print(f"{'arm':<13}{'work/Mpkt':>11}{'peak RSS':>10}{'vs ref':>10}"
          f"{'95% CI':>18}{'sign test':>22}")

    for a in arms:
        v, med = per[a][:n], statistics.median(per[a][:n])
        mem = statistics.median(rss[a][:n])
        if a == ref:
            print(f"{a:<13}{med:>11.2f}{mem:>9.1f}M{'reference':>10}")
            continue
        rel = [(x - y) / y for x, y in zip(v, per[ref][:n])]
        higher = sum(1 for x in rel if x > 0)
        k = min(higher, n - higher)
        p = min(2 * sum(comb(n, i) for i in range(k + 1)) / 2 ** n, 1.0)
        random.seed(7)
        bs = sorted(statistics.median(random.choices(rel, k=n)) for _ in range(20000))
        lo, hi = bs[int(0.025 * len(bs))], bs[int(0.975 * len(bs))]
        verdict = "significant" if p < 0.05 else "NOT significant"
        print(f"{a:<13}{med:>11.2f}{mem:>9.1f}M{statistics.median(rel):>+10.1%}"
              f"{f'[{lo:+.1%}, {hi:+.1%}]':>18}"
              f"{f'p={p:.4f} {verdict}':>22}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
