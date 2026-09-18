#!/usr/bin/env python3
"""Summarise bench.sh CSV: per-arm median, min and max, and the spread.

Medians, not means: the host this runs on is not quiet, and a single contended
repeat moves a mean far more than it moves a median. The spread is printed
alongside so that a difference smaller than the noise cannot be read as a
result.
"""
import csv
import statistics
import sys


def main(path: str) -> int:
    rows = list(csv.DictReader(open(path)))
    if not rows:
        print("no rows", file=sys.stderr)
        return 1

    arms = []
    for r in rows:
        if r["arm"] not in arms:
            arms.append(r["arm"])

    def col(arm, name):
        return [float(r[name]) for r in rows if r["arm"] == arm]

    n = len(col(arms[0], "cpu_pct_a"))
    print(f"{n} repeats, {rows[0]['mode']} load, "
          f"{rows[0]['mbits']} Mbit/s offered, {rows[0]['mpkts']} Mpkt per run\n")

    hdr = (f"{'arm':<9}{'CPU% of one core':<26}{'peak RSS MB':<13}"
           f"{'work units / Mpkt (calibrated)':<32}")
    print(hdr)
    print("-" * len(hdr))
    base = None
    for arm in arms:
        cpu = col(arm, "cpu_pct_a") + col(arm, "cpu_pct_b")
        rss = col(arm, "hwm_kb_a") + col(arm, "hwm_kb_b")
        # The calibrated column is the one to compare on: raw CPU seconds are
        # not a unit of work on a host whose cores change clock between runs.
        norm = col(arm, "norm_a") + col(arm, "norm_b")
        med = statistics.median(norm)
        if base is None:
            base = med
        rel = f"  (x{med / base:.2f})" if arm != arms[0] else "  (reference)"
        print(f"{arm:<9}"
              f"{statistics.median(cpu):5.1f}  [{min(cpu):4.1f}-{max(cpu):4.1f}]      "
              f"{statistics.median(rss)/1024:6.1f}       "
              f"{med:6.2f}  [{min(norm):5.2f}-{max(norm):5.2f}]{rel}")

    def spread(arm, name):
        v = col(arm, name) + col(arm, name.replace("_a", "_b"))
        return (max(v) - min(v)) / statistics.median(v)

    print(f"\nspread of the reference arm, raw CPU%: {spread(arms[0], 'cpu_pct_a'):.0%}"
          f"; calibrated: {spread(arms[0], 'norm_a'):.0%}."
          "\nCompare arms on the calibrated column, and treat a difference smaller"
          "\nthan its spread as not resolvable on this host.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "-"))
