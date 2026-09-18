#!/usr/bin/env python3
"""Read a ladder.sh CSV and say where each arm stops keeping up.

The ceiling is reported as the highest offered rate the arm carried with loss
under LOSS_OK (default 1 %), together with the CPU it was using there. The
`none' rows are the control: no daemon, iperf3 straight down the veth. If the
control stops keeping up at the same rate as an arm, the number measured is the
lab's limit and not the daemon's, and this prints that rather than hiding it.
"""
import csv
import statistics
import sys

LOSS_OK = 1.0


def main(path: str) -> int:
    rows = list(csv.DictReader(open(path)))
    arms, rates = [], []
    for r in rows:
        if r["arm"] not in arms:
            arms.append(r["arm"])
        if r["offered"] not in rates:
            rates.append(r["offered"])

    def cell(arm, rate):
        v = [r for r in rows if r["arm"] == arm and r["offered"] == rate]
        if not v:
            return None
        return (
            statistics.median(float(r["mbits"]) for r in v),
            statistics.median(float(r["loss_pct"]) for r in v),
            statistics.median((float(r["cpu_pct_a"]) + float(r["cpu_pct_b"])) / 2 for r in v),
        )

    print("achieved Mbit/s (loss %) [CPU % of one core]\n")
    print(f"{'offered':<10}" + "".join(f"{a:>24}" for a in arms))
    for rate in rates:
        line = f"{rate:<10}"
        for a in arms:
            c = cell(a, rate)
            line += "".ljust(24) if c is None else f"{c[0]:>10.0f} ({c[1]:4.1f}%) [{c[2]:5.1f}]".rjust(24)
        print(line)

    print("\nceiling: highest offered rate carried with loss under "
          f"{LOSS_OK:.0f} %")
    ctrl_ceiling = None
    for a in arms:
        best, cpu = None, None
        for rate in rates:
            c = cell(a, rate)
            if c and c[1] < LOSS_OK:
                best, cpu = rate, c[2]
        if a == "none":
            ctrl_ceiling = best
            print(f"  {a:<12} {str(best):>7}   (control: the lab itself, no daemon)")
        else:
            note = ""
            if best is not None and best == ctrl_ceiling:
                note = "  <-- equals the control: this is the LAB's limit, not the daemon's"
            if best == rates[-1]:
                note = note or "  <-- never fell over; the ladder does not reach its ceiling"
            print(f"  {a:<12} {str(best):>7}   at {cpu:5.1f} % of a core{note}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
