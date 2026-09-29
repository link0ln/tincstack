# Junk-packet DoS cost (T1e), 2026-09-30

`testing/perf/junk-cost-test.sh`, `CORE_IMAGE=tincstack/core:t1e` (this tree),
`CONTROL=1`, `NLIST="1 4 16 64"`, `RATELIST="15000 auto"`, `DURATION=8`,
`REPEATS=3`. One vCPU host. Verdict lines in `junk-cost.report.txt`; medians in
`medians.txt`; every row in `junk-cost.csv`.

## Question

Can an attacker who floods a node's UDP port with unauthenticated junk make
`tincd` spend CPU in proportion to how hard they flood, or to how many peers the
node knows? For obfs / DirectSeal an unknown-source datagram reaches the
cold-start classifier (`obfs_udp_try`), which decides with a keyed check whether
it belongs to any known peer. A naive handler would key-check all N peers per
junk datagram — O(N) per packet, a DoS lever. tincstack caps that scan at a
per-second budget (`OBFS_SCAN_PER_SEC`..`OBFS_SCAN_MAX`, obfs.c) with a
round-robin cursor.

## Result

CPU µs per junk packet (median of 3), and flood-window CPU %:

| build | rate | N=1 | N=4 | N=16 | N=64 |
|---|---|---|---|---|---|
| shipped   | 15000 pps | 6.08 / 9 % | 6.75 / 10 % | 7.67 / 12 % | 7.50 / 11 % |
| controlON | 15000 pps | 5.08 / 8 % | 8.33 / 12 % | 10.92 / 16 % | **23.25 / 35 %** |
| shipped   | auto (max) | 4.25 / 55 % | 5.38 / 53 % | 5.71 / 52 % | 4.79 / 65 % |
| controlON | auto (max) | 4.39 / 56 % | 4.49 / 62 % | 6.97 / 59 % | 9.49 / **91 %** |

- **shipped is bounded in N** at both rates: 6.08 → 7.50 µs/pkt at 15000 pps
  (1.23×), 4.25 → 4.79 at auto (1.13×). No O(N)-per-packet lever. The per-second
  scan budget means the keyed work does not grow with the flood.
- **controlON** (the O(N) build) proves the meter is not blind: at the
  sub-saturation rate its per-packet cost rises 4.6× with N (5.08 → 23.25); at
  the max rate it pegs the core to 91 % where the shipped build sits at 65 %.

## Why two rates

A max-rate flood saturates one core, so the kernel drops junk before `tincd`
sees it: an O(N) handler then shows as CPU near 100 % with only a modest
per-packet rise (controlON auto: 4.39 → 9.49 µs/pkt, but CPU 56 → 91 %), not a
clean N× per-packet blow-up. The 15000 pps run (~7–35 % CPU, no drops) shows the
O(N) cost per packet unmasked. The first 2026-09-30 run used only `auto` and a
naive ">3× per packet" control assertion; under saturation that read as
"meter may be broken" (control rose only 1.83×). The lesson is recorded in the
harness: judge an O(N) DoS lever by per-packet cost at a sub-saturation rate,
or by CPU saturation at max rate — not by per-packet cost at max rate.

## Positive-control build

`tincstack/core-junk-on:t1e` is compiled from a copy of `core/` with the
per-second scan budget neutered (every junk datagram scans the whole node
tree). The shipped source is not modified. Image ids in `images.txt`.
