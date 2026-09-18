# testing/perf — CPU and memory cost of the tunnel

What it answers: at a given line rate, how much CPU and how much RAM does
`tincd` need, and how does the hardened tincstack build compare with upstream
tinc 1.1pre18.

    sh testing/perf/bench.sh [core-image] [baseline-image]

Env: `RATE` (100M), `SECONDS_RUN` (30), `REPEATS` (3), `CPUSET` (0-3),
`ARMS` (`baseline plain sf obfs`), `MODE` (`udp` | `tcp`), `DGRAM` (1300).
Output is CSV on stdout; `summarise.py` turns it into medians and spreads.

    sh testing/perf/bench.sh > /tmp/bench.csv
    python3 testing/perf/summarise.py /tmp/bench.csv

## How it is set up, and why

Both daemons live in **one image** (the NAT-lab image: tincd under test at
`/usr/local/sbin`, upstream at `/opt/baseline/sbin`) and run in **one
privileged container** in two network namespaces joined by a veth pair. No NAT,
no shaping, no docker bridge. The arms therefore differ in the tincd binary and
in the `PreferredTransports` lines, and in nothing else: same kernel, same
OpenSSL, same config file format (classic `tinc.conf`, which both accept), same
keys layout.

* **CPU** is `utime + stime` from `/proc/<pid>/stat`, read immediately before
  and after the transfer. Not `docker stats`: a sampler cannot integrate a 30 s
  window accurately and mixes in the harness's own work.
* **Memory** is `VmHWM` from `/proc/<pid>/status` — peak resident, because the
  question "will this fit on the router" is about the peak.
* Both daemons run at `-d0`. Logging is not free and the arms must not differ
  in how much of it they do.
* The container is pinned to a fixed `cpuset` so that foreign load moves all
  arms together rather than one of them.
* Arms are interleaved (all four, then all four again), never batched, so a
  slow patch of the host cannot land on one arm only.

## Two traps this harness exists to avoid

**Do not compare CPU under a TCP load.** TCP does not hold the packet count
still: the tun device coalesces segments, so the daemon can see half as many,
twice as large reads on one run as on the next. Measured that way one arm came
out at 23.7 %, 10.6 % and 23.9 % of a core across three runs — a spread wider
than the difference being looked for, and in the wrong direction. The default
load is therefore UDP with a fixed datagram size, and the **packet count is
printed with every row** so a CPU figure can always be checked against the work
that produced it. `MODE=tcp` is still available for a throughput question.

**Do not read a difference smaller than the host's own noise.** On a machine
with other containers running, repeats of the *same* arm varied by 70 % of their
median. `summarise.py` prints that spread next to the numbers on purpose. If the
arms differ by less than it, the honest answer is "not resolvable here", and the
fix is more repeats or a quiet machine, not a bolder claim.

## Measured, 2026-09-18 — 100 Mbit/s, i9-10900K

`results/2026-09-18-100mbit-a.csv` (12 repeats, 4 arms) and
`-b.csv` (14 repeats, 5 arms), `tincstack/core:sf5` (master 3bff008) against
upstream tinc 1.1pre18. UDP load, 1300-byte datagrams, 0.433 Mpkt per 45 s run,
both directions counted, `-d0`, cpuset 0-3.

Per node, at 100 Mbit/s:

| arm | CPU, % of one core | peak RSS | vs upstream (26 paired repeats) |
|---|---|---|---|
| upstream 1.1pre18 (-O2) | 23.3 | 6.8 MB | reference |
| upstream 1.1pre18 (-O3) | 23.3 | 6.8 MB | -0.1 %, not significant |
| tincstack, `plain` | 22.0 | 11.9 MB | **-12.0 %** [-15.1, -4.0], p = 0.009 |
| tincstack, `sf` | 21.8 | 11.8 MB | **-8.9 %** [-15.8, -4.9], p = 0.003 |
| tincstack, `obfs` | 26.4 | 11.8 MB | **+11.9 %** [+5.6, +19.1], p = 0.029 |

Memory is the firm number: **+5 MB per node**, in every one of the 118 runs, no
overlap between the two groups. CPU differences come from the pooled paired
comparison (`paired.py`), not from the single-run column — an unpaired read of
the same data resolves nothing, because the same arm varies by 83 % of its
median between repeats.

Two things this does **not** say. The `-O3` arm exists because the obvious
explanation for "our build is cheaper" was that meson builds release at -O3
while upstream's autotools default is -O2; it isn't -- upstream at -O3 is
indistinguishable from upstream at -O2. And the ~12 % the `plain` path wins has
**no established mechanism**: `recvmmsg` was the first guess and it is in both
binaries (it is upstream's, not ours). An unexplained win is not a claim; it is
a measurement waiting for one.
