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

## Saturation, 2026-09-18 — where one core runs out

`results/2026-09-18-saturation.csv`, produced by `ladder.sh` (two passes, coarse
then refined around the knee), read by `saturation.py`. Same lab, UDP load,
1300-byte datagrams, 20 s per rung, 2 repeats, cpuset 0-7 — wider than the
fixed-rate bench because near the ceiling iperf3 needs a core at each end, and a
harness starving the daemon it measures would report its own limit as the
daemon's.

**The `none` arm is the control**: no daemon, iperf3 straight down the veth. It
carried 2400 Mbit/s at 0.1 % loss, so nothing below that is the lab's limit and
every ceiling here belongs to a daemon.

Highest offered rate carried with under 1 % loss, and the CPU it took:

| arm | ceiling | CPU there | vs upstream |
|---|---|---|---|
| upstream 1.1pre18 | 1200 Mbit/s | 80 % of a core | reference |
| tincstack `plain` | 1400 Mbit/s | 81 % | +17 % |
| tincstack `sf` | 1400 Mbit/s | 82 % | +17 % |
| tincstack `obfs` | 1000 Mbit/s | 85 % | -17 % |
| tincstack `https` | 1000 Mbit/s | 95 % | -17 % |
| tincstack `quic` | 700 Mbit/s | 83 % | **-42 %** |

The rungs are 100 Mbit/s apart through the knee, so each ceiling is that rung
plus at most one: `quic` was at 1.3 % loss at 800 and 4.0 % at 900, `obfs` at
1.1 % at 1100, `plain` and `sf` at 2.1 % and 1.4 % at 1600.

`https` is the odd one: it never drives a core past ~95 % and still loses
packets, so what limits it is not CPU but the TCP flow underneath — an inner UDP
stream has no congestion control to back off with, and the carrier's socket
absorbs the difference until it cannot.

**A light-load measurement does not predict a ceiling.** From the 100 Mbit/s
numbers this was extrapolated at ~470 Mbit/s for upstream and ~340 for `quic`;
the measured ceilings are 1200 and 700, i.e. the extrapolation was wrong by
2.2-2.6x in the pessimistic direction. At 100 Mbit/s a fixed cost that does not
scale with traffic (event loop, timers, pings, UDP discovery) dominates: upstream
spends 23.7 % of a core there but only 35.2 % at four times the rate. Quote the
ladder for capacity questions and the fixed-rate bench for cost-per-packet ones;
neither substitutes for the other.

## A relay forwarding UDP bursts onto an https link, 2026-09-29

    flock /tmp/tincstack-lab.lock testing/perf/relay-burst-test.sh [outdir]
    CORES="old=<image> new=<image>" DELAY=20ms LIMIT=50mbit RATE=40M SECONDS_RUN=20 ...

Three containers: sender --(UDP, SPTPS)--> relay --(https carrier)--> receiver,
no path between sender and receiver. The relay reads UDP with `recvmmsg()`
(up to 64 packets a call) and forwards them onto the receiver's TCP link in the
same event-loop pass, where `random_early_drop()` discards once more than
`maxoutbufsize / 2` bytes are pending. It is the phone's shape: https to
ruvds2, the exit behind it on quic. Three cores, interleaved, 3 repeats each:
`v052` (writes every append at once: two TLS records per packet, and the
dialler's second record waits for a delayed ACK), `defer` (writes only from
the event loop: one record per pass), `hybrid` (as `defer`, but writes as soon
as `maxoutbufsize / 4` is pending -- what `https.c` does now).

`results/2026-09-29-relay-burst-lan.csv` -- no bottleneck, 10 s per load:

| core | TCP Mbit/s (median, runs) | TCP retransmits (median) | UDP 300M loss % (median) |
|---|---|---|---|
| v052 | 334 (336 / 334 / 245) | 12365 | 0.97 |
| defer | 677 (677 / 711 / 334) | 40680 | 0.04 |
| hybrid | 426 (617 / 408 / 426) | 1159 | 0.11 |

`results/2026-09-29-relay-burst-wan.csv` -- relay <-> receiver 20 ms each way,
50 Mbit/s relay -> receiver (netem), UDP offered 40 Mbit/s (below the
bottleneck), 20 s per load:

| core | TCP Mbit/s (median) | TCP retransmits (median, runs) | UDP 40M loss % (runs) |
|---|---|---|---|
| v052 | 39.5 | 15 (15 / 15 / 15) | 0.06 / 0.06 / 0.06 |
| defer | 41.2 | 94 (94 / 24 / 101) | 0.69 / 0.13 / 0.44 |
| hybrid | 41.1 | 15 (15 / 15 / 15) | 0.00 / 0.00 / 0.00 |

Reading: writing only from the event loop lets a burst pile up past the
early-drop threshold before the first byte leaves, so `defer` loses packets
the link had room for (UDP loss below the bottleneck rate, 6x the TCP
retransmits) -- on a LAN it still "wins" because it makes the fewest,
largest writes. `hybrid` keeps the coalescing (one record per write pass,
never two per packet) without that loss; on the LAN it is slower than
`defer` (more, smaller writes -- inferred, CPU was not sampled in this test)
and still faster than `v052`; on the shaped link it is the best or equal best
on every column. Images:
`tincstack/core:t1a-https` (defer) and `:t1a-https2` (hybrid) were built from
this tree's `https.c` at the two stages; `v052` is `ghcr.io/link0ln/tincstack/core:v0.5.2`.

## Junk-packet DoS cost, 2026-09-30 (T1e)

    flock /tmp/tincstack-lab.lock testing/perf/junk-cost-test.sh [outdir]

Env: `CORE_IMAGE`, `CONTROL` (1 = also build+run the O(N) positive control),
`NLIST` (peer counts, default `1 4 16 64`), `RATELIST` (default `15000 auto`:
one sub-saturation numeric rate and one max-rate run; `auto` alone works too),
`DURATION` (8 s), `REPEATS` (3).

What it answers: can an attacker who floods a node's UDP port with
unauthenticated junk make the daemon spend CPU in proportion to how hard they
flood, or to how many peers the node knows? For the obfs / DirectSeal carrier
an unknown-source datagram reaches the cold-start classifier
(`obfs_udp_try`), which decides with a keyed check whether it belongs to any
known peer. A naive version would key-check every one of the N peers on every
junk datagram — O(N) per packet, a DoS lever. tincstack caps that scan at a
per-second budget (`OBFS_SCAN_PER_SEC`..`OBFS_SCAN_MAX`) with a round-robin
cursor, so the keyed work is bounded per wall-second no matter the flood rate.

How it is set up:

* **Victim.** One `tincd` with obfs in the accept mask (so the cold-start scan
  is live) and **N host records** carrying well-formed random Ed25519 public
  keys — `ecdsa_set_base64_public_key` checks length only and
  `obfs_derive_base` hashes the base64 text, so a random-but-well-formed key
  exercises the full per-peer derivation the scan runs. The peers are never
  live: the junk comes from an unknown address, the exact cold-start path.
* **Attacker.** A python-stdlib UDP sender (throwaway container) sends 1300-byte
  datagrams whose first byte is `< 0x40` (so the classifier routes them to the
  obfs keyed check, not SF and not a QUIC long/short header) for `DURATION`
  seconds, and prints the count it sent.
* **Metric.** `utime+stime` from `/proc/<pid>/stat` over the flood window minus
  an equal idle window, in CPU-microseconds, divided by packets sent →
  **CPU µs per junk packet**, median over repeats. As in `bench.sh`, CPU is
  integrated from `/proc`, never sampled with `docker stats`.
* **Positive control.** A deliberately O(N)-per-packet build is compiled from a
  *copy* of `core/` with the per-second budget neutered (every junk datagram
  scans the whole node tree). It must show CPU rising with N; the shipped build
  must not. The shipped source is never modified.

Two rates, because a max-rate flood **saturates one core**: the kernel then
drops junk before `tincd` sees it, so an O(N) handler shows up as CPU pegged
near 100 % with only a modest per-packet rise, not a clean N× per-packet
blow-up. A **sub-saturation** numeric rate (default 15000 pps, ~7 % CPU, no
drops) shows the O(N) per-packet cost unmasked; the **`auto`** run shows the DoS
lever as CPU saturation.

Assertions: at every rate the shipped build's µs/packet at the largest N is
within 3× of the smallest N (bounded, not O(N)). The meter is proven by the
control build — at the sub-saturation rate its µs/packet more than doubles from
smallest to largest N, and/or at `auto` it pegs the core (≥ 90 %, ≥ 15 points
above the shipped build at the same rate) where the shipped build does not. If
the control never shows a rise, the run fails: an unproven meter makes the
shipped PASS untrustworthy.
