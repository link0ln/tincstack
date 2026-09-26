# NAT lab, stream N — 2026-09-26

Images: `tincstack/core:ww-n` / `tincstack/baseline:ww-n` (core master
`7ff64c2`, upstream tinc 1.1pre18), `tincstack/core:ww-n-fix` (+ the flagged
relay fix). Linux 6.8. Analysis: `docs/nat.md`.

| directory | run | what |
|---|---|---|
| `.` (`pair-*`, `laptop/`, `glare/`, `rtt50/`, `validate-nat*`, `matrix-summary.md`) | `ww-n-base` | full matrix both images, laptop both, glare, validate-nat |
| `ext/` | `ww-n-ext` | masqfw/cgnat pairs, quic/https/obfs/IPv6 rows, mesh (+ relay-down), rekey, portmap, punch |
| `capture/` | `ww-n-cap` | peer-to-peer WAN capture + dpi-fingerprint: plain, obfs, quic |
| `tcponly/` | `ww-n-tcponly` | `TCPOnly = yes` through a relay, both images (0 pings) |
| `core-fix/` | `ww-n-fix` | the same with the fix + https 4 pairs + `matrix --quick` |
| `rtt40/`, `rtt40b/`, `rtt40c/` | `ww-n-rtt40*` | poisoned pairs at 40 ms RTT, three runs |

## Matrix vs 2026-09-16 (base run, cell = seconds until direct both ways)

| A x B | core 09-16 | core 09-26 | baseline 09-16 | baseline 09-26 |
|---|---|---|---|---|
| fullcone x fullcone | 6s | 6s | 6s | 12s |
| fullcone x masq | 10s | 6s | 16s | 14s |
| fullcone x portrestricted | 10s | 10s | 12s | 7s |
| fullcone x restricted | 6s | 6s | 12s | 6s |
| fullcone x symmetric | 6s | 10s | 15s | 14s |
| masq x fullcone | 6s | 6s | 7s | 6s |
| masq x masq | relay | relay | relay | relay |
| masq x portrestricted | relay | relay | 12s | relay |
| masq x restricted | 6s | 6s | 12s | 13s |
| masq x symmetric | relay | relay | relay | relay |
| portrestricted x fullcone | 6s | 6s | 12s | 12s |
| portrestricted x masq | relay | relay | relay | relay |
| portrestricted x portrestricted | 10s | 6s | 6s | 12s |
| portrestricted x restricted | 6s | 6s | 12s | 14s |
| portrestricted x symmetric | relay | relay | relay | relay |
| restricted x fullcone | 6s | 8s | 12s | 12s |
| restricted x masq | 7s | 10s | 6s | 6s |
| restricted x portrestricted | 6s | 6s | 12s | 12s |
| restricted x restricted | 6s | 6s | 12s | 6s |
| restricted x symmetric | 6s | 10s | 6s | 24s |
| symmetric x fullcone | 6s | 6s | 18s | 18s |
| symmetric x masq | relay | relay | relay | relay |
| symmetric x portrestricted | relay | relay | relay | relay |
| symmetric x restricted | 6s | 6s | 6s | 18s |
| symmetric x symmetric | relay | relay | relay | relay |
| udpblock x fullcone | tcp | tcp | tcp | tcp |
| udpblock x portrestricted | tcp | tcp | tcp | tcp |
| udpblock x udpblock | tcp | tcp | tcp | tcp |

- 09-16 core: direct 17/25 UDP pairs (68 %), time to direct median 6 s, max 10 s
- 09-16 baseline: direct 18/25 UDP pairs (72 %), time to direct median 12.0 s, max 18 s
- 09-26 core: direct 17/25 UDP pairs (68 %), time to direct median 6 s, max 10 s
- 09-26 baseline: direct 17/25 UDP pairs (68 %), time to direct median 12 s, max 24 s

No verdict changed. The one pair upstream lost (`masq x portrestricted`,
12 s on 09-16, relay now) is a race it wins sometimes (§3.5 of docs/nat.md).

## Key numbers

- validate-nat: 7/7 profiles as declared (`ext/validate-nat*`; masqfw =
  EIM + APDF, port-preserving).
- New profiles, core: `masqfw x masqfw` 4 s, `cgnat x masqfw` 4 s,
  `masqfw x portrestricted` 6 s, `masq x masqfw` 10 s; `cgnat x cgnat`,
  `cgnat x masq`, `masqfw x symmetric` relay.
- Laptop: core PASS (4-8 s), upstream FAIL (mapping-dropped never recovers).
  Glare: core clean 1 s, upstream 90 s (rtt 0) / 12 s (rtt 50).
- Carriers (core): quic kills direct for port-changing pairs
  (`restricted x restricted`, `fullcone x fullcone` relay); https through a
  relay: 0 pings on 4/4 before the fix, 4/4 PASS after; `TCPOnly = yes`
  through a relay: 0 pings on upstream and core, ok with the fix.
- Capture: plain 111/181 datagrams zero-prefixed + 51-byte probes; obfs
  56/417 + probes; quic 97/304 + constant source id + probes.
- IPv6 both sides: `masq x masq`, `symmetric x symmetric` direct in 4 s.
  Only one side dual-stack: `masq x restricted` relay (regression vs IPv4).
- rtt 40, three runs: core `masq x masq` 0/3, `masq x portrestricted` 2/3,
  `cgnat x cgnat` 2/3; upstream 1/3, 0/3, 1/3.
- Punch harness (`ext/punch/summary.md`): uncoordinated rtt 0 0/3, 2/3, 0/3
  on the same pairs; `--sync` 3/3, 3/3, 2/3; rtt 40 3/3 each.
- Mesh 5 NATed nodes: core 8/10 and 7/10 direct in 6-10 s, relay 2-7 pkt/s;
  upstream 7/10 and 8/10 in 9-61 s, relay 13-18 pkt/s. Relay down 20 s:
  core default 0 lost pings; core `UdpMetaFallback = no` and upstream
  0 replies, 30.5-30.8 s gap on direct *and* relayed pairs.
- Rekey (KeyExpire 20 s, 120 s): upstream 30.7 % of packets relayed, core
  without `sf` 8.6 %, core default 0 %.

Gateway conntrack dumps of the `+spray848` punch rows are not committed
(~850 entries each, 22 files); every other punch row keeps its first-trial dumps.
