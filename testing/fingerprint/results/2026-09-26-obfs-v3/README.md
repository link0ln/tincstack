# obfs frame v3 against the 2026-09-26 wire audit

The same audit as `../2026-09-26-audit/obfs/` (stream F, core `tincstack/core:dev`
at master 7ff64c2, obfs frame v2), re-run unchanged on the frame-v3 core
(`tincstack/core:ww-o`, image id in `obfs-setup.txt`):

    flock /tmp/tincstack-lab.lock env CORE_IMAGE=tincstack/core:ww-o \
        testing/fingerprint/obfs-audit.sh <outdir>

Exit 0, both configurations. The only change to the script is one extra
section: how many captured datagrams a mesh member can unseal with the
bootstrap keys it derives from the two public keys
(`testing/transports/obfs_probe.py`, which parses v2 and v3). Captures and
keys stayed in the run directory, deleted on exit.

## Before (v2) and after (v3)

| measurement | v2 default | v3 default | v2 shaped | v3 shaped | uniform random |
| --- | --- | --- | --- | --- | --- |
| `bytes[8:10] == len - 10` | 9283/9283 | 0/9313 | 0/9315 | 0/9324 | 2^-16 |
| `16 <= bytes[8:10] <= len - 10` | 9283/9283 | 74/9313 (0.79 %) | 9259/9315 | 76/9324 (0.82 %) | (len-25)/65536, ~0.8 % at these sizes |
| `len - 10 - bytes[8:10]` constant | 0 x9283 | none repeats > 4x | 16 x9252 | none repeats > 4x | -- |
| consecutive L>F with equal bytes 0-5 | 4620/4643 | 0/4657 | 4607/4658 | 0/4663 | 0 |
| consecutive F>L with equal bytes 0-5 | 4621/4638 | 0/4654 | 4609/4655 | 0/4659 | 0 |
| distinct bytes 0-1 prefixes L>F | 12 | 4500 of 4658 | 40 | 4497 of 4664 | ~4500 of 4660 |
| byte chi2 positions 0-15 flagged (p < 1e-6) | 0-6, 8, 9 | none | 0-6, 8, 9 | none | none |
| bytes 16.. pooled chi2 p / entropy | 0.87 / 8.0000 | 0.25 / 8.0000 | 0.71 / 8.0000 | 0.59 / 8.0000 | -- |
| bulk (4000 datagrams/direction) distinct sizes | 2 (1087, 151) | 130 | 2 (1103, 167) | 130-131 | -- |
| handshake-phase distinct sizes (n ~ 62/dir) | 12 | 48-52 | 16 | 49-50 | -- |
| handshake positions whose size never varied (7 dials) | 0, 1, 2, 3, 4 | none | 4, 9 | none | none |
| identical first-10 size sequences | 4 of 7 | 1 of 7 | 1 of 7 | 1 of 7 | 1 of 7 |
| idle distinct sizes F>L (n ~ 138) | 11 | 96 | 11 | 85 | -- |
| idle burst gap median | 1.9 s | 2.3 s | 2.0 s | 1.2 s | -- |
| datagrams >= 400 B while idle | 1472 B both ways | 1472 B both ways | same | same | -- |
| answers to 11 stranger probes + 6 replays | none | none | none | none | -- |
| unsealed by a mesh member (bootstrap keys) | not measured | 286/9330, all v3 | not measured | 272/9341, all v3 | -- |

## What it means

- The two 🔴 rules are gone: the length field and the constant prefix are at
  the level of random bytes in both configurations, and no header byte fails
  the chi-square any more.
- Sizes no longer mirror the inner sizes plus a constant: every inner size is
  spread over 65 (steady) or up to 257 (handshake) wire sizes, the dial no
  longer opens with a fixed sequence, and shaping widens the random range
  instead of shifting a histogram.
- Not changed, and not claimed: sizes are still *bounded below* by the inner
  size (a tail is added, never removed), so the bulk histogram is two 65-wide
  bands around the inner sizes rather than noise; datagrams that fill the path
  budget (tinc's PMTU probes, 1472 B here) get no tail unless
  `ObfsTransportHeaderJunkSize` reserves room; and the idle link still bursts
  every few seconds (tinc's UDP discovery and PMTU probing, `net_packet.c`),
  now with random sizes but the same cadence.
- 286 / 272 datagrams (about 3 %) are readable by any mesh member: the frames
  sealed under the bootstrap key before each of the 7 dials' session keys
  existed. That is finding M5-2's documented cold-start window, now measured on
  the wire for the first time; it is also the proof that the probe's v3
  derivation is the daemon's (every one of them unsealed as v3).
