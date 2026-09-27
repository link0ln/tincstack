# N2 final regression (image tincstack/core:ww-n2 = 65010402a900, built from b1c71d7)

`regression.txt` is the machine record (exit code, seconds including time
waiting for the shared lab lock, finish time). Every step ran under
`flock /tmp/tincstack-lab.lock`, one lock per step. Node logs stay in
`results/run/` (ignored); the curated subset is under `runs/`, `../punch/`
and `../capture-final/`.

| step | exit | what it shows |
|---|---|---|
| `obfs-test.sh` | 0 | incl. PART 8 churn: 0 of 754 steady frames under the bootstrap key, 0 stuck |
| `quic-carrier-test.sh` (+ `ww-n2-noquic`) | 0 | |
| `https-carrier-test.sh` | 0 | |
| `quic-loss-test.sh` (`PROBER_IMAGE=tincstack/fp-prober:ww-n2`) | 0 | 2000/2000 under 10 % loss, no ASan report |
| `mixed-version-test.sh`, `OLD_IMAGE=ww-n2-base` | 0 | then again with the wire check on: `mixed-version-wire.txt` |
| `mixed-version-test.sh`, `OLD_IMAGE=ww-n2-pre-deb13` | 0 | same |
| `same-nat-meta-test.sh` | 0 | UdpMetaFallback over the sealed path |
| `obfs-confirmed-peer-test.sh` | 0 | switch of a running network to obfs |
| `lab.sh laptop --image core` | 0 | |
| `lab.sh glare --image core` | 0 | key in 1 s, 0 SPTPS restarts |
| `lab.sh matrix --quick --image core` | 0 | 6/6 PASS, masqfw/masqfw direct 4 s |
| `lab.sh matrix --image core` | 0 | 28/28 PASS, 19/25 direct, median 6 s, max 8 s |
| `matrix --transport obfs`, 6 pairs | 0 | 6/6 direct and ping ok (obfs_close race fired once, 1 unreadable datagram) |
| `matrix --transport quic`, 6 pairs | 0 | 6/6 direct, 4-6 s |
| `matrix --transport https`, 6 pairs | 0 | 6/6 PASS (TCP only, relayed) |
| `lab.sh rekey restricted symmetric --keyexpire 20 --node-conf UdpMetaFallback=no` | 0 | core 0/0 resets, 0/632 relayed; upstream 38/33, 21.7 % |
| `--capture` rows plain/obfs/quic/https | 0 | `../capture-final/`, docs/nat.md 5.3 |
| punch, 4 relay-only pairs, rtt 40 x5, rtt 0 x3 | 0 (all 8) | `../punch/ww-n2-fin2-punch-*`, docs/nat.md 9.3 |

Outside the lock: unit tests (meson, 17 OK, 2 expected fail, 0 fail),
`test/fuzz/run.sh check` (7/7 ok, `IMAGE=tincstack/fuzz:ww-n2`), `make lint`
0, gitleaks over the tracked tree 0 leaks.

Substitute images (the brief's were pruned from the host before this run):
`tincstack/baseline:ws-f` -> `tincstack/baseline:ww-n2`,
`tincstack/core:pre-deb13` -> `tincstack/core:ww-n2-pre-deb13`,
`tincstack/core:ww-a-noquic` -> `tincstack/core:ww-n2-noquic`,
`tincstack/fp-prober:ww-f` -> `tincstack/fp-prober:ww-n2`. Built in this
stream: `ww-n2-base` from `git archive 11e02ef core` (pre-N2 master);
`ww-n2-pre-deb13` from a kept copy of the pre-Debian-13 core source;
`ww-n2-noquic` from the branch at item 3 with `QUIC=disabled` (only its
lack of quic matters to the test); `baseline:ww-n2` from
`testing/baseline/Dockerfile` and tinc-1.1pre18.tar.gz; `fp-prober:ww-n2`
from `testing/fingerprint/prober`.
