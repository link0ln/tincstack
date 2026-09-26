# NAT lab summary — 2026-09-25T22:36Z

Cell = seconds until `tinc info <peer>` reported *directly with UDP* on that side; `-` = never within the wait. `expected` = yes (direct UDP must come up), no (pair cannot hole-punch: traffic must still flow via the relay), tcp (UDP blocked: meta/TCP path must carry traffic).

| A x B | image | carrier | expected | direct a->b | direct b->a | ping | verdict |
|---|---|---|---|---|---|---|---|
| fullcone x fullcone | baseline | plain | yes | 12s | 0s | ok | PASS |
| fullcone x fullcone | core | plain | yes | 6s | 0s | ok | PASS |
| fullcone x masq | baseline | plain | yes | 14s | 2s | ok | PASS |
| fullcone x masq | core | plain | yes | 6s | 2s | ok | PASS |
| fullcone x portrestricted | baseline | plain | yes | 7s | 0s | ok | PASS |
| fullcone x portrestricted | core | plain | yes | 10s | 0s | ok | PASS |
| fullcone x restricted | baseline | plain | yes | 6s | 0s | ok | PASS |
| fullcone x restricted | core | plain | yes | 6s | 0s | ok | PASS |
| fullcone x symmetric | baseline | plain | yes | 14s | 3s | ok | PASS |
| fullcone x symmetric | core | plain | yes | 10s | 0s | ok | PASS |
| masq x fullcone | baseline | plain | yes | 6s | 0s | ok | PASS |
| masq x fullcone | core | plain | yes | 6s | 0s | ok | PASS |
| masq x masq | baseline | plain | no | - | - | ok | PASS |
| masq x masq | core | plain | no | - | - | ok | PASS |
| masq x portrestricted | baseline | plain | no | - | - | ok | PASS |
| masq x portrestricted | core | plain | no | - | - | ok | PASS |
| masq x restricted | baseline | plain | yes | 13s | 0s | ok | PASS |
| masq x restricted | core | plain | yes | 6s | 2s | ok | PASS |
| masq x symmetric | baseline | plain | no | - | - | ok | PASS |
| masq x symmetric | core | plain | no | - | - | ok | PASS |
| portrestricted x fullcone | baseline | plain | yes | 12s | 0s | ok | PASS |
| portrestricted x fullcone | core | plain | yes | 6s | 0s | ok | PASS |
| portrestricted x masq | baseline | plain | no | - | - | ok | PASS |
| portrestricted x masq | core | plain | no | - | - | ok | PASS |
| portrestricted x portrestricted | baseline | plain | yes | 12s | 0s | ok | PASS |
| portrestricted x portrestricted | core | plain | yes | 6s | 0s | ok | PASS |
| portrestricted x restricted | baseline | plain | yes | 14s | 2s | ok | PASS |
| portrestricted x restricted | core | plain | yes | 6s | 0s | ok | PASS |
| portrestricted x symmetric | baseline | plain | no | - | - | ok | PASS |
| portrestricted x symmetric | core | plain | no | - | - | ok | PASS |
| restricted x fullcone | baseline | plain | yes | 12s | 0s | ok | PASS |
| restricted x fullcone | core | plain | yes | 8s | 0s | ok | PASS |
| restricted x masq | baseline | plain | yes | 6s | 2s | ok | PASS |
| restricted x masq | core | plain | yes | 10s | 0s | ok | PASS |
| restricted x portrestricted | baseline | plain | yes | 12s | 0s | ok | PASS |
| restricted x portrestricted | core | plain | yes | 6s | 0s | ok | PASS |
| restricted x restricted | baseline | plain | yes | 6s | 0s | ok | PASS |
| restricted x restricted | core | plain | yes | 6s | 0s | ok | PASS |
| restricted x symmetric | baseline | plain | yes | 24s | 2s | ok | PASS |
| restricted x symmetric | core | plain | yes | 10s | 0s | ok | PASS |
| symmetric x fullcone | baseline | plain | yes | 18s | 0s | ok | PASS |
| symmetric x fullcone | core | plain | yes | 6s | 0s | ok | PASS |
| symmetric x masq | baseline | plain | no | - | - | ok | PASS |
| symmetric x masq | core | plain | no | - | - | ok | PASS |
| symmetric x portrestricted | baseline | plain | no | - | - | ok | PASS |
| symmetric x portrestricted | core | plain | no | - | - | ok | PASS |
| symmetric x restricted | baseline | plain | yes | 18s | 0s | ok | PASS |
| symmetric x restricted | core | plain | yes | 6s | 0s | ok | PASS |
| symmetric x symmetric | baseline | plain | no | - | - | ok | PASS |
| symmetric x symmetric | core | plain | no | - | - | ok | PASS |
| udpblock x fullcone | baseline | plain | tcp | - | - | ok | PASS |
| udpblock x fullcone | core | plain | tcp | - | - | ok | PASS |
| udpblock x portrestricted | baseline | plain | tcp | - | - | ok | PASS |
| udpblock x portrestricted | core | plain | tcp | - | - | ok | PASS |
| udpblock x udpblock | baseline | plain | tcp | - | - | ok | PASS |
| udpblock x udpblock | core | plain | tcp | - | - | ok | PASS |

## Laptop regression — image: core (rtt=0ms, CGNAT udp conntrack timeouts 10/30s, pause=70s, recover budget 60s)

| stage | result | seconds | note |
|---|---|---|---|
| setup | ok | 6 | direct L<->P through 2-tier CGNAT / restricted-cone |
| peer-restart | ok | 8 | P's tincd restarted; L must re-establish direct UDP |
| sleep-resume | ok | 6 | L frozen 70s (SIGSTOP/SIGCONT), then resumed |
| mapping-dropped | ok | 4 | L frozen 70s; NAT conntrack flushed, inbound to L's old socket (port 51288) black-holed; L's port after: 57283 |

- tunnel ping L->P after all stages (any path): ok
- `Invalid packet seqno` lines (all logs): 0; `Got REQ_KEY ... already started a SPTPS session` lines: 0 (livelock threshold: > 20 either)
- L: `Awaking from dead` events: 2; `Rebound UDP socket` events: 2; same tincd process throughout: yes
- **verdict: PASS**

## Laptop regression — image: baseline (rtt=0ms, CGNAT udp conntrack timeouts 10/30s, pause=70s, recover budget 60s)

| stage | result | seconds | note |
|---|---|---|---|
| setup | ok | 12 | direct L<->P through 2-tier CGNAT / restricted-cone |
| peer-restart | ok | 8 | P's tincd restarted; L must re-establish direct UDP |
| sleep-resume | ok | 12 | L frozen 70s (SIGSTOP/SIGCONT), then resumed |
| mapping-dropped | FAIL | 61 | L frozen 70s; NAT conntrack flushed, inbound to L's old socket (port 655) black-holed; L's port after: 655 |

- tunnel ping L->P after all stages (any path): ok
- `Invalid packet seqno` lines (all logs): 0; `Got REQ_KEY ... already started a SPTPS session` lines: 0 (livelock threshold: > 20 either)
- L: `Awaking from dead` events: 2; `Rebound UDP socket` events: 0; same tincd process throughout: yes
- **verdict: FAIL**


## REQ_KEY glare (both sides initiate at once; full-cone x full-cone)

Each image is graded against what it is SUPPOSED to do: `clean` = the
tie-break holds (key within 10s, no SPTPS restart, no seqno error),
`defect` = the unpatched control still demonstrates the glare it is there
to demonstrate. A control that recovers cleanly fails this table, and so
does a patched binary that does not.

| image | expected | key established after | `Invalid packet seqno` | glare lines | SPTPS restarts | verdict |
|---|---|---|---|---|---|---|
| core | clean | 1s | 0 | 2 | 0 | PASS |
| baseline | defect | 12s | 2 | 3 | 1 | PASS |

- core: PASS -- key in 1s (limit 10s), no SPTPS restart, no seqno error
- baseline: PASS -- the defect reproduced: 1 SPTPS restart(s), 2 seqno error(s), key after 12s

## NAT emulation self-check (udpprobe)

```
fullcone: {"sport": 4001, "obs": {"s1": ["100.64.0.2", 40655], "s1b": ["100.64.0.2", 40655], "s2": ["100.64.0.2", 40655], "s2b": ["100.64.0.2", 40655]}, "xport": true, "xhost": true, "mapping": "EIM", "filtering": "EIF", "type": "fullcone", "port_preserving": false, "expect": "fullcone", "ok": true}
restricted: {"sport": 4002, "obs": {"s1": ["100.64.0.2", 40655], "s1b": ["100.64.0.2", 40655], "s2": ["100.64.0.2", 40655], "s2b": ["100.64.0.2", 40655]}, "xport": true, "xhost": false, "mapping": "EIM", "filtering": "ADF", "type": "restricted", "port_preserving": false, "expect": "restricted", "ok": true}
portrestricted: {"sport": 4003, "obs": {"s1": ["100.64.0.2", 40655], "s1b": ["100.64.0.2", 40655], "s2": ["100.64.0.2", 40655], "s2b": ["100.64.0.2", 40655]}, "xport": false, "xhost": false, "mapping": "EIM", "filtering": "APDF", "type": "portrestricted", "port_preserving": false, "expect": "portrestricted", "ok": true}
masq: {"sport": 4004, "obs": {"s1": ["100.64.0.2", 4004], "s1b": ["100.64.0.2", 63039], "s2": ["100.64.0.2", 63039], "s2b": ["100.64.0.2", 63039]}, "xport": false, "xhost": false, "mapping": "EIM-after-first", "filtering": "APDF", "type": "masq", "port_preserving": true, "expect": "masq", "ok": true}
symmetric: {"sport": 4005, "obs": {"s1": ["100.64.0.2", 52865], "s1b": ["100.64.0.2", 51821], "s2": ["100.64.0.2", 29827], "s2b": ["100.64.0.2", 20285]}, "xport": false, "xhost": false, "mapping": "APDM", "filtering": "APDF", "type": "symmetric", "port_preserving": false, "expect": "symmetric", "ok": true}
udpblock: {"sport": 4006, "obs": {}, "xport": false, "xhost": false, "type": "udpblock", "mapping": null, "filtering": null, "expect": "udpblock", "ok": true}
```
