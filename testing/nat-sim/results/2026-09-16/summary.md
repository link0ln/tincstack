# NAT lab summary — 2026-09-15T23:09Z

Cell = seconds until `tinc info <peer>` reported *directly with UDP* on that side; `-` = never within the wait. `expected` = yes (direct UDP must come up), no (pair cannot hole-punch: traffic must still flow via the relay), tcp (UDP blocked: meta/TCP path must carry traffic).

| A x B | image | expected | direct a->b | direct b->a | ping | verdict |
|---|---|---|---|---|---|---|
| fullcone x fullcone | baseline | yes | 6s | 0s | ok | PASS |
| fullcone x fullcone | core | yes | 6s | 0s | ok | PASS |
| fullcone x masq | baseline | yes | 16s | 0s | ok | PASS |
| fullcone x masq | core | yes | 10s | 0s | ok | PASS |
| fullcone x portrestricted | baseline | yes | 12s | 0s | ok | PASS |
| fullcone x portrestricted | core | yes | 10s | 0s | ok | PASS |
| fullcone x restricted | baseline | yes | 12s | 0s | ok | PASS |
| fullcone x restricted | core | yes | 6s | 0s | ok | PASS |
| fullcone x symmetric | baseline | yes | 15s | 2s | ok | PASS |
| fullcone x symmetric | core | yes | 6s | 0s | ok | PASS |
| masq x fullcone | baseline | yes | 7s | 0s | ok | PASS |
| masq x fullcone | core | yes | 6s | 0s | ok | PASS |
| masq x masq | baseline | no | - | - | ok | PASS |
| masq x masq | core | no | - | - | ok | PASS |
| masq x portrestricted | baseline | no | 12s | 0s | ok | PASS |
| masq x portrestricted | core | no | - | - | ok | PASS |
| masq x restricted | baseline | yes | 12s | 0s | ok | PASS |
| masq x restricted | core | yes | 6s | 2s | ok | PASS |
| masq x symmetric | baseline | no | - | - | ok | PASS |
| masq x symmetric | core | no | - | - | ok | PASS |
| portrestricted x fullcone | baseline | yes | 12s | 0s | ok | PASS |
| portrestricted x fullcone | core | yes | 6s | 0s | ok | PASS |
| portrestricted x masq | baseline | no | - | - | ok | PASS |
| portrestricted x masq | core | no | - | - | ok | PASS |
| portrestricted x portrestricted | baseline | yes | 6s | 0s | ok | PASS |
| portrestricted x portrestricted | core | yes | 10s | 0s | ok | PASS |
| portrestricted x restricted | baseline | yes | 12s | 0s | ok | PASS |
| portrestricted x restricted | core | yes | 6s | 2s | ok | PASS |
| portrestricted x symmetric | baseline | no | - | - | ok | PASS |
| portrestricted x symmetric | core | no | - | - | ok | PASS |
| restricted x fullcone | baseline | yes | 12s | 0s | ok | PASS |
| restricted x fullcone | core | yes | 6s | 0s | ok | PASS |
| restricted x masq | baseline | yes | 6s | 2s | ok | PASS |
| restricted x masq | core | yes | 7s | 0s | ok | PASS |
| restricted x portrestricted | baseline | yes | 12s | 0s | ok | PASS |
| restricted x portrestricted | core | yes | 6s | 0s | ok | PASS |
| restricted x restricted | baseline | yes | 12s | 0s | ok | PASS |
| restricted x restricted | core | yes | 6s | 2s | ok | PASS |
| restricted x symmetric | baseline | yes | 6s | 2s | ok | PASS |
| restricted x symmetric | core | yes | 6s | 0s | ok | PASS |
| symmetric x fullcone | baseline | yes | 18s | 0s | ok | PASS |
| symmetric x fullcone | core | yes | 6s | 0s | ok | PASS |
| symmetric x masq | baseline | no | - | - | ok | PASS |
| symmetric x masq | core | no | - | - | ok | PASS |
| symmetric x portrestricted | baseline | no | - | - | ok | PASS |
| symmetric x portrestricted | core | no | - | - | ok | PASS |
| symmetric x restricted | baseline | yes | 6s | 0s | ok | PASS |
| symmetric x restricted | core | yes | 6s | 0s | ok | PASS |
| symmetric x symmetric | baseline | no | - | - | ok | PASS |
| symmetric x symmetric | core | no | - | - | ok | PASS |
| udpblock x fullcone | baseline | tcp | - | - | ok | PASS |
| udpblock x fullcone | core | tcp | - | - | ok | PASS |
| udpblock x portrestricted | baseline | tcp | - | - | ok | PASS |
| udpblock x portrestricted | core | tcp | - | - | ok | PASS |
| udpblock x udpblock | baseline | tcp | - | - | ok | PASS |
| udpblock x udpblock | core | tcp | - | - | ok | PASS |

## Laptop regression — image: core (rtt=0ms, CGNAT udp conntrack timeouts 10/30s, pause=70s, recover budget 60s)

| stage | result | seconds | note |
|---|---|---|---|
| setup | ok | 6 | direct L<->P through 2-tier CGNAT / restricted-cone |
| peer-restart | ok | 8 | P's tincd restarted; L must re-establish direct UDP |
| sleep-resume | ok | 6 | L frozen 70s (SIGSTOP/SIGCONT), then resumed |
| mapping-dropped | ok | 4 | L frozen 70s; NAT conntrack flushed, inbound to L's old socket (port 45620) black-holed; L's port after: 46161 |

- tunnel ping L->P after all stages (any path): ok
- `Invalid packet seqno` lines (all logs): 0; `Got REQ_KEY ... already started a SPTPS session` lines: 0 (livelock threshold: > 20 either)
- L: `Awaking from dead` events: 2; `Rebound UDP socket` events: 2; same tincd process throughout: yes
- **verdict: PASS**

## Laptop regression — image: baseline (rtt=0ms, CGNAT udp conntrack timeouts 10/30s, pause=70s, recover budget 60s)

| stage | result | seconds | note |
|---|---|---|---|
| setup | ok | 12 | direct L<->P through 2-tier CGNAT / restricted-cone |
| peer-restart | ok | 8 | P's tincd restarted; L must re-establish direct UDP |
| sleep-resume | ok | 4 | L frozen 70s (SIGSTOP/SIGCONT), then resumed |
| mapping-dropped | FAIL | 60 | L frozen 70s; NAT conntrack flushed, inbound to L's old socket (port 655) black-holed; L's port after: 655 |

- tunnel ping L->P after all stages (any path): ok
- `Invalid packet seqno` lines (all logs): 0; `Got REQ_KEY ... already started a SPTPS session` lines: 0 (livelock threshold: > 20 either)
- L: `Awaking from dead` events: 2; `Rebound UDP socket` events: 0; same tincd process throughout: yes
- **verdict: FAIL**


## REQ_KEY glare (both sides initiate at once; full-cone x full-cone)

| image | key established after | `Invalid packet seqno` | glare lines | SPTPS restarts | verdict |
|---|---|---|---|---|---|
| core | 64s | 4 | 5 | 3 | PASS |
| baseline | 45s | 8 | 9 | 7 | PASS |

## NAT emulation self-check (udpprobe)

```
fullcone: {"sport": 4001, "obs": {"s1": ["100.64.0.2", 40655], "s1b": ["100.64.0.2", 40655], "s2": ["100.64.0.2", 40655], "s2b": ["100.64.0.2", 40655]}, "xport": true, "xhost": true, "mapping": "EIM", "filtering": "EIF", "type": "fullcone", "port_preserving": false, "expect": "fullcone", "ok": true}
restricted: {"sport": 4002, "obs": {"s1": ["100.64.0.2", 40655], "s1b": ["100.64.0.2", 40655], "s2": ["100.64.0.2", 40655], "s2b": ["100.64.0.2", 40655]}, "xport": true, "xhost": false, "mapping": "EIM", "filtering": "ADF", "type": "restricted", "port_preserving": false, "expect": "restricted", "ok": true}
portrestricted: {"sport": 4003, "obs": {"s1": ["100.64.0.2", 40655], "s1b": ["100.64.0.2", 40655], "s2": ["100.64.0.2", 40655], "s2b": ["100.64.0.2", 40655]}, "xport": false, "xhost": false, "mapping": "EIM", "filtering": "APDF", "type": "portrestricted", "port_preserving": false, "expect": "portrestricted", "ok": true}
masq: {"sport": 4004, "obs": {"s1": ["100.64.0.2", 4004], "s1b": ["100.64.0.2", 55532], "s2": ["100.64.0.2", 55532], "s2b": ["100.64.0.2", 55532]}, "xport": false, "xhost": false, "mapping": "EIM-after-first", "filtering": "APDF", "type": "masq", "port_preserving": true, "expect": "masq", "ok": true}
symmetric: {"sport": 4005, "obs": {"s1": ["100.64.0.2", 39385], "s1b": ["100.64.0.2", 48391], "s2": ["100.64.0.2", 35147], "s2b": ["100.64.0.2", 6387]}, "xport": false, "xhost": false, "mapping": "APDM", "filtering": "APDF", "type": "symmetric", "port_preserving": false, "expect": "symmetric", "ok": true}
udpblock: {"sport": 4006, "obs": {}, "xport": false, "xhost": false, "type": "udpblock", "mapping": null, "filtering": null, "expect": "udpblock", "ok": true}
```
