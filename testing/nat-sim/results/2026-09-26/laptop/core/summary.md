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
