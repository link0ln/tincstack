# T1c — cross-session linkability of the carriers (2026-09-29)

Plan item T1c (PLAN.md, masking hardening): can an observer who
cannot block the protocol still tell that two sessions, seen from different
addresses, belong to the same node?

```
flock /tmp/tincstack-lab.lock testing/fingerprint/linkability-audit.sh [outdir]
```

Lab: a founder and two leaves whose names differ only in length -- `leaf`
(4 characters) and `leafwithaverylongname01` (23). Each leaf dials the founder
6 times over each of https, quic and obfs, interleaved (36 sessions, one
capture each): the dial, five pings of 64/300/600/900/1200 B, 65 s idle, stop.
Reference: two identical curl clients ("users") fetch the nginx page 6 times
each over HTTP/1.1+TLS and over HTTP/3. Core `tincstack/core:t1a-https2`
(this tree, with the 2026-09-29 `https.c` change). `linkability.py` reduces
the captures; files here: `linkability.report.txt` (the run's report),
`sessions.tsv` (every session, its epochs and the carrier it actually got --
36/36 as asked), `linkability.json`.

## Results

| carrier | per-node constant (every session of a node) | per-node, >= 2/3 of sessions | inner packet length readable |
|---|---|---|---|
| **https** | **yes, 2 records**: node->server #1 332 vs 357 B, #2 29 vs 48 B | node->server #4 223 vs 261 B; server->node #9 271 vs 290 B, #15 1305 vs 1384 B | yes, +-1 B (overhead 76-77 B per record) |
| **quic** | none exact | **node->server #9 262 vs 301 B, #13 183 vs 202 B** | **yes, exactly** (83 B up, 60 B down) |
| obfs | none | none | no: random tail, spread 0..146 B |
| reference h1 / h3 (two identical curl users) | none | none | (not probed) |

What the https records are, by their size (a TLS 1.3 record is plaintext +
17 B): #2 is 12 B of plaintext for `leaf` and 31 for the long name, i.e.
tinc's `ID` line `0 leaf 17.7\n` carried as is inside TLS; #1 is the
`GET /ws` request whose cookie carries the authenticator with the node name
(+25 B = the base64 of 19 more characters); #4 (+38 = 2 x 19) and the
server's #9 (+19) and #15 (+79) are, by their deltas, meta records that name
the node once or several times (not decrypted to confirm). quic carries
the same `ID` line (+19) and authenticator (+39) in its first datagrams; there
the sizes blur with coalesced ACK/stream frames, so they hold in most
sessions rather than all -- which costs an observer with many sessions
nothing.

**So both TLS carriers leak the node's name length in their first records,
in every session.** An observer who sees many sessions to one server groups
them by that number and follows a node across address changes; with a
handful of nodes (the owner's network) the length alone names the node.
obfs does not: its random tails cover a 19-B difference. The reference users
have no such constant because nothing user-specific travels in a plain
request -- a real site's session cookie of per-user length would, but that is
the site's leak, not the protocol's.

It is a privacy defect, not a detection one: it helps follow a node that is
already visible, it does not make the carrier look less like curl/nginx.
Fix direction (not done here, an owner call): make every node's first
records the same size -- pad the authenticator's name field to a fixed
length (a new authenticator version, the listener keeps accepting the old)
and pad the `ID` line and the first meta records at the carrier (TLS 1.3
record padding is standard and invisible to the peer's application; QUIC
PADDING frames). Recorded in PLAN.md Known Issues.

**LengthTracksPayload** is the other finding: on quic every tunnelled
packet's length is readable exactly, on https to one byte (the
`SPTPS_PACKET` line carries the length in decimal). That is what the
TLS-in-TLS burst model feeds on (T1a, `testing/dpi-proof/results/2026-09-29-tls-in-tls/`);
plain TLS and QUIC have the same property, so it is not a tell by itself,
only the reason inner handshakes show through.

**SameGaps**: no per-node timing. Idle https sends 7-11 records in 65 s,
quic 42-81 datagrams, obfs 76-86 datagrams (its ~1-3 s heartbeat, already
listed as 🟡 in PLAN.md); the median gaps overlap between the two nodes. The
reference sessions have no idle phase here (the idle behaviour of nginx and
curl is in `2026-09-26-audit`), so this column compares our nodes with each
other only.

## Not measured

Nodes with names of equal length (by construction they would not be told
apart by these records), more than two nodes, other session workloads
(the first records are the dial's meta exchange, the same whatever the user
does), Windows/Android diallers, real networks.
