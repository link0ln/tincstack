# Stream Q, 2026-09-26: quic carrier fixes (items 0-5)

Images, all built from commits of this branch (`git archive`), never from a
dirty tree:

| tag | commit | contents |
| --- | --- | --- |
| `tincstack/core:ww-q-base` | 5076472 | master |
| `ww-q0` / `ww-q0-asan` | 175bd51 | item 0 |
| `ww-q1` | 1816c52 | + item 1 |
| `ww-q2` | 1c4dd84 | + item 2 |
| `ww-q3` | 30d8a14 | + item 3 |
| `ww-q4` | 9776e8a | + item 4 |
| `ww-q5`, `ww-q5-noquic` | ed58a14 | + item 5 (first cut) |
| `ww-q6` / `ww-q6-asan` | 0644fa9 | + the decoy's FIN frame |
| `ww-q7` | 2160350 | + decoy upstream Content-Length, final |

Every lab run took `/tmp/tincstack-lab.lock`; `logs/results.txt` lists each
run with its exit code, in the order the lock was granted.

## Item 0 -- send buffers that never move

`item0-loss/README.md`. Master fails the meta loss run (2/2000, link dead)
and the ASan qpack run (heap-use-after-free, freed by `decoder_append`'s
realloc); 175bd51 passes both. Final tree: `logs/loss-asan-q6.log` (ASan,
both sections) and `logs/loss-meta-q7.log`, exit 0.

## Item 1 -- the authenticator in the request's HEADERS

`post405-before/` (master) vs `post405-after/` (`ww-q2`), RTT 20/80/200 ms,
jitter 0, 12 probes per cell (6 head-only):

| h3 row, RTT 200 | listener before | listener after | nginx |
| --- | --- | --- | --- |
| post-pause (body 1 s later) | 1201.5 ms, waited 12/12 | 228.1 ms, waited 0/12 | 200.8 ms |
| post-authver | 1202.5 ms, waited 12/12 | 227.5 ms, waited 0/12 | 200.8 ms |
| post-nobody (no body ever) | no answer 6/6 (70 s: none) | 405 at 227.6 ms (70 s: 405) | 405 at 202.6 ms |

The structural tell (answer after the body / never) is gone in every cell.
What stays is the known constant delay: +2.3 ms at RTT 20, +10 at 80, +26
at 200 on every h3 row, `get` included (AUC 1.00) -- not caused or changed
here.

Mixed versions (`logs/mixed-*.log`, NEW = `ww-q2`): OLD = `ww-q-base`
(5076472), `pre-tps`, `pre-deb13`: all pairs connect (exit 0 each). New
dialler -> old listener: quic, dialled once (base, pre-tps; pre-deb13 cannot
send datagrams and gives quic up once, as before). Old dialler -> new
listener: answered as a web server, gives quic up once, lands on the next
carrier. Final tree: `logs/qwire-q6.log`, `logs/qwire2-q7.log`,
`logs/h3i-q6.log`, `logs/carrier-q6.log`, `logs/lwire-q7.log`: all exit 0.

## Item 2 -- every request field to the HTTP/3 decoy

`logs/decoy-h3-before.log` (`ww-q1`): 11 h3 probes FAIL (If-*, Range,
Accept-Encoding: 200 where nginx says 304/412/206/416 or gzips), the root
set's h3-page and the proxy set. `logs/decoy-h3-after.log` (`ww-q2`): only
the proxy set (the upstream got `content-length` where nginx puts its own
`Content-Length`), fixed in d25942c: `logs/decoy-q7.log`, full run, 98
PASS, exit 0.

## Item 3 -- an idle link

`audit-before/` (`ww-q2`), `audit-idle-after/` (`ww-q3`),
`audit-pad-after/` (`ww-q4`); 200 s idle after the pings:

| | packets | bursts | median gap |
| --- | --- | --- | --- |
| before | 266 | 79 | ~2 s |
| after (item 3) | 55 | 19 | 14.3 s |
| after (item 4 too) | 61 | 20 | 15.0 s |
| curl waiting on nginx (`curl-idle/`) | 20 in 150 s | 10 | 15.0 s (42-B PING, 24-B ACK) |

Cause, from `idle-dbg/before-founder-probes.log` (tincd -d5): tinc's UDP
keepalive probes and replies both ways every 10 s, the gratuitous probe
replies, each DATAGRAM drawing a QUIC ACK. After: `idle-dbg/after-*`: the
dialler's PING every 15 s and its ACK, the meta PING/PONG per PingInterval,
and the lab containers' own IPv6 traffic through the tunnel (62-B packets,
not ours).

## Item 4 -- full packets

Download, server -> client (`audit-before` vs `audit-pad-after`): 1160 B in
4737 of 6383 datagrams, never 1200 -> 1200 B in 4978 of 6386; nginx 1200 B
in 3888 of 4599. The client's 130-B datagrams (tunnelled TCP ACKs) stay:
2726 of 5266 (52 %) vs curl's 48-B ACKs (100 % < 100 B) -- not fixed.

## Item 5 -- field encoding and framing

Listener (`listener-wire/`, `logs/lwire-q7.log`): the answer to GET / was
one STREAM frame with FIN, 831 B (HEADERS 210) in an 867-B datagram; nginx
writes 750 + an empty FIN frame, HEADERS 129, 791 B (with Alt-Svc on both).
Now byte-for-byte those sizes; quic-listener-wire-test.sh 10/10.
`lwire-base.log` and `lwire-q2.log` ran before the test's nginx got its
Alt-Svc (8b09060): master fails the answers check there too.

Dialler, first 1-RTT-only datagrams (udp length; `logs/qwire2-*.log`):
`ww-q2` 66/53/53/463, `ww-q7` 66/53/53/397 (Huffman), curl 67/52/52/81.
