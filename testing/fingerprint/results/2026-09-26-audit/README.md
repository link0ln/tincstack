# Wire audit 2026-09-26: obfs, post-handshake traffic, POST-405 timing, slow client

Measurement only; no product code changed. Core under test: `tincstack/core:dev`
(`sha256:80354c6b6aad...`, master 7ff64c2). References: Debian 13 nginx 1.26.3
(`tincstack/nginx-deb13:dev`, the founder's own certificate), curl 8.14 and
tshark 4.4 (`tincstack/fp-tools:dev`), aioquic 1.2.0 as the prober
(`tincstack/fp-prober:ww-f`, `testing/fingerprint/prober/Dockerfile`).
Every run held `/tmp/tincstack-lab.lock`; all exited 0.

| directory | script | what |
| --- | --- | --- |
| `obfs/` | `testing/fingerprint/obfs-audit.sh` (+ `obfs_stats.py`) | obfs, default and shaped config: handshake, ping, 2x2000 flood pings, 150 s idle (KeyExpire 30), 6 restarts, 11 UDP + 3 TCP probes, 6 replays |
| `carrier-traffic/` | `carrier-traffic-audit.sh` (+ `carrier_stats.py`, `bulk_server.py`) | https and quic tunnels: 20 MiB down/up, 20 pings, 200 s idle; curl<->nginx over h1/TLS and h3 for the same, and one idle connection each |
| `post405/` | `post405-timing.sh` (+ `post_probe.py`, `post405_summary.py`) | POST split head/pause/body against our listener and nginx, h3 and h1, RTT 20/80/200 x jitter 0/10 ms, 12 probes per cell (6 head-only) |
| `post405-jitter-inorder/` | same, `JITTERS=10`, netem with `rate 10gbit` | the jitter cells again without netem reordering (see below) |
| `slow-client/`, `slow-client-n20/` | `slow-client-flight.sh` | our quic dialler and curl under the same `--cpus` quota (0.03 and 1), 6 and 20 dials each |

Captures and key material stay in the scripts' `run-*` directories, which are
deleted on exit; nothing here is a pcap or a key.

## Findings (PLAN.md-style item text; priorities are proposals)

### obfs -- does not look like random UDP

- [ ] 🔴 **obfs: the ciphertext length is on the wire in clear.** Bytes 8-9 of
  every obfs datagram are `clen`, big-endian, unmasked (`obfs.c`
  `obfs_seal`). Default config: `bytes[8:10] == len - 10` in **9283 of 9283**
  tunnel datagrams (uniform random: 2^-16 = 0.0015 %); shaped config (header
  junk): `len - 10 - bytes[8:10]` is **16 in 9252 of 9315** and 64 in 7 (the
  configured `ObfsTransport/InitHeaderJunkSize`, a constant, not random), and
  `16 <= bytes[8:10] <= len - 10` holds for 99.4 % (random 1000-byte UDP:
  1.5 %). A one-datagram, stateless DPI rule; chi-square of bytes 8 and 9
  ~10^6 (255 dof). Repro: `flock /tmp/tincstack-lab.lock
  testing/fingerprint/obfs-audit.sh`, `obfs-*.txt` "structural rules".
  Blast radius: every obfs datagram of every obfs link, every platform,
  every config (magic headers only shift it by 4). Fix: protect the header
  as QUIC does -- mask nonce+clen with a keystream block keyed by a separate
  header key over a ciphertext sample, and derive the tail-junk length from
  it; frame v3, mesh upgrades together (as v1->v2). Cost: ~1 day incl.
  `fuzz_obfs`/self-tests; one extra ChaCha20 block per datagram.
- [ ] 🔴 **obfs: the whitened counter leaves the first six bytes constant per
  flow.** The nonce is `counter XOR mask` with a fixed per-keyset mask and a
  big-endian counter, so consecutive datagrams share bytes 0-5: **4620 of
  4643** consecutive pairs (L->F), 4621/4638 (F->L); over a 10-minute
  capture only 12 distinct 2-byte prefixes per direction (one per keyset:
  bootstrap + rekeys) where random gives one per datagram; byte 6 skewed
  (chi2 8.7e4). Shaped config identical (46/41 prefixes). A per-flow rule
  after two datagrams. Repro: same script, "consecutive datagrams with equal
  bytes 0-5". Blast radius: all obfs links. Fix: the same header protection
  as above (one fix for both). Cost: included above.
- [ ] 🟠 **obfs: sizes are the inner sizes plus a constant.** Default: the
  first five datagrams of a dial are 62, 50, 65, 50, 118 B on **7 of 7**
  dials; 4000 flood-ping datagrams have 2 distinct sizes (1087, 151 = inner
  + 26). Shaped: the four junk datagrams are random, but the fifth (126 B)
  and the tenth are fixed on 7/7 dials and the sequence after the junk
  (`<66 <81 >66 <134 >134`) repeats on 7/7; header junk is a fixed 16/64
  bytes, so shaped sizes are default sizes + 16. Repro: same script,
  "handshakes" and "sizes per phase". Blast radius: all obfs links; shaping
  options do not help. Fix: per-datagram random tail length (keyed, after
  the header fix) and padding handshake frames to random sizes. Cost:
  small once the header is protected; bandwidth.
- [ ] 🟡 **obfs: an idle link heartbeats in identical-size pairs, plus a
  full-MTU datagram.** 150 s idle: 63 bursts (median gap 1.9 s), mostly two
  77-B datagrams (93 B shaped), and a 1472-B datagram both ways (tinc's
  PMTU probe at the path MTU; source inferred from size and cadence, not
  from a log). Repro: same script, "idle phase". Blast radius: all idle obfs
  links. Fix: slow and jitter UDP discovery on a link that is up, pad
  probes to random sizes. Cost: small-moderate.
- [ ] 🟡 **obfs rides UDP 655 next to a TCP 655 that answers HTTP as
  nginx.** A stranger's `GET /` on TCP 655 gets `HTTP/1.1 200 OK Server:
  nginx`; UDP 655 is tinc's IANA port. The port is configurable, the default
  is the tell. Repro: same script, probes. Fix: document / default obfs
  deployments to another port. Cost: docs.
- What holds: 11 UDP probe shapes (random 1-1400 B, zeros, SPTPS-shaped,
  obfs-shaped) and 6 replayed handshake datagrams got **no answer** in both
  configs (0 datagrams to strangers); bytes 10.. are uniform (chi2 p 0.14 /
  0.36, 8.0000 bits/byte).

### https -- post-handshake

- [ ] 🟠 **https: every tunnel packet is two TLS records, 44 B + the
  packet.** 20 MiB download through the tunnel: 14483 records of 44 B and
  14483 of 1550 B (50/50), the other direction 7468x42 + 7466x102; curl
  from nginx: 1280 of 1289 records are 16401 B (full 16 KiB), and the
  client sends 5 records. One flow, one histogram. Repro: `flock
  /tmp/tincstack-lab.lock testing/fingerprint/carrier-traffic-audit.sh`,
  "bulk transfers". Blast radius: every https session carrying traffic.
  Fix: write the frame header and the packet in one `SSL_write`, and
  coalesce what is queued per event-loop pass into records up to 16 KiB
  (nginx's `ssl_buffer_size`). Cost: small-moderate (https.c send path;
  latency trade-off). The upstream ACK stream of tunnelled TCP stays (see
  the quic item).
- [ ] 🟡 **https: an idle tunnel pings every 60 s where nginx closes at
  75 s.** 200 s idle: four 43-B records at 36.8, 96.3, 156.6 s (PingInterval)
  plus 47+103-B pairs at irregular 9-50 s; nginx closes an idle keep-alive
  connection at 75.4 s (close_notify + FIN). Inside TLS we claim a
  WebSocket, which may live long, so the exact period is the tell more than
  the lifetime. Fix: jitter the ping, size it like a WebSocket ping. Cost:
  small.

### quic -- post-handshake

- [ ] 🟠 **quic: an idle tunnel exchanges packets every ~2.5 s.** 200 s idle:
  264 packets in 69 bursts (median gap 2.5 s; 42-126 B, both directions);
  nginx with an idle client sends nothing and closes at 75.4 s. Right after
  link-up `tinc info` showed `validkey` without `udp_confirmed`; the cadence
  matches tinc's UDP discovery probing at its 2-s interval (inferred, not
  logged; the obfs heartbeat has the same median). Repro: same
  script, "idle". Blast radius: every idle quic link, for its whole life.
  Fix: no UDP discovery / PMTU probing over a quic datagram path (the
  carrier already knows its ceiling), or a browser-like PING cadence.
  Cost: small.
- [ ] 🟠 **quic: full datagrams are 1160 B and tunnelled TCP ACKs form a
  second size mode.** Download: server datagrams 1160 B in 19747 of 25052
  (max 1174, never 1200); nginx 1200 B in 15350 of 19209. Client side: 130-B
  datagrams are 50 % (inner TCP ACKs as DATAGRAM frames) vs curl's 48-B ACKs
  (100 % < 100 B); client bytes 8.1 % of server bytes vs 2.1 %. Upload:
  server->client alternates 42/107 B (9969/9942) vs nginx 24-27 B. Repro:
  same script. Blast radius: every quic session with bulk traffic. Fix:
  pad packets carrying DATAGRAM frames to the path maximum (1200) -- small,
  +3.4 % bytes; hiding the inner-ACK mode (ACK thinning/aggregation,
  padding ACK-only datagrams) is expensive and a design question.
- [ ] 🟠 **quic: a POST that never sends its body is never answered (the
  POST-405 item, measured).** See the numbers below: a head-only POST gets
  nginx's 405 within one RTT and nothing from our listener (54 of 54 probes over 9 path cells; 2 of 2 waited out to 70 s),
  a POST whose body comes 1 s later is
  answered by us after the body and by nginx before it, 12/12 + 12/12 in
  every cell. One probe, no statistics, any RTT or jitter. Fix and cost:
  recommendation below.
- [ ] 🟡 **quic: our listener answers any request ~RTT/8 later than
  nginx.** GET / and POST-with-body, jitter 0: +2.2 ms at RTT 20, +10.3 ms
  at 80, +25.3 ms at 200 (median 227.6 vs 202.3 ms; AUC 1.00 at 80 and 200,
  a single threshold separates 100 % of 24 probes); with 10 ms in-order
  jitter AUC 0.62 / 0.83 / 1.00. The TCP front shows no such delay (AUC
  0.0-0.6). Cause unmeasured (candidates: ngtcp2 pacing of the first
  response, or waiting for handshake confirmation). Repro:
  `post405-timing.sh`, rows `h3 get`. Blast radius: every HTTP/3 answer of
  the listener; a timing prober with a few probes on a long path. Fix:
  find the cause first (listener log with ngtcp2 debug, or a key-logged
  capture). Cost: unknown.
- [ ] 🟡 **quic: the slow-client second flight is ours, not OpenSSL's --
  reproduced on Linux.** Under `--cpus 0.03`, the first client datagram
  carrying a Handshake packet is Handshake-only (62 B, Length 25, no
  Initial) in **8 of 26** of our dials (4/6 and 4/20) and **0 of 26** of
  curl's under the same quota (hypergeometric p ~ 0.002); at 1 CPU 0/26 vs
  0/26. So the Android emulator's behaviour is ngtcp2's PTO path, and a
  slow OpenSSL client does not do it. Repro: `slow-client-flight.sh`.
  Blast radius: slow or loaded clients (low-end phones, emulators). Fix: in
  openssl-client mode, make ngtcp2's handshake PTO probe what OpenSSL sends
  (or suppress it until the Initial can be padded along). Cost: moderate
  (tincstack-wire.patch), re-measured by this script.
  (A second difference suspected from the 6-dial run -- three Initial-only
  datagrams before the Finished -- did not hold: curl sends three in 36 of
  40 dials too.)

## POST-405 timing (item 3)

Time from sending the request head to the first byte / HEADERS of the
answer, median [p10..p90] ms, 12 probes per cell (6 for head-only).
Per-probe = the structural rule "answered before the body was sent / at
all" -- no statistics needed.

| path | h3 POST, body after 1 s: ours | nginx | h3 head-only POST: ours | nginx | per-probe |
| --- | --- | --- | --- | --- | --- |
| RTT 20, jitter 0 | 1022.9 [1022.2..1023.1] | 21.1 [20.8..21.7] | never (6/6) | 21.1 | 100 % |
| RTT 20, jitter 10 (in order) | 1018.2 [1013.4..1027.5] | 22.4 [19.3..29.1] | never | 25.6 | 100 % |
| RTT 80, jitter 0 | 1082.7 [1082.0..1083.2] | 80.8 [80.7..80.9] | never | 81.9 | 100 % |
| RTT 80, jitter 10 (in order) | 1083.3 [1075.1..1090.7] | 88.0 [85.7..89.9] | never | 86.0 | 100 % |
| RTT 200, jitter 0 | 1201.1 [1201.0..1201.2] | 201.1 [200.6..204.2] | never | 202.4 | 100 % |
| RTT 200, jitter 10 (in order) | 1200.7 [1194.6..1206.6] | 202.5 [197.9..207.2] | never | 204.6 | 100 % |

- Our listener answers exactly one RTT after the body (`t_body` 20.7-22.1
  ms at RTT 20): it waits for the body, never for anything else. A body
  whose first bytes look like an authenticator (version 2, name length 32)
  waits the same; a body starting with any other byte gets 405 on that
  byte.
- A head-only POST, no netem, waited out for 70 s: nginx 405 in 0.6 ms; our
  listener never answers (one run shows one 84-B packet at +59.7 s, the
  60-s web-front close; the other run nothing until the prober gave up).
- The TCP front (HTTP/1.1 over TLS, `h1` rows) does not have the problem:
  it answers 405 at the head in every cell (378 of 378 POST probes, head-only
  included), and the AUC against nginx stays 0.0-0.8 around chance -- the
  authenticator rides the `Cookie` header there, so the decision is made at
  the head, as nginx's.
- The first run's jitter cells (`post405/`) used plain netem jitter, which
  reorders packets; QUIC loss recovery then made nginx's median 600 ms at
  200+-10 ms (AUC reversed). `post405-jitter-inorder/` repeats them with
  `rate 10gbit`, which keeps order; the table uses those.

**Recommendation.** This is not a subtle timing channel: one head-only
POST separates us from nginx with certainty on any path, and the pause
variant does too. Do not answer early on a guess, and do not add an
unkeyed marker (the repository is public, so a static path or header is
a signature). Do what the https carrier already does and measures
indistinguishable: carry the authenticator (or a keyed token derived from
it and the TLS exporter) in the request HEADERS -- e.g. a `cookie` field --
so the listener decides when the HEADERS are whole and answers every
non-tinc POST with 405 at nginx's time. A prober cannot produce the token
without a mesh key. Cost: dialler and listener change in
`transport_quic.c`/`h3.c`, a quic wire break handled like 2026-09-25's
(an old dialler gets answered as a web server and falls back), and this
script as the acceptance test (its `h3 post-*` rows must look like the
`h1` rows). Until then the quic front is identifiable by a single active
probe; rate it 🟠, not 🟡.

## Not measured

- The cause of the RTT/8 answer delay (needs an ngtcp2 debug log or a
  key-logged capture of the listener).
- Rekey datagrams at the default KeyExpire (3600 s): the lab used 30 s to
  see rotations; the rekey bursts (seven 50-B + 125/211/212-B datagrams)
  are in the idle phase of `obfs-*.txt` but a 1-hour cadence was not
  captured.
- Real paths: every number is a docker bridge plus netem; no real mobile
  network, no ARM, no Windows/Android capture in this audit.
- The obfs heartbeat's and the quic idle burst's source is inferred from
  size and cadence, not confirmed from a tincd log.
- The upload reference for h1 is a WebDAV PUT (nginx answers 201), ours a
  POST to a Python server inside the tunnel; record sizes are what is
  compared, not status codes.
