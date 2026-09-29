# T1a — the TLS-in-TLS burst model against our carriers (2026-09-29)

Plan item T1a of `docs/masking-hardening-plan.md`: before shaping anything,
measure whether the traffic *after* our byte-perfect handshakes is caught by
the one published steady-state detector, nDPI's encapsulated-TLS-handshake
heuristic (Xue et al., USENIX Security 2024).

```
flock /tmp/tincstack-lab.lock testing/dpi-proof/tls-in-tls-audit.sh [outdir]
```

Tools (all in containers, nothing on the host):

- `testing/dpi-proof/ndpi/Dockerfile` — upstream nDPI **6.0** (the latest
  release; the plan's "5.1" does not exist) built from source at
  `1a5293396337f9a72dfee1fa070b2c4b0a0a3aaf`, with nDPI's own proxy captures
  in `/samples` for the arbiter's self-check.
- `testing/dpi-proof/tls_in_tls.py` — the model reimplemented from nDPI's
  source and the paper (stdlib; no the compared project code), scoring every flow with a
  margin (distance minus threshold of the nearest centroid; < 0 = caught):
  as nDPI runs it (`ndpi<N>`), as nDPI would with its server-first exclusion
  removed (`fix<N>`), over the whole connection (`flow`), and over the whole
  connection with the tunnel's measured overhead subtracted (`tuned`). It
  also keeps, per centroid, the smallest distance any scored 4-gram reached,
  which is what the separability test below compares.
- `testing/dpi-proof/tls_forward.py` — a per-connection TLS tunnel (the
  trojan/VLESS shape) for the controls.

## The lab

Inner workload through every tunnel: 10 curl GETs and 4 Chromium page loads
of an nginx 1.26.3 site with a web-sized chain (RSA-2048 leaf + intermediate,
2051 B DER), each a new inner TLS connection. Each carrier: the clients right
after the tunnel pings ("early"), 20 pings (overhead calibration), a 4 MiB
HTTPS download, the clients again ("late"). Segmentation offloads off on
both nodes.

**The plain-HTTPS reference** (what the carrier claims to be; no tunnel):

| name | what | why |
|---|---|---|
| `keepalive` | curl, 80 requests on one HTTP/1.1 connection, a 605-B browser header set | a long-lived connection with browser-sized requests |
| `kasmall` | the same with curl's default headers | the same shape with small requests |
| `kah2` | curl, 80 requests on one HTTP/2 connection (nginx `http2 on`, port 8444) | what browsers actually speak |
| `h2page` | Chromium loading a page with 80 images over HTTP/2 | a real browser's burst pattern |

Controls: `direct` (the same 14 inner fetches without a tunnel), `proxy`
(per-connection TLS tunnel, web chain, tickets — a realistic trojan) and
`proxy0` (the same tunnel as nDPI's samples look: small ECDSA certificate,
P-256, no tickets — the positive control).

Cores, three runs each, interleaved: `ghcr.io/link0ln/tincstack/core:v0.5.2`
(what runs on euvds and ruvds2; `v0.5.2-run{1,2,3}/`) and
`tincstack/core:t1a-https2`, this tree with the 2026-09-29 `https.c` fix
below (`hybrid-run{1,2,3}/`). Per run: `tls-in-tls.report.txt` (the run's
report), per-flow scores in `*.score.report.txt`, the arbiter's output in
`*.ndpi{25,255}.report.txt`, machine-readable `*.json`, `summary.json`.
Captures are not kept here (they are in the scratch area of the session that
ran them, not needed to reproduce: rerun the script).

## The oracle is valid

- **Arbiter self-check:** ndpiReader flags nDPI's own trojan, vmess-tls and
  shadowsocks captures (3/3, every run).
- **Positive control in the lab:** `proxy0` — **14/18 flows flagged by the
  arbiter in all 6 runs**; the other 4 are Chromium's short side connections
  with no complete 4-gram.
- **Analyser = arbiter:** on every TLS flow of every scenario and run, the
  analyser's nDPI-faithful verdict equals ndpiReader's (the report's
  "agrees with the arbiter" column; 0 mismatches in 6 runs). For the non-TLS
  obfs flow they agree too.

## Results (six runs)

nDPI config: `--cfg=tls,dpi.heuristics,0x07` (the heuristics are **off** in
a stock nDPI, `0x00`; an operator must enable them), window 25 (stock
limits) and 255 (every packet budget raised: `max_packets_extra_dissection`,
`packets_limit_per_flow`, ndpiReader `-U/-T`). Ranges are over the runs;
where the two cores differ, `v0.5.2 → hybrid`.

| scenario | stock nDPI 6.0 (arbiter), window 25 / 255 | nDPI with the gate removed, window 25 / 255 | whole flow: caught 4-grams per 1000 | chrome centroid, closest 4-gram (threshold 3.0) |
|---|---|---|---|---|
| direct (14 short connections) | 0 / 0 | not scored (too short) | — | — |
| keepalive | 0 / 0 | **caught, −1.62** (tls13) in 6/6 | **264–295** | 3.25 |
| kasmall | 0 / 0 | **caught, −0.58** (tls12) in 6/6 | 51 | 4.64 |
| kah2 | 0 / 0 | below bar, +0.54 | 0 | 4.81 |
| h2page (8 flows) | 0 / 0 | caught in 3/6 runs (min −1.03), below bar otherwise | 0–88 | 4.62 |
| proxy | 0/18 | caught 11–14/18, min −1.97 … −2.14 | 314–500 | **0.86–1.03** |
| **proxy0** (positive control) | **14/18 / 14/18** | caught 14/18, min −1.85 | 500–583 | **1.15–1.17** |
| **https** carrier | 0 / 0 | 25: below bar in 4/6, caught in 2/6 (hybrid 2, 3); **255: caught 6/6** | 11–26 → 35–38 | **0.92–1.46 → 0.58** |
| **obfs** carrier (UDP 655) | TINC by port / **flagged 6/6** | 25: below bar (0.00–0.57); **255: caught 6/6** | 30–96 | 0.41–0.49 |
| quic carrier | QUIC, heuristic not run | n/a (not TLS over TCP) | 9–42 | 0.45–2.83 (not like for like, see below) |

The 0.9 bar of the plan ("margin ≥ 0.9 = safe") is quoted per flow: `fix`
margins below it are "below-bar", below 0 "CAUGHT".

**Which of nDPI's own centroids, at nDPI's own thresholds, flag the
reference** (closest 4-gram of the whole reference population, all runs):
tls12 at 2.47–2.92 (< 3.5: **flags it**), tls13 at 0.28–1.10 (< 3.0:
**flags it**), chrome at 3.25–3.44 (≥ 3.0: **does not**).

**Separability** (a threshold on centroid *m* flags us and none of the
reference iff our closest 4-gram is nearer *m* than the reference's):

| ours | by | ours / reference, whole flow | at nDPI's threshold 3.0 |
|---|---|---|---|
| https | chrome | 0.92–1.46 → 0.58 / 3.25 | flags https, not the reference |
| proxy, proxy0 | chrome | 0.86–1.17 / 3.25 | flags the tunnels, not the reference |
| obfs | chrome | 0.41–0.49 / 3.25 | flags obfs, not the reference |
| quic | chrome or tls12 | chrome 0.45–2.83, tls12 1.78–2.69 / TCP reference | no like-for-like reference |

Within nDPI's windows (`fix255`) the same holds for https: chrome 0.58–2.74
against the reference's 3.44. For obfs within the windows the closest
4-grams are tls12 at 2.57–3.14, which the reference also reaches
(2.47–2.92): in 5 of 6 runs obfs is not separable there by the model (in
the sixth an inner ClientHello fell into the window, chrome 0.42); it is
flagged anyway because stock nDPI scores it at all (below).

## What this means

1. **nDPI 6.0 as shipped scores none of our TLS, and none of anyone's
   current TLS.** It starts looking after the packet with the ServerHello
   and gives up on the flow if the server writes again before the client
   does. A post-quantum ServerHello (X25519MLKEM768: curl's, Chrome's and
   ours by default) is ~1.1 KB, so the server's first flight never fits one
   segment; OpenSSL/nginx also send session tickets right after. The https
   carrier, every reference and the realistic `proxy` are all "excluded";
   only the pre-PQ, ticketless `proxy0` is scored — and caught. So "nDPI does
   not flag our https" is **not scored, not clean** (the plan's rule), and
   says nothing about us.

2. **nDPI with the gate removed and all three centroids cannot be deployed:
   it flags plain HTTPS.** keepalive (tls13, −1.62) and kasmall (tls12,
   −0.58) are caught within 25 packets in every run, h2page in half. Over
   the whole connection plain keep-alive HTTPS crosses a threshold 10–25
   times as often as the carrier (264–295 vs 11–38 per 1000). This part of
   the earlier draft stands.

3. **But the chrome centroid alone separates the https carrier from every
   reference, at nDPI's own threshold.** The draft of this README concluded
   from (2) that the model "scores ordinary HTTPS as a tunnel more readily
   than it scores our tunnel" and that A3 should not start. **That was
   wrong**: it judged the three centroids together. Taken one by one, tls12
   and tls13 flag the reference and chrome does not (3.25–3.44 ≥ 3.0), while
   chrome flags the https carrier in every run (whole flow 0.58–1.46; within
   255 packets 6/6), both tunnels and obfs. A censor needs one change to
   nDPI's shipped parameters — drop the server-first exclusion, which any
   operator who wants the heuristic to work on 2026 TLS has to drop anyway —
   and one choice — keep the chrome centroid. What it catches is the inner
   browser handshake: a ~1.86 KB client burst (Chromium's post-quantum
   ClientHello) answered by a ~4.2 KB server burst, mid-connection. No
   request/response pattern of the four references gets closer than 3.25.
   **The gate the plan set for A3 ("a detector that flags the https carrier
   and not the keep-alive control") is met.** Caveat: four reference
   scenarios in a lab are not the Internet's HTTPS; the chrome centroid's
   false-positive rate on real traffic is unknown, and a censor would have
   to accept it.

4. **obfs is caught, by stock nDPI.** A stock nDPI labels the flow `TINC`,
   category `VPN` ("Match by port": UDP 655, tinc's IANA port) — no
   heuristic needed. With the TLS heuristics enabled it is flagged
   "Obfuscated TLS traffic" within 255 packets in 6/6 runs (0/6 within 25):
   it is not TLS to nDPI, so the server-first gate that spares every TLS
   flow does not apply. The first hit is a 100–260 B client burst answered
   by 1.4–1.8 KB during the inner browse (4 runs), the dial itself
   (261/250/95/265, 1 run) or an inner ClientHello (2071/2854/182/2614,
   chrome, 1 run), all within the loose tls12 centroid or chrome; the
   random tails (0–146 B) are too small to move bursts of that size.
   → PLAN.md Known Issues.

5. **quic is not judged here.** nDPI does not run this heuristic on QUIC;
   the analyser's whole-flow numbers treat each datagram as a unit, and the
   reference is TLS over TCP, so the "separable" lines for quic compare
   unlike things. An HTTP/3 reference is needed before saying anything.

6. **Found on the way and fixed: the https dialler added ~40 ms to every
   packet.** 20 pings through the carrier on v0.5.2: https 37.6–39.0 ms
   average, obfs 0.28–1.18 ms, quic 0.17–0.36 ms. Each tunnelled packet was
   two TLS records (the `SPTPS_PACKET` request line, then the packet),
   written by two `SSL_write`s, and the dialling socket had no
   `TCP_NODELAY`: the second record waited for the delayed ACK of the first
   (pcap: 48-B record, 41.9 ms, then the 183-B record; the listener, whose
   accepted socket has `TCP_NODELAY`, sends both back to back). Fixed in
   this tree (`core/tincd/PATCHES.md` §41): one record per packet, flushed
   from the loop, or at once when a quarter of `maxoutbufsize` is queued;
   `TCP_NODELAY` on the dialler.

   | | v0.5.2 | hybrid (this tree) |
   |---|---|---|
   | https ping, average | 37.6–39.0 ms | **0.17–0.26 ms** |
   | 4 MiB download through https | 0.19–0.26 s | **0.08–0.12 s** |
   | TCP payload packets of the https flow, whole run | 12165–13666 | **6435–6528** |
   | per-packet overhead (calibrated) | 55 B + a separate 48-B record | 81 B, one record |

   Effect on T1a: none on the verdict. The https carrier sits closer to the
   chrome centroid (0.92–1.46 → 0.58); the framing changed (one record per
   tunnelled packet instead of two), the mechanism was not isolated.
   Window 25 reaches the first inner handshake in 2/3 hybrid runs (0/3
   before): whether it does is a race between the dial's meta exchange and
   the first browse, and fewer packets per exchange make it likelier.

## Verdict for A3 (steady-state countermeasure for https)

**Gate met; A3 is justified.** Not started in this pass (the plan orders
T1c/T1d/T1b/T1e first, and the design is an owner call). What the numbers
say about a design, from the model (not measured on the wire):

- The target is narrow: the inner handshake, not the steady state. The
  carrier's bulk and idle traffic is not what the chrome centroid catches.
- Padding the client burst of each inner handshake by ~1.5 KB moves the
  worst 4-grams seen here (1856/4216/515/792, 1905/4424/590/883,
  1905/4135/62/538) from chrome 0.43–0.86 to 3.9–4.1 (margin ≥ 0.9 against
  every centroid); +1 KB is not enough (2.7–2.9), +2 KB gives 5.2–5.4.
- The dialler sees the inner packets in clear before sealing them, so it
  can tell an inner ClientHello (TCP payload `16 03 01`, handshake type 1)
  and add TLS 1.3 record padding to the records around it
  (`SSL_set_record_padding_callback`: standard, invisible to the peer's
  application, no protocol change). A fixed pad only moves the cluster;
  it has to be random, and the listener side needs the same for the server
  burst if a censor retrains on the padded shape.
- Cost: ~1.5 KB per inner TLS handshake, nothing on bulk.

## Calibration notes

The `tuned` scoring subtracts the tunnel's per-packet overhead, measured
from the 20 calibration pings as the mode of (outer − inner) when the mode
holds at least a third of the packets, else the floor as a lower bound.
https (55 B on v0.5.2, 81 B hybrid) and quic (78 B) are constant; obfs is
not (random tails: 2–62 B floors), so its `tuned` rows are not used. The
reference is tuned at the https overhead of the same run, so the `tuned`
separability line compares https with the reference like for like; for
obfs and quic it is `n/a`. Only keepalive has 4-grams left after tuning
(kasmall, kah2 and h2page have none that nDPI would score), so the tuned
reference is one scenario.

## Not measured

Real-world RTTs (bursts are formed by direction changes; a WAN RTT changes
how inner packets group), more than 3 runs per core, an HTTP/3 reference
for quic, browsers other than Chromium, a wider plain-HTTPS population
(video, websockets, gRPC, long polls), sealed direct paths in a mesh
(DirectSeal rides the obfs frame on the node's Port, 655 by default, so
finding 4 should apply to it by construction — not captured: this lab has
two nodes and no direct path besides the carrier), Windows/Android
diallers (their stacks may segment differently), the padding design above
on the wire.
