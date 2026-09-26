# NAT traversal in tincstack — how two nodes without a public address meet

Stream N, 2026-09-26. Code as of master `7ff64c2`; every behaviour claimed
below is either traced to a function (file and name given) or measured in
`testing/nat-sim/` (evidence under `testing/nat-sim/results/2026-09-26/`).
Anything neither traced nor measured is marked **unmeasured**. All
measurements: Linux 6.8 netfilter inside one lab container; lab RTT 0 ms
unless a row says `rtt40` (netem 20 ms on every gateway's WAN egress: 40 ms
RTT site to site, 20 ms site to relay).

Vocabulary is RFC 4787: *mapping* EIM (endpoint-independent) / APDM
(address-and-port-dependent); *filtering* EIF / ADF (address-dependent) / APDF
(address-and-port-dependent). "Relay-facing" = the external ip:port a NAT gives
a node's UDP socket towards the relay; "peer-facing" = the one it gives the
same socket towards another peer. They are equal only under EIM.

## 0. The short version

- tinc has **one** guess per peer (`n->address`), learns it from three
  indirect sources (edge address, `UDP_INFO`, the `ANS_KEY` reflexive
  address — all "what the relay saw") and one direct source (an authenticated
  datagram from the peer). There is no candidate list, no second reflector, no
  port prediction, no coordinated start, no UPnP/PCP in the build.
- With plain meta connections that is enough for every pair that has at least
  one endpoint-independent, non-poisoned side: **17/25 NAT pairs of the 5x5
  matrix go direct in 6-10 s (core) / 6-24 s (upstream)**, unchanged since
  2026-09-16 (§3.1).
- **The "Linux MASQUERADE is not EIM on kernels >= 6.7" conclusion of
  2026-09-16 was wrong.** MASQUERADE is EIM and port-preserving; what moved
  the ports was the lab gateway's *open INPUT chain*: an unsolicited datagram
  (a peer's early hole-punch probe) leaves a local conntrack entry that
  pushes every later flow onto another port (§3.2, `portmap`). A Linux router
  with its firewall on (new profile `masqfw`) is a clean EIM + APDF NAT, and
  `masqfw x masqfw` goes direct in 4 s, `cgnat x masqfw` in 4 s.
- The pairs that stay relay-only fall in two groups: (a) **poisoned Linux NATs
  without a firewall** (`masq`, the lab's CGN tier) — tinc itself poisons
  them by probing before the other side has sent, and keeps them poisoned by
  re-probing every 2 s; a coordinated start fixes them in the hole-punch
  harness (3/3, 3/3, 2/3 at rtt 0, where uncoordinated probing gets 0/3,
  2/3, 0/3; at rtt 40 ms even uncoordinated harness probing gets 3/3, while
  tinc goes direct in only 4 of 9 attempts, §3.5, §9) — and (b) **APDM
  (symmetric)** against anything filtering on port: a port spray over the NAT's port class fixes them in the
  lab (3/3) but is lab-specific (§9).
- **Carriers break traversal.** `quic`: the relay records the peer's *QUIC
  flow* as its UDP address and hands it out as the hole-punch hint, so every
  port-changing NAT pair loses its direct path (`restricted x restricted`:
  direct in 6 s plain, never with quic). `https`: two nodes that both reach the
  relay over `https` **cannot exchange a single packet** (the relay drops
  every relayed SPTPS packet for a TCP-only neighbour it never keyed with;
  inherited from upstream `TCPOnly = yes`, fixed on this branch by a
  separate flagged commit, §5.2).
  And whatever the carrier, the peer-to-peer direct path is **plain tinc
  UDP** (obfs: 13 % of the datagrams still are), fingerprintable by
  `dpi-fingerprint` (§5.3).
- The mesh is healthier than the pair matrix suggests: with `AutoConnect`
  and `UdpMetaFallback` (both default on) NATed nodes build direct `sf` meta
  links over their confirmed UDP paths, route relay-only pairs through other
  NATed nodes, and **a 20 s relay outage costs the 5-node mesh zero pings**
  (§4, §7.5).

## 1. The state that decides everything

Per peer `node_t` (node.h), the fields NAT traversal lives in:

| field | meaning | written by |
|---|---|---|
| `address`, `sock` | the ONE UDP address (and local socket) we currently believe reaches the peer | `update_node_udp()` (node.c), called from the four places in §2.2 |
| `status.udp_confirmed` | a probe *reply* came back over that address | `udp_probe_h()` sets it; `udp_probe_timeout_handler()` (30 s without a reply) and **every** `update_node_udp()` clear it |
| `minmtu` / `maxmtu` / `mtuprobes` | PMTU of the direct path; `minmtu > 0` is what `tinc info` prints as "directly with UDP" | `try_mtu()`, `udp_probe_h()`; reset by `update_node_udp()` |
| `via`, `nexthop` | static relay (`IndirectData`) and first hop of the shortest meta path | `sssp_bfs()` (graph.c) |
| `status.validkey` | SPTPS session to the peer is up | `receive_sptps_record()` |

Timers and defaults (net_packet.c, protocol_misc.c, net.c): discovery probe
every `UDPDiscoveryInterval` 2 s while unconfirmed, as a burst of
`UDPDiscoveryBurst` 5 (core; upstream sends 1), one keepalive probe every
`UDPDiscoveryKeepaliveInterval` 10 s once confirmed, `UDPDiscoveryTimeout`
30 s without a reply drops the confirmation, `UDPInfoInterval` /
`MTUInfoInterval` 5 s rate-limit the hints, the ping timer runs every 1 s
(`timeout_handler`) and AutoConnect every 5 s (`periodic_handler`).

## 2. Step by step: A and B behind NAT, R public, `ConnectTo = R` on both

### 2.1 Meta connections and edges

1. A dials R over TCP (`do_outgoing_connection()`, net_socket.c; the carrier
   walk of docs/transports.md §2 picks plain/https/quic/...). R never dials A
   (no `Address` for A).
2. After authentication, `ack_h()` (protocol_auth.c) builds the edge R→A:
   `edge->address` = **the source IP of A's meta connection as R sees it +
   the `Port` A advertised in its ACK** (`sockaddr_setport(&c->edge->address,
   hisport)`), `edge->local_address` = A's own local address of that
   connection. ADD_EDGE floods both to every node.
3. `sssp_bfs()` (graph.c) makes B reachable for A with `nexthop = R`,
   `via = B`, and — because B just became reachable — seeds
   `B->address` with that edge address (`update_node_udp(e->to,
   &e->address)`). So **the very first UDP address A has for B is "B's public
   TCP source IP, port 655"**: right for a port-preserving NAT, wrong for any
   NAT that changes the port, wrong in IP for a CGNAT pool that gives UDP and
   TCP different addresses (RFC 4787 REQ-2 "paired" pooling is a SHOULD).

### 2.2 Where A's idea of B's UDP address can come from

| source | carried by | what it is | applied when |
|---|---|---|---|
| edge address | ADD_EDGE (flooded) | B's TCP-observed IP + B's configured port | B becomes reachable, or `address` still unset (`sssp_bfs`) |
| relay's view | `UDP_INFO` (protocol_misc.c `send_udp_info` / `udp_info_h`) | R's `B->address`: the source of the last authenticated **direct** datagram R got from B (or, if B never sent R UDP, the edge address again) | A has no meta connection to B **and** `!udp_confirmed` |
| relay's view | trailing tokens of `ANS_KEY` (protocol_key.c `ans_key_h`, forwarding branch appends `from->address` when R has a PMTU to the destination, `to->minmtu`) | same as above | **always** once `validkey` — also on every rekey, even when the pair is direct (§7.6) |
| the peer itself | any authenticated direct datagram (`process_sptps_udp()`: `if(direct && sockaddrcmp(addr, &n->address)) update_node_udp(n, addr)`) | B's **peer-facing** mapping, the only place tinc ever learns it | the datagram got through A's NAT |

There is no fourth source: no second reflector, no port prediction, no
UPnP/PCP-learned external address (upnp.c only *maps* ports and never tells
anyone, and the core image is built `-Dminiupnpc=disabled`), no candidate
list. `n->address` holds exactly one guess.

Who triggers UDP_INFO: the *receiver* of relayed traffic.
`process_sptps_udp()` (a datagram that arrived via R), `receive_tcppacket_sptps()`
and `req_key_ext_h()` (SPTPS over the meta connection) call
`send_udp_info(myself, from)` when they are the destination: B, receiving A's
first relayed packets, sends UDP_INFO(from=B,to=A) towards A; R, which has a
connection to B, does not trust the originator's address field and substitutes
its own `B->address`; A applies it. Rate limit: one per destination per 5 s at
the originator. Measured: in `pair-masq-masq/core` nodea logs "UDP address of
nodeb set to 100.64.0.3 port 655" (edge) and the relay's view arrives the
same way; in `pair-restricted-restricted/core-quic` the relay's view is the
wrong socket (§5.1).

### 2.3 The first packet from A to B

1. `route()` → `send_packet(B)` → `send_sptps_packet()`: no key yet, so the
   packet is dropped (`!validkey && !connection → return`) and
   `try_tx(B)` → `try_tx_sptps()` → `try_sptps()` → `send_req_key()` starts the
   SPTPS handshake. **Its records never touch UDP**: `send_sptps_data()` sends
   `SPTPS_HANDSHAKE` as REQ_KEY/ANS_KEY over the meta connection, hop by hop
   through R.
2. `try_udp(B)` runs in the same call, but its probes go through
   `send_udppacket()` → `send_sptps_packet()`, which returns silently without a
   key. **No UDP is sent towards B before the key exchange completes** (one
   meta round trip through R). The first packets are lost, not relayed.
3. With the key, data rides the relay: `send_sptps_data()` picks
   `relay = to->via` only if the record fits `to->via->minmtu` (the *direct*
   PMTU) — 0 until B is confirmed — so it picks `nexthop` = R, and sends to R
   over UDP if `R->minmtu` fits, else over TCP (SPTPS_PACKET inside the meta
   connection).
4. Meanwhile `try_udp(B)` sends a burst of 5 probes every 2 s. Each probe's
   destination comes from `choose_udp_address()`: a **process-global** static
   counter sends every third call to `B->address` and the other two to the
   `->reverse->address` of a random edge of B (the edge address of §2.1) with
   a random listen socket, plus one probe to an edge's `local_address` when
   `LocalDiscovery` is on. For a NATed B with one edge (to R) that is "1/3 of
   the burst to the relay's view, 2/3 to TCP-IP:655" — and because the counter
   is shared by all peers, which probe of a burst goes where depends on what
   was probed before.
5. B probes A only when **B** sends something to A (`send_packet` → `try_tx`),
   e.g. the replies to A's pings, or relays for A. Purely one-way traffic A→B
   never makes B punch; any pair that needs both sides to open (restricted,
   port-restricted, Linux masq on both ends) then stays relayed (traced,
   **unmeasured**: every lab scenario uses ping, which is two-way).
6. A probe that gets through is answered (`udp_probe_h()` →
   `send_udp_probe_reply()`, sent back "exactly the way it came in"); the reply
   sets `udp_confirmed`, the sender's address is taken from the authenticated
   datagram (§2.2 last row), `try_mtu()` starts PMTU discovery, and the first
   reply makes `minmtu > 0` = "directly with UDP". Data moves to the direct
   path packet by packet as `minmtu` grows past the packet size.

### 2.4 Simultaneous open, as tinc times it

There is no explicit rendezvous. Both sides start probing when their own
traffic to the other resumes after the key exchange; in the lab (ping from A,
replies from B) the two bursts start within one relay round trip of each
other, and both repeat every 2 s **for as long as there is traffic**. That is
enough for every cone pair. It fails when (a) the two sides' ports towards
each other differ from what the other believes (APDM, §3.4), or (b) the
first probe to arrive is itself what changes the port (§3.2) — the second is
the dominant failure in the lab and tinc makes it permanent by probing every
2 s with no back-off.

## 3. What each NAT type does to it

### 3.1 The matrix, 2026-09-16 vs 2026-09-26

`lab.sh matrix --image both` (run `ww-n-base`), seconds until both sides report
"directly with UDP", `relay` = never within 90 s (traffic flowed via the
relay: PASS for the pairs the table expects there), `tcp` = UDP blocked, meta
connection carried the traffic. All 56 scenarios PASS on both days.

| A x B | core 09-16 | core 09-26 | upstream 09-16 | upstream 09-26 |
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

- core: direct 17/25 UDP pairs (68 %) both days, median 6 s, max 10 s.
- upstream: 18/25 (72 %) on 09-16 (`masq x portrestricted` by luck, see
  README), 17/25 on 09-26; median 12 s, max 18 s / 24 s.
- The core's advantage is speed (5-probe burst), not reach: the same 8 pairs
  are relay-only for both binaries.

New profiles, core, run `ww-n-ext` (`--pairs`):

| A x B | direct after | note |
|---|---|---|
| masqfw x masqfw | 4 s | EIM + APDF on both sides: the edge address (TCP IP:655) is right |
| masqfw x portrestricted | 6 s | |
| masqfw x restricted | 6 s | |
| masq x masqfw | 10 s | the unpoisoned side lets the poisoned one through |
| masqfw x symmetric | relay | APDM vs APDF, §3.4 |
| cgnat x fullcone | 6 s | |
| cgnat x restricted | 6 s | |
| cgnat x masqfw | 4 s | |
| cgnat x masq | relay | both sides Linux NAT with open INPUT (the carrier tier) |
| cgnat x cgnat | relay | same |

### 3.2 Linux MASQUERADE: EIM until poisoned (`masq` vs `masqfw`)

`lab.sh portmap` (nattrav, no tincd; two trials each; full table in
`results/2026-09-26/ext/portmap/summary.md`):

| NAT | 5 destinations, nothing unsolicited | after 2 unsolicited datagrams to the mapping | burn datagram first |
|---|---|---|---|
| `masq` (INPUT open) | all 655 | earlier flows keep 656; every flow opened after a clash: 935 / 647 (trial 1 / 2); sport 4004 → 60376 / 44401 | all 657 |
| `masqfw` (INPUT drops new) | all 655 | all keep 656 / 4004 | all 657 |
| `cgnat` (2 x masq) | all 655 | 766 / 1010; 57361 / 38517 | — |
| `symmetric` (random-fully) | 5 different ports in 600-1023 | 5 different ports; sport 4004: 1909-52737 | — |

Mechanism (conntrack, `results/2026-09-26/pair-masq-masq/core/gw-gw?.txt`):
nodeb's probe `gwb:655 → gwa:655` reaches gwa's own INPUT chain and is
confirmed as a *local* flow `100.64.0.3:655 → 100.64.0.2:655`. nodea's later
flows (to the relay and to nodeb) clash with that reply tuple and are
SNATed to 684; nodea's probes from 684 do the same to gwb (818). Each side
then probes the other's *previous* port every 2 s, which refreshes the
poisoning entries: a permanent deadlock, 216 probes in 90 s, no give-up.
udpprobe's own XPORT/XHOST tests are unsolicited datagrams too — that is
where the "EIM-after-first" classification of 2026-09-16 came from.

Consequences:

- A home router with its firewall on (OpenWrt `wan` input REJECT, every CPE
  firewall) behaves like `masqfw`: **EIM + APDF, port-preserving** — the best
  case after a full cone. `validate-nat` now checks it (`expect masqfw`).
- `masq` remains a real case: any Linux box doing NAT that accepts WAN input,
  and the lab's CGN tier. Carrier-grade NATs that are not Linux boxes do not
  create local entries for unsolicited inbound (**unmeasured** on real
  hardware).
- The failure is self-inflicted and timing-dependent: in the hole-punch
  harness (§9) `masq x masq` goes direct 3/3 at rtt 40 ms without any
  coordination (both first datagrams leave before either arrives) and 0/3 at
  rtt 0; tinc's asynchronous start (§2.4) wins it only sometimes at rtt 40
  (core: `masq x masq` 0/3, `masq x portrestricted` 2/3, `cgnat x cgnat`
  2/3; §3.5).

### 3.3 Per NAT type

| NAT | what tinc does | measured |
|---|---|---|
| full cone (EIM+EIF, port changed) | first probe to TCP-IP:655 is lost; UDP_INFO carries the relay's view (right port); first probe to it passes | direct with every type, 6-10 s |
| address-restricted (EIM+ADF) | as full cone once this side has sent to the peer's IP (any port) | direct with everything incl. symmetric: the symmetric side's own probe arrives from its peer-facing port and is learned from the datagram (README "Why symmetric x fullcone ...") |
| port-restricted (EIM+APDF) | needs the peer's exact peer-facing port and must have sent to it first | direct with cones and `masqfw`; relay with `masq` (poisoned), `symmetric` |
| `masqfw` = Linux MASQUERADE + firewall (EIM+APDF, port-preserving) | like port-restricted, and the edge address is already right | 4 s with itself and `cgnat`; relay with `symmetric` |
| `masq` = Linux MASQUERADE, INPUT open (EIM until poisoned, APDF) | poisoned by the first unsolicited probe (§3.2) | direct only with full-cone/restricted/`masqfw` peers |
| symmetric (`--random-fully`, APDM+APDF) | the relay's view is useless to the peer; only works if the peer accepts its first probe (EIF/ADF) | direct with full cone, restricted; relay with port-restricted, masq, symmetric |
| CGNAT two-tier (`cgnat`: masq behind a masq carrier tier with 10/30 s UDP timeouts) | as `masq`, the carrier tier is the one that gets poisoned | direct with fullcone/restricted/`masqfw` (4-6 s), relay with masq/cgnat; laptop regression (§7) |
| UDP blocked (`udpblock`) | no UDP at all; SPTPS data rides the meta connection (TCP) | all three udpblock pairs carry traffic over TCP, both images |

### 3.4 APDM (symmetric) in the lab is a 424-port NAT

With source port 655 (a privileged port), `MASQUERADE --random-fully` picks
external ports only in 600-1023 (every observed port, 40+ samples); with
source port 4004 it uses 1024-65535. tinc listens on 655, so a lab symmetric
NAT has 424 candidate ports — which is why a spray works in §9. A real CGN
does not keep the port class (RFC 6888 recommends only port-parity/range
preservation as options): **unmeasured** on real hardware.

### 3.5 Latency (`--rtt 40`)

`--rtt 40` puts 20 ms of netem delay on every gateway's external interface
(egress: 40 ms RTT between the two sites, 20 ms to the relay). Runs `ww-n-rtt40`,
`ww-n-rtt40b`, `ww-n-rtt40c`; a cell counts runs in which the pair went
direct, with the seconds to direct.

| A x B | core | upstream | rtt 0 (base run) |
|---|---|---|---|
| masq x masq | **0/3** | 1/3 (4 s) | relay, both |
| masq x portrestricted | 2/3 (10 s, 12 s) | 0/3 | relay, both |
| cgnat x cgnat | 2/3 (4 s, 4 s) | 1/3 (4 s) | relay, both (`ww-n-ext`) |
| masq x symmetric | 0/1 | 0/1 | relay, both |
| masqfw x masqfw | 1/1 (4 s) | 1/1 (4 s) | 4 s (`ww-n-ext`) |
| restricted x restricted | 1/1 (6 s) | 1/1 (12 s) | 6 s / 6 s |

Latency turns the poisoned pairs from "never" into a **coin flip**: 4 of 9
core attempts and 2 of 9 upstream attempts at the three poisoned pairs went
direct, with no pattern a user could rely on (n=3 per cell; the core/upstream
difference is not significant). The harness does better — `masq x masq`
3/3 with plain `first` at rtt 40 (§9) — because its two sides start within
milliseconds of each other through the rendezvous; tinc's two sides start
probing whenever their own key exchange and 2 s probe timer happen to fire,
up to a second or more apart, so whether the first unsolicited probe lands
before the peer's own outgoing packet is luck. That is the argument for a
coordinated start (fix 4), not for tuning timers.

## 4. Relay choice, upgrade and downgrade, and the mesh

- **Which relay.** `nexthop` = first hop of the shortest path over the meta
  graph (`sssp_bfs()`, edge weight = measured RTT); `via` = static relay only
  with `IndirectData = yes` on the path (`OPTION_INDIRECT`). With `via != n`
  tinc never tries UDP to the peer at all (`try_tx_sptps()` forwards to the
  relay only). `TCPOnly` (option on either side) skips SPTPS-over-UDP
  entirely: data rides the meta connection (`send_sptps_data()` `tcponly`).
- **How data is relayed.** Per hop: over UDP if the hop's PMTU is known,
  otherwise inside the meta connection; a relaying node re-sends with
  `send_sptps_data(to, from, ...)` and the same UDP/TCP choice for its own next
  hop (net_packet.c `process_sptps_udp`, `receive_tcppacket_sptps`,
  protocol_key.c `req_key_ext_h`). Records stay end-to-end SPTPS; a relay sees
  ids and sizes, not content. **A relay forwards a TCP-borne SPTPS packet
  only if it has its own valid key with the destination**
  (`receive_tcppacket_sptps`: `if(to->status.validkey) send_sptps_data(...)`)
  — see §5.2 for what that does to `https`.
- **Upgrade to direct** is continuous and traffic-driven: every sent packet
  calls `try_tx()`, which keeps probing while `!udp_confirmed`. There is no
  give-up and no back-off: a relay-only pair keeps sending a 5-probe burst
  every 2 s for as long as it has traffic.
- **Downgrade**: 30 s without a probe reply (`udp_probe_timeout_handler`), or
  any `update_node_udp()` (a new hint, a rekey, §7.6); the next packet goes
  via the relay again while probing resumes. A pair that goes idle loses its
  confirmation after 30 s (keepalive probes are only sent from `try_udp()`,
  i.e. while there is traffic; meta neighbours additionally get `try_tx()`
  from the 1 s ping timer).
- **The mesh routes around the relay.** `AutoConnect` (default on) makes each
  node dial others; a NATed peer's advertised address is not dialable, so the
  dial fails, and `UdpMetaFallback` (default on, docs/transports.md §2.2)
  then opens an `sf` meta connection over the pair's *confirmed* UDP path.
  Those links become graph edges, so a pair that cannot go direct is routed
  through a NATed node both can reach.

`lab.sh mesh` — 5 nodes (fullcone, restricted, portrestricted, masq,
symmetric), each behind its own NAT, one public relay, every ordered pair
pinging at 1 pps:

| | core | upstream |
|---|---|---|
| pairs direct | 8/10 and 7/10 (two runs) | 7/10 and 8/10 (two runs) |
| time until every traversable pair is direct | 8-10 s | 34 s and 61 s |
| per-pair time to direct | 6-10 s | 9-61 s |
| relay load, steady state, 20 pings/s offered in total | 2.0-7.0 pkt/s, 171-1040 B/s | 13-18 pkt/s, 1.9-2.6 kB/s |
| how the relay-only pairs travel | through another NATed node over `sf` meta links ("forwarded via m1") | through the relay |
| meta connections per node at the end | 3-4 (`sf` links to the peers it has a confirmed path to) | 1 (the relay) |

(`results/2026-09-26/ext/mesh/`.) The relay's load in the core mesh is its own
keepalives plus at most one relayed pair: the "relay" of a relay-only pair
is usually a NATed full-cone or restricted node, which is cheap for the relay
but puts the forwarding load on that user's uplink without asking — a policy
question N2 should at least surface (e.g. an option to refuse to relay).
`portrestricted x masq` went direct in one core run and not in the other: it
is exactly the race of §3.2.

## 5. What the carriers change

The meta carrier decides three things for traversal: which socket the relay
sees, whether SPTPS data to the relay is UDP at all, and what the direct path
looks like on the wire.

| carrier | meta to relay | SPTPS data to the relay | relay's view of the node (`R->A->address`, the hole-punch hint) | peer-to-peer direct path |
|---|---|---|---|---|
| plain | TCP | plain UDP from the data socket | data socket's relay-facing mapping (right) | plain SPTPS UDP |
| sf | UDP single flow | same flow | the sf flow = data socket (right) | plain SPTPS UDP |
| obfs | sealed UDP single flow | sealed, same socket | data socket (right) | **plain** SPTPS UDP unless an obfs link to that peer is up (`obfs_wrap_send()` returns `OBFS_SEND_PLAIN` otherwise) |
| quic | QUIC from a **fresh ephemeral socket** (transport_quic.c, "like every QUIC client") | QUIC DATAGRAM frames on that flow (`send_datagram` hook) | **the QUIC flow's mapping** — `cb_recv_datagram()` hands the record to `process_sptps_udp()` with the QUIC peer address, which runs `update_node_udp()` (wrong socket) | plain SPTPS UDP |
| https | TLS/TCP, link marked `OPTION_TCPONLY \| OPTION_INDIRECT` (https.c `become_established`) | inside TLS | never set from UDP | none: the node is `indirect`, no UDP is attempted to it |

### 5.1 quic hands out the wrong port

`pair-restricted-restricted/core-quic` (run `ww-n-ext`, quic rerun):
the relay logs "UDP address of nodea set to 100.64.0.2 port 41973" — the QUIC
dial socket's mapping — and forwards that in UDP_INFO/ANS_KEY; nodea's data
socket is mapped to 40655. nodeb probes 41973 (a QUIC client socket that drops
non-QUIC) and TCP-IP:655; neither is the right port. Result:

| pair (core) | plain (base run) | `--transport quic` |
|---|---|---|
| fullcone x fullcone | direct 6 s | **relay** (FAIL) |
| restricted x restricted | direct 6 s | **relay** (FAIL) |
| masqfw x masqfw | direct 4 s (`ww-n-ext`) | direct 4 s |
| masq x masq, masq x portrestricted, masq x symmetric, portrestricted x symmetric, symmetric x symmetric | relay | relay |

(The first quic run of the day is void: the relay's host record did not
advertise `quic`, so every node fell back to plain. The lab now writes
`Transports`/`QuicPort`/`HttpsPort` into the relay's host record when
`--transport` is set; the table is the rerun, meta carrier `relay:quic` on
every row.)

Only pairs whose edge address is already right (port-preserving EIM on both
sides: `masqfw x masqfw`, 4 s) survive. Every NAT that changes the port loses
its direct path under quic.

### 5.2 https: relayed traffic between two https nodes is dropped

`matrix --transport https` (4 pairs, all FAIL, ping 0): both NATed nodes reach
the relay over https, so both links are `TCPONLY|INDIRECT`. The relay receives
nodea's `SPTPS_PACKET` for nodeb ("Got SPTPS_PACKET from nodea ... 21 117",
repeatedly) and never forwards it: `receive_tcppacket_sptps()` forwards only
`if(to->status.validkey)`, and the relay never starts SPTPS with nodeb because
`try_tx_sptps()` returns immediately for a TCP-only neighbour ("we'll only use
cleartext PACKET messages anyway"). `tinc info` shows the symptom:
"Reachability: indirectly via nodea" (nodea's own name — `via` resolves to
`myself` through the indirect edges). This is total loss of connectivity
between https nodes that are not directly connected, not a traversal
weakness. `testing/transports/https-carrier-test.sh` only covers two directly
connected nodes, which is why it was not seen.

It is **inherited from upstream**: the same topology with `TCPOnly = yes` on
both NATed nodes instead of a carrier (run `ww-n-tcponly`) delivers nothing
with upstream tinc 1.1pre18 either.

| topology (NATed nodes → public relay) | upstream | core `7ff64c2` | core + fix (`ww-n-fix`) |
|---|---|---|---|
| `TCPOnly = yes` on both, restricted x restricted / fullcone x fullcone | ping 0 / 0 | ping 0 / 0 | ping ok / ok |
| `--transport https`, 4 pairs | — | ping 0 on 4/4 | ping ok on 4/4, PASS (graded `tcp`) |
| `matrix --quick` regression (5 pairs) | — | — | 5/5 PASS |

The fix (a separate, flagged commit on this branch) removes the `validkey`
gate in `receive_tcppacket_sptps()`; its UDP twin in `process_sptps_udp()`
never had one, and relaying needs no key of the relay's own.

### 5.3 The direct path is plain tinc UDP, whatever the carrier

`--capture` records everything that crosses between the two NATed sites
(gwa's WAN side, `udp and host gwb`) and classifies it with
`dpi-fingerprint`:

| pair, carrier (run `ww-n-cap`) | meta links of nodea | datagrams between the sites | start with 6 zero bytes (`udp_null_dstid`) | 51-byte probes (`udp_probe_size`) | constant source id | dpi-fingerprint verdict |
|---|---|---|---|---|---|---|
| restricted x restricted, plain | relay:plain, nodeb:sf | 181 | 111 (61 %) | 46 | absent | `udp_null_dstid`, `udp_probe_size` PRESENT |
| restricted x restricted, obfs | relay:obfs, nodeb:obfs | 417 | 56 (13 %) | 44 | absent | `udp_probe_size` PRESENT |
| masq x restricted, obfs | relay:obfs, nodeb:obfs | 402 | 53 (13 %) | 33 | absent | `udp_probe_size` PRESENT |
| masqfw x masqfw, quic | relay:quic, nodeb:sf + nodeb:quic | 304 | 97 (32 %) | 33 | PRESENT (`bc4facaf7de5`) | `udp_constant_srcid`, `udp_probe_size` PRESENT |

All four pairs went direct (6, 6, 6, 4 s). Reading the rows:

- **plain**: the classic tinc UDP picture — most datagrams carry the zero
  destination id, 51-byte PMTU probes.
- **obfs**: AutoConnect built a direct *obfs* meta link between the two
  NATed nodes, and the zero-prefixed share drops from 61 % to 13 %, which is
  below `dpi-fingerprint`'s threshold — but 53-56 datagrams per 90 s still
  start with 6 zero bytes and 33-44 are exactly 51 bytes. "Mostly sealed"
  is not "looks like the declared protocol": one plain SPTPS datagram is
  enough for a classifier that knows tinc. (The first obfs capture of this
  stream, taken before the `sf`/obfs side link had formed, was 40/40 plain.)
- **quic**: the node reaches its peer through a direct QUIC connection (the
  11 datagrams of 1200 bytes are its Initials) *and* a plain `sf` link, and
  the data path is plain tinc UDP with a constant source id — the worst of
  the three.

So a node that chose `quic` or `obfs` to hide its meta connection still puts
on the wire between the two sites datagrams that start with 6 zero bytes,
51-byte probes and (quic) a constant 6-byte node id; `obfs` reduces but does
not remove them. `https` nodes are TCP-only and send no peer UDP at all (their
traffic is relayed, §5.2). By the owner's rule (a carrier must look like the protocol
it claims, failure paths included) the direct path is the uncovered one. This
also interacts with every traversal technique in §9: anything that makes
more pairs direct makes more plain tinc UDP.

## 6. IPv4 and IPv6

- `n->address` is one address of one family. `update_node_udp()` picks the
  first listen socket of that family.
- The edge address has the family of the meta connection (§2.1). A dual-stack
  node whose connection to the relay is IPv6 advertises only an IPv6 edge;
  its UDP_INFO/ANS_KEY hint is the relay's IPv6 view.
- `choose_udp_address()` probes only `n->address` and the edges' addresses;
  there is no "also try the other family". An IPv4-only peer therefore never
  learns the dual-stack node's IPv4 mapping unless the dual-stack node's own
  probe reaches it (the authenticated-datagram rule).
- Lab: `--ipv6 both` gives every site a routed 2001:db8::/32 prefix behind a
  stateful ip6tables firewall (inbound only `ESTABLISHED,RELATED`: the CPE
  default), the relay is dual-stack and lists its IPv6 address first,
  `AddressFamily = any`. `--ipv6 a` does that for nodea only.

| pair | IPv4 only (base run) | `--ipv6 both` | `--ipv6 a` (only nodea dual-stack) |
|---|---|---|---|
| masq x masq | relay | **direct in 4 s**, over 2001:db8:b::5 | — |
| symmetric x symmetric | relay | **direct in 4 s** | — |
| masq x restricted | direct in 6 s | — | **relay** (FAIL of an expected-direct pair) |

- Both sides on IPv6: the stateful v6 firewalls are EIM + APDF with no
  translation, both sides probe each other's real address, and the
  NAT-hardest IPv4 pairs go direct faster than any IPv4 pair.
- One side dual-stack is **worse than no IPv6 at all**: nodea's relay link is
  IPv6, so nodeb (IPv4 only) gets nodea's IPv6 address as the edge address
  and as the hint ("UDP address of nodea set to 2001:db8:a::5 port 655"), and
  logs "Error sending UDP SPTPS packet to nodea (2001:db8:a::5 port 655):
  Network is unreachable" 298 times in 90 s. nodeb never sends to nodea's IPv4
  address, so its address-restricted filter never opens for nodea's IPv4
  probes (nodea does know nodeb's IPv4 mapping, 100.64.0.3:41655). W10.

## 7. Events

| event | what the code does | measured |
|---|---|---|
| NAT mapping expires while idle | no traffic → no probes → `udp_confirmed` dropped after 30 s; the next packet goes via the relay and probing restarts from the current hints | covered indirectly by the laptop arm (carrier tier 10/30 s UDP timeouts) |
| mapping changes port (NAT reboot, CGN rebinding) | the peer's next authenticated datagram from the new port updates `n->address` (`process_sptps_udp`), SPTPS packets carry node ids so they are recognised from any source (`lookup_node_id`) | laptop `mapping-dropped`: core 4 s, upstream FAIL (61 s, never recovers: its socket stays black-holed) |
| sleep/resume (> 60 s, i.e. > 2 × `UDPDiscoveryTimeout`) | `timeout_handler()`: "Awaking from dead", close all connections, `UDPRebindOnWake` rebinds the UDP socket to a fresh port (`rebind_udp_sockets`) | laptop `sleep-resume`: core 6 s, upstream 12 s |
| sleep 30-60 s | no "dead" detection, no rebind; confirmation lost after 30 s, recovery through normal probing | **unmeasured** |
| peer restart | new SPTPS session, address from the edge again, probing from scratch | laptop `peer-restart`: 8 s both |
| relay restart | meta connections drop; the graph loses every edge through the relay; nodes with direct `sf` links keep routing; others are unreachable until the relay is back | §7.5 |
| rekey (`KeyExpire`, default 3600 s) | §7.6 | §7.6 |

### 7.5 Relay restart

`lab.sh mesh --image core --relay-down 20`: after the mesh settled, the
relay's tincd is stopped for 20 s while one direct pair and one relay-only
pair ping at 5 pps (`ping -D`, gaps from the timestamps).

| config | direct pair: replies while relay down / longest gap / first reply after restart | relay-only pair: same |
|---|---|---|
| core, defaults (`UdpMetaFallback = yes`) | 96 of ~100 / 0.2 s / — (never interrupted) | 96 / 0.2 s / — (was already routed through a NATed node over `sf`) |
| core, `UdpMetaFallback = no` | **0 / 30.5 s / 10.5 s** | **0 / 30.7 s / 10.7 s** |
| upstream (no `sf`, no AutoConnect side links) | **0 / 30.8 s / 10.7 s** | **0 / 30.8 s / 10.6 s** |

Reachability is a property of the meta graph (`check_reachability()`,
graph.c), not of the UDP path. When the only meta edges a NATed node has
run through the relay, a relay restart makes every peer unreachable and
`send_packet()` drops traffic for it — **including pairs that have a
confirmed, working direct UDP path.** The outage is the relay's downtime plus
~10 s of reconnect and re-keying. With the default `UdpMetaFallback`, the
`sf` side links keep the graph connected and the relay's outage is invisible.
W12.

### 7.6 Rekey resets a direct path — unless an `sf` link carries it

`send_key_changed()` → `sptps_force_kex()`; the handshake records travel as
`ANS_KEY`. If they go through the relay, the relay appends the reflexive
address (§2.2) and `ans_key_h()` applies it with `update_node_udp()`, which
clears `udp_confirmed` and the PMTU state even when the address is
unchanged or worse than the confirmed one (symmetric: the relay-facing port is
not the peer-facing one). `lab.sh rekey restricted symmetric --keyexpire 20`,
120 s window after the pair went direct:

| image (config) | KeyExpire | rekeys | peer-address resets A / B | A→B packets via relay / direct | relayed share |
|---|---|---|---|---|---|
| upstream | 20 s | 6 | 46 / 36 | 206 / 464 | 30.7 % |
| core, `UdpMetaFallback = no` | 20 s | 6 | 48 / 36 | 61 / 649 | 8.6 % |
| core, defaults | 20 s | 6 | 0 / 0 | 0 / 641 | 0 % |
| core, defaults (control) | 3600 s | 0 | 0 / 0 | 0 / 631 | 0 % |

The code path is the same in the core and upstream; the core hides it only
because AutoConnect + `UdpMetaFallback` give the pair a direct `sf` meta
connection, so the rekey's `ANS_KEY` goes peer to peer and no relay appends
an address (`rekey/*/meta.txt`). Without that link each rekey costs ~8 address
flips (relay hint → the peer's real datagram → ...) and a few relayed
packets; no ping was lost in any run (578/600 replies everywhere, the same
count as without rekeys). At the default `KeyExpire` of 3600 s the cost is a
few seconds of relaying per hour: real, measurable, not urgent (W7).

## 8. Weak points

Numbered so the fix list (§10) can point at them. "Proof" = where the lab
shows it.

| # | weak point | where | effect | proof |
|---|---|---|---|---|
| W1 | `https` links are `TCPONLY\|INDIRECT`; a relay forwards a TCP-borne SPTPS packet only with its own key to the destination, and never keys with a TCP-only neighbour | https.c `become_established`, net_packet.c `receive_tcppacket_sptps` / `try_tx_sptps` | two nodes that reach the relay over https exchange **no data at all** | `matrix --transport https`: 4/4 FAIL, ping 0 |
| W2 | the relay records a quic node's UDP address from the QUIC flow and hands it out as the hole-punch hint | transport_quic.c `cb_recv_datagram` → `handle_incoming_vpn_packet_decap` → `process_sptps_udp` → `update_node_udp` | every port-changing NAT pair loses its direct path under quic | `pair-restricted-restricted/core-quic`: relay (plain: 6 s) |
| W3 | the peer-to-peer direct path is plain SPTPS UDP for every carrier (obfs only wraps once an obfs link to that very peer is up) | net_packet.c `send_sptps_data`, obfs.c `obfs_wrap_send` | the traffic a disguising carrier exists to hide is on the wire between the sites | `--capture` + `dpi-fingerprint` (§5.3): plain 111/181 zero-prefixed, quic 97/304 + constant id, obfs 56/417; 51-byte probes in every row |
| W4 | probing starts unsolicited and never backs off: the first probe poisons an open-INPUT Linux NAT, every later burst (5 every 2 s, forever) keeps it poisoned | net_packet.c `try_udp`; no rendezvous | `masq x masq`, `masq x portrestricted`, `cgnat x cgnat`, `cgnat x masq` relay-only | conntrack in `pair-masq-masq/core`; 216 probes / 90 s |
| W5 | one address per peer, three indirect sources that all mean "the relay's view", no candidate list | node.h `address`, §2.2 | APDM peers are unreachable unless the other side is EIF/ADF | matrix: 5 of 8 relay-only pairs involve `symmetric` |
| W6 | `choose_udp_address()` spends 2 of 3 unconfirmed probes on the edge address (TCP IP + configured port) and its counter is process-global | net_packet.c | for port-changing NATs 2/3 of every burst is wasted; which probe goes where depends on unrelated peers | traced; the core's 5-probe burst hides it (core 6-10 s vs upstream 6-24 s) |
| W7 | every `update_node_udp()` clears `udp_confirmed` and PMTU, and `ans_key_h()` applies the relay's reflexive address even on a confirmed direct path | node.c, protocol_key.c | each SPTPS rekey (default hourly) drops a direct pair to the relay until re-confirmed; on APDM pairs the relay's address is also the wrong one | `rekey` (§7.6) |
| W8 | no UDP is sent to a peer before the SPTPS key is up; the first packets are dropped, not relayed | net_packet.c `send_sptps_packet` | first ping lost on every new pair; time-to-direct is key RTT + 1-2 bursts | traced; every matrix cell includes it |
| W9 | a side punches only when it sends; one-way traffic never opens the receiving side | net_packet.c `send_packet` → `try_tx` | receive-only nodes behind APDF/ADF stay relayed | traced, **unmeasured** |
| W10 | a dual-stack node's hint has the family of its relay connection; there is no cross-family probing | node.c, graph.c | IPv4-only peers of a node whose relay link is IPv6 depend on that node's own probe | §6 |
| W11 | no UPnP/PCP/NAT-PMP in the build, and upnp.c never learns the external address even when compiled | core/Dockerfile.build `-Dminiupnpc=disabled`, upnp.c | a router that would open a port on request is never asked | traced |
| W12 | the relay is a single point of failure for every pair without an `sf` side link — direct ones included, because reachability is a meta-graph property | graph.c `check_reachability`, UdpMetaFallback | with `UdpMetaFallback = no` (or an operator who removes `sf`) a 20 s relay restart cuts **direct and relayed** pairs for 30.5-30.7 s | §7.5 |

## 9. The relay-only pairs: techniques, measured

The harness is `nattrav punch` (testing/nat-sim/nattrav.py): two processes
behind the real lab gateways, a rendezvous on the public side, each side
advertises an address and then sends a datagram to the peer every 100 ms for
8 s. It isolates the NAT question from tincd; every row is 3 trials. Evidence:
`results/2026-09-26/ext/punch/` (`punch.jsonl`, `summary.md`, first-trial
conntrack of every gateway).

strategy: `first` = advertise what the rendezvous (first destination) saw -- what tinc's UDP_INFO/ANS_KEY carry today; `second` = advertise what a second reflector port on the same host saw; `burn` = one throwaway datagram before the rendezvous, advertise the rendezvous' view; `+sprayN` = also send to N ports around the advertised one; `+sync` = neither side sends to the other before the rendezvous says GO to both at once; `+rttN` = netem on every gateway's external interface.

| A x B | strategy | bidirectional contact | median time to contact | advertised ports (a/b, per trial) |
|---|---|---|---|---|
| masq x masq | first | 0/3 | - | 655/655 |
| masq x masq | second | 0/3 | - | 655/655 |
| masqfw x masqfw | first | 3/3 | 0.50 s | 655/655 |
| masqfw x masqfw | second | 3/3 | 0.50 s | 655/655 |
| masq x portrestricted | first | 2/3 | 0.00 s | 655/41655 |
| masq x portrestricted | second | 1/3 | 0.50 s | 655/41655 |
| masqfw x portrestricted | first | 3/3 | 0.50 s | 655/41655 |
| masqfw x portrestricted | second | 3/3 | 0.00 s | 655/41655 |
| masq x symmetric | first | 0/3 | - | 655/1003 655/744 655/766 |
| masq x symmetric | second | 0/3 | - | 655/817 655/920 655/972 |
| cgnat x cgnat | first | 0/3 | - | 655/655 |
| cgnat x cgnat | second | 0/3 | - | 655/655 |
| symmetric x symmetric | first | 0/3 | - | 1002/609 673/702 888/983 |
| symmetric x symmetric | second | 0/3 | - | 608/929 843/835 886/939 |
| restricted x masq | first | 3/3 | 0.49 s | 40655/655 |
| restricted x masq | second | 3/3 | 0.00 s | 40655/655 |
| masqfw x symmetric | first+spray848 | 2/3 | 0.50 s | 655/699 655/811 655/861 |
| portrestricted x symmetric | first+spray848 | 3/3 | 0.01 s | 40655/829 40655/931 40655/976 |
| masq x symmetric | first+spray848 | 0/3 | - | 655/692 655/702 655/719 |
| symmetric x symmetric | first+spray848 | 0/3 | - | 653/983 665/896 896/1005 |
| masq x masq | first+rtt40 | 3/3 | 0.04 s | 655/655 |
| masq x symmetric | first+spray848+sync+rtt40 | 3/3 | 0.12 s | 655/676 655/767 655/975 |
| masqfw x symmetric | first+spray848+sync+rtt40 | 3/3 | 0.13 s | 655/654 655/757 655/795 |
| cgnat x symmetric | first+spray848+sync+rtt40 | 3/3 | 0.07 s | 655/1012 655/777 655/846 |
| masq x masq | first+sync | 3/3 | 0.00 s | 655/655 |
| masq x portrestricted | first+sync | 3/3 | 0.00 s | 655/41655 |
| cgnat x cgnat | first+sync | 2/3 | 0.00 s | 655/655 |
| masq x masqfw | first+sync | 2/3 | 0.00 s | 655/655 |
| masq x masq | first+sync+rtt40 | 3/3 | 0.04 s | 655/655 |
| masq x portrestricted | first+sync+rtt40 | 3/3 | 0.04 s | 655/41655 |
| cgnat x cgnat | first+sync+rtt40 | 3/3 | 0.06 s | 655/655 |
| masq x symmetric | first+spray848+rtt40 | 3/3 | 0.14 s | 655/1012 655/812 655/886 |
| masqfw x symmetric | first+spray848+rtt40 | 3/3 | 0.14 s | 655/604 655/768 655/897 |
| symmetric x symmetric | first+spray848+rtt40 | 3/3 | 0.14 s | 670/912 729/869 957/989 |
| symmetric x symmetric | first+spray848+sync+rtt40 | 1/3 | 0.06 s | 660/810 767/722 892/999 |
| masq x portrestricted | first+rtt40 | 3/3 | 0.04 s | 655/41655 |
| cgnat x cgnat | first+rtt40 | 3/3 | 0.06 s | 655/655 |

Read against each other:

| pair | `first`, rtt 0 | `first`, rtt 40 | `first+sync`, rtt 0 | `first+sync`, rtt 40 | tinc core, rtt 40 (§3.5) |
|---|---|---|---|---|---|
| masq x masq | 0/3 | 3/3 | 3/3 | 3/3 | 0/3 |
| masq x portrestricted | 2/3 | 3/3 | 3/3 | 3/3 | 2/3 |
| cgnat x cgnat | 0/3 | 3/3 | 2/3 | 3/3 | 2/3 |

The NATs are not the obstacle: two processes that start within milliseconds
of each other get through every poisonable pair once there is any latency,
and a coordinated start gets through at rtt 0. tinc gets through the same
pairs at the same latency in 4 of 9 attempts — the difference is tinc's own
uncoordinated, repeating probe schedule.

### 9.1 Per technique

| technique | gain (pairs made direct, lab) | cost | risk | wire visibility |
|---|---|---|---|---|
| **coordinated start** (`--sync`: the relay tells both sides "go" at once; nobody probes a peer before that) | at rtt 0 (where uncoordinated `first` gets 0/3, 2/3, 0/3): `masq x masq` 3/3, `masq x portrestricted` 3/3, `cgnat x cgnat` 2/3; at rtt 40 3/3 each (as plain `first`) | one message pair through the relay per attempt; implementation: a new request (or a flag on UDP_INFO) and suppressing unsolicited probes until it | if one side's clock/queue delays it by more than the one-way latency, it degrades to today's race; a stale GO after a mapping change repeats the poisoning | none beyond today's probes (fewer of them) |
| **latency** (none — just `rtt40`) | in the harness plain `first` at rtt 40 is 3/3 on `masq x masq`, `masq x portrestricted`, `cgnat x cgnat`; real tinc at rtt 40 wins the race only by luck: 0/3 `masq x masq`, 2/3 `masq x portrestricted`, 2/3 `cgnat x cgnat` (core, §3.5) | 0 | not a fix: nondeterministic | — |
| **back-off after a failed round** (stop probing an unconfirmed peer for > the unreplied UDP conntrack timeout, 30 s, then restart coordinated) | lets poisoned `masq`/`cgnat` entries expire so a coordinated round can start clean; **unmeasured** as such (the `sync` rows start clean by construction) | +30-60 s to direct after a lost race | slower direct path for pairs that would have won a later race | fewer probes on the wire |
| **second reflector** (`second`: advertise what another reflector port saw) | none: 0/3 `masq x masq`, 1/3 vs 2/3 `masq x portrestricted`, 0/3 `masq x symmetric` | a second relay socket | — | — |
| **burn** (throwaway datagram before the relay) | none: `burn` keeps the port (portmap C) | — | — | — |
| **port spray over the NAT's port class** (`--spray 848`: ±424 around the advertised port) | APDM x APDF at rtt 0: `portrestricted x symmetric` 3/3, `masqfw x symmetric` 2/3, `masq x symmetric` 0/3; at rtt 40 ms: `masq x symmetric`, `masqfw x symmetric` 3/3 without `sync`, and `cgnat x symmetric` 3/3 with it | 849 datagrams every 100 ms from the EIM side until contact (~0.1 s in the lab, 34 kB per round); 849 conntrack entries on both gateways | works only because Linux keeps 655 in the 600-1023 class; a CGN allocating from 1024-65535 needs 64k probes — infeasible; must only ever be sent from the EIM side (an APDM side would burn one port per probe) | a burst to 849 ports looks like a port scan to any IDS, whatever the carrier; conflicts with "look like the declared protocol" |
| **birthday** (many flows on both sides) | the only option for symmetric x symmetric. Spray on *both* sides is a birthday attack inside the lab NAT's 424-port class: 0/3 at rtt 0, **3/3 at rtt 40 ms** without `sync`, 1/3 with `sync` (n=3 each, the difference is not significant). Many-sockets birthday against a 64k class: **unmeasured** | hundreds of sockets/mappings per side; CGN port quotas | exhausts per-subscriber port blocks on real CGNs | as port spray, both directions |
| **separate mappings** (a dedicated socket per peer) | none for these pairs: the problem is who sends first, not port sharing | one socket per peer | loses the single-port property the relay's view depends on | more distinct flows |
| **UPnP-IGD / PCP / NAT-PMP** | on a home router that answers: that side becomes a full cone with a known port → every pair with it goes direct; nothing for a CGN tier unless the carrier offers PCP | link miniupnpc (currently disabled), learn the external address (upnp.c does not), advertise it | library attack surface; a router-side mapping is a permanently open UDP port that answers active probes | LAN-side only (SSDP/SOAP), invisible on the WAN; the open port itself is visible to scanners |
| **IPv6** | stateful v6 firewalls are EIM + APDF with no translation: a coordinated or simply two-sided start goes direct | nothing new if both sides have global v6 | W10 (family mixing) | as today |

### 9.2 What this means for masq x masq, masq x portrestricted, masq x symmetric

- `masq x masq` and `masq x portrestricted` are **not** mapping problems — both
  NATs are EIM and port-preserving. They are an ordering problem that tinc
  creates: the first unsolicited probe changes the peer's port, and tinc never
  stops probing long enough for it to change back. A coordinated start fixes
  them 3/3 in the harness at 40 ms RTT; the same logic applies to `cgnat`.
- `masq x symmetric` is a mapping problem on the symmetric side plus the
  ordering problem on the `masq` side. Spray + coordinated start fixed it 3/3
  in the lab, but only because the lab's symmetric NAT stays in a 424-port
  class; on a real CGN this pair stays relayed. It should stay relayed rather
  than grow a port scanner — the relay path works.

## 10. Ranked fixes for stream N2

Ranked by what a user loses today, not by how interesting the fix is. Each
entry: the pairs it changes, the lab proof that must turn green, the code.

1. 🔴 **P0 — https: relayed data between https nodes is dropped (W1).**
   **Status: fixed on the stream N branch** by a separate commit flagged
   `[CORE FIX - flagged, stream N]` (the `validkey` gate removed); N2 only
   reviews it and wires the proof into `make check`. Measured with the fix
   (`ww-n-fix`): https 4/4 PASS, `TCPOnly = yes` 2/2 ping ok, `matrix
   --quick` 5/5 PASS.
   Pairs: every pair of nodes that are not directly connected and reach their
   common neighbour over `https` — 0 % delivery without the fix, not "relayed".
   Fix as committed: let a relay forward TCP-borne SPTPS packets without its own key to the
   destination (the `validkey` gate in `receive_tcppacket_sptps()` guards
   nothing the relay needs: it does not decrypt), or key with TCP-only
   neighbours instead of returning early in `try_tx_sptps()`. Check the UDP
   twin (`process_sptps_udp` relay branch) for the same gate.
   Proof: `lab.sh matrix --image core --transport https --pairs
   "restricted/restricted masq/masq portrestricted/portrestricted
   symmetric/restricted"` → ping ok on all 4 (today 4/4 FAIL), plus a
   `https-carrier-test.sh` case with a relay in the middle; `--node-conf
   TCPOnly=yes` row for the upstream comparison (§5.2).
   Code: net_packet.c `receive_tcppacket_sptps`, `try_tx_sptps`; https.c
   `become_established` (the reason the link is TCP-only).

2. 🟠 **P1 — quic: the relay hands out the QUIC flow as the node's UDP
   address (W2).**
   Pairs: every expected-direct pair with a port-changing NAT on either side
   loses its direct path under `quic` (lab: `restricted x restricted`,
   `fullcone x fullcone` relay instead of 6 s; only port-preserving EIM pairs
   such as `masqfw x masqfw` survive).
   Fix: a datagram that arrived inside a carrier flow must not move
   `n->address` (`handle_incoming_vpn_packet_decap()` → a `process_sptps_udp`
   variant that skips `update_node_udp` and `send_udp_info`); the relay then
   needs another way to learn the node's *data-socket* mapping — either the
   node keeps probing the relay from the data socket (plain UDP on the wire:
   see fix 3 before choosing) or the relay does not advertise a reflexive
   address for carrier-borne nodes at all.
   Proof: `matrix --image core --transport quic --pairs "restricted/restricted
   fullcone/fullcone masqfw/masqfw"` → direct on all three.
   Code: transport_quic.c `cb_recv_datagram`, net_packet.c
   `handle_incoming_vpn_packet_decap` / `process_sptps_udp`, protocol_misc.c
   `send_udp_info`.

3. 🟠 **P1 — decide what the peer-to-peer path is when the carrier disguises
   the meta connection (W3).**
   Pairs: none change reachability; every direct pair of a node on
   quic/obfs puts plain (obfs: partly plain), fingerprintable tinc UDP
   between the sites.
   Options (a decision, not a patch): (a) `DirectData = no` implied by a
   disguising carrier — relay everything through the carrier; costs the relay
   bandwidth measured in §4; (b) seal peer-to-peer datagrams the way obfs
   seals its link, from the first probe; (c) accept and document it.
   Proof: `--capture` rows of §5.3 flip from `udp_null_dstid PRESENT` to
   absent (b), or show no peer-to-peer UDP at all (a).
   Code: net_packet.c `send_sptps_data`, `try_udp`; obfs.c `obfs_wrap_send`.

4. 🟠 **P1 — coordinated start + back-off for unconfirmed peers (W4, W6).**
   Pairs: `masq x masq`, `masq x portrestricted`, `portrestricted x masq`,
   `cgnat x cgnat`, `cgnat x masq` (5 of the 8 + 2 relay-only pairs in the
   lab); harness proof 3/3 at 40 ms RTT (§9).
   Fix: do not probe a peer unsolicited; when both sides have a key and want
   a direct path, the relay (which already forwards both sides' UDP_INFO)
   triggers one simultaneous burst on both ends; after a failed round, stop
   probing that peer for > 30 s (the unreplied UDP conntrack timeout) so
   poisoned entries expire, then repeat. Stop spending 2/3 of the burst on the
   TCP-IP:655 edge guess once a relay view exists.
   Proof: `WSF_RUN=... lab.sh matrix --image core --rtt 40 --pairs "masq/masq
   masq/portrestricted cgnat/cgnat cgnat/masq"`, three runs → direct in 3/3
   each (today core 0/3, 2/3, 2/3 by luck, §3.5; relay at rtt 0), and
   `--rtt 0` at least 2/3; no regression in the full matrix and laptop.
   Code: net_packet.c `try_udp`, `choose_udp_address`; protocol_misc.c
   `send_udp_info`/`udp_info_h` (carry a "go" flag or a new request).

5. 🟡 **P2 — a confirmed direct path must survive a relayed rekey (W7).**
   Pairs: every direct pair whose rekey handshake goes through a relay (no
   `sf` side link): 8.6 % of A→B packets relayed at KeyExpire 20 s in
   the lab (`UdpMetaFallback = no`), 30.7 % for upstream; ~8 address
   flips per rekey.
   Fix: in `ans_key_h()` apply the reflexive address only while
   `!from->status.udp_confirmed` (what `udp_info_h()` already does), and make
   `update_node_udp()` a no-op for an unchanged address.
   Proof: `lab.sh rekey restricted symmetric --image core --keyexpire 20
   --node-conf "UdpMetaFallback=no"` → 0 address resets, 0 packets via relay.
   Code: protocol_key.c `ans_key_h` (two sites), node.c `update_node_udp`.

6. 🟡 **P2 — the lab and CI must know `masqfw` and the carriers.**
   `make check`'s quick matrix should include `masqfw/masqfw` (a real home
   router) and one carrier row (`--transport quic`, `--transport https`), so
   W1/W2 cannot come back silently. Done in this stream for the lab; the
   `make check` wiring is N2's.
   Code: testing/nat-sim (this stream), Makefile.

7. 🟡 **P2 — dual-stack hints (W10).** Probe both families when a peer has
   edges in both, or advertise one address per family.
   Proof: the `--ipv6 a` rows of §6.
   Code: net_packet.c `choose_udp_address`, graph.c, protocol_misc.c.

8. 🟢 **P3 — UPnP/PCP (W11).** Build with miniupnpc (or a PCP client),
   learn the external address and advertise it. Gains every pair with a
   UPnP-capable home router; nothing behind CGN. Needs a lab IGD first
   (miniupnpd in a gateway namespace) — **unmeasured** today.

9. 🟢 **P3 — probe before the key / one-way punching (W8, W9).** Measure first
   (one-way traffic scenario); only then decide.

10. 🟢 **P3 — port spray for APDM peers.** Lab-only gain (§9.1); a port scan on
    the wire. Recommend *not* doing it.

## 11. Not measured

- **Real NAT hardware.** Everything above is Linux 6.8 netfilter. Whether a
  given CGN or ISP router behaves like `masqfw` (drops unsolicited, EIM) or
  like `masq` (poisonable) is not known from the lab; the fix list is written
  so that both work.
- **Other kernels.** Only 6.8 was measured; the "EIM-after-first" story of
  2026-09-16 was never tied to a kernel version by measurement.
- **Symmetric NATs outside the 600-1023 class.** A CGN allocating from
  1024-65535 (the lab's own `--random-fully` does with a source port >= 1024)
  was not punched; spray and birthday against it are unmeasured.
- **Birthday** (many sockets per side) — not implemented in the harness.
- **UPnP-IGD / PCP / NAT-PMP** — the core is built without miniupnpc and the
  lab has no IGD; no number exists.
- **One-way traffic** (W9) — every scenario pings, which is two-way.
- **Sleep between 30 and 60 s** (no "Awaking from dead", no rebind).
- **The tinc daemon with a coordinated start** — §9 proves the NAT side in
  the harness, not a tincd implementation.
- **Carriers other than plain on the mesh arm**, and `obfs` beyond the two
  capture pairs.
- **Loss and jitter** — only fixed delay (`--rtt`) was used.
