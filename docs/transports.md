# tincstack transports — negotiation, classification, single-flow, carrier contract

This document specifies the transport (carrier) layer built in M4: how carriers
are advertised and chosen, how the inbound front tells them apart, the
single-flow wire format, and the contract a new carrier (M5: obfs / https / quic)
implements. It is the reference the classifier and the negotiation code are
written against.

The one principle that governs everything here: **a carrier never touches
SPTPS.** SPTPS (Ed25519 identity, ChaCha20-Poly1305, the meta+data records) runs
unchanged *inside* whichever carrier is selected. A carrier only decides which
flow the SPTPS records ride and what the bytes around them look like. With every
default in place the behaviour is byte-for-byte plain tinc.

Source: `core/tincd/src/transport.h`, `transport.c` (registry, negotiation,
front dispatch), `transport_table.c` (names + classifier, no daemon deps),
`transport_sf.c` (the single-flow carrier). The plain carrier's dial lives in
`net_socket.c` (`transport_plain_dial`).

---

## 1. Carriers

| id | name  | compiled | flow model | status |
|----|-------|----------|-----------|--------|
| `TRANSPORT_PLAIN` | `plain` | always | TCP meta connection + UDP SPTPS data (upstream tinc) | done |
| `TRANSPORT_SF`    | `sf`    | always | one UDP flow carries meta *and* data (single-flow) | done (M4) |
| `TRANSPORT_OBFS`  | `obfs`  | always | obfuscated single UDP flow | done (M5) |
| `TRANSPORT_HTTPS` | `https` | M5 | TLS front, meta+data in one TLS flow | reserved |
| `TRANSPORT_OBFS`  | `obfs`  | M5 | obfuscated single UDP flow | reserved |
| `TRANSPORT_HTTPS` | `https` | OpenSSL builds | TLS front, meta+data in one TLS flow | done (M5, G1) |
| `TRANSPORT_QUIC`  | `quic`  | OpenSSL builds with ngtcp2 + GnuTLS (`-Dquic`, default in `Dockerfile.build`) | QUIC v1: meta on one bidi stream, SPTPS data in DATAGRAM frames | done (M5, G3) |
| `TRANSPORT_TEST`  | `test`  | `-Dtransport_test=true` only | — (dial always fails) | test aid |

The ids are stable bit positions: a carrier's advertisement and the accept mask
are `1u << id`. Names are matched case-insensitively.

---

## 2. Negotiation: `Transports` and `PreferredTransports`

Two deliberately separate lists (decision 2, 2026-09-16):

- **`Transports` — the accept list.** What this node's listener classifies and
  answers. **Default: every carrier compiled in** (currently `plain, sf, obfs`). It is
  advertised two ways so a peer always learns it:
  1. in the node's **host record** (`Transports = ...`, written by
     `zeroconf.c` into the node's own YAML host entry, so it propagates through
     the mesh and through invitations like `Subnet`); and
  2. as a **trailing token on the ACK** of the authentication handshake, so a
     peer learns it even without a host record.
  `plain` is always forced into the accept list (the control connection and any
  upstream peer need it).

- **`PreferredTransports` — the dial preference**, in order. **Default:
  `[plain]`.** The first carrier on this list that is also in the peer's accept
  list is dialled. This is the "tick QUIC in the GUI" knob: only the dialling
  side changes, because the peer already accepts the carrier.

`SingleFlow = yes` (default **no**) is sugar for putting `sf` at the head of
`PreferredTransports`. The default is `no` because single-flow trades tinc's
separate, independently-recovering TCP meta channel for one UDP flow; it is opt-in
until it has field mileage, and the plain TCP path stays as the fallback when UDP
is blocked (see §4).

### Selection algorithm (outbound), per connection

1. On the first dial to a node, build the candidate list: walk
   `PreferredTransports`, keep each carrier that is (a) in the peer's accept
   mask and (b) dial-capable in this build. If the list is empty, it is
   `[plain]`.
2. Dial the current candidate. If its `dial` hook fails immediately (no socket),
   advance to the next candidate and retry (`net_socket.c`).
3. If the connection dies **before it is activated** (the carrier's handshake
   never completed — detected in `terminate_connection` by the absence of an
   edge), advance to the next candidate on the automatic reconnect. A failing
   carrier therefore walks down the list and ends at `plain`.
4. When a connection **activates** (ACK received), the candidate cycle is reset,
   so the next reconnect re-evaluates preferences from the top.

One side's choice is enough; nothing has to be configured on both ends. A peer
that advertises no list at all (upstream tinc) is treated as `plain`-only.

### ACK wire format (backward compatible)

    <ACK> <udp-port> <weight> <options-hex> [<transports>]

The trailing `<transports>` token (e.g. `plain,sf`) is new. An unmodified
upstream peer's `ack_h` reads only the first three fields with `sscanf` and
ignores the rest, and our `ack_h` treats a missing token as `plain`. The `ID`
line is unchanged, so the handshake is wire-compatible with upstream tinc.

---

## 3. Inbound front classifier

One TCP listen port and one UDP port serve every carrier. On a new inbound
connection the front peeks the first bytes (`MSG_PEEK`, up to
`TRANSPORT_TCP_PEEK` = 8) and routes by them. The bytes stay in the socket so
the carrier that claims them reads them itself (`SSL_accept` needs the
ClientHello). A client that sends nothing holds only a peeked, unclassified
slot and is reaped by the normal authentication timeout (`net.c
timeout_handler`), so it cannot occupy a slot forever.

An *undecided* connection (bytes present but fewer than the classifier needs,
e.g. a lone `G`) is **parked** (review R-1): its read interest is dropped, one
global 200 ms timer re-arms every parked connection for another peek, and a
connection still undecided 2 s after accept is closed and tarpitted. Before
this the level-triggered `select()` re-ran the front on every loop turn and one
pending byte pinned the daemon at 100 % CPU until `pingtimeout`. With 8 bytes
the classifier always decides (a `fuzz_classify` property), so parking is
bounded by bytes as well as by time.

### TCP decision table (`transport_classify_tcp`)

| first bytes | class | routed to |
|---|---|---|
| `30 20` (`"0 "`) | `TINC` | plain tinc meta parser (`receive_meta`) |
| `16 03 00..04` | `TLS` | https carrier `accept` hook (§7): TLS handshake, then tinc auth or decoy |
| `GET `/`HEAD `/`POST `/`PUT `/`DELETE `/`OPTIONS `/`PATCH `/`CONNECT `/`TRACE `/`PRI ` | `HTTP` | decoy handler (`decoy_serve_plain`: the real decoy over plain HTTP) |
| first byte `0xA0..0xAF` | `OBFS` | obfs carrier `accept` hook (M5 G2, reserved); if none built, close |
| `30` then not `20` | `UNKNOWN` | close + tarpit |
| an uppercase letter that is a prefix of an HTTP method but not yet complete | `NEED_MORE` | wait for more bytes |
| anything else | `UNKNOWN` | close + tarpit |

Notes:
- The tinc ID line always begins `"0 "` — request number `ID` is `0`, followed
  by a space and the name / `^controlcookie` / `?invitationkey`. Two bytes decide
  it; the protocol parser validates the remainder.
- TLS is a handshake record (`0x16`) with a legacy record version `3.0`–`3.4`.
- Only carriers in the **accept mask** are honoured. On an OpenSSL build `https`
  is compiled and accepted by default, so a TLS ClientHello always gets a real
  TLS handshake and then either the tinc carrier (if it authenticates) or the
  decoy (§7) — the port is probe-resistant with no configuration (decision 1).
  On a non-OpenSSL build `https` is not compiled and a TLS ClientHello is closed.

### UDP decision table (`transport_classify_udp`, given the accept mask)

Checked in order; the first match wins, everything else is the existing SPTPS
data path.

| test | class | routed to |
|---|---|---|
| `len ≥ 24` and bytes `0..5` == the SF magic `9f 74 73 66 6c 77` | `SF` (if accepted) | `sf_udp_receive` |
| `len ≥ 5`, `(b0 & 0xC0) == 0xC0` and `b1..b4` == `00 00 00 01` (QUIC v1 only) | `QUIC` (if accepted) | `quic_udp_try`: consumed only as a live session or a well-formed ≥ 1200-byte Initial, else falls through |
| `len ≥ 9`, `(b0 & 0xC0) == 0x40` and `b1..b8` == a connection id this node issued (keyed lookup, matcher set by `quic_init`) | `QUIC` (if accepted) | `quic_udp_try` (1-RTT short header) |
| none of the above, obfs accepted, keyed check passes | `OBFS` | `obfs_udp_try` → decap → SF/SPTPS (M5) |
| otherwise | `SPTPS` | unchanged tinc UDP path (`handle_incoming_vpn_packet`) |

Why these are unambiguous:
- **SF magic** occupies the position of the SPTPS relay datagram's 6-byte
  *destination node id*. A real node id is the first 6 bytes of SHA-512 of the
  node name, so a genuine data packet collides with the magic with probability
  2⁻⁴⁸. The magic's first byte `0x9f` also has the QUIC fixed bit clear, is not a
  TLS content type, and is not printable ASCII.
- **QUIC long headers** set the high two bits (`form|fixed`). A relayed SPTPS
  datagram whose destination id happens to start `0xC0..0xFF` (2⁻²) *and* whose
  next four bytes are exactly the v1 version word `00 00 00 01` (2⁻³²) is a
  2⁻³⁴-per-node coincidence. Review R-10 caught that the earlier "known
  version" set (v2, drafts, grease, VN: ~2¹⁷ words) made it about 2⁻¹⁷; the
  rule now matches v1 only, which is all the carrier speaks. Even on a hit the
  packet is only consumed if ngtcp2 accepts it as a ≥ 1200-byte Initial or its
  DCID belongs to a live session; otherwise `quic_udp_try` returns `false` and
  the dispatcher continues to obfs/SPTPS (§9.6). QUIC is only ever claimed when
  the `quic` carrier is in the accept mask, so a node that does not run QUIC
  never mis-routes a data packet.
- **QUIC short headers** (every 1-RTT packet) carry no version word, so they
  are a keyed lookup: first byte `0x40..0x7F` (2⁻²) and the next 8 bytes equal
  a connection id this node issued for a live session (2⁻⁶⁴). The matcher is a
  function pointer `transport_table.c` calls only when set (`quic_init`); a
  build without the carrier, or a node with `quic` not accepted, never runs it.
  A peer's stateless reset looks like a short header with an unknown CID and
  falls through to SPTPS, where it fails authentication and is dropped.
- **obfs magic headers**: obfs frames are random, so they hit either QUIC rule
  with the same 2⁻³⁴ / 2⁻⁶⁴ odds and are then handed back by `quic_udp_try`
  (§9.5). The only way to force a collision is to set `ObfsInitMagicHeader` /
  `ObfsTransportMagicHeader` to a QUIC-shaped value on a node that accepts
  `quic`; do not.
- **obfs** frames carry no magic — they are sealed and look uniformly random, so
  they cannot be told apart by pattern. They are therefore *not* matched by
  `transport_classify_udp` (which returns `SPTPS`); instead `transport_udp_dispatch`
  runs the obfs carrier's keyed check **after** the SF and QUIC pattern tests, so
  those unambiguous patterns (and `quic_udp_try`'s confirmation) win first and
  there is no range collision. The keyed check is a single Poly1305 verification for an established peer (looked up by
  source address) and a rate-limited node-key scan for a cold session. A plain
  SPTPS datagram fails every obfs key (2⁻¹²⁸) and falls through untouched, so a
  node with obfs in its accept list but no obfs peer behaves exactly like plain
  tinc. See §5.
- A carrier that is not in the accept mask never claims a datagram, so it falls
  through to SPTPS untouched — behaviour is identical to plain tinc when no extra
  carrier is enabled.

---

## 4. Single-flow framing (`sf`)

Goal (ARCHITECTURE §6, PLAN M4): remove the tinc-shaped TCP meta connection so a
link is a single UDP flow. The meta channel (tinc requests, then the SPTPS
*stream* records once authenticated) needs an ordered, reliable byte stream; SF
provides exactly that over UDP, in place of the TCP socket. SPTPS is unchanged —
SF frames its records, it does not re-implement them.

### Frame

    offset size field
    0      6    magic   9f 74 73 66 6c 77   (reserved; see §3)
    6      1    type    1 DATA · 2 ACK · 3 CLOSE · 4 RESET
    7      1    flags   bit0 SYN (first segment of a new session)
    8      8    cid     64-bit session id, random, chosen by the initiator
    16     4    seq     stream offset of the first payload byte (DATA)
    20     4    ack     next stream offset the sender expects from the peer
    24     ..   payload (DATA only, ≤ SF_MAX_PAYLOAD = 1200 bytes)

Header is 24 bytes. All multi-byte integers are network byte order.

### Reliability

Go-back-N: up to `SF_WINDOW` (32) segments in flight, cumulative ACKs, an
exponential retransmission timer (500 ms → 4 s cap), and fast retransmit on three
duplicate ACKs. A DATA frame also carries `ack`, so a busy link needs no separate
ACK frames. Out-of-order arrivals are not buffered (go-back-N): the receiver
re-ACKs the last in-order offset and the sender resends from there.

### Cold-start identification

The receiver classifies the **very first** datagram of a new session with no
prior state: a `DATA` frame with `SYN` set and `seq == 0` and an unknown `cid`
opens a new inbound session (`sf_accept`), creating the connection and letting
the ID/ACK handshake proceed over SF. This is exactly what `tinc-obfs` could not
do (it forced the handshake onto UDP but could not recognise the first packet, so
a cold tunnel deadlocked). Here the fixed magic makes the first datagram
self-identifying.

### Session identity and injection

The 64-bit random `cid` is what an off-path attacker must guess to inject a
frame; on-path attackers can at most force a teardown (equivalent to a TCP RST),
because everything of value is inside authenticated SPTPS. An unknown-`cid`
non-SYN frame is answered with one rate-limited `RESET` so a stale sender fails
fast instead of retransmitting into the void. New inbound sessions are rate
limited by `MaxConnectionBurst`, mirroring the TCP tarpit.

### Relay awareness

SF is a point-to-point meta/dial carrier between two adjacent nodes. Relayed
data (A↔R↔B) continues to use tinc's existing SPTPS relay datagrams
(`send_sptps_data`, `dst-id|src-id|record`), which are classified as `SPTPS` and
forwarded unchanged — the SF magic is distinct from any relay prefix, so a relay
never double-wraps or misclassifies a record. Proven by the three-node relay
test in `testing/transports/`.

### TCP fallback

SF is a dial *preference*, not a mode that removes TCP. If the SF handshake does
not complete (UDP blocked or filtered), selection falls back down the preference
list to `plain`, which dials the TCP meta connection (§2). The listener always
accepts `plain` as well, so a peer can always reach a single-flow node over TCP.

---

## 5. Obfuscated UDP (`obfs`)

Goal (ARCHITECTURE §6, PLAN M5): shape the UDP datagrams so they do not match
tinc's SPTPS fingerprint, for the cheap tier where a full TLS front is
unnecessary. This is a redesign of the `tinc-obfs` prototype and fixes its four
defects. `obfs` is a **UDP-only** carrier: it reuses the single-flow engine
(§4) for the meta channel and seals every datagram of the flow. SPTPS is never
touched — obfs seals the bytes SPTPS already produced.

Source: `core/tincd/src/obfs.c` (framing, keys, junk, inbound keyed check),
`transport_sf.c` (the sealed single-flow hooks), `net_packet.c`
(`obfs_wrap_send` on the SPTPS data path, `handle_incoming_vpn_packet_decap`
for re-injection).

### Frame

Every obfs datagram — a sealed single-flow meta frame or a sealed SPTPS data
datagram — is:

    offset size field
    0      8    nonce      random; the ChaCha20-Poly1305 IV, also on the wire
    8      2    clen       length of the ciphertext that follows (network order)
    10     clen ciphertext ChaCha20-Poly1305(inner)  = inner_len + 16-byte tag
    10+clen P   tail junk  P random bytes (handshake/steady header-junk knob)

`inner` is the exact datagram that would have been sent in the clear: the
single-flow frame (which itself begins with the SF magic) or the SPTPS relay/
direct datagram (`dst-id|src-id|record`). Nothing of tinc's structure is on the
wire — the nonce and ciphertext are indistinguishable from random, and the SF
magic and the SPTPS record are inside the sealed region.

### Discriminator derivation (defect 1: authenticated, not a cleartext flag)

The per-link key is

    key(64B) = SHA-512( "tincstack-obfs-v1\0" || lo || "|" || hi )

where `lo`/`hi` are the two nodes' base64 Ed25519 public keys sorted so both
ends compute the same key. It is used as the ChaCha20-Poly1305 key. The
**Poly1305 tag is the junk/real discriminator**: a real frame verifies, junk
(random bytes) and forgeries do not. An on-path censor without the node public
keys can neither forge a "real" frame nor tell junk from real. The key is
available before any handshake (the public keys are already in the host
records), which is what makes cold-start classification possible. The seal
provides classification and anti-forgery, not confidentiality — SPTPS inside
provides that — so a random 64-bit nonce is sufficient.

### Junk schedule (defect 2: around the handshake, never per data packet)

`ObfsJunkPacketCount` standalone junk datagrams, each of a random size in
`[ObfsJunkPacketMinSize, ObfsJunkPacketMaxSize]` filled with random bytes, are
emitted **once per link (re)establishment**: by the dialer in `obfs_dial` before
the first real frame, and by the acceptor in `sf_accept` when it adopts the
flow. They carry no valid tag, so the peer drops them after the keyed check.
Steady-state data never emits junk (the prototype's 3× amplification is gone).

### Header shaping (the AmneziaWG S1/S2/H1–H4 vocabulary)

- `ObfsInitHeaderJunkSize` / `ObfsTransportHeaderJunkSize` (S1/S2): extra random
  bytes appended after the ciphertext of handshake-phase / steady-state frames,
  to change the size distribution. The receiver ignores them (`clen` delimits
  the ciphertext).
- `ObfsInitMagicHeader` / `ObfsTransportMagicHeader` (H1/H2): if set, the first
  four bytes of the nonce are forced to this value, so the leading bytes of the
  frame can be made to mimic another protocol. Default: fully random nonce.

A frame is in the *handshake phase* until its single-flow session is
established (the peer has acknowledged); after that it uses the transport-phase
knobs.

### Cold-start classification (defect 3)

obfs frames look random, so `transport_classify_udp` cannot spot them and
returns `SPTPS`. `transport_udp_dispatch` then runs `obfs_udp_try`, **after** the
SF and QUIC pattern tests:

1. **Fast path** — an active link whose remembered source address matches: one
   Poly1305 verification. On failure it falls through to SPTPS (so a still-plain
   datagram during the brief setup window, or junk, is handled correctly).
2. **Cold path** — an unknown, not-yet-confirmed source, obfs accepted: a
   rate-limited scan (≤ 25/s, like `try_harder`) over the node keys. The first
   key that verifies identifies the peer and the link is activated.

On success the inner datagram is unsealed and re-injected: an SF frame goes to
`sf_udp_receive_obfs` (its replies are sealed with the same key), anything else
to `handle_incoming_vpn_packet_decap` (the SPTPS data path). Re-injection
bypasses the dispatcher, so the inner bytes are never scanned as obfs again and
there is no recursion. A plain SPTPS datagram fails every obfs key (2⁻¹²⁸), so a
node with obfs merely in its accept list behaves exactly like plain tinc.

### Relay handling (defect 4: per-hop, no double prefix)

The seal is a **per-hop** wrapper. On receive, `obfs_udp_try` strips it *before*
the relay logic in `handle_incoming_vpn_packet` runs, so the relay forwards the
plain SPTPS record exactly as it always did. On send, `send_sptps_data` calls
`obfs_wrap_send`, which re-seals for the next hop with **that hop's** key (or
sends unchanged if the next hop is not an obfs link). A→R→B is therefore
A—[key AR]→R—[key RB]→B, each hop independently sealed; the prototype's
double-prefix corruption cannot occur.

### SingleFlow on vs off

- `SingleFlow` / obfs selected (`PreferredTransports: [obfs, plain]`): the meta
  channel rides the sealed single-flow UDP stream and the SPTPS data datagrams
  are sealed on the same flow — **one shaped UDP flow, no TCP**.
- With the meta channel still on plain TCP: obfs seals only the SPTPS **data**
  datagrams (the `obfs_wrap_send` path); the TCP meta connection stays plain.
  Data-path sealing follows the obfs link, which is brought up together with the
  obfs carrier, so in practice enabling obfs gives the single-flow shape above;
  the data-only sealing is what keeps a relayed hop sealed even when its meta
  never was.

The TCP `OBFS` class in §3 (first byte `0xA0..0xAF`) is reserved and unused by
this UDP-only carrier; obfs never sends a TCP preamble, so an inbound match with
no obfs TCP `accept` hook is simply closed.

### Config surface

See `docs/config-schema.md` for defaults. All `Obfs*` options are server-scoped,
propagate through invitations (M2 `PROPAGATED_OPTIONS`), and are re-read on every
`tinc reload` (`obfs_read_config` from `transport_read_config`). The runtime CLI
is `tinc obfs status|enable|disable|set <key> <value>|get <key>|tag <spec>`,
which writes through the YAML-aware `tinc set` path so changes persist.

---

## 6. Carrier contract (what M5 implements)

A carrier is a `transport_t` (in `transport.c`'s `transports[]` table) with an id,
a name, a capability mask, and these optional hooks. Registering a carrier is
adding one table row plus its hook implementations; no other file changes.

```
bool init(void)                         // one-time setup after listen sockets exist; NULL = nothing
void exit(void)                         // teardown at shutdown
bool dial(connection_t *c)              // OUTBOUND: bring up the flow to c->address,
                                        //   then drive the handshake (call finish_connecting()
                                        //   or send_id()). Return false to fall back to the
                                        //   next carrier. NULL = cannot be dialled.
bool accept(connection_t *c,            // INBOUND: adopt a front-classified connection; the
            const uint8_t *peek,        //   peeked bytes are still in the socket. Return true
            size_t len)                 //   once c is a live tinc connection.
bool send(connection_t *c)             // flush c->outbuf onto the flow (called by
                                        //   transport_meta_flush after buffer_add). NULL =
                                        //   default: io_set(IO_READ|IO_WRITE) on the TCP socket.
void close(connection_t *c)            // release carrier-private state before the connection
                                        //   is freed (called from terminate_connection).
bool local_address(connection_t *c,     // fill *sa with our local address for edge/local
                   sockaddr_t *sa)      //   discovery. NULL = getsockname(c->socket).
void udp_receive(listen_socket_t *ls,   // handle a datagram the UDP classifier assigned to this
                 const uint8_t *buf,    //   carrier.
                 size_t len,
                 const sockaddr_t *addr)
```

Capabilities (`caps`): `TRANSPORT_CAP_META_TCP` (meta is a TCP stream on the
front port), `TRANSPORT_CAP_SINGLE_FLOW` (meta+data share one flow, no
tinc-shaped TCP), `TRANSPORT_CAP_DATA_UDP` (data path is the SPTPS datagram flow).

How a carrier wraps SPTPS records:
- **Meta:** tinc calls `send_meta()`/`send_meta_raw()`, which append to
  `c->outbuf` and call `transport_meta_flush(c)`; the carrier's `send` hook puts
  those bytes on its flow. Inbound bytes are handed to `receive_meta_bytes(c,
  buf, len)` (the socket-independent half of `receive_meta`), which runs the
  normal SPTPS/stream parser. The carrier is a pipe; it never inspects records.
- **Data:** the SPTPS *datagram* path (`send_sptps_data` /
  `handle_incoming_vpn_packet`) is unchanged. A carrier that also carries data
  frames those datagrams on its flow and delivers them back to
  `handle_incoming_vpn_packet` via `udp_receive`.

How a carrier participates in negotiation:
- Set the carrier's bit in the compiled mask (its `compiled` flag in
  `transport_table.c`) so it appears in the default accept list and the
  advertised `Transports` line.
- Provide `dial` so it can appear in `PreferredTransports` candidate lists.
- Provide `accept` (TCP) and/or a classifier case + `udp_receive` (UDP) so the
  front routes inbound flows to it. Add the classifier pattern to
  `transport_classify_tcp` / `transport_classify_udp` and keep this table in sync.

How failure triggers fallback: return `false` from `dial` for an immediate
failure, or simply let the handshake not complete — an outgoing connection that
dies before it activates advances to the next candidate automatically (§2).

---

## 7. Defaults summary

| option | default | meaning |
|---|---|---|
| `Transports` | all compiled (`plain, sf, obfs, https, quic` on the Docker build) | accept list; advertised; `plain` always included |
| `PreferredTransports` | `plain` | dial order; always ends at `plain` |
| `SingleFlow` | `no` | `yes` = dial `sf` first (TCP kept as fallback) |
| `HttpsSni` | peer `Address` name, else `localhost` | SNI the https dial presents |
| `TlsCert` / `TlsKey` | generated self-signed | PEM files; else `keys.tls_cert/tls_key` |
| `HttpsDecoyRoot` | built-in page | static files served to probers |
| `HttpsDecoyUpstream` | (unset) | `host:port` to proxy probers to instead |
| `QuicPort` | the tinc `Port` | extra UDP listener for the quic carrier (also a host-record key: the port to dial); default = no extra socket |
| `QuicSni` | `HttpsSni`, else peer `Address` if a name | SNI the quic dial presents |
| `QuicAlpn` | `h3` | ALPN offered/required by the quic carrier |

With all defaults, a node dials `plain` and accepts everything compiled: identical
on the wire to upstream tinc, and interoperable with an unmodified upstream peer.
`quic` is only used when a dialler lists it in `PreferredTransports`.

---

## 8. The `https` carrier (M5, G1)

The `https` carrier runs the tinc meta channel **and** the SPTPS data records
inside one outward TLS flow, and makes the listen port look like an ordinary
HTTPS server to anything that is not an authenticated tinc peer. It is the
REALITY-analogue done correctly: no cleartext bearer token, no VPN-shaped bytes
on the wire, and the certificate is not the trust root — SPTPS/Ed25519 is
(principle 1). TLS is only a carrier and a decoy.

### 8.1 Certificate

One certificate per node, shared with the future QUIC carrier (decision 1).
`TlsCert`/`TlsKey` name a real certificate if the operator has one; otherwise the
daemon generates a self-signed **P-256** X.509v3 certificate at first start
(`tls.c`) and persists both PEMs — in YAML mode under `keys.tls_cert` /
`keys.tls_key`, in classic confbase mode as `tls_cert.pem` / `tls_key.pem` — so
the fingerprint is stable across restarts and the cert is replaceable with no
other change. The subject/SAN is a generic **`localhost`** on purpose: a scanner
must not be able to tie the port to a specific mesh node (the tinc-vless front
leaked its identity with a cert named after itself). The SHA-256 fingerprint is
shown in `tinc info`/dump and written as `TlsFingerprint` into the node's own
host record, so M2 propagation carries it in invitations and an invitee pins the
inviter's certificate.

### 8.2 Dial and certificate pinning

`https_dial` opens a non-blocking TCP connection to the peer's front port and a
TLS client handshake with a plausible SNI (`HttpsSni`, else the peer's `Address`
if it is a hostname, else `localhost`). PKI verification is off
(`SSL_VERIFY_NONE`); instead the peer's certificate is pinned by SHA-256
fingerprint: if the peer's host record has a `TlsFingerprint`, it must match, or
the dial fails. If none is pinned, the dial proceeds **without writing anything**
(review M5-7): the certificate alone proves nothing, and a pin written on first
contact would let an on-path attacker pin its own certificate forever. The
fingerprint of the session is remembered in the dialer's session state and is
written to the host record only once the SPTPS handshake inside that TLS session
activated the link (`c->edge` set by the ACK), i.e. once the peer proved its
Ed25519 identity over the very session the certificate belongs to (the exporter
in the authenticator, §8.3, binds the two). A malformed existing pin is ignored
and never overwritten (logged). ALPN offers `http/1.1`.

### 8.3 Authenticator

After the TLS handshake the client sends **one** HTTP/1.1 request that looks like
an ordinary WebSocket upgrade; the authenticator rides in a `Cookie: sid=<b64url>`
value. The payload is:

    ver(1) || namelen(1) || node-name || nonce(16) || timestamp_be(8) || Ed25519-sig

where the signature (authenticator **version 2**, review M5-11; built and
verified by the carrier-neutral `authn.c`, shared with `quic`) is over

    "tincstack-authn-v2\0" || server-cert-fp(32) || TLS-exporter(32) || nonce(16) || timestamp_be(8)

The fixed NUL-terminated label separates this signature domain from SPTPS and
from any future message signed with the same node key. The `ver` byte is `2`;
a `ver` of `1` (the label-less pre-review format) is refused like any other
failed authenticator, so both ends of an `https` link must run this format.

- **server-cert-fp** is the SHA-256 of the certificate the server just presented
  (the client uses the fingerprint it verified; the server uses its own
  `tls_own_fp`). This binds the authenticator to *this server's* identity.
- **TLS-exporter** is 32 bytes from `SSL_export_keying_material` (RFC 5705) with
  the label `EXPORTER-tincstack-https-v1`, computed identically by both ends of
  the TLS session. This binds the authenticator to *this TLS session*: a captured
  authenticator replayed on any new TLS session has the wrong exporter, so its
  signature fails and it is treated exactly like a forgery.
- the signature is made by the client's tinc **Ed25519 node key**; the server
  verifies it with that node's `Ed25519PublicKey` from its host DB.

The server also checks the node name is known and is not itself, the timestamp is
within ±90 s, and the nonce has not been seen recently (a small replay cache;
belt-and-suspenders on top of the exporter binding). The failure path has a
constant shape (review M5-9): an unknown name still parses a host record (the
node's own) and still runs a full Ed25519 verification (against the own public
key; the result is discarded), and the freshness check is folded into the final
AND rather than returning early, so a prober cannot enumerate node names by
timing.

### 8.4 Success and the meta+data flow

On success the server answers `101 Switching Protocols` (a real
`Sec-WebSocket-Accept` is computed, so the exchange is a textbook WebSocket
upgrade to any observer that could see inside the TLS). From then on the raw tinc
meta byte stream runs inside the TLS session: `send_meta*` → `transport_meta_flush`
→ `https_send` (`SSL_write`), and inbound `SSL_read` → `receive_meta_bytes`. The
carrier is a pipe; it never inspects a record.

The link is marked **TCP-only-equivalent** (`OPTION_TCPONLY | OPTION_INDIRECT`,
set before the ACK so it reaches the edge and the peer), so tinc's own data path
frames the SPTPS **data** datagrams over the meta stream (`send_sptps_tcppacket`)
instead of a separate UDP flow. The result is a single outward TLS flow (also
PLAN point 5); `tcpdump` on the port shows only TLS records — no UDP, no
cleartext tinc ID line. SPTPS itself is unchanged: `https` wraps its records.

### 8.5 Failure = the decoy (probing resistance)

If **anything** fails — not a TLS ClientHello, a completed TLS handshake with no
valid authenticator, an unknown node, a bad signature, a stale timestamp, a
replayed nonce — the server serves the decoy (`decoy.c`) and closes, identically
to any other prober. That identical treatment *is* the active-probing resistance:
a prober cannot tell a tinc node from a plain web server. The decoy is a static
page (built-in default, or files under `HttpsDecoyRoot`) or a transparent proxy to
`HttpsDecoyUpstream`. The same decoy content is served over plain HTTP to a
cleartext prober (`decoy_serve_plain`). No response path emits a
tinc-identifying string.

Everything on the decoy path is driven by the event loop (review M5-1, M5-8,
M5-10):

- the upstream fetch is a non-blocking connect/send/recv on the loop with a
  3 s total deadline and a 1 MiB cap (`decoy_fetch_start`); the upstream address
  is resolved once when the config is (re)loaded, never per probe; on any
  failure or timeout the static page is served instead, so the port never breaks
  character and a black-holed upstream costs the loop nothing;
- the request forwarded to the upstream has `Host:` rewritten,
  `Connection: close` forced, and `Cookie`, `Upgrade`, `Sec-WebSocket-*` and
  `Authorization` stripped, so a failed tinc authenticator (e.g. a clock-skewed
  peer) never reaches the upstream in the clear;
- the plain-HTTP path reads the request head and writes the response on
  readiness, never busy-waiting on a client that does not read; an exchange that
  does not finish is reaped by the authentication timeout like any other
  unauthenticated connection.

The client side also falls back: if the dial cannot pin the cert or the server
answers anything other than `101`, `https_dial`'s connection dies before it
activates and the outbound selector advances to the next carrier (ending at
`plain`, §2).

### 8.6 What a middlebox sees

Only TLS records to the standard front port, with a normal-looking certificate
and (if it could decrypt, which it cannot) a WebSocket upgrade. Whether `101`
(success) or a static page (decoy) is chosen is invisible on the wire because it
is inside TLS; `101 Switching Protocols` was chosen for the success case because
WebSocket-over-HTTPS is ubiquitous and needs no polling. There is no separate
UDP flow to correlate.

## 9. The `quic` carrier (M5, G3)

Status: **implemented** (`core/tincd/src/transport_quic.c`,
`transport_quic_tls.c`; stream G3, 2026-09-16) on the library and the
primitives stream Q de-risked (`testing/quic-spike/`, decision table in §9.1).
The carrier is compiled whenever meson finds ngtcp2 + GnuTLS (`-Dquic=auto`,
the default) on an OpenSSL build; `core/Dockerfile.build` ships it. Proof
script: `testing/transports/quic-carrier-test.sh`.

### 9.1 Library decision (stream Q)

| | msquic 2.6.1 | **ngtcp2 1.25.0** (chosen) | quiche |
|---|---|---|---|
| language / API | C, function table (`MsQuicOpen2`), stable | C, versioned structs, stable since 1.0 (11/2023) | Rust + C FFI |
| build on Debian 12 | cmake + its own quictls submodule (system OpenSSL 3.0 has no QUIC API; msquic accepts system OpenSSL only >= 3.5): minutes, network fetch of submodules | autotools, one 700 KB tarball (sha256-pinned), GnuTLS 3.7.9 from apt (needs >= 3.7.3): **16 s** | needs a Rust toolchain: rejected |
| Debian package | none | `libngtcp2-dev` 0.12.1: pre-1.0 API, not usable; source build instead | none |
| socket / threads | owns its UDP sockets and worker threads; **no API to hand it a datagram read from a foreign socket**; every callback arrives on a library thread | **no I/O, no threads, no timers**: caller feeds packets with `ngtcp2_conn_read_pkt(path, ...)` and drains with `ngtcp2_conn_writev_*` | owns nothing, similar to ngtcp2 |
| fits M4 front (one UDP socket, classifier, single-threaded loop) | no: would need its own port and a marshalling layer into tinc's event loop (what `tinc-quic` fought and lost) | **yes, exactly** | yes |
| DATAGRAM (RFC 9221) | yes | yes (`max_datagram_frame_size`, `recv_datagram`, `writev_datagram`) | yes |
| connection migration | yes | yes: passive (peer address change -> path validation) and active (`initiate_immediate_migration`) | yes |
| crypto backends | Schannel / quictls | GnuTLS, wolfSSL, BoringSSL, picotls, OpenSSL >= 3.5; backend-specific code is ~60 lines | BoringSSL |

Decision: **ngtcp2 with the GnuTLS backend** on Linux. Least build risk (one
pinned tarball, distro TLS library), and the only candidate whose model (the
application owns the socket, the loop and the timers) matches how the M4 front
dispatches datagrams (`transport_udp_dispatch` -> `udp_receive`). The
reference `tinc-quic` used msquic and had to give it its own socket and
threads; that is where its dead stream muxing came from.

The spike (`testing/quic-spike/run.sh`, three runs `ALL PASS`) proved the
primitives the carrier is built on: handshake with a PEM cert + SHA-256 pin,
pin mismatch => TLS alert 42, datagrams and one bidi stream both ways, NAT
rebind => `PATH_VALIDATION success`, explicit migration, clean close; first
packet on the wire `c3 00 00 00 01 08 ...` (1200 bytes). Two findings carried
into the carrier: `active_connection_id_limit` must be > 2 (8 is used) or the
second migration in a session fails, and the §3 classifier needed a keyed
short-header rule (§9.5).

### 9.2 Where the carrier sits

- Registry row (`transport.c`, under `HAVE_QUIC && HAVE_OPENSSL`):
  `{ .name = "quic", .caps = TRANSPORT_CAP_SINGLE_FLOW, .init, .exit, .dial,
  .send, .close, .local_address, .udp_receive, .send_datagram }`. Meta *and*
  data ride the one QUIC connection: no tinc-shaped TCP connection, no plain
  SPTPS UDP flow between the two nodes. `accept` (TCP) is NULL.
- Socket: **tinc's existing UDP listen sockets**, picked by address family
  like `sf_pick_socket()`; the front classifier (§3) hands QUIC datagrams to
  the carrier. With `QuicPort` set to something other than the tinc port, the
  carrier additionally binds one UDP socket per address family on that port
  (private `listen_socket_t` entries fed to the same `handle_incoming_vpn_data`
  path, so `listen_socket[]` indices stay valid) and dials from it. Default:
  `QuicPort` = the tinc port, no extra socket.
- Loop: tinc's `event.c`. Reads arrive through `handle_incoming_vpn_data` ->
  `transport_udp_dispatch` -> `quic_udp_try()`. Writes are `sendto()` on the
  session's socket to the path ngtcp2 returns. One `timeout_t` per session,
  re-armed after every flush from `ngtcp2_conn_get_expiry()`; its callback
  runs `ngtcp2_conn_handle_expiry()` and flushes.
- Per-session state (`quic_session_t`, `c->transport_data`): `ngtcp2_conn *`,
  the GnuTLS session (`quic_tls_t`), socket fd + family index, the peer
  `sockaddr_t`, the meta stream id, the meta TX ring with absolute offsets
  (bytes stay valid until `acked_stream_data_offset`), a 64-entry datagram TX
  queue, the timer, the list of connection ids this node issued (for the keyed
  lookup), and the recorded `ngtcp2_ccerr`. `c->socket = -1` as in SF.
- Re-entrancy rules the code enforces: nothing is written to ngtcp2 from
  inside one of its callbacks (a `reading` flag defers the flush), a session
  is never freed inside a callback (a `dead` flag + reaper timer, like
  `sf_reap`), and `receive_meta_bytes()` may terminate the connection, after
  which the callback returns without touching the session.

### 9.3 Hook mapping (as implemented)

| hook | what it does |
|---|---|
| `init()` | `tls_init()` then the node certificate PEM from `tls_current_pem()` (the single node cert, `keys.tls_cert/tls_key`, G1) -> `gnutls_certificate_set_x509_key_mem`; 32-byte static secret for stateless-reset tokens; registers the CID matcher with `transport_set_quic_cid_matcher()`; binds the `QuicPort` sockets when configured. Logs `QUIC carrier ready (ngtcp2 1.25.0, GnuTLS)`. `quic_read_config()` on `tinc reload` rebuilds the credential when the certificate fingerprint changed. |
| `exit()` | close every session, free the credential, `gnutls_global_deinit()`. |
| `dial(c)` | pin = the peer's `TlsFingerprint` host-record key (absent => accept-on-first-use, §9.7); port = the peer's host-record `QuicPort`, else own `QuicPort`, else the port as dialled; socket by family; GnuTLS client session with ALPN `QuicAlpn` (default `h3`) and SNI from §9.8; random DCID(8) + SCID(8); `ngtcp2_conn_client_new(..., NGTCP2_PROTO_VER_V1, ...)`; `connection_add(c)`; flush (the Initial goes out). `finish_connecting()` is *not* called here. Logs `Dialling <peer> via quic`. |
| `udp_receive` / `quic_udp_try(ls, buf, len, addr)` | `ngtcp2_pkt_decode_version_cid`; DCID in the session table => `ngtcp2_conn_read_pkt(path = {socket addr, datagram source}, ...)` then flush -- the remote of the path is always the datagram's real source, which is the whole NAT-rebind mechanism. Unknown DCID: only a packet `ngtcp2_accept()` takes as a well-formed v1 Initial (>= 1200 bytes) opens a session (`quic_accept`, burst-limited by `max_connection_burst`, `new_connection()` named `<unknown>`, `allow_request = ID`); anything else **returns `false` and falls through** to the obfs keyed check and SPTPS. `read_pkt` errors: `DRAINING/CLOSING/DROP_CONN` => silent teardown; `NGTCP2_ERR_CRYPTO` => `CONNECTION_CLOSE` with the TLS alert; other => `CONNECTION_CLOSE` with `ngtcp2_ccerr_set_liberr`. Every teardown ends in `terminate_connection()`. |
| `send(c)` | append `c->outbuf` to the TX ring, flush: queued datagrams first (`ngtcp2_conn_writev_datagram`), then `ngtcp2_conn_writev_stream` on the meta stream; `sendto` each packet; `NGTCP2_ERR_STREAM_DATA_BLOCKED` marks the stream blocked until `extend_max_stream_data`; then `ngtcp2_conn_update_pkt_tx_time` + re-arm the timer. `EMSGSIZE` from the socket is ignored (ngtcp2's PMTUD probes). |
| `send_datagram(c, buf, len)` | queue + flush; returns `false` when `len > 1400` or `len > ngtcp2_conn_get_max_tx_udp_payload_size() - 35`, which `send_sptps_data()` treats like `EMSGSIZE` (-> `reduce_mtu`); when the 64-entry queue is full the datagram is dropped (SPTPS tolerates loss). |
| `close(c)` | best-effort `ngtcp2_conn_write_connection_close` (the recorded `ccerr`, else app error 0) + `sendto`; drop the CIDs; `ngtcp2_conn_del`, `gnutls_deinit`; free. |
| `local_address(c, sa)` | `getsockname()` on the session's socket. |

Settings / transport parameters: `initial_max_streams_bidi = 1`,
`initial_max_streams_uni = 0`, `initial_max_data = 1 MiB`,
`initial_max_stream_data_bidi_{local,remote} = 256 KiB`,
`max_datagram_frame_size = 65535`, `active_connection_id_limit = 8`,
`max_idle_timeout = 3 x PingTimeout`, `handshake_timeout = PingTimeout` (so
the library gives up in step with tinc's reaper, §2 step 3).

### 9.4 Framing: authenticator, meta stream, SPTPS datagrams

**Stream 0** (one bidirectional stream, opened by the dialler in
`handshake_completed`; the acceptor adopts the first stream it sees and shuts
any other with app error 1) carries, in this order:

1. the **§8.3 authenticator**, byte for byte the `https` one, built by the
   shared `authn_build()` (`authn.c`): `ver(1) || namelen(1) || name ||
   nonce(16) || ts_be(8) || Ed25519 sig(64)` over `"tincstack-authn-v2\0" ||
   server-cert-fp(32) || TLS-exporter(32) || nonce || ts` (version 2, §8.3),
   exporter label
   `EXPORTER-tincstack-https-v1` via `gnutls_prf_rfc5705`. The acceptor
   (`recv_stream_data`) buffers exactly `authn_expected_len()` bytes and
   calls `authn_verify()` against its own certificate fingerprint and
   exporter -- same replay cache, same +/-90 s skew as `https`. Not a single
   byte reaches `receive_meta_bytes()` before it passes; on failure the
   session is closed with a generic transport error (`quic: authenticator
   from <host> rejected`) and the dialler falls back (§9.9). Success sets
   `c->name` and logs `quic: authenticated peer <name>`.
2. the tinc `ID` line and everything after it: `finish_connecting(c)` runs
   from `handshake_completed` right after the authenticator is queued, so
   `send_id()` -> `send` hook -> the same stream. The unchanged Ed25519 SPTPS
   handshake inside the stream then proves the name (SPTPS is untouched).

Inbound stream bytes go to `receive_meta_bytes(c, data, len)`; the
flow-control credit is returned afterwards with
`ngtcp2_conn_extend_max_stream_offset` + `ngtcp2_conn_extend_max_offset`.

**Data path**: the SPTPS *datagram* records ride **DATAGRAM frames**, one tinc
UDP packet per frame, byte for byte what `send_sptps_data()` would have put on
the wire (`dst-id | src-id | record`, or the direct/legacy forms), so a relay
never sees a difference. `send_sptps_data()` calls
`relay->connection->transport->send_datagram` (before `obfs_wrap_send`) when
the relay's meta connection has that hook; `false` => `reduce_mtu`, so tinc's
own MTU probing converges on the datagram ceiling. `recv_datagram` delivers
with `handle_incoming_vpn_packet_decap(ls, data, len, &session peer)`: the
classifier is skipped (the bytes came from a carrier) and the unchanged SPTPS
receive path authenticates, decrypts and forwards relayed packets as today.
Ceiling: ~1160 bytes at the initial 1200-byte UDP payload, ~1410 after PMTUD
on Ethernet; `SF_MAX_PAYLOAD` is 1200 for comparison.

### 9.5 Classifier (what G3 changed in §3)

- **Long header, v1 only.** `(b0 & 0xC0) == 0xC0` and version word
  `00 00 00 01`. Stream Q's draft matched a set of ~2^17 version words (v2,
  every draft, the greased pattern, VN), which review R-10 correctly priced at
  about 2^-17 per node against a genuine SPTPS relay datagram; the carrier
  speaks v1 only, so the match is now exactly one word and the residual is
  2^-34 per node, as §3 states. On top of that the carrier only *consumes* a
  long-header packet if `ngtcp2_accept()` takes it as a >= 1200-byte Initial
  (or its DCID is a live session); a lookalike falls through to obfs/SPTPS.
- **Short header, keyed.** `(b0 & 0xC0) == 0x40`, `len >= 9`, and bytes
  `1..8` equal a connection id this node issued for a live session
  (`transport_set_quic_cid_matcher()`, set by `quic_init`; NULL in a build
  without the carrier, and never consulted when `quic` is not in the accept
  mask). Residual 2^-64 per session. Stateless resets from a peer look like
  short headers with an unknown CID and fall through to SPTPS, where they
  fail authentication and are dropped.
- Order: SF magic -> QUIC long header -> QUIC short header (keyed) -> obfs
  keyed check -> SPTPS. SF (`0x9f`, top bits `10`) and QUIC never overlap.
- **obfs interaction.** obfs frames are sealed and uniformly random, so a
  frame whose first byte lands in `0xC0..0xFF` *and* whose next four bytes
  are `00 00 00 01` (2^-34) or whose first 9 bytes match a live CID (2^-64)
  would be classified QUIC first; the carrier does not consume it (no session,
  not an acceptable Initial) and `transport_udp_dispatch` continues to the
  obfs keyed check, so nothing is lost. The one configuration that can force
  the collision is `ObfsInitMagicHeader` / `ObfsTransportMagicHeader` set to
  a QUIC-looking value (`0xC?000000`-ish): do not do that on a node that
  accepts `quic`; documented, not guarded.
- Unit test: `testing/transports/classify_test.c` grew from 26 to 37 checks
  (v2 / draft-29 / grease / VN long headers -> SPTPS, a 1200-byte v1 Initial
  -> QUIC, short header with a live CID -> QUIC, and no matcher / unknown CID
  / not accepted / fixed bit clear / truncated -> SPTPS).

### 9.6 Coexistence rule for `quic_udp_try`

`transport_udp_dispatch` calls `quic_udp_try()` for `UDP_CLASS_QUIC` and only
stops there when it returns `true` (packet consumed: live session, or a new
session was opened). `false` means "not mine after all" and the dispatcher
proceeds exactly as for `UDP_CLASS_SPTPS`. This is what keeps the
pattern-based rule safe: the pattern selects, the library confirms.

### 9.7 Certificate, pinning, identity binding

- The node serves its **own** certificate (`keys.tls_cert` / `tls_key`, G1:
  self-signed EC P-256 at first start, or `TlsCert`/`TlsKey`). Same object as
  the HTTPS front's, obtained through `tls_current_pem()`; reloaded on
  `tinc reload` when its fingerprint changed.
- The dialler pins the peer's `TlsFingerprint` (host record). `verify_pin`
  (`transport_quic_tls.c`): DER of the presented leaf -> SHA-256 -> compare
  with the pinned hex. **Nothing else is checked**: no CA, no name, no
  validity period; the pin *is* the identity. Mismatch => `LOG_ERR` with both
  fingerprints, TLS alert (bad_certificate), fallback per §9.9.
- **Accept-on-first-use**: when the host record has no `TlsFingerprint` the
  dialler accepts the presented certificate, logs
  `quic: no pinned TlsFingerprint for <peer>; accepting <fp> on first use and
  pinning it` and appends `TlsFingerprint = <fp>` to the peer's host record
  (`append_config_file`), so the second dial is pinned. This is the same
  trust model as `https` (§8.2) and is bounded by the authenticator + SPTPS
  handshake that follow: a wrong server can at most be pinned as a peer that
  then fails to authenticate.
- Identity binding: the pin ties the QUIC session to the certificate recorded
  under the peer's node name; the authenticator (§9.4) ties the session to
  the tinc Ed25519 key of the dialler before any tinc request is parsed; then
  the unchanged SPTPS handshake inside the stream proves both names. A
  certificate alone never authenticates a node. No client certificate is
  used.

### 9.8 What the wire shows (for later DPI shaping)

`QuicAlpn` (default `h3`) and the SNI (`QuicSni`, else `HttpsSni`, else the
peer's `Address` when it is a DNS name, else no SNI) are the only knobs;
Initial packets are padded to 1200 bytes by the library, as browsers do.
Captured by `quic-carrier-test.sh` (a): 288 UDP datagrams on the port, the
first three long headers (`L L L` = client Initial, server Initial+Handshake,
client Handshake), then short headers only; 0 datagrams without the QUIC fixed
bit (an SPTPS datagram would clear it half the time); no TCP connection
established. HTTP/3 conformance beyond the handshake is out of scope
(ARCHITECTURE §10).

### 9.9 Handshake failure and fallback

All of these end in the §2 walk to the next candidate, ending at `plain`,
because the connection dies before it activates:

| failure | detection | action (observed in `quic-carrier-test.sh`) |
|---|---|---|
| peer does not accept `quic` (config `Transports: [plain]`, or a build without the carrier) | negotiation, §2 | `Carrier candidates for <peer>: plain`; QUIC never dialled (c) |
| no UDP socket of the peer's address family | `dial` | return `false` immediately |
| QUIC dropped by the network | ngtcp2 retransmits the Initial with backoff; `handshake_timeout = PingTimeout` expires | `Carrier quic failed for <peer>, falling back to plain`, tunnel comes up on plain (c, UDP DROP'd) |
| pin mismatch / TLS failure | `NGTCP2_ERR_CRYPTO` | `CONNECTION_CLOSE` with the alert, log both fingerprints, next candidate |
| Version Negotiation packet | `decode_version_cid` | v1 only: not claimed, session times out as above |
| authenticator rejected (acceptor) | §9.4 | generic close, `quic: authenticator from <host> rejected`; the dialler logs `Carrier quic failed ..., falling back to plain` and dials plain, where the wrong key fails SPTPS too (d) |
| mid-session: idle timeout, peer close, library error | `read_pkt` / `handle_expiry` errors | `terminate_connection` => reconnect re-evaluates preferences from the top (§2 step 4) |

**NAT rebind** needs no code on the dialling side: tinc's socket does not
move, the NAT mapping does; the *acceptor* sees a new source address in
`udp_receive`, ngtcp2 validates the path, and on `path_validation` SUCCESS the
carrier copies the new remote into the session, `c->address` and
`c->hostname` (so `dump connections` follows) and logs `quic: path validated
for <peer>, remote now <addr>`. Observed (b): mapping flipped 40000 -> 40001
mid-session, ping continues both ways, exactly one `quic: connection from`
before and after (no re-handshake), the dialler never fell back. Active
migration (`ngtcp2_conn_initiate_immediate_migration`) is only for a *local*
socket change (Android Wi-Fi -> LTE), which tinc does not do today.

### 9.10 Build wiring

`meson_options.txt`: `option('quic', type: 'feature', value: 'auto')`.
`src/meson.build` looks up `libngtcp2 >= 1.0`, `libngtcp2_crypto_gnutls` and
`gnutls >= 3.7.3`; when all three are found *and* `crypto=openssl` (the node
certificate comes from `tls.c`, which is OpenSSL) it adds `transport_quic.c`
+ `transport_quic_tls.c` and defines `HAVE_QUIC`; `-Dquic=enabled` on a
non-OpenSSL crypto build is an error. `transport_table.c`'s `quic` row is
`compiled` under `HAVE_QUIC && HAVE_OPENSSL`, so the default accept list and
the advertised `Transports = plain, sf, obfs, https, quic` line (`zeroconf.c`)
include `quic` only in builds that have it. `tinc info` / `dump connections`
show `quic` like any carrier.

Docker: the ngtcp2 dependency is **folded into `core/Dockerfile.build`**
(stage `quicdeps`, sha256-pinned tarball, `ARG QUIC=enabled`) and
`core/Dockerfile.build-quic` was removed. Reason: decision 2 ("one side's
tick is enough") only holds if every default node image carries the carrier,
and the compose lab (`platforms/linux/docker`) builds from
`Dockerfile.build`. Cost: +16 s build, runtime image 100 MB (+5.4 MB). The
QUIC-less build stays green and is proven with
`--build-arg QUIC=disabled` (image `ws-g3-noquic`: `tincd` links neither
ngtcp2 nor GnuTLS, `Transports accept=plain,sf,obfs,https`).

Windows (mingw) and Android (NDK, M8): GnuTLS is the heavy part of this
choice. ngtcp2's API is backend-independent; only the TLS object setup differs
(`ngtcp2_crypto_<backend>_configure_*_session` plus the backend's credential
calls, ~150 lines in `transport_quic_tls.c`), so wolfSSL or BoringSSL can
replace GnuTLS per platform without touching the carrier.

### 9.11 Known limits

1. `QuicPort` is read at start only (a change needs a restart); `QuicSni` /
   `QuicAlpn` are read per dial.
2. The datagram queue is bounded (64) and drops when full; SPTPS handles the
   loss, but a burst larger than that is not paced.
3. Replay of the authenticator is proven at the shared-code level (the
   `https` test forges and replays one); over QUIC a capture cannot be
   replayed at all because the exporter differs per session, and the same
   `authn_verify` replay cache is on the path. There is no QUIC-level replay
   injector in the test suite.
4. IPv6 is handled by socket family selection but the proof runs IPv4 only.
