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
| `TRANSPORT_QUIC`  | `quic`  | M5 | QUIC datagrams + one stream | reserved |
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
`TRANSPORT_TCP_PEEK` = 8) and routes by them. A client that sends nothing holds
only a peeked, unclassified slot and is reaped by the normal authentication
timeout (`net.c timeout_handler`), so it cannot occupy a slot forever.

### TCP decision table (`transport_classify_tcp`)

| first bytes | class | routed to |
|---|---|---|
| `30 20` (`"0 "`) | `TINC` | plain tinc meta parser (`receive_meta`) |
| `16 03 00..04` | `TLS` | https carrier `accept` hook (M5); if none built, close (tarpit) |
| `GET `/`HEAD `/`POST `/`PUT `/`DELETE `/`OPTIONS `/`PATCH `/`CONNECT `/`TRACE `/`PRI ` | `HTTP` | decoy handler (M4 stub: a minimal `200 OK`; M5: real decoy) |
| first byte `0xA0..0xAF` | `OBFS` | obfs carrier `accept` hook (M5, reserved); if none built, close |
| `30` then not `20` | `UNKNOWN` | close + tarpit |
| an uppercase letter that is a prefix of an HTTP method but not yet complete | `NEED_MORE` | wait for more bytes |
| anything else | `UNKNOWN` | close + tarpit |

Notes:
- The tinc ID line always begins `"0 "` — request number `ID` is `0`, followed
  by a space and the name / `^controlcookie` / `?invitationkey`. Two bytes decide
  it; the protocol parser validates the remainder.
- TLS is a handshake record (`0x16`) with a legacy record version `3.0`–`3.4`.
- Only carriers in the **accept mask** are honoured. A TLS ClientHello when
  `https` is not accepted (or not built) is closed, not served, so the port does
  not accidentally behave like a half-built web server before M5 lands the decoy.

### UDP decision table (`transport_classify_udp`, given the accept mask)

Checked in order; the first match wins, everything else is the existing SPTPS
data path.

| test | class | routed to |
|---|---|---|
| `len ≥ 24` and bytes `0..5` == the SF magic `9f 74 73 66 6c 77` | `SF` (if accepted) | `sf_udp_receive` |
| `len ≥ 5`, `(b0 & 0xC0) == 0xC0` and `b1..b4` a known QUIC version | `QUIC` (if accepted) | quic carrier (M5) |
| none of the above, obfs accepted, keyed check passes | `OBFS` | `obfs_udp_try` → decap → SF/SPTPS (M5) |
| otherwise | `SPTPS` | unchanged tinc UDP path (`handle_incoming_vpn_packet`) |

Why these are unambiguous:
- **SF magic** occupies the position of the SPTPS relay datagram's 6-byte
  *destination node id*. A real node id is the first 6 bytes of SHA-512 of the
  node name, so a genuine data packet collides with the magic with probability
  2⁻⁴⁸. The magic's first byte `0x9f` also has the QUIC fixed bit clear, is not a
  TLS content type, and is not printable ASCII.
- **QUIC** long headers set the high two bits (`form|fixed`). A relayed SPTPS
  datagram whose destination id happens to start `0xC0..0xFF` *and* whose next
  four bytes form a known QUIC version word is a 2⁻³⁴-per-node coincidence; and
  QUIC is only ever claimed when the `quic` carrier is in the accept mask, so a
  node that does not run QUIC never mis-routes a data packet. Documented residual.
- **obfs** frames carry no magic — they are sealed and look uniformly random, so
  they cannot be told apart by pattern. They are therefore *not* matched by
  `transport_classify_udp` (which returns `SPTPS`); instead `transport_udp_dispatch`
  runs the obfs carrier's keyed check **after** the SF and QUIC pattern tests, so
  those unambiguous patterns win first and there is no range collision. The keyed
  check is a single Poly1305 verification for an established peer (looked up by
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
| `Transports` | all compiled (`plain, sf, obfs`) | accept list; advertised; `plain` always included |
| `PreferredTransports` | `plain` | dial order; always ends at `plain` |
| `SingleFlow` | `no` | `yes` = dial `sf` first (TCP kept as fallback) |

With all defaults, a node dials `plain` and accepts `plain,sf,obfs`: identical on the
wire to upstream tinc, and interoperable with an unmodified upstream peer.
