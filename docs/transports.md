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
| `TRANSPORT_OBFS`  | `obfs`  | M5 | obfuscated single UDP flow | reserved |
| `TRANSPORT_HTTPS` | `https` | OpenSSL builds | TLS front, meta+data in one TLS flow | done (M5, G1) |
| `TRANSPORT_QUIC`  | `quic`  | M5 | QUIC datagrams + one stream | reserved |
| `TRANSPORT_TEST`  | `test`  | `-Dtransport_test=true` only | — (dial always fails) | test aid |

The ids are stable bit positions: a carrier's advertisement and the accept mask
are `1u << id`. Names are matched case-insensitively.

---

## 2. Negotiation: `Transports` and `PreferredTransports`

Two deliberately separate lists (decision 2, 2026-09-16):

- **`Transports` — the accept list.** What this node's listener classifies and
  answers. **Default: every carrier compiled in** (currently `plain, sf`). It is
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
| `len ≥ 5`, `(b0 & 0xC0) == 0xC0` and `b1..b4` a known QUIC version | `QUIC` (if accepted) | quic carrier (M5) |
| obfs keyed marker | `OBFS` (reserved) | obfs carrier's keyed check (M5) |
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

## 5. Carrier contract (what M5 implements)

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

## 6. Defaults summary

| option | default | meaning |
|---|---|---|
| `Transports` | all compiled (`plain, sf, https`) | accept list; advertised; `plain` always included |
| `PreferredTransports` | `plain` | dial order; always ends at `plain` |
| `SingleFlow` | `no` | `yes` = dial `sf` first (TCP kept as fallback) |
| `HttpsSni` | peer `Address` name, else `localhost` | SNI the https dial presents |
| `TlsCert` / `TlsKey` | generated self-signed | PEM files; else `keys.tls_cert/tls_key` |
| `HttpsDecoyRoot` | built-in page | static files served to probers |
| `HttpsDecoyUpstream` | (unset) | `host:port` to proxy probers to instead |

With all defaults, a node dials `plain`, accepts `plain,sf,https`, and answers a
TLS ClientHello with the decoy: identical on the tinc wire to upstream tinc for a
plain/sf peer, and a plausible HTTPS server to everyone else.

---

## 7. The `https` carrier (M5, G1)

The `https` carrier runs the tinc meta channel **and** the SPTPS data records
inside one outward TLS flow, and makes the listen port look like an ordinary
HTTPS server to anything that is not an authenticated tinc peer. It is the
REALITY-analogue done correctly: no cleartext bearer token, no VPN-shaped bytes
on the wire, and the certificate is not the trust root — SPTPS/Ed25519 is
(principle 1). TLS is only a carrier and a decoy.

### 7.1 Certificate

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

### 7.2 Dial and certificate pinning

`https_dial` opens a non-blocking TCP connection to the peer's front port and a
TLS client handshake with a plausible SNI (`HttpsSni`, else the peer's `Address`
if it is a hostname, else `localhost`). PKI verification is off
(`SSL_VERIFY_NONE`); instead the peer's certificate is pinned by SHA-256
fingerprint: if the peer's host record has a `TlsFingerprint`, it must match, or
the dial fails; if none is pinned, the fingerprint is accepted on first use and
written to the host record (logged). ALPN offers `http/1.1`.

### 7.3 Authenticator

After the TLS handshake the client sends **one** HTTP/1.1 request that looks like
an ordinary WebSocket upgrade; the authenticator rides in a `Cookie: sid=<b64url>`
value. The payload is:

    ver(1) || namelen(1) || node-name || nonce(16) || timestamp_be(8) || Ed25519-sig

where the signature is over

    server-cert-fp(32) || TLS-exporter(32) || nonce(16) || timestamp_be(8)

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
belt-and-suspenders on top of the exporter binding).

### 7.4 Success and the meta+data flow

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

### 7.5 Failure = the decoy (probing resistance)

If **anything** fails — not a TLS ClientHello, a completed TLS handshake with no
valid authenticator, an unknown node, a bad signature, a stale timestamp, a
replayed nonce — the server serves the decoy (`decoy.c`) and closes, identically
to any other prober. That identical treatment *is* the active-probing resistance:
a prober cannot tell a tinc node from a plain web server. The decoy is a static
page (built-in default, or files under `HttpsDecoyRoot`) or a transparent proxy to
`HttpsDecoyUpstream` (Host rewritten). The same decoy content is served over
plain HTTP to a cleartext prober (`decoy_serve_plain`). No response path emits a
tinc-identifying string.

The client side also falls back: if the dial cannot pin the cert or the server
answers anything other than `101`, `https_dial`'s connection dies before it
activates and the outbound selector advances to the next carrier (ending at
`plain`, §2).

### 7.6 What a middlebox sees

Only TLS records to the standard front port, with a normal-looking certificate
and (if it could decrypt, which it cannot) a WebSocket upgrade. Whether `101`
(success) or a static page (decoy) is chosen is invisible on the wire because it
is inside TLS; `101 Switching Protocols` was chosen for the success case because
WebSocket-over-HTTPS is ubiquitous and needs no polling. There is no separate
UDP flow to correlate.
