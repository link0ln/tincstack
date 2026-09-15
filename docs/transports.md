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
| `TRANSPORT_HTTPS` | `https` | M5 | TLS front, meta+data in one TLS flow | reserved |
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
| `Transports` | all compiled (`plain, sf`) | accept list; advertised; `plain` always included |
| `PreferredTransports` | `plain` | dial order; always ends at `plain` |
| `SingleFlow` | `no` | `yes` = dial `sf` first (TCP kept as fallback) |

With all defaults, a node dials `plain` and accepts `plain,sf`: identical on the
wire to upstream tinc, and interoperable with an unmodified upstream peer.

---

## 7. QUIC carrier (design, stream Q)

Status: **design + de-risking only.** Stream Q (2026-09-16) picked the library,
made its build reproducible (`core/Dockerfile.build-quic`) and proved every
primitive the carrier needs in a standalone spike (`testing/quic-spike/`). The
carrier itself (`transport_quic.c`) is stream G3's work and is gated on G1's
certificate automation. This section is written so G3 can implement from it
without re-deriving anything.

### 7.1 Library decision

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

Measured (`core/Dockerfile.build-quic`, no cache): build stage 60 s total, of
which ngtcp2 configure+make+install 16 s; +16 MB on the build stage (466 vs
449 MB), **+5.4 MB on the runtime image** (100.3 vs 94.9 MB: libgnutls30 and
its dependencies, libngtcp2 + libngtcp2_crypto_gnutls).

### 7.2 Spike results (testing/quic-spike, three consecutive runs, all PASS)

| primitive | observed |
|---|---|
| handshake | QUIC v1, TLS 1.3, server cert + key loaded from PEM (EC P-256, self-signed, generated at run time), client verifies by **SHA-256 fingerprint pin only**: `PIN ok sha256=...`, `HANDSHAKE ok alpn=h3 sni=cdn.example.net tls=TLS1.3 cipher=AES-128-GCM group=X25519` |
| pin mismatch | wrong pin -> client aborts with TLS alert 42 (bad_certificate), server never completes the handshake, both exit |
| datagrams | 5/5 both ways per round, three rounds |
| stream | one client-opened bidirectional stream (id 0), bytes both ways |
| NAT rebind | client's source port changes, client only calls `ngtcp2_conn_set_local_addr`; server logs `PATH_VALIDATION success remote=127.0.0.1:<new port>` and stream + datagrams continue |
| active migration | `ngtcp2_conn_initiate_immediate_migration` to a third port with a fresh connection id; both sides validate; traffic continues |
| close | `CONNECTION_CLOSE`, both processes exit 0 |
| wire | first packet: `c3 00 00 00 01 08 ...` (1200 bytes); 71 packets in the session: 3 long-header, 68 short-header |

Two findings that must carry into the carrier: `active_connection_id_limit`
must be raised from the default 2 (the spike uses 8) or the second migration in
a session kills the connection with `ERR_CONNECTION_ID_LIMIT`; and (see 7.6)
**the current UDP classifier only recognises long headers**, i.e. the
handshake; every 1-RTT packet after it is a short header that the table in §3
would route to the SPTPS path.

### 7.3 Where the carrier sits

- Registry row: `[TRANSPORT_QUIC] = { .id, .name = "quic", .caps =
  TRANSPORT_CAP_SINGLE_FLOW, .init, .exit, .dial, .send, .close,
  .local_address, .udp_receive, .send_datagram }`. Meta *and* data ride the
  one QUIC connection; there is no tinc-shaped TCP connection and no separate
  plain SPTPS UDP flow between the two nodes. `accept` (TCP) stays NULL.
- Socket: **tinc's existing UDP listen sockets** (`listen_socket[i].udp.fd`),
  picked by address family like `sf_pick_socket()`. No extra socket, no extra
  port: the front classifier (§3) hands QUIC datagrams to `udp_receive`. The
  `QuicPort` key in `docs/config-schema.md` is *reserved* for an additional
  QUIC-only UDP listener (443/UDP for HTTP/3 plausibility); it is not part of
  the first implementation.
- Loop: tinc's `event.c`. Reads arrive through `handle_incoming_vpn_data` ->
  `transport_udp_dispatch`. Writes are `sendto()` on the listen socket to the
  path ngtcp2 returns. Timers: one `timeout_t` per session, re-armed after
  every flush from `ngtcp2_conn_get_expiry()`; its callback runs
  `ngtcp2_conn_handle_expiry()` then flushes. (`spike_run_until` in
  `testing/quic-spike/common.c` is this loop in 40 lines.)
- Per-session state (`quic_session_t`, `c->transport_data`): `ngtcp2_conn *`,
  `gnutls_session_t`, `ngtcp2_crypto_conn_ref`, listen-socket index, the
  peer `sockaddr_t`, the meta stream id, the meta TX ring (bytes must stay
  valid until `acked_stream_data_offset` says so), a small datagram TX queue,
  the timer, and the list of connection ids we issued (for the lookup in 7.6).
  `c->socket = -1` as in SF.

### 7.4 Hook mapping

| hook | ngtcp2 / GnuTLS |
|---|---|
| `init()` | `gnutls_global_init()`; build the server credentials once from the node's own `keys.tls_cert` / `keys.tls_key` (PEM text in the YAML, G1) with `gnutls_certificate_set_x509_key_mem(cred, &cert, &key, GNUTLS_X509_FMT_PEM)`; draw a 32-byte static secret for stateless-reset tokens; init the CID -> session hash. Re-run on `tinc reload` so a replaced certificate is served without restart. |
| `exit()` | close every session (`close` below), free credentials, `gnutls_global_deinit()`. |
| `dial(c)` | Peer's `TlsFingerprint` from its host record: **absent => return `false`** (falls to the next carrier, §2). Pick the listen socket by family; `gnutls_init(GNUTLS_CLIENT...)`, `ngtcp2_crypto_gnutls_configure_client_session`, priority `NORMAL:-VERS-ALL:+VERS-TLS1.3:...:%DISABLE_TLS13_COMPAT_MODE`, `gnutls_certificate_set_verify_function(cred, verify_pin)`, ALPN and SNI (7.8); random DCID (8) + SCID (8); `ngtcp2_conn_client_new(path = {listen socket addr, c->address}, NGTCP2_PROTO_VER_V1, callbacks, settings, params)`; `ngtcp2_conn_set_tls_native_handle`; `c->status.connecting = false; connection_add(c)`; flush (sends the Initial). Return `true`. **Do not** call `finish_connecting()` here: it runs from the `handshake_completed` callback (7.5) after the authenticator bytes are queued, so the tinc `ID` line is the second thing on the stream. |
| `udp_receive(ls, buf, len, addr)` | `ngtcp2_pkt_decode_version_cid(&vc, buf, len, 8)`; look the DCID up; known session => `ngtcp2_conn_read_pkt(conn, path = {ls->sa, *addr}, pi, buf, len, now)` then flush; **the path's remote is the datagram's real source, always** (that is the whole NAT-rebind mechanism). Unknown DCID and `ngtcp2_accept(&hd, buf, len) == 0` => `quic_accept()` (7.5), rate-limited by `max_connection_burst` like `sf_accept()`. Unknown DCID otherwise => drop (a stateless reset reply is optional; not needed between our own daemons). Errors from `read_pkt`: `NGTCP2_ERR_DRAINING` / `CLOSING` / `DROP_CONN` => `terminate_connection(c, false)`; `NGTCP2_ERR_CRYPTO` => log the TLS alert and terminate; anything else => send `CONNECTION_CLOSE` with `ngtcp2_ccerr_set_liberr` and terminate. |
| `send(c)` | Move `c->outbuf` into the session's meta TX ring, clear it, flush. The flush loop is the spike's `spike_flush()`: queued datagrams first with `ngtcp2_conn_writev_datagram` (pop on `accepted`), then `ngtcp2_conn_writev_stream(stream_id, remaining ring bytes)`, `sendto()` every non-empty packet to `ps.path.remote`, stop at `nwrite == 0`, then `ngtcp2_conn_update_pkt_tx_time` and re-arm the timer. `NGTCP2_ERR_STREAM_DATA_BLOCKED` => mark blocked until `extend_max_stream_data`. Return `true`. |
| `send_datagram(c, buf, len)` (new hook, see 7.5) | queue + flush; `false` if `len > ngtcp2_conn_get_max_tx_udp_payload_size() - 35` (the caller then treats it like `EMSGSIZE` -> `reduce_mtu`). |
| `close(c)` | `ngtcp2_conn_write_connection_close` (app error 0, or the recorded `ngtcp2_ccerr`) -> `sendto`; `timeout_del`; drop the session's CIDs from the hash; `ngtcp2_conn_del`, `gnutls_deinit`; free. |
| `local_address(c, sa)` | `getsockname(listen_socket[s->sock].udp.fd)`, as SF. |

ngtcp2 callbacks (the table `spike_callbacks()` builds is the complete list):
the `ngtcp2_crypto_*_cb` set for crypto, `rand` and `get_new_connection_id2`
from `gnutls_rnd`, `remove_connection_id` (maintain the CID hash),
`handshake_completed`, `recv_stream_data`, `acked_stream_data_offset`,
`stream_open`, `recv_datagram`, `path_validation`, `extend_max_stream_data`.
`ack_datagram` / `lost_datagram` are not needed: SPTPS handles loss.

Settings / transport parameters (from the spike): `initial_max_streams_bidi =
1` (we use one), `initial_max_streams_uni = 0`, `initial_max_data = 1 MiB`,
`initial_max_stream_data_bidi_{local,remote} = 256 KiB`,
`max_datagram_frame_size = 65535`, **`active_connection_id_limit = 8`**,
`max_idle_timeout = 3 x PingTimeout`, `settings.handshake_timeout =
PingTimeout` (so the library gives up in step with tinc's reaper, §2 step 3).

### 7.5 Framing SPTPS records

**Meta path** (ordered bytes: tinc requests, then SPTPS stream records) rides
**one bidirectional stream**, opened by the dialler in `handshake_completed`
(`ngtcp2_conn_open_bidi_stream` -> id 0). The acceptor adopts the first stream
it sees in `stream_open`/`recv_stream_data` and shuts any other
(`ngtcp2_conn_shutdown_stream`, app error 1): there is deliberately no muxing.
Inbound bytes go to `receive_meta_bytes(c, data, len)` from
`recv_stream_data`, then the credit is returned with
`ngtcp2_conn_extend_max_stream_offset` + `ngtcp2_conn_extend_max_offset`
**after** the call; `c` may have been terminated inside it, exactly the caveat
`sf_deliver()` documents.

The first bytes on the stream, before the tinc `ID` line:

```
    +----------------------------------------------------------------+
    | PLACEHOLDER (G1): the in-session peer authenticator that G1     |
    | defines for the `https` carrier: the same bytes, same           |
    | derivation from the tinc node keys, same verification. The QUIC |
    | carrier sends them as the first bytes of stream 0; the acceptor |
    | verifies them before it lets a single byte reach                |
    | receive_meta_bytes(). Final format: the https section of this   |
    | document once G1 lands. Until then the carrier sends nothing    |
    | here.                                                           |
    +----------------------------------------------------------------+
```

Dialler order in `handshake_completed`: open stream -> queue authenticator ->
`finish_connecting(c)` (which calls `send_id()` -> `send` hook -> same stream).
Acceptor: verify authenticator -> `c->allow_request = ID` and continue as SF's
`sf_accept()` does (`new_connection()`, name `<unknown>`, `connection_add`).

**Data path** (the SPTPS *datagram* records) rides **DATAGRAM frames**, one
tinc UDP packet per frame, byte-for-byte what `send_sptps_data()` would have
put on the wire (`dst-id | src-id | record`, or the direct/legacy forms), so a
relay never sees a difference. Hook points:

- send: at the end of `send_sptps_data()`, where it has built `buf` and would
  `choose_udp_address()` + `sendto()`: if `relay->connection &&
  relay->connection->transport->send_datagram` and the session is up, call
  it instead. Returning `false` is handled like `EMSGSIZE` (-> `reduce_mtu`),
  so tinc's own MTU probing converges on the datagram ceiling by itself.
- receive: `recv_datagram` -> `handle_incoming_vpn_packet(ls, &pkt, &addr)`
  with the frame payload as `pkt->data` and the session's peer address as
  `addr` (net_packet.c exposes this as `transport_deliver_udp()`; the
  classifier path is skipped because the bytes already came from a carrier).
  The unchanged SPTPS receive path authenticates and decrypts; relayed packets
  are forwarded as today.
- `n->status.udp_confirmed` / MTU probes: no special casing. Probes are SPTPS
  records and go through the same datagram hook; oversize probes fail there.
- Ceiling: with the initial 1200-byte UDP payload the DATAGRAM payload is about
  1160 bytes (1 flags + 8 DCID + 1-4 packet number + 3 frame header + 16 AEAD
  tag); after PMTUD on Ethernet about 1410. Compare `SF_MAX_PAYLOAD` 1200.

### 7.6 Coexistence on the UDP socket: classifier changes G3 must make

The §3 rule `(b0 & 0xC0) == 0xC0` + known version claims **long-header packets
only**: Initial, 0-RTT, Handshake, Retry, Version Negotiation. Header
protection scrambles the low bits of the first byte (the spike saw `c3`, `cb`,
`c0` for Initials, `c4` for the server's), so only the top two bits and the
version word may be keyed on, which is what the table does. Recorded from the
capture, the bytes the classifier keys on for our own Initial:

```
    offset 0   1  2  3  4   5
           c3  00 00 00 01  08 ...     b0 & 0xC0 == 0xC0, version = 0x00000001, dcidlen = 8
```

After the handshake every packet is a **short header**: `(b0 & 0xC0) == 0x40`
followed directly by the destination connection id. §3 routes those to the
SPTPS path today, so the carrier cannot work with the table as it stands.
Required change (the "keyed check" slot the obfs row in §3 already reserves):

| test | class |
|---|---|
| `(b0 & 0xC0) == 0x40`, `len >= 1 + 8 + 20`, and bytes `1..8` equal a connection id **this node issued** for a live QUIC session | `QUIC` (keyed; done in `transport_udp_dispatch` by `quic_udp_lookup()` before falling through to SPTPS) |

Residual: an SPTPS datagram whose first byte is `0x40..0x7F` (a quarter of
node ids) *and* whose next 8 bytes equal one of our live CIDs: 2^-64 per
session, the same class of argument as the SF magic. Stateless resets from a
peer look like short headers with an unknown CID and fall through to SPTPS,
where they fail authentication and are dropped; acceptable. Update the §3
table in the same commit as the code; `testing/transports/classify_test.c`
gets the new row (a fake session table is enough since `transport_table.c`
stays daemon-free: expose the lookup as a function pointer it calls when set).

SF (`0x9f...`) and QUIC never overlap (`0x9f & 0xC0 == 0x80`, neither form);
obfs remains keyed and is checked after QUIC.

### 7.7 Certificate, pinning, identity binding

- The node serves its **own** certificate (G1: `keys.tls_cert` / `tls_key`,
  self-signed EC P-256 at first start, replaceable). Same object as the HTTPS
  front's; loaded in `init`, reloaded on `tinc reload`.
- The dialler pins the peer's `TlsFingerprint` (host record, propagated with
  the host file and in invitations). `verify_pin` is the spike's: DER of the
  presented leaf -> `gnutls_fingerprint(GNUTLS_DIG_SHA256)` -> constant-time
  compare with the pinned hex. **Nothing else is checked**: no CA, no name,
  no validity period; the pin *is* the identity, and a renewed certificate
  changes the pin in the host record anyway. The SNI sent is shaping, never
  validated. Mismatch => TLS alert 42, connection closed, `LOG_ERR` line with
  both fingerprints (the spike prints exactly that), fallback per 7.9.
- Identity binding (the gap `tinc-quic` left open): the pin ties the QUIC
  session to the certificate recorded under the peer's **node name**; the
  authenticator (7.5, G1) ties the session to the tinc keys of that name before
  any tinc request is parsed; then the unchanged Ed25519 SPTPS handshake inside
  the stream proves the name. A certificate alone never authenticates a node.
- No client certificate: the acceptor learns who the peer is from the
  authenticator and the SPTPS handshake, not from TLS.

### 7.8 What the wire shows (for later DPI shaping)

`QuicAlpn` (default `h3`) and `QuicSni` (default: the peer's `Address` when it
is a DNS name, else the configured value, else no SNI) are the only knobs. The
spike shows both sides can report what was negotiated
(`gnutls_alpn_get_selected_protocol`, `gnutls_server_name_get`). HTTP/3
conformance beyond the handshake is out of scope (ARCHITECTURE §10); Initial
packets are padded to 1200 bytes by the library, as browsers do. Both keys are
`Quic*`-prefixed so M2/M6's invitation copy and the GUI panel pick them up
without further changes; add them to `docs/config-schema.md` with the code.

### 7.9 Handshake failure and fallback

All of these end in the §2 walk to the next candidate, ending at `plain`,
because the connection dies before it activates:

| failure | detection | action |
|---|---|---|
| peer has no `TlsFingerprint` in its host record | `dial` | return `false` immediately (§2 step 2) |
| no UDP socket of the peer's address family | `dial` | return `false` |
| QUIC dropped by the network (UDP/443-style filtering, DPI) | no packet ever arrives; ngtcp2 retransmits the Initial with backoff; `handshake_timeout = PingTimeout` expires, or tinc's reaper hits first | `terminate_connection` before activation => next candidate (§2 step 3) |
| pin mismatch / TLS failure | `NGTCP2_ERR_CRYPTO` from `read_pkt` | `CONNECTION_CLOSE`, log both fingerprints, terminate => next candidate |
| Version Negotiation packet | `NGTCP2_ERR_VERSION_NEGOTIATION` from `decode_version_cid` | we speak v1 only: treat as failure, terminate |
| authenticator rejected (acceptor) | 7.5 | close with app error; never deliver bytes to `receive_meta_bytes` |
| mid-session: idle timeout, path validation failure, peer close | `read_pkt` / `handle_expiry` errors, `path_validation` FAILURE | `terminate_connection` => automatic reconnect re-evaluates preferences from the top (§2 step 4) |

NAT rebind on wake needs no code on the dialling side: tinc's listen socket
does not move, the NAT mapping does, the *acceptor* sees a new source address
in `udp_receive` and ngtcp2 validates it (spike `rebind`). After
`path_validation` SUCCESS the carrier copies `ngtcp2_conn_get_path()->remote`
into `c->address` / the node's UDP address so edges and `hostname` follow.
Active migration (`ngtcp2_conn_initiate_immediate_migration`) is only for a
*local* socket change (Android Wi-Fi -> LTE), which tinc does not do today;
the spike proves it works when M8 needs it.

### 7.10 Build wiring for G3

`meson_options.txt`:

```
option('quic', type: 'feature', value: 'auto',
       description: 'QUIC carrier (ngtcp2 with the GnuTLS backend)')
```

`src/meson.build`, next to the other dependencies:

```
opt_quic = get_option('quic')
dep_ngtcp2 = dependency('libngtcp2', version: '>=1.0', required: opt_quic, static: static)
dep_ngtcp2_crypto = dependency('libngtcp2_crypto_gnutls', required: opt_quic, static: static)
dep_gnutls = dependency('gnutls', version: '>=3.7.3', required: opt_quic, static: static)
if dep_ngtcp2.found() and dep_ngtcp2_crypto.found() and dep_gnutls.found()
  src_tincd += 'transport_quic.c'
  deps_tincd += [dep_ngtcp2, dep_ngtcp2_crypto, dep_gnutls]
  cc_flags_tincd += '-DHAVE_QUIC'
endif
```

`transport_table.c`: the `compiled` flag of the `quic` row becomes
`#ifdef HAVE_QUIC` (as `HAVE_TRANSPORT_TEST` does), so the default accept
list and the advertised `Transports` line include `quic` only in builds that
have it. `transport.c`: fill the row (7.3) under the same guard.

Docker: `core/Dockerfile.build-quic` already provides the three pkg-config
modules in the build stage and the shared objects + `libgnutls30` in the
runtime stage; when the option exists, add `-Dquic=enabled` to its meson line
so a missing dependency fails the build instead of silently producing a
QUIC-less daemon. The plain `core/Dockerfile.build` keeps building without
QUIC (`auto` finds nothing there): with all defaults the daemon is unchanged.

Windows (mingw) and Android (NDK, M8): GnuTLS is the heavy part of this
choice. ngtcp2's API is backend-independent; only the TLS object setup differs
(`ngtcp2_crypto_<backend>_configure_*_session` plus the backend's own
credential calls, ~60 lines, the spike's `spike_tls_init`). Keep that in
`transport_quic_tls.c` so the wolfSSL or BoringSSL backend can replace GnuTLS
per platform without touching the carrier.

### 7.11 Open risks for G3

1. **Classifier gap** (7.6): short-header packets. Without the keyed CID
   lookup the carrier handshakes and then goes deaf. Must land with the
   carrier and its unit test.
2. **Authenticator format** is G1's; the carrier has a marked placeholder. If
   G1's `https` authenticator relies on TLS early data / ClientHello
   extensions, the QUIC variant is the same bytes on stream 0 instead; agree
   on that before either side ships.
3. **Buffers must outlive acknowledgement**: meta TX bytes stay in the ring
   until `acked_stream_data_offset`; `c->outbuf` cannot be handed to ngtcp2
   directly.
4. **`receive_meta_bytes` may terminate the connection** from inside a
   ngtcp2 callback; the callback must return without touching the session
   afterwards (SF has the same rule).
5. **Cross-platform TLS backend** (7.10).
6. Relay through a QUIC-carried link is designed (7.5) but not measured:
   the three-node proof in `testing/transports/` must be repeated with the
   middle hop on `quic`.
