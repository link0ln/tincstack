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
| `TRANSPORT_QUIC`  | `quic`  | OpenSSL >= 3.5 builds with ngtcp2 (`-Dquic`, default in `Dockerfile.build`) | QUIC v1: meta on one bidi stream, SPTPS data in DATAGRAM frames | done (M5, G3) |
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
  `plain` is in the accept list by default, and `Transports` alone cannot take
  it out: a list that omits it gets a warning and `plain` back. Removing it is
  a separate, deliberate switch — `AllowPlainMeta` below.

- **`PreferredTransports` — the dial preference**, in order. **Default:
  `[plain]`.** The first carrier on this list that is also in the peer's accept
  list is dialled. This is the "tick QUIC in the GUI" knob: only the dialling
  side changes, because the peer already accepts the carrier.

- **`AllowPlainMeta` — may the listener take an inbound *cleartext* tinc meta
  connection at all.** **Default: `yes`**, which is what tinc has always done.
  `no` removes `plain` from the effective accept mask, which is then both
  advertised to peers (host record and ACK) and enforced by the TCP front.
  What it does and does not buy you is §2.1.

- **`UdpMetaFallback` — may a meta connection fall back onto the peer's
  confirmed direct UDP flow** when every address we know for that peer has just
  refused a meta connection? **Default: `yes`** (defect E, §2.2). `no` restores
  the pre-fix behaviour, in which such a pair stays relayed through a third
  node for ever.

`SingleFlow = yes` (default **no**) is sugar for putting `sf` at the head of
`PreferredTransports`. The default is `no` because single-flow trades tinc's
separate, independently-recovering TCP meta channel for one UDP flow; it is opt-in
until it has field mileage, and the plain TCP path stays as the fallback when UDP
is blocked (see §4).

### 2.1 `AllowPlainMeta = no`: refusing cleartext on the listening port

**What it is for.** Every carrier wraps SPTPS, and SPTPS is never bypassed, so
a plain meta connection is *already* authenticated and encrypted. Refusing it
buys nothing for secrecy and everything for **classification**. Until this
option existed, a node configured `Transports: [obfs]` because it sits behind a
DPI box still answered an unadorned tinc handshake on its port: one TCP
connection carrying the ID line `0 <any member name> 17.7` got the node's own
ID line back, so the node stayed fingerprintable as tinc by a **probe**, not a
man-in-the-middle. That is the thing this project exists to prevent, so
"circumvention is opt-in" (guardrail 5) must not mean "cleartext is mandatory".

**What it does.** `AllowPlainMeta: no` takes `plain` out of the effective
accept mask. Two consequences, in two different places:

1. The mask is what the node **advertises** (host record and the trailing ACK
   token), so peers stop putting `plain` on their candidate list for it.
2. The **TCP front** (`transport_front_dispatch`, `TCP_CLASS_TINC`) consults
   the mask exactly like the `TCP_CLASS_TLS` branch next to it, and refuses:

       WARNING Front: refusing cleartext tinc meta connection from 10.37.155.50 port 60508: `plain' is not in this node's Transports accept list (AllowPlainMeta = no)

   The socket is **tarpitted**, exactly like an unrecognised preamble, so the
   refusal is not itself a distinguisher: a prober gets an open, silent socket
   and no bytes, not an RST and not a banner.

**What it does NOT buy you.**

- It is not confidentiality. SPTPS protected the payload before and after.
- It is not invisibility of the *port*. Something still listens; what changed
  is that it no longer identifies itself as tinc to anyone who asks in tinc.
- It does not touch the **UDP data path**. `plain`'s bit gates meta
  classification only; SPTPS datagrams are still received (they have to be —
  `obfs`, `sf` and `quic` all still use the plain SPTPS data path or the plain
  UDP socket underneath).

**What it costs — read this before turning it on.**

- **`tinc join` against this node stops working.** The invitee's `tinc join`
  opens a raw TCP connection and sends `0 ?<key> ...` (`invitation.c`); that is
  a cleartext tinc ID line and it is refused like any other. Measured:

      Timed out waiting for the server to reply.
      Cannot read greeting from peer
      Could not connect to inviter. Please make sure the URL you entered is valid.

  Invite from a node that still allows plain, or turn the option off for the
  duration of the join (`tinc set AllowPlainMeta yes ; tinc reload`, then back
  — both directions are proven live in `plain-refuse-test.sh`).
  This is the real trade-off of the option and it is why the default is `yes`.
- **Upstream (unmodified) tinc peers cannot connect to it at all**, and neither
  can any tincstack peer whose `PreferredTransports` is the default `[plain]`:
  a peer must opt into a wrapped carrier of its own to reach this node. The
  carrier candidate list deliberately still falls back to `[plain]` when the
  operator's preference list and the peer's accept list have nothing in common
  — the dialler is never silently upgraded into a covert carrier it did not
  ask for.
- The node **still dials `plain` outbound** if it prefers to. `AllowPlainMeta`
  is a listener policy, not a dial policy; use `PreferredTransports` for that.
- Your own **host record** is not rewritten. `zeroconf.c` wrote
  `Transports = plain, sf, obfs, ...` into it when the node was created, and
  `tinc dump nodes` keeps printing that for `MYSELF`. Peers that have only the
  host record (never connected yet) will therefore still try `plain` once and
  be refused; they learn the real list from the ACK on any carrier that works.
  Set `Transports` on the node to match if you care about the first attempt.

**The local CLI is unaffected**, deliberately. On POSIX the control connection
arrives on the UNIX socket and never reaches the TCP front at all. On Windows
there is no UNIX socket and `tinc` reaches its own daemon by connecting to this
very port with `0 ^<cookie> ...` — a tinc ID line — so the front exempts
**loopback** from the refusal. An attacker who can already connect from
127.0.0.1 does not need to fingerprint the port, and locking the operator out
of their own node would buy nothing.

`AllowPlainMeta` is re-read by `setup_myself_reloadable()` like `Transports`
and `SingleFlow`, so `tinc set AllowPlainMeta no ; tinc reload` takes effect on
a running daemon (proof: `testing/transports/plain-refuse-test.sh` PART 3).

It is **not** `VAR_SAFE` and **not** in `PROPAGATED_OPTIONS`: an inviter must
not be able to switch a per-node listener policy on the invitee's machine
(`invitation.c`, security review R).

### 2.2 `UdpMetaFallback`: a meta connection on the data path

**The case.** Two nodes behind one NAT. Neither has an address for the other
except the shared public one, because that is the only address either
advertises: `router` is itself behind its ISP's NAT and advertises `192.168.0.2`
as its local address, `laptop` lives in a docker bridge and advertises
`10.16.8.2` — neither is dialable by the other, so "advertise your LAN address"
does not help this pair. The NAT hairpins UDP and not TCP (measured on the field
NAT: `laptop → router` 10 packets, 0 % loss, 5.7 ms each way, while every TCP
connect times out). The result is a half-state: the **data** path is direct and
healthy, the **meta** connection is relayed through a VPS abroad
(`nexthop euvds … distance 2`), and each node logs an ERROR every backoff round
for ever.

**What the daemon does now.** When `do_outgoing_connection()` has walked every
address the graph and the config know for a peer and every one of them refused
a meta connection, it asks `transport_udp_meta_fallback()` for one more address:
the one the peer's **confirmed direct UDP flow** already uses. If it gets one,
the meta connection is dialled there over the `sf` carrier — the same path, the
same 5-tuple, the same NAT mapping that the data packets are already using.

Every condition has to hold, and none of them is a guess:

| condition | why |
|---|---|
| `UdpMetaFallback` is on | the operator can turn the whole thing off |
| `sf` is compiled, dialable, and in **our** `Transports` | an operator who removed `sf` does not want it dialled |
| `sf` is in the **peer's** advertised accept list | never dial a carrier the peer has not said it takes |
| the peer is reachable and `status.udp_confirmed` | there is a UDP path, and we measured it, not assumed it |
| `n->via == n` | the UDP path goes to the peer, not through a relay |
| once per reconnect cycle | the backoff, not a loop, bounds the attempt rate |

Nothing about authentication changes: the `sf` carrier hands the same ID
exchange and the same SPTPS session to the same code, and the acceptor still
enforces its own `Transports`/`AllowPlainMeta`. The fallback is an **address**
of last resort, not a preference: it sits outside the `PreferredTransports`
walk, which has already been exhausted over the known addresses by the time it
fires.

Because the fallback needs a *confirmed* UDP path and confirmation is normally
driven by traffic, `setup_outgoing_connection()` also calls `try_tx()` for a
reachable peer with no confirmed path — the same call ordinary traffic makes,
rate-limited by `try_udp`/`try_sptps` and by the growing reconnect backoff. A
pair with nothing to say to each other would otherwise never qualify.

Proof: `testing/transports/same-nat-meta-test.sh` (and the same script with
`SET_OPTS='UdpMetaFallback no' --expect-relayed` as the negative control).

### Selection algorithm (outbound), per connection

1. On the first dial to a node, build the candidate list: walk
   `PreferredTransports`, keep each carrier that is (a) in the peer's accept
   mask and (b) dial-capable in this build. If the list is empty, it is
   `[plain]`. The walk order is always the operator's preference order.
2. Dial the current candidate. If its `dial` hook fails immediately (no socket),
   the failure counts as in step 3 (`net_socket.c`); if the walk advanced, the
   next candidate is dialled right away against the same addresses.
3. If the connection dies **before it is activated** (the carrier's handshake
   never completed — detected in `terminate_connection` by the absence of an
   edge), the walk advances to the next candidate on the automatic reconnect,
   **except** for the carrier that last activated a link *we dialled* to this
   peer: that one is retried, with the normal reconnect backoff, until it has
   failed `TRANSPORT_STICKY_FAILURES` (**3**) times in a row (`Carrier https
   failed for nodeb before activation (1/3) but worked before, retrying it`).
   Only then is it given up (`Carrier https failed 3 times in a row for nodeb,
   no longer preferred`) and the walk moves on. A carrier that never worked
   is abandoned on its first failure, so a peer that cannot do it costs one
   attempt, as before. A dial cut by `tinc retry` is not such a failure:
   `retry()` expires every connection still being set up so it is re-dialled
   at once, and since 2026-09-24 it marks them (`outgoing->retry_requested`),
   so the re-dial uses the **same** carrier (`The dial was restarted by
   \`tinc retry', not failed by the carrier: trying https again`). Before,
   a retry during a TLS or QUIC handshake fell back to plain for the rest of
   the session; the Android app runs `tinc retry` on every connectivity
   change, the VPN coming up included, so its https link nearly always ended
   on plain (`testing/transports/retry-carrier-test.sh`).
4. When a connection **activates** (ACK received), the walk is reset to the
   top of the preference list and, if the activated connection is the one we
   dialled (not a link the peer opened towards us that inherited our
   `outgoing`), its carrier is remembered as the one that works for this peer.
5. An **activated link that drops** (peer reload, restart, RST, ping
   timeout, `UDPRebindOnWake`) never advances the walk: the reconnect starts
   at the first preference again, so a downgrade obtained through step 3 is
   undone at the next reconnect and the walk never settles on `plain`.
6. When every candidate has failed, the cycle restarts from the first
   preference (`Every carrier failed for nodeb, restarting from https`).

Why 3 and not 1 (review row L-2): before this rule a single refused re-dial —
the peer still restarting, one blocked or reset TLS/QUIC handshake — moved an
`https`/`quic` link to `plain`, and the link then stayed there until it
dropped again. Now a downgrade needs the preferred carrier to fail three
consecutive dials (5 s + 10 s + 15 s of backoff, so ~30 s of sustained
blocking of that carrier towards that peer), and it is reverted at the next
reconnect anyway. This is a nuisance bound, not a guarantee: an on-path party
that can block the covert carrier for long enough still gets `plain`, because
`plain` is the deliberate last resort of the list. To forbid it outright, leave
it out of `PreferredTransports` **and** off the peer's accept list — which
since `AllowPlainMeta` (§2.1) the peer *can* express: a node that sets
`AllowPlainMeta: no` advertises an accept mask without `plain`, and the
dialler's candidate list then never contains it.

One side's choice is enough; nothing has to be configured on both ends. A peer
that advertises no list at all (upstream tinc) is treated as `plain`-only.

### When the peer dials first (acceptor-side rule, review row L-2 residual)

The rules above govern *our* dials. When the peer dials us first
(`AutoConnect`, its own `ConnectTo`) the link runs on the carrier *it*
prefers, and tinc keeps the newer of two connections between the same pair
(`protocol_auth.c id_h`), parking our `outgoing` on that inbound link. A
rendezvous with the default `PreferredTransports: [plain]` that knows our
address therefore used to bring a restarted link back as `plain` regardless of
our preference, and it stayed there until the next drop (observed in the L-2
lab: after `kill -9` of B, B's autoconnect reached A over `plain` before A's
own https re-dial, which then found `Already connected`).

The acceptor now has one rule, and it is deliberately the smallest one that
cannot oscillate:

> **7.** If a link the *peer* opened towards us runs on a carrier that ranks
> **below** the candidate our own `outgoing` would dial next, we dial ours
> anyway instead of suppressing it with `Already connected`
> (`net_socket.c setup_outgoing_connection`; `protocol_auth.c ack_h` arms the
> dial when our `outgoing` was parked on the inbound link). The peer's link
> stays up and carries traffic the whole time; when ours activates, the
> existing `id_h` dedup keeps the newer connection and drops the older one, so
> the pair is never left with zero connections.

The ranking is **not** each node's own preference list — that would flap, as
two nodes with mirrored lists would each keep overriding the other. It is the
fixed carrier order `plain < sf < obfs < https < quic` (the `transport_id_t`
enum, `transport_outranks_connection()`), which every build compiles
identically, so:

- only one of the two nodes can ever want to re-dial (if A's candidate
  outranks B's carrier, B's cannot outrank A's), and
- a re-dial moves the surviving link strictly **up** a bounded order, so the
  rule terminates after at most one extra dial per drop.

It is also bounded on the failure side: `transport_current()` only ever offers
a carrier the peer's accept list advertises, and if that dial keeps failing,
step 3's walk moves on after `TRANSPORT_STICKY_FAILURES` attempts, at which
point our candidate no longer outranks the inbound carrier and the rule
disengages. On default settings (`PreferredTransports: [plain]` on both ends)
it never fires at all: it can only engage when an operator asked for a
more-wrapped carrier.

What the rule does **not** do: it does not let us refuse a link, and it does
not stop a peer from reaching us over `plain` in the first place — `plain` is
forced into every accept list. It only stops a peer's `plain` re-dial from
*keeping* our covert carrier down.

    A: PreferredTransports [https, plain], ConnectTo nodeb
    B: PreferredTransports [plain] (default), AutoConnect yes, knows A's Address

    kill -9 B  ->  B restarts, dials A over plain, link activates
    A: "Connected to nodeb over plain, which we rank below https:
        dialling https as well"
    A's https link activates -> id_h drops the plain one on both ends
    A, B: dump connections -> transport https

### ACK wire format (backward compatible)

    <ACK> <udp-port> <weight> <options-hex> [<transports>]

The trailing `<transports>` token (e.g. `plain,sf`) is new. An unmodified
upstream peer's `ack_h` reads only the first three fields with `sscanf` and
ignores the rest, and our `ack_h` treats a missing token as `plain`. The `ID`
line is unchanged, so the handshake is wire-compatible with upstream tinc.

---

## 3. Inbound front classifier

One TCP listen port and one UDP port serve every carrier (plus the front-only
ports of §3.1, which admit TLS and QUIC and nothing else). On a new inbound
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

### 3.1 The front ports: TLS and QUIC on 443 (2026-09-23)

The fingerprint audit (`testing/fingerprint`) found the `https` and `quic`
fronts on tinc's own port, 655 by IANA assignment: a TLS or QUIC flow to 655 is
tinc to anyone who looks at the port, however good the TLS is. Now:

- A node that accepts inbound connections (`Port` unset or non-zero) also
  listens on **TCP `HttpsPort`** and **UDP `QuicPort`**, both **443** by
  default, one socket per address family. These sockets are front-only: TCP
  `HttpsPort` hands TLS to the `https` carrier and answers anything else as
  nginx does on its TLS port (§8.5.1; `c->status.front_tls_only`,
  `transport_front_dispatch`); UDP `QuicPort`
  feeds only `quic_udp_try()` and drops what it does not claim. `plain`,
  `sf` and `obfs` stay on the tinc port, and the tinc port still accepts
  `https` and `quic` for peers that do not know the new port.
- The UDP front socket is opened **without `SO_REUSEADDR`**
  (`setup_udp_socket(sa, false)`). On Linux two UDP sockets that both set it
  share the port and the kernel splits datagrams between them, so with it the
  front would silently take part of another QUIC server's traffic on 443
  instead of failing to bind.
- The node writes the ports it actually bound into **its own host record**
  (`transport_advertise_port()`), and removes the line when it bound nothing,
  so `tinc invite` and host-record exchange tell peers where to dial. A node
  that cannot bind (no root / `CAP_NET_BIND_SERVICE`, port taken) logs
  `could not listen on TCP|UDP port 443 (the default); peers reach the ...
  front on the tinc port ..., where it is easy to spot` and advertises
  nothing.
- A dial goes to the peer's host-record `HttpsPort` / `QuicPort`, else the
  dialler's own configured option, else the tinc port it dials. The node's own
  host record is merged into its config tree, so the dialler's "own option"
  lookup skips host-record lines (`lookup_option_not_host()`); otherwise its
  own advertisement would read back as an option and it would dial every peer
  on 443.
- The `quic` dial sends from a **fresh socket on an ephemeral port**, like
  every QUIC client, instead of from the node's listening socket (source port
  655 or 443 is a server's port, not a client's).
- `HttpsPort = 0` / `QuicPort = 0` turns a front listener off.

Limits: the advertised port is the port bound, so an operator port-forward that
maps a different external port is overwritten on every start (publish the
same port; the Linux compose files do, `FRONT_PORT`). `tinc join` is still
cleartext tinc on the tinc port. Non-TLS bytes on `HttpsPort` get nginx's
answer since the decoy step (§8.5.1); until then they were closed without one.

Proof: `testing/transports/front-port-test.sh` -- listeners and
advertisement, the invitation carrying the ports, https and quic joins over
443 (SYN destination ports only 443, QUIC from an ephemeral source port), no
answer to a tinc ID line on TCP 443 or random bytes on UDP 443, the https dial
(the decoy step later made that 400 -- see §8.5.1), the https dial
falling back to the tinc port without an advertisement, a node without
`CAP_NET_BIND_SERVICE` warning and advertising nothing, and a quic front that
refuses to share UDP 443 with an `SO_REUSEADDR` DTLS server (on the code
before that change it shared it and advertised 443).

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

**Silence and refusal are different evidence (defect G).** The budget above —
8 retransmissions, about 24 s — is the right answer to "we heard nothing back",
because a path can simply be lossy. It is the wrong answer when the kernel
returned `EPERM`, `ENETUNREACH` or `EHOSTUNREACH` on every one of those sends:
that is the local stack saying, synchronously, that the bytes never left the
machine. So `sf_send_raw()` reports *why* a send failed, and after
`SF_MAX_HARD_ERRORS` (3) **consecutive** refusals (`sockunreachable()` in
`utils.h`) the session is declared dead — about 3.5 s instead of 27 s, measured
in `singleflow-test.sh` PART 2 on a link severed with `iptables -j DROP`.
Consecutive is the whole point: any send the kernel accepts, and any frame that
arrives, resets the count, so a route that flaps and comes back is forgiven and
only an unbroken run of refusals ends the link. A dead session is the defined
degradation — the reaper terminates the connection, the graph reroutes, and the
dialler falls back to the next carrier — so the cost of being wrong is one
redial on the backoff, while the cost of being slow is a graph that keeps
routing key exchanges into an edge that no longer exists.

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
An SF link that drops *after* activation is re-dialled over SF first (§2 step
5); only three consecutive handshake failures make the walk move on.

### Sleep/wake and `UDPRebindOnWake` (review R-12)

An SF (or obfs, or quic) session lives on the UDP socket. When the daemon
detects that it slept (`net.c`, `sleeptime`) it closes every connection, and
with `UDPRebindOnWake` it also rebinds the UDP sockets to fresh ports, so the
session cannot survive: the link is torn down through `terminate_connection()`
exactly like a peer's reload, and the outgoing re-dials. Because those links
were *activated*, the re-dial starts from the first preference (§2 step 5) and
comes back on the same carrier; the `outgoing_t` (candidates, last-activated
carrier, failure count) is untouched by the rebind. The cost is one re-dial
per link after wake, which is what the option is for.

### `tinc reload` does not drop the carrier (stream P)

A reload is *not* a drop. `reload_configuration()` closes a meta connection only
when that peer's host record changed, and in YAML mode "changed" means the
record's **content** changed — `yamlconf_host_digest()` (SHA-512 truncated to
256 bits) against the snapshot taken when we last read the record, not the
mtime of a `hosts/<peer>` file that YAML mode does not have. Before this, every
reload closed every link, and since `tinc set/add/del` reloads the running
daemon itself, so did every configuration change; each of those drops then had
to be repaired by the §2 step-5 re-dial, so a covert carrier survived only
because that rule exists. Lines the daemon appends to a peer's record itself —
the learned `Ed25519PublicKey`, the `TlsFingerprint` pinned after SPTPS
activation (§8.3) — refresh the snapshot instead of counting as a change, so
the first reload after an https or quic link comes up no longer bounces it.
A genuine edit of a peer's record still terminates that one connection, which
then re-dials from the first preference like any other activated-link drop.

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

> **Frame version.** The layout and key schedule below are obfs **v2**
> (`tincstack-obfs-v2`), which replaces the v1 seal that review R found to be
> forgeable mesh-wide, nonce-reusing and replayable (findings M5-2…M5-6). v2 is
> not wire-compatible with v1, but the two only ever meet *inside one mesh*
> (obfs needs no upstream compat): a v1 node's frames simply fail a v2 node's
> keyed check and are dropped as junk, and vice-versa, so neither crashes the
> other — the obfs handshake never completes across the version boundary and
> the link falls back to `plain`. Upgrade all nodes of a mesh together.

### Frame

Every obfs datagram — a sealed single-flow meta frame or a sealed SPTPS data
datagram — is:

    offset size field
    0      M    magic      optional plaintext prefix (M = 4 if a magic header is
                           configured for this phase, else 0)
    M      8    nonce      the whitened per-direction counter; the ChaCha20-
                           Poly1305 IV is the un-whitened counter
    M+8    2    clen       length of the ciphertext that follows (network order)
    M+10   clen ciphertext ChaCha20-Poly1305(inner)  = inner_len + 16-byte tag
    M+10+clen P tail junk  P random bytes (handshake/steady header-junk knob)

`inner` is the exact datagram that would have been sent in the clear: the
single-flow frame (which itself begins with the SF magic) or the SPTPS relay/
direct datagram (`dst-id|src-id|record`). Nothing of tinc's structure is on the
wire — with no magic configured the leading bytes are the whitened counter and
the rest is ciphertext, both indistinguishable from random; the SF magic and
the SPTPS record are inside the sealed region.

### Key schedule (findings M5-2, M5-5): bootstrap key → per-link session key

The seal uses **direction-separated** ChaCha20-Poly1305 keys, in two tiers.

**Bootstrap tier (cold start only).** A base secret is derived from the two
nodes' public keys, sorted so both ends agree:

    base(64B) = SHA-512( "tincstack-obfs-v2\0" || lo_pubkey || "|" || hi_pubkey )

From it, per-direction keys and nonce-whitening masks:

    key_dir  = SHA-512( "tincstack-obfs-key\0" || dir || base )      (dir ∈ {l2h, h2l})
    mask_dir = SHA-512( "tincstack-obfs-iv\0"  || dir || base )[:8]

The `lo` node sends with the `l2h` key and receives with `h2l`; the `hi` node
does the reverse. Because every mesh member holds every public key, this key is
**not a per-link secret** — so it is used only for the first datagrams of a
link, until a session key exists. It is what makes cold-start classification
possible (the receiver can derive it before any handshake). The Poly1305 tag is
the junk/real discriminator: junk and forgeries fail it.

**Session tier (steady state).** Once the connection is up and its SPTPS meta
channel is authenticated, the two nodes exchange a fresh 32-byte seed each over
that channel — a new `OBFS_KEY` request (SPTPS is untouched; the seed rides the
already-authenticated, already-encrypted meta stream):

    OBFS_KEY <flag> <base64(seed)>      flag 0 = offer, flag 1 = ack

On receiving the peer's seed a node derives the session base and, when it
receives the peer's *ack* (proof the peer holds our seed and computed the same
key), switches its sender to the session keys:

    sbase(64B) = SHA-512( "tincstack-obfs-sess-v2\0" || lo_seed || hi_seed )
    skey_dir   = SHA-512( "tincstack-obfs-skey\0" || dir || sbase )
    smask_dir  = SHA-512( "tincstack-obfs-siv\0"  || dir || sbase )[:8]

The receiver always tries the session key first, then the bootstrap key (two
Poly1305 trials on the fast path), so the sender's switch never causes a
black-out. Only the two endpoints know the seeds, so a third mesh member — even
one holding every public key or a leaked `tinc.yaml` — cannot classify or forge
steady traffic (finding M5-2).

Direction separation also fixes reflection (finding M5-5): a datagram captured
in one direction is sealed with, say, the `l2h` key, and the receiver of a
reflection checks it with its own receive key (`l2h` for the other node), so a
reflected `CLOSE`/`RESET` never verifies.

The session key is re-derived periodically (aligned with `KeyExpire`, the SPTPS
rekey period): a node re-runs the seed exchange, keeps sending on the current
session key until the new one is acknowledged, then switches. This bounds the
per-key nonce space and gives forward secrecy on the obfuscation layer.
Rotation costs no traffic, because the sender only switches once the peer has
acknowledged the new keyset.

An **offer** (`OBFS_KEY` flag 0) always re-arms the answer, even from a node
that already acknowledged the previous round, so one node can rotate the key on
its own schedule: each side's `KeyExpire` is its own. (Until this was fixed the
responder stayed silent after its first acknowledgement, so rotation only
happened when both timers fired together and the effective period was the
*larger* of the two `KeyExpire` values — measured with a 10 s and a 3600 s node:
one session key in 80 s, eight offers ignored.) Proof:
`platforms/linux/docker/obfs-rekey-test.sh` — symmetric and one-sided rotation,
both over 80 s of 1 Hz traffic with 0 % packet loss.

The link state is **per node**, shared by every connection to that node. When
two nodes dial each other, tinc keeps one connection and closes the other. The
obfs close hook resets the shared link only when **no other connection to that
node survives** — decided by scanning the live `connection_list`, not by looking
at `node->connection`. That distinction matters: `terminate_connection()` clears
`node->connection` *before* it calls the carrier close hook, so at close time
`node->connection` is NULL exactly when the owner is being closed — which is also
the moment a replacement connection may already be on the list about to take the
node over. Keying the reset off `node->connection` therefore wiped the session
the surviving connection had just negotiated (or was about to); the list scan
sees the survivor and keeps the session (review R M5-2, residual). This is
proven deterministically by the `fuzz_obfs` self-test
`selftest_close_preserves_session`, which reproduces that exact ordering and
aborts on the pre-fix condition.

Two backstops bound the window in the cases the reset does fire (a genuine
owner-only close, or the rare scheduler interleaving where a wiped session is
not immediately re-negotiated). First, the **send path self-heals**: whenever a
datagram is about to be sealed under the mesh-wide bootstrap key on an active,
authenticated link, obfs schedules a one-shot timer (`OBFS_SELFHEAL_DELAY`, 1 s,
rate-limited to at most one offer per second per link) that re-issues the
`OBFS_KEY` seed exchange, so a link that lost its session key re-negotiates in
about a second. Second, as a slower catch-all, the 30 s rekey tick also
re-issues the exchange for any active link still on the bootstrap key. **Worst
case:** a link that reverts to the bootstrap key is back on a per-link session
key within roughly one `OBFS_SELFHEAL_DELAY` plus a meta-channel round trip
(≈ 1 s), not the previous up-to-30 s; the 30 s tick is now only a backstop of a
backstop. A *fresh* connection still legitimately uses the bootstrap key for the
first few frames until its first `OBFS_KEY` exchange completes — that is the
documented cold-start window, not a revert. (The residual was first seen by
`obfs-test.sh` PART 4 under host load, but it does **not** need load: on an idle
host, 2026-09-16, `obfs-test.sh` PART 8 against the pre-fix build left **6 of 10
connection replacements stuck on the bootstrap key** for the full 120 s deadline
— 673 of 1099 steady frames readable by anyone holding both public keys — while
the fixed build measured 0 stuck and 0 of 1172 on the same lab minutes later,
and 0 of 1182 under a parallel fuzz campaign. PART 8 is therefore both the churn
regression and a live before/after; the `fuzz_obfs` self-test is the
deterministic mechanism proof.)

### Nonce and replay window (findings M5-3, M5-4)

The ChaCha20-Poly1305 nonce is a **strict per-direction 64-bit counter**, so it
never repeats under a given key — no keystream reuse, no Poly1305 forgery. On
the wire the counter is whitened (`counter XOR mask_dir`) so it does not read as
a plaintext sequence number; the receiver recovers it by XORing the same mask.
The counter starts at a random 48-bit value per keyset, so the leading wire
bytes never look like a low counter. (That random start does **not** keep a
restarted node above the peer's window — see "Key epochs" below, which is what
actually prevents the black-out.) A configured **magic
header is a separate plaintext prefix and consumes no nonce entropy** — the v1
defect where the magic overwrote nonce bytes and left only 32 random bits is
gone.

Each direction keeps a **sliding replay window** (64 counters) over the
recovered counter. A datagram that fails the window (a replay, or one too old to
prove fresh) is dropped. Crucially, the remembered peer UDP address is moved
**only after** a datagram both verifies (Poly1305) and is fresh (replay
window), so a replayed sealed datagram from any source address can no longer
re-point the link before SF/SPTPS checks run (finding M5-4). A frame dropped by
the window is logged at `DEBUG_TRAFFIC` — the drop used to be entirely silent,
which is how the black-out below hid through every lab and two field sessions.

### Key epochs: a peer that restarts (defect F, second cause)

A replay window is only meaningful **inside one key epoch**. The session keyset
lives exactly one link, so its window is unambiguous. The **bootstrap** keyset
is not: it is derived from the two nodes' public keys and therefore outlives
both daemons, while the counter under it is re-randomised on every start. A peer
that restarts (or a container that is recreated) thus begins below the
acceptor's remembered high-water mark with probability `mark / 2^48`, and the
mark only ever moves up. Measured on a two-node stand: **1 of 6 restarts**
recovered obfs before the fix. Every frame of the dial decrypted correctly, was
counted as classified, and was dropped by the window without a log line.

So a frame that **opens a new single-flow session** (an `SF_TYPE_DATA` with
`SF_FLAG_SYN` and `seq == 0`) under the *bootstrap* key may start a new epoch:
the window is reset to that counter. It is rate-limited to once per 5 s per
link, and the session keyset's window is never restarted this way.

What that concedes, stated plainly: someone who recorded an old SYN can replay
it to reset the bootstrap window once per 5 s and then feed stale frames from
around that counter. They gain nothing — those frames land in a *new* single-flow
session whose tinc ID exchange runs under SPTPS and fails closed without the
peer's private key, `sf_accept`'s `max_connection_burst` bounds how many such
sessions a flood can create, and the live session's own window is untouched.
After the fix: **6 of 6 restarts** recovered obfs
(`testing/transports/obfs-restart-test.sh`).

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
- `ObfsInitMagicHeader` / `ObfsTransportMagicHeader` (H1/H2): if set, a 4-byte
  **plaintext prefix** is prepended to the frame, so the leading bytes can be
  made to mimic another protocol. Unlike v1, this prefix is separate from the
  nonce and costs no nonce entropy (finding M5-3). The receiver tries the
  no-prefix and 4-byte-prefix offsets when unsealing, so both ends only need to
  agree that a magic is in use (the values propagate through invitations).
  Default: no prefix.

A frame is in the *handshake phase* until its single-flow session is
established (the peer has acknowledged); after that it uses the transport-phase
knobs.

### obfs and the path MTU (stream AB)

tinc sets `IP_MTU_DISCOVER` on its UDP sockets, so nothing is fragmented: a
datagram larger than the path MTU comes back as `EMSGSIZE` ("Message too long")
and is simply not sent. Everything obfs adds — the seal and the junk — therefore
has to be counted against the path, not against a compile-time constant.

**The arithmetic.** With IPv4 the usable UDP payload is `pathMTU − 20 − 8`. On
top of the inner frame obfs puts

| part | bytes |
|---|---|
| magic prefix (`Obfs*MagicHeader`, optional) | 0 or 4 |
| nonce + `clen` (`OBFS_HDR_LEN`) | 10 |
| Poly1305 tag | 16 |
| tail junk (`Obfs*HeaderJunkSize`) | 0 … `OBFS_MAX_JUNK` (1400) |

so the fixed seal costs 26 bytes (30 with a magic header). The two things it
wraps are a single-flow frame (`SF_HDR_LEN` 24 + up to `SF_MAX_PAYLOAD` 1200)
and an SPTPS data datagram (8 relay ids + the tinc packet + 21 bytes of SPTPS
overhead). The second one is the trap: `choose_initial_maxmtu()` sizes a tinc
packet as `pathMTU − IP − UDP − SPTPS − relay ids`, i.e. so that the datagram is
*exactly* the path MTU — it knows nothing about a carrier. Adding the seal put
every full-size data datagram 26 bytes over the path **on every path, 1500-byte
docker bridges included**, and a configured `ObfsInitHeaderJunkSize` could put
every handshake frame up to 1400 bytes over it.

**What it does now.**

- Every size is measured against a **per-link path budget**: the kernel's route
  MTU toward that peer (`getsockopt(IP_MTU)` / `IPV6_MTU` on a throwaway
  connected socket — the same source `choose_initial_maxmtu()` uses, so it also
  reflects a PMTU the kernel learned from an ICMP "fragmentation needed") minus
  the IP and UDP headers. It is cached for 10 s per link, because it is
  consulted per frame, and re-queried immediately when the peer address moves or
  the kernel refuses a datagram anyway. When the kernel will not answer (a
  platform with no `IP_MTU`), obfs assumes 1280 bytes, the IPv6 minimum link
  MTU — the largest value that is safe on any path.
- **Junk is made to fit, never dropped.** It is the obfuscation, so it is
  reserved *before* the payload: the single-flow carrier asks `obfs_max_inner()`
  how much room is left after the seal and the configured junk and chunks the
  meta stream against that, so shaping costs one extra segment rather than a
  datagram the kernel refuses. Junk yields only if the payload would fall below
  `OBFS_INNER_FLOOR` (256 bytes). Standalone junk datagrams
  (`ObfsJunkPacketMaxSize`) are clamped to the budget the same way.
- **The data path cannot chunk**, so instead it reports. `obfs_wrap_send()`
  returns `OBFS_SEND_TOOBIG` with the exact number of bytes that did not fit and
  `send_sptps_data()` feeds that to `reduce_mtu()` — the same contract the quic
  carrier already had, except that obfs knows the overshoot, so PMTU discovery
  converges **in one probe** instead of losing every top-end probe silently.
- **`EMSGSIZE` is never silent.** A kernel refusal on the data path logs the
  size that failed and the re-queried budget at `DEBUG_ALWAYS` and re-enters the
  same `reduce_mtu()` path. A single-flow frame the path refuses fails the
  session immediately (`sf_send_frame`) instead of letting three retransmissions
  of identical bytes time out, so the carrier fails over to the next entry in
  `PreferredTransports` at once rather than after ~3.5 s of apparent hang.

Measured: on a 1400-byte docker network with `ObfsInitHeaderJunkSize: 1400`, the
released core logged four `Error sending single-flow frame: Message too long`
lines and then `Carrier obfs failed for nodeb, falling back to plain`; with the
fix the same lab comes up on obfs, the largest datagram on the wire is 1372
bytes (exactly the budget) and tinc fixes its MTU to 1273 after one probe. On a
1500-byte network the fixed MTU is 1413 — below the 1443 a plain link reaches,
which is the seal being accounted for. The proof is
`testing/transports/obfs-mtu-test.sh`.

Limits: the budget is only as good as the kernel's route MTU. A middlebox that
silently drops oversized datagrams without sending ICMP is invisible to it, and
tinc's own PMTU probing (which now converges) is what covers that case for the
data path; the meta path relies on single-flow frames being at most 1254 bytes
sealed, which fits any path of 1282 bytes or more.

### Cold-start classification (defect 3)

obfs frames look random, so `transport_classify_udp` cannot spot them and
returns `SPTPS`. `transport_udp_dispatch` then runs `obfs_udp_try`, **after** the
SF and QUIC pattern tests:

1. **Fast path** — an active link whose remembered source address matches: at
   most two Poly1305 verifications (session key then bootstrap key). On failure
   it falls through to SPTPS (so a still-plain datagram during the brief setup
   window, or junk, is handled correctly).
2. **Cold path** — a source with no active obfs link, obfs accepted: a
   **per-peer round-robin scan** over the node keys. A persistent cursor
   resumes where the previous datagram left off, so no peer is starved and, in a
   mesh larger than the per-second floor, the last node is still reached within
   a bounded number of ticks (finding M5-6). The budget **scales with the peer
   count** (floor 25/s, capped at 512/s) so a junk flood cannot exhaust it and
   the > 25th node is still classified. The first key that verifies identifies
   the peer.

   The scan is skipped for a source address that is bound to a node with
   `udp_confirmed` **only when the datagram would actually be claimed by the
   SPTPS path** — `sptps_udp_addresses_known_nodes()` (net_packet.c) runs the
   same identification `process_sptps_udp()` runs: an all-zero destination id
   (a direct datagram) or two ids that resolve to known nodes. Skipping it
   unconditionally, which is what the code did before stream AD, made obfs
   undialable on any network that was already carrying traffic: the sealed
   handshake frames arrive from exactly such an address, and they were dropped
   as `unknown source and/or destination ID` while the dialler timed out in
   authentication. An obfs frame opens with its whitened nonce, so its
   destination id is neither zero nor a known node and it reaches the keyed
   check. The cost in the steady state is one six-byte `memcmp` per direct
   datagram from a confirmed plain peer, plus two node-id lookups for a
   relayed one. `sf` and `quic` need no such test: their classifier keys on a
   magic prefix, a version word or a live connection id and never looks the
   source address up.

On a verified frame the **replay window** is checked before anything else moves:
a replay (or a too-old counter) is dropped and the link's remembered address is
**not** touched (finding M5-4). A fresh frame activates the link (its address is
adopted) and the inner datagram is unsealed and re-injected: an SF frame goes to
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
| `Transports` | all compiled (`plain, sf, obfs, https, quic` on the Docker build) | accept list; advertised; `plain` is put back if this list omits it (use `AllowPlainMeta`) |
| `AllowPlainMeta` | `yes` | `no` = refuse inbound cleartext tinc meta connections; drops `plain` from the accept mask (§2.1; breaks `tinc join` against this node) |
| `PreferredTransports` | `plain` | dial order; always ends at `plain` |
| `SingleFlow` | `no` | `yes` = dial `sf` first (TCP kept as fallback) |
| `HttpsSni` | peer `Address` name, else none | SNI the https dial presents |
| `TlsCert` / `TlsKey` | generated self-signed | PEM files; else `keys.tls_cert/tls_key` |
| `HttpsDecoyRoot` | built-in page | static files served to probers |
| `HttpsDecoyUpstream` | (unset) | `host:port` to proxy probers to instead |
| `HttpsPort` | `443` on a listening node, none with `Port = 0` | TCP listener for the https front only (§3.1); advertised in the own host record, where it is the port peers dial; `0` = off |
| `QuicPort` | `443` on a listening node, none with `Port = 0` | UDP listener for the quic front only (§3.1); advertised like `HttpsPort`; `0` = off |
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

### 8.1.1 Replacing the self-signed certificate (`tinc cert`)

A self-signed certificate is the default, not the ceiling. An operator who owns
a domain in Cloudflare can set `CertDomain` and `CloudflareToken` and run
`tinc cert issue`, which obtains a publicly trusted certificate through the ACME
DNS-01 challenge and stores it in the same `keys.tls_cert` / `keys.tls_key`
slots. Nothing else changes: SPTPS is still the trust root, peers still pin the
fingerprint, and the carrier code does not know the difference.

What it buys is the decoy. A self-signed certificate for `localhost` on a port
that claims to be an HTTPS service is a tell; a real certificate for a real name
is not. It only pays off if the peer's host record for this node carries
`Address = <CertDomain>`, because that is where §8.2's SNI comes from — a
certificate for `vpn.example.com` presented to a client that asked for
`localhost` is worse than the generic one.

The fingerprint changes with it. Peers holding the old pin follow on their own
(§8.2, "A moved pin"): they accept the new certificate for the next session and
re-pin it once SPTPS has authenticated this node. `tinc cert issue` rewrites this
node's own `TlsFingerprint`.

It runs in the CLI, never in the daemon — issuing blocks for as long as the CA
takes. See docs/config-schema.md for every option and every failure code, and
`testing/acme/run.sh` for the proof.

### 8.2 Dial and certificate pinning

`https_dial` opens a non-blocking TCP connection to the peer's front port (its
host-record `HttpsPort`, else the dialler's own `HttpsPort` option, else the port
dialled; §3.1) and a
TLS client handshake with a plausible SNI (`HttpsSni`, else the peer's `Address`
if it is a hostname, else **none**: a peer dialled by IP gets no SNI and a
`Host:` of that IP, plus `:port` when it is not 443 -- what curl sends to an
IP. Until 2026-09-23 it sent SNI `localhost` and `Host: localhost`, which no
client dialling an IP does; found comparing the Windows dialler with curl,
`testing/transports/windows-wine-test.sh`). PKI verification is off
(`SSL_VERIFY_NONE`); instead the peer's certificate is pinned by SHA-256
fingerprint (`TlsFingerprint` in the peer's host record). A match needs nothing
more; a mismatch is handled like a first contact (below). If none is pinned, the
dial proceeds **without writing anything**
(review M5-7): the certificate alone proves nothing, and a pin written on first
contact would let an on-path attacker pin its own certificate forever. The
fingerprint of the session is remembered in the dialer's session state and is
written to the host record only once the SPTPS handshake inside that TLS session
activated the link (`c->edge` set by the ACK), i.e. once the peer proved its
Ed25519 identity over the very session the certificate belongs to (the exporter
in the authenticator, §8.3, binds the two). A malformed existing pin is ignored
and never overwritten (logged).

**The ClientHello is curl's** (since 2026-09-23, Debian 13 / OpenSSL 3.5).
The dialler uses OpenSSL's defaults as curl 8.14 does, plus curl's three
choices: ALPN `h2, http/1.1`, no `session_ticket` extension
(`SSL_OP_NO_TICKET`), `post_handshake_auth` offered. Measured
(`testing/fingerprint/results/2026-09-23-deb13/`): JA4
`t13d3013h2_1d37bd780c83_8537cf56674e`, JA3
`32e4b8812cda0c0d50783b438492a769`, 1646 bytes -- all three identical to
curl's; before, OpenSSL 3.0 with ALPN `http/1.1` only, 403 bytes, a JA4 no
reference client shared. A tinc server selects `http/1.1` (it offers no
h2); a server that selects `h2` is a web server, and the dial gives up
right after the handshake (`answered like a web server (ALPN h2)`,
checked against nginx with `http2 on`). Not a browser: Chromium's
ClientHello (GREASE, ECH, ALPS) needs BoringSSL.

**A moved pin.** When the presented certificate does not match the pin, the
dial carries on exactly like a first contact: the handshake completes as any TLS
handshake would (no `bad_certificate` alert, no early close — an observer sees an
ordinary HTTPS session), the new fingerprint is logged, and it **replaces** the
old `TlsFingerprint` line (`replace_config_file`, no second line) only once SPTPS
inside that very session has proved the peer's Ed25519 identity. Nothing about
the certificate is checked — no CA, no name, no dates — because nothing depends
on it: the authenticator (§8.3) is signed over this session's exporter and the
fingerprint the client saw, and the server checks it against its own; SPTPS then
authenticates both ends end to end. A box that terminates TLS with its own
certificate therefore gets a session that never activates and never becomes the
pin, whatever CA it holds. That makes renewal, a re-issued self-signed
certificate and a switch between the two work on every platform, Windows and
Android included, and for peers that dial by IP address.
What the pin still buys: a log line when the certificate changes, and nothing a
client must refuse on. What a TLS-intercepting middlebox does learn, pinned or
not, before the session dies: the authenticator cookie (node name, nonce,
timestamp, signature) — it cannot replay it (exporter-bound) or verify it without
the node's public key.
Proof: `testing/transports/cert-repin-test.sh`, per carrier: renewal and a
self-signed replacement both reconnect and leave exactly one new pin; a server
that cannot prove the expected key — first contact or a moved pin — is neither
connected to nor pinned.

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
  readiness, never busy-waiting on a client that does not read; an exchange
  that does not finish is reaped by the web front's timeouts (§8.5.1), on the
  tinc port as well: 60 s without progress, not tinc's authentication
  timeout.

The client side also falls back: if the dial cannot pin the cert or the server
answers anything other than `101`, `https_dial`'s connection dies before it
activates and the outbound selector advances to the next carrier (ending at
`plain`, §2).

### 8.5.1 The decoy answers as nginx does (2026-09-23)

The fingerprint audit found a decoy no web server resembles: `200` with the
same page for every path, for `POST` and for garbage; no `Date`; silence for
plain bytes on the TLS port; a bare FIN without `close_notify`; and a client
that sends nothing kept open for ever (tinc's tarpit) -- and `Server: nginx`
over Apache's "It works!" page. The decoy now imitates nginx 1.27 with
`server_tokens off`, measured probe by probe against a real one. The
built-in page is nginx's own welcome page, byte for byte, with the stock
`nginx:1.27.5` file's `Last-Modified` and `ETag` (`"67ff9c07-267"`), not the
daemon's start time.

| Probe | Answer (as nginx) |
| --- | --- |
| `GET`/`HEAD` of a file that exists (`/`, or under `HttpsDecoyRoot`) | `200`, headers `Server: nginx`, `Date`, `Content-Type` (nginx's `mime.types`), `Content-Length`, `Last-Modified`, `Connection`, `ETag: "<mtime>-<len>"` (hex), `Accept-Ranges: bytes`, in that order; `HEAD` without the body |
| an unknown path, or one that climbs out of the root (the latter not in the lab) | `404` with nginx's page |
| any other method | `405 Not Allowed` with nginx's page |
| a request line nginx cannot parse, or HTTP/1.1 without `Host` | `400` with nginx's page, answered at the first line |
| HTTP/1.1 without `Connection: close` | keep-alive: the next request on the same connection is answered too, pipelined ones included |
| `Connection: close`, HTTP/1.0, any error | TLS `close_notify`, then the FIN |
| plain HTTP (or a tinc ID line) on `HttpsPort` | `400 The plain HTTP request was sent to HTTPS port` / `400 Bad Request`, nginx's pages, and close |
| a first byte `0x80`+ that is not TLS on `HttpsPort` | closed without an answer |
| nothing at all | closed after 60 s (`client_header_timeout`); an idle kept-alive connection after 75 s (`keepalive_timeout`; set, not measured by the lab) |
| 30 connections at once from one address | all answered |

Connections on the fronts (TCP `HttpsPort`, UDP `QuicPort`, TLS on any port
until the peer authenticates, and the plain-HTTP decoy) carry
`c->status.web_front`: `timeout_handler` closes them after
`DECOY_HEADER_TIMEOUT` (60 s) without progress -- no request, or no byte of
the response taken (nginx's `client_header_timeout` / `send_timeout`) --
instead of tarpitting them, and the accept
path skips `check_tarpit()` / the per-second QUIC budget (a prober opening
eleven connections in a second used to get a socket that never answered).
They are capped at `DECOY_MAX_WEB_CLIENTS` (256) concurrent unauthenticated
clients instead -- the equivalent of nginx's `worker_connections`; past it a
new TCP connection is closed and a new QUIC Initial dropped. The tinc port
keeps `MaxConnectionBurst` and the tarpit.

With `HttpsDecoyUpstream` set the upstream's own answer is relayed, as before;
only the first request of a pipelined burst is forwarded.

Proof: `testing/transports/decoy-conformance-test.sh` sends the same probes to
a tinc node and to `nginx:1.27` side by side and compares status lines, header
names in order, error pages byte for byte, keep-alive, the TLS-port answers,
the burst, the silent-client timing and, from decrypted captures,
`close_notify` before the FIN. All 20 checks pass; on the core before this
change (`tincstack/core:pre-h3`) 19 fail -- only the high-byte case matched
(`testing/fingerprint/results/2026-09-23-decoy/conformance*.txt`).

Not imitated (open, PLAN): ALPN `h2` (an nginx with `http2 on` selects it; we
offer `http/1.1` only, which matches nginx's default but not every site's),
`Range` requests, `If-Modified-Since`/`304`, directory redirects (`/dir` →
`301`), the TLS session-ticket size, and `Alt-Svc`: a site that serves
HTTP/3 normally advertises it on its TCP answers (the fingerprint lab's
nginx does), ours never does. The HTTP/3 decoy always serves the `/` page
and never uses `HttpsDecoyUpstream`.

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
The carrier is compiled whenever meson finds ngtcp2 with its OpenSSL backend
and OpenSSL >= 3.5 (`-Dquic=auto`, the default) on an OpenSSL build; `core/Dockerfile.build` ships it. Proof
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

Decision: **ngtcp2 with the GnuTLS backend** on Linux (2026-09-16). Least
build risk (one pinned tarball, distro TLS library), and the only candidate whose model (the
application owns the socket, the loop and the timers) matches how the M4 front
dispatches datagrams (`transport_udp_dispatch` -> `udp_receive`). The
reference `tinc-quic` used msquic and had to give it its own socket and
threads; that is where its dead stream muxing came from.

**Revised 2026-09-23: ngtcp2 with the OpenSSL backend, on Debian 13.** The
wire-fingerprint audit found GnuTLS 3.7.9's QUIC ClientHello unique (no
reference client shares its JA4) and its ServerHello different from the
OpenSSL one the https front sends from the same host (§9.8). Debian 13's
OpenSSL 3.5 has the QUIC TLS API `ngtcp2_crypto_ossl` needs, and it is the
stack curl 8.14 and nginx use there, so the carriers now share one TLS
library. ngtcp2 is still built from the pinned tarball (`--with-openssl`):
trixie's `libngtcp2` is 1.11 without the ossl backend. Mixed pairs -- a
GnuTLS node and an OpenSSL node -- interoperate over `quic` (and `https`)
in both directions: the authenticator's TLS 1.3 exporter is the same value
in both stacks (`testing/transports/mixed-version-test.sh`).

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
  the carrier. On a listening node the carrier also binds one UDP socket per
  address family on `QuicPort` (443 by default, §3.1; private
  `listen_socket_t` entries read by `quic_listen_read()`, which feeds
  `quic_udp_try()` only, so `listen_socket[]` indices stay valid). A dial
  does not use either: it opens its own socket on an ephemeral port
  (`quic_client_read()`), which the session closes with it.
- Loop: tinc's `event.c`. Reads arrive through `handle_incoming_vpn_data` ->
  `transport_udp_dispatch` -> `quic_udp_try()`. Writes are `sendto()` on the
  session's socket to the path ngtcp2 returns. One `timeout_t` per session,
  re-armed after every flush from `ngtcp2_conn_get_expiry()`; its callback
  runs `ngtcp2_conn_handle_expiry()` and flushes.
- Per-session state (`quic_session_t`, `c->transport_data`): `ngtcp2_conn *`,
  the TLS session (`quic_tls_t`: OpenSSL `SSL` + `ngtcp2_crypto_ossl_ctx`), socket fd + family index, the peer
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
| `init()` | `tls_init()` then the node certificate PEM from `tls_current_pem()` (the single node cert, `keys.tls_cert/tls_key`, G1) -> a TLS 1.3 `SSL_CTX` (`quic_tls_set_server_cert`); 32-byte static secret for stateless-reset tokens; registers the CID matcher with `transport_set_quic_cid_matcher()`; binds the `QuicPort` sockets when configured. Logs `QUIC carrier ready (ngtcp2 1.25.0, OpenSSL 3.5.7 ...)`. `quic_read_config()` on `tinc reload` rebuilds the credential when the certificate fingerprint changed. |
| `exit()` | close every session, free both `SSL_CTX`s. |
| `dial(c)` | pin = the peer's `TlsFingerprint` host-record key (absent => accept-on-first-use, §9.7); port = the peer's host-record `QuicPort`, else own configured `QuicPort` (not the own host record's advertisement), else the port as dialled; a fresh socket on an ephemeral port (§3.1); OpenSSL client session with ALPN `QuicAlpn` (default `h3`, checked after the handshake: a server that selected none is not ours) and SNI from §9.8; random DCID(8) + SCID(8); `ngtcp2_conn_client_new(..., NGTCP2_PROTO_VER_V1, ...)`; `connection_add(c)`; flush (the Initial goes out). `finish_connecting()` is *not* called here. Logs `Dialling <peer> via quic`. |
| `udp_receive` / `quic_udp_try(ls, buf, len, addr)` | `ngtcp2_pkt_decode_version_cid`; DCID in the session table => `ngtcp2_conn_read_pkt(path = {socket addr, datagram source}, ...)` then flush -- the remote of the path is always the datagram's real source, which is the whole NAT-rebind mechanism. Unknown DCID: only a packet `ngtcp2_accept()` takes as a well-formed v1 Initial (>= 1200 bytes) opens a session (`quic_accept`, burst-limited by `max_connection_burst`, `new_connection()` named `<unknown>`, `allow_request = ID`); anything else **returns `false` and falls through** to the obfs keyed check and SPTPS. `read_pkt` errors: `DRAINING/CLOSING/DROP_CONN` => silent teardown; `NGTCP2_ERR_CRYPTO` => `CONNECTION_CLOSE` with the TLS alert; other => `CONNECTION_CLOSE` with `ngtcp2_ccerr_set_liberr`. Every teardown ends in `terminate_connection()`. |
| `send(c)` | append `c->outbuf` to the TX ring, flush: queued datagrams first (`ngtcp2_conn_writev_datagram`), then `ngtcp2_conn_writev_stream` on the meta stream; `sendto` each packet; `NGTCP2_ERR_STREAM_DATA_BLOCKED` marks the stream blocked until `extend_max_stream_data`; then `ngtcp2_conn_update_pkt_tx_time` + re-arm the timer. `EMSGSIZE` from the socket is ignored (ngtcp2's PMTUD probes). |
| `send_datagram(c, buf, len, &excess)` | queue + flush; returns `false` when the record plus its quarter stream id exceeds `min(1400, ngtcp2_conn_get_path_max_tx_udp_payload_size() - 35)` -- the *path's* limit, which the peer's `max_udp_payload_size` caps -- and sets `excess` to the overshoot, so `send_sptps_data()` reduces the MTU by exactly that (like `EMSGSIZE`, one step); when the 64-entry queue is full the datagram is dropped (SPTPS tolerates loss). The flush drops a queued datagram that no longer fits the path (it would otherwise block the queue, and the meta stream behind it, for good: until 2026-09-24 the check used the configured limit, 1452, and a dialler announcing 1200 got nothing through). |
| `close(c)` | best-effort `ngtcp2_conn_write_connection_close` (the recorded `ccerr`, else app error 0) + `sendto`; drop the CIDs; `ngtcp2_conn_del`, `ngtcp2_crypto_ossl_ctx_del`, `SSL_free`; free. |
| `local_address(c, sa)` | `getsockname()` on the session's socket. |

Settings / transport parameters (`quic_settings()`): 100 bidirectional
streams, 100 unidirectional (a listener: 3, as nginx), 512 KiB stream
windows, 768 KiB connection window, `max_datagram_frame_size = 65536`,
`active_connection_id_limit = 8`, `max_idle_timeout = 3 x PingTimeout`
(at least 30 s), `handshake_timeout = PingTimeout` (so the library gives up
in step with tinc's reaper, §2 step 3). The dialler, as curl: also
`disable_active_migration`, `max_udp_payload_size = 1200`, sends 1200-byte
packets at most and never probes the path MTU; on the wire it writes its
parameters as curl does (§9.8): `active_connection_id_limit` 2 and no
`max_datagram_frame_size`, although it accepts 8 and 65536.

### 9.4 Framing: an HTTP/3 request (since 2026-09-23)

The carrier is an HTTP/3 connection (RFC 9114) to everyone, the peer
included (`h3.c`; before 2026-09-23 it announced ALPN `h3` and then spoke raw
tinc on stream 0 -- a new node and an older one do not speak `quic` to each
other and fall back to the next carrier):

- **Both ends**, right after the handshake, open their three
  unidirectional streams, as HTTP/3 endpoints do: a control stream with
  SETTINGS (`QPACK_MAX_TABLE_CAPACITY 0`, `QPACK_BLOCKED_STREAMS 0`,
  `MAX_FIELD_SECTION_SIZE 65536`, `H3_DATAGRAM 1`) and the QPACK encoder and
  decoder streams. What the peer sends on its unidirectional streams is
  consumed and credited; with a dynamic table capacity of 0 no QPACK
  instruction can arrive.
- **The dialler** sends one request on its first bidirectional stream:
  HEADERS `POST https://<authority>/` (`:authority` = the SNI, else the
  address; `content-type: application/octet-stream`, a browser
  `user-agent`), then a body of DATA frames. The first DATA frame is the
  **§8.3 authenticator**, byte for byte the `https` one (`authn_build()`:
  `ver(1) || namelen(1) || name || nonce(16) || ts_be(8) || Ed25519 sig(64)`
  over `"tincstack-authn-v2\0" || server-cert-fp(32) || TLS-exporter(32) ||
  nonce || ts`, exporter label `EXPORTER-tincstack-https-v1` via
  `SSL_export_keying_material`); every later DATA frame is tinc meta: the `ID` line
  from `finish_connecting()` and everything after it.
- **The listener** parses every request stream's frames. The first stream
  whose DATA carries a valid authenticator (`authn_verify()` against its own
  certificate fingerprint and exporter, same replay cache and +/-90 s skew as
  `https`) becomes the meta stream: it answers `HEADERS :status 200,
  server: nginx` and streams its meta back as DATA frames. Not a single byte
  reaches `receive_meta_bytes()` before that.
- **Anyone else** -- a browser, curl, a prober, a POST whose body is not an
  authenticator (`quic: authenticator from <host> rejected`) -- gets the
  static decoy page (`decoy_respond_static()`, the https front's page) as an
  HTTP/3 response on each request stream: HEADERS + DATA + FIN. The
  connection stays open; tinc's authentication timeout ends it later with
  `H3_NO_ERROR`. Up to 8 request streams are answered per connection, more
  are refused with `H3_REQUEST_REJECTED`.
- **The dialler checks the answer**: the HEADERS payload must be byte for
  byte the listener's fixed 200 response; anything else (a decoy, a real web
  server) logs `quic: <peer> answered like a web server, not a tinc peer`
  and the dialler falls back (§9.9).
- QPACK uses the static table only, literals are not Huffman-coded, and
  received field sections are not decoded (the carrier needs nothing from
  them). Graceful closes carry `H3_NO_ERROR` (0x100).

Proof that other stacks read this as HTTP/3:
`testing/transports/h3-interop-test.sh` -- curl (ngtcp2/nghttp3) and
Chromium get the decoy page over HTTP/3 from a tinc node; decrypted with their
key logs, the node's control stream carries SETTINGS; the dialler's request
is parsed and logged by nginx (`POST / HTTP/3.0`, the user agent) and the
dialler recognises nginx's answer as a web server's. On the core before this
change every one of those checks fails.

Meta bytes out of DATA frames go to `receive_meta_bytes(c, data, len)`; the
flow-control credit for everything consumed is returned afterwards with
`ngtcp2_conn_extend_max_stream_offset` + `ngtcp2_conn_extend_max_offset`.

**Data path**: the SPTPS *datagram* records ride **DATAGRAM frames**, one tinc
UDP packet per frame, as HTTP/3 datagrams (RFC 9297: the request's quarter
stream id, one byte, then the record), the record byte for byte what
`send_sptps_data()` would have put on the wire (`dst-id | src-id | record`, or the direct/legacy forms), so a relay
never sees a difference. `send_sptps_data()` calls
`relay->connection->transport->send_datagram` (before `obfs_wrap_send`) when
the relay's meta connection has that hook; `false` => `reduce_mtu`, so tinc's
own MTU probing converges on the datagram ceiling. `recv_datagram` delivers
with `handle_incoming_vpn_packet_decap(ls, data, len, &session peer)`: the
classifier is skipped (the bytes came from a carrier) and the unchanged SPTPS
receive path authenticates, decrypts and forwards relayed packets as today.
Ceiling: ~1165 bytes, since a dialler takes and sends 1200-byte packets at
most (§9.8): tinc's path MTU over `quic` is 1131 in the lab (1366 before
2026-09-24, when PMTUD took it to Ethernet's); `SF_MAX_PAYLOAD` is 1200 for
comparison.

**Datagrams nobody announced** (since 2026-09-24): the dialler's
transport parameters are curl's, and curl announces no
`max_datagram_frame_size`, so by the book the listener may not send it
DATAGRAM frames. The dialler accepts them anyway (its local limit stays
65536); the listener, once the authenticator checks out, sets the peer's
limit itself (`ngtcp2_conn_set_remote_max_datagram_frame_size`, from the
patch) and follows its 200 answer with an empty reserved frame
(`H3_FRAME_TINC_DGRAM`, type `0x38ae` = 0x1f * 467 + 0x21, which HTTP/3
endpoints ignore, RFC 9114 §7.2.8). Only an authenticated tinc peer ever
sees it, encrypted. A dialler whose listener's answer lacks it -- a tinc from
before -- gives `quic` up before the link activates (`quic: <peer> runs a
tinc too old to send datagrams to this one; not using quic`) and the next
carrier is tried (§9.9). An older dialler announces the frame size itself
and ignores the reserved frame, so a current listener serves it as before
(`mixed-version-test.sh`).

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
  with the pinned hex. On a match nothing else is checked: no CA, no name, no
  validity period. On a mismatch the handshake completes anyway, with no
  alert (§8.2, "A moved pin" — the same rule, for the same reason), the new
  fingerprint is logged and marked for re-pinning after SPTPS; the
  authenticator (§9.4) and SPTPS decide, not the certificate.
- **No pin yet**: when the host record has no `TlsFingerprint` the dialler
  accepts the presented certificate for this session and logs
  `quic: no pinned TlsFingerprint for <peer>; will pin <fp> once SPTPS
  authenticates the peer`. Nothing is written at TLS time (review M5-7, which
  until 2026-09-23 was fixed for `https` only: quic appended the pin at the
  end of the TLS handshake, so a server holding the wrong Ed25519 key got
  pinned). The pin — first or moved — is written by `learn_pin()` once the
  SPTPS meta handshake over this stream set `c->edge`, and replaces any
  existing `TlsFingerprint` line (`replace_config_file`).
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
established. HTTP/3 conformance beyond the handshake was out of scope
until the wire-fingerprint audit (2026-09-23) and is now §9.4.

What an observer can still tell (testing/fingerprint, re-measured
2026-09-23 after §9.4; the Initial re-measured 2026-09-24 by
`quic-wire-test.sh`):

- **the dialler's Initial is curl's** since 2026-09-24. curl 8.14 on Debian
  13 runs OpenSSL 3.5's own QUIC stack (no ngtcp2 in `curl -V`); the
  dialler runs ngtcp2 with `core/ngtcp2/tincstack-wire.patch`
  (`ngtcp2_conn_set_openssl_client_wire`), and `quic-wire-test.sh`, curl
  and the dialler capturing side by side, finds them equal in: the transport
  parameters -- set, order and values: `disable_active_migration`,
  `initial_source_connection_id` (empty), `max_idle_timeout 30000`,
  `max_udp_payload_size 1200`, `active_connection_id_limit 2`,
  `initial_max_data 786432`, three stream windows of 524288, 100 + 100
  streams; the ClientHello (JA4_r, 1477 bytes dialling an IP); both Initial
  packets: 4-byte packet numbers, a 2-byte Length field, the ClientHello in
  order in one CRYPTO frame each (0+1158, 1158+323), 834 bytes of PADDING.
  Before, ngtcp2 1.25 wrote `version_information` and
  `max_datagram_frame_size`, another order, 1-byte packet numbers and 4-byte
  Length fields, and cut the ClientHello into ~11 shuffled CRYPTO frames
  between PING and PADDING frames (its defence against middleboxes that read
  SNI, and a fingerprint of its own). Consequences: packets of 1200 bytes at
  most both ways (§9.4 ceiling), and datagrams negotiated inside the tunnel
  (§9.4);
- **the dialler's second flight is curl's** since 2026-09-24, late: the
  datagram that carries the client's Finished is, from both, an Initial
  with ACK and 1026 bytes of PADDING (Length 1051), the Handshake packet
  (Length 80) and a 34-byte 1-RTT packet with an ACK -- 1200 bytes. Stock
  ngtcp2 padded the 1-RTT packet and left the Initial at Length 25; the
  Length field of a long header is not header-protected, so that was
  readable without decrypting anything. OpenSSL also moves to the connection
  ID the server issues in its first 1-RTT packet (NEW_CONNECTION_ID, seq 1)
  as soon as it has it, so the Destination Connection ID of that datagram
  and every later one differs from the one before; stock ngtcp2 kept the
  original. And ngtcp2 added a PING to an ACK-only Initial when the server's
  flight took longer than the RTT estimate (seen in the lab, timing-bound),
  which OpenSSL never does. The patch now does all three as OpenSSL
  (`conn_write_openssl_client_flight`: the Handshake and 1-RTT packets are
  written first, then the Initial padded to what is left).
  `quic-wire-test.sh` requires the datagram's size, packets, Length fields,
  the Initial's frames and the moved DCID to equal curl's; tshark cannot
  follow a connection across that move without the TLS secrets, so the
  Initials are decrypted by `testing/transports/quic_initial.py` (standard
  library, keys from the client's first DCID as any observer derives them).
  Windows (Wine) sends the same datagram. The Android emulator, which needs
  ~25 ms per server datagram, mostly does not: its Finished leaves without
  an Initial, unpadded (146 bytes), the server's last Initial unacknowledged
  -- by all signs ngtcp2's PTO firing first on a slow client; what OpenSSL
  does in that timing is unmeasured (PLAN.md);
- the first 1-RTT packets after that datagram (HTTP/3 control and QPACK
  streams, the request) are 54, 41, 41 and 315 UDP bytes from the dialler,
  55, 40, 40 and 69 from curl (re-measured 2026-09-24, late):
  another SETTINGS, and a POST carrying the authenticator where curl sends a
  GET. Encrypted, but their sizes show;
- the listener's side of QUIC (its Initial and Handshake packets, its
  transport parameters -- `max_datagram_frame_size`, 1-byte packet numbers)
  has not been compared with nginx's;
- until 2026-09-23 the ClientHello was GnuTLS 3.7.9's (JA4
  `q13d0315h3_55b375c5d22e_84684a673e38`: `status_request`,
  `record_size_limit`, `session_ticket`, `renegotiation_info`, SHA-1
  signature schemes) and the listener's ServerHello GnuTLS's while the TCP
  front on the same host was OpenSSL's. Since the move to OpenSSL 3.5
  (§9.1, re-measured in `testing/fingerprint/results/2026-09-23-deb13/`):
  the ClientHello is curl's -- JA4 `q13d0312h3_55b375c5d22e_e01b5de7605b`,
  JA3 `018311bdaf15f0b071fa2e5eeb923473`, 1248 bytes, identical to curl
  8.14's (the dialler sets `SSL_OP_NO_TICKET`, as curl's has no
  `session_ticket`); the ServerHello's JA3S is nginx's
  (`15af977c...` to curl, `f4febc55...` to Chromium) on both carriers;
- not a browser: Chromium's JA4 (`..._178839b6cec1`: GREASE, ECH, ALPS)
  needs BoringSSL;
- the lab's reference nginx (`nginx:1.27`, Debian 12, OpenSSL 3.0) has no
  post-quantum key exchange; ours selects `X25519MLKEM768` when the client
  offers it, as an OpenSSL 3.5 server (nginx on Debian 13) does -- its
  ServerHello flight is ~660 bytes larger than the lab nginx's.

### 9.9 Handshake failure and fallback

All of these end in the §2 walk to the next candidate, ending at `plain`,
because the connection dies before it activates:

| failure | detection | action (observed in `quic-carrier-test.sh`) |
|---|---|---|
| peer does not accept `quic` (config `Transports: [plain]`, or a build without the carrier) | negotiation, §2 | `Carrier candidates for <peer>: plain`; QUIC never dialled (c) |
| no UDP socket of the peer's address family | `dial` | return `false` immediately |
| QUIC dropped by the network | ngtcp2 retransmits the Initial with backoff; `handshake_timeout = PingTimeout` expires | `Carrier quic failed for <peer>, falling back to plain`, tunnel comes up on plain (c, UDP DROP'd) |
| TLS failure (a pin mismatch is not one, §9.7) | `NGTCP2_ERR_CRYPTO` | `CONNECTION_CLOSE` with the alert, next candidate |
| Version Negotiation packet | `decode_version_cid` | v1 only: not claimed, session times out as above |
| authenticator rejected (acceptor) | §9.4 | generic close, `quic: authenticator from <host> rejected`; the dialler logs `Carrier quic failed ..., falling back to plain` and dials plain, where the wrong key fails SPTPS too (d) |
| the listener is a tinc from before 2026-09-24 (cannot send datagrams to a dialler that does not announce them, §9.4) | no `H3_FRAME_TINC_DGRAM` after the listener's 200 answer | `quic: <peer> runs a tinc too old to send datagrams to this one; not using quic`, closed before activation => next candidate, dialled once (`mixed-version-test.sh`) |
| mid-session: idle timeout, peer close, library error | `read_pkt` / `handle_expiry` errors | `terminate_connection` on an *activated* link => the reconnect starts from the first preference again, i.e. quic is re-dialled, and it is abandoned only after three consecutive pre-activation failures (§2 steps 3-5; `quic-carrier-test.sh` (l): reload, UDP black-hole, `kill -9` + restart all come back as quic) |

**NAT rebind** needs no code on the dialling side: tinc's socket does not
move, the NAT mapping does; the *acceptor* sees a new source address in
`udp_receive`, ngtcp2 validates the path, and on `path_validation` SUCCESS the
carrier copies the new remote into the session, `c->address` and
`c->hostname` (so `dump connections` follows) and logs `quic: path validated
for <peer>, remote now <addr>`. Observed (b): mapping flipped 40000 -> 40001
mid-session, ping continues both ways, exactly one `quic: connection from`
before and after (no re-handshake), the dialler never fell back; a second
flip 40001 -> 40002 in the same session works as well, with the dialler
announcing `active_connection_id_limit` 2 (it accepts 8: the spike's second
migration failed at 2 with `ERR_CONNECTION_ID_LIMIT`). Active
migration (`ngtcp2_conn_initiate_immediate_migration`) is only for a *local*
socket change (Android Wi-Fi -> LTE), which tinc does not do today.

### 9.10 Build wiring

`meson_options.txt`: `option('quic', type: 'feature', value: 'auto')`.
ngtcp2 is built from the pinned 1.25.0 tarball with
`core/ngtcp2/tincstack-wire.patch` applied, on every platform
(`core/Dockerfile.build`, `core/Dockerfile.build-win`,
`platforms/android/native/build-core.sh`, which also rebuilds its cached
dependencies when the patch changes); `transport_quic.c` does not compile
against an unpatched ngtcp2 (`NGTCP2_TINCSTACK_WIRE`). The patch leaves
ngtcp2's behaviour unchanged unless `ngtcp2_conn_set_openssl_client_wire` is
called: ngtcp2's own test suite passes on the patched tree (266/266).
`src/meson.build` looks up `libngtcp2 >= 1.12`, `libngtcp2_crypto_ossl` and
`openssl >= 3.5` (until 2026-09-23: `libngtcp2_crypto_gnutls` and `gnutls`);
when all three are found *and* `crypto=openssl` (the node
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
`--build-arg QUIC=disabled` (image `ws-g3-noquic`: `tincd` links no
ngtcp2, `Transports accept=plain,sf,obfs,https`). Base image: Debian 13
(`debian:13-slim`) since 2026-09-23, for OpenSSL 3.5.

**Windows** (mingw) has both carriers since 2026-09-23: `core/Dockerfile.build-win`
builds OpenSSL 3.5.7, zlib 1.3.1, zstd 1.5.7 and ngtcp2 1.25.0 from
sha256-pinned tarballs and links them statically into `tincd.exe` (`-Dcrypto=openssl
-Dquic=enabled`; it still imports only system DLLs). The same OpenSSL with
the same client settings is the point: a different TLS library gives a
platform its own ClientHello. zlib and zstd are there for that alone --
Debian's OpenSSL offers `compress_certificate` (zlib, zstd), so without them
the Windows ClientHello lacked extension `001b`. OpenSSL is configured
`no-autoload-config no-module no-dso` with `OPENSSLDIR` under Program Files:
the elevated service never reads an `openssl.cnf` or loads a provider from a
user-writable path. Proof, under Wine in Docker (`testing/transports/windows-wine-test.sh`,
14 checks, `testing/fingerprint/results/2026-09-23-windows/`): a Linux leaf
connects to a Windows founder over both carriers and back; curl gets the
decoy from the Windows node over TLS and HTTP/3 and nginx's 400 to plain
bytes; its ServerHellos have the Linux build's JA3S; its https and QUIC
ClientHellos equal the Linux dialler's in JA4_r and byte count, which equal
curl's when all three dial the same IP; and a hung dial no longer stalls the
daemon (mingw has no `O_NONBLOCK`, so the https dial socket had stayed
blocking -- the same check fails in 10 s on a build without the fix). Not
proven: a real Windows kernel, and the Wintun data path (the lab runs
`DeviceType = dummy`).

**Android** (NDK, M8) has both carriers since 2026-09-24:
`platforms/android/native/build-core.sh` cross-builds OpenSSL 3.5.7, zstd
1.5.7 and ngtcp2 1.25.0 per ABI from the same sha256-pinned tarballs, with
the same OpenSSL options (zlib is the NDK's), and links them statically;
`libtincd.so` needs only `libc`, `libm` and `libz`. Until then it linked
LibreSSL 3.7.3's libcrypto alone, which no longer compiled against `tls.c`,
so every APK was built `--crypto nolegacy` without either carrier. Proof on
the Android 14 emulator (`testing/transports/android-emulator-test.sh`): the
NDK binaries dial a Linux founder over https and quic, and their ClientHellos
equal the Linux dialler's (JA4_r, handshake length, QUIC transport
parameters). Frame lengths differ there only because the emulator's
user-mode NAT re-segments TCP. The app itself tunnels over both carriers:
join through the UI, VpnService, ping both ways, the inviter's link on
https / quic (`platforms/android/docker/join-on-emulator.sh` with
`TRANSPORT=https|quic`, `testing/fingerprint/results/2026-09-24-android/`).
Not proven: an ARM device, a mobile network.

What "the same ClientHello as curl" covers: JA4_r (cipher and extension
lists), TLS handshake length and the Initial's size. It does **not** cover
the QUIC transport parameters inside the Initial: ours are ngtcp2's
(`15,5,6,7,4,8,9,1,14,32,17`: with `max_datagram_frame_size`, which the
datagram data path needs, and `version_information`), curl 8.14's on Debian
13 are OpenSSL's own QUIC stack's (`12,15,1,3,14,4,5,6,7,8,9`), 10 bytes
shorter. Anyone can decrypt an Initial, so this is visible (PLAN.md Known
Issues). ngtcp2's API is backend-independent; the backend code is
`transport_quic_tls.c` (~300 lines).

### 9.11 Known limits

1. `QuicPort` / `HttpsPort` are read at start only (a change needs a restart); `QuicSni` /
   `QuicAlpn` are read per dial.
2. The datagram queue is bounded (64) and drops when full; SPTPS handles the
   loss, but a burst larger than that is not paced.
3. Replay of the authenticator is proven at the shared-code level (the
   `https` test forges and replays one); over QUIC a capture cannot be
   replayed at all because the exporter differs per session, and the same
   `authn_verify` replay cache is on the path. There is no QUIC-level replay
   injector in the test suite.
4. IPv6 is handled by socket family selection but the proof runs IPv4 only.
