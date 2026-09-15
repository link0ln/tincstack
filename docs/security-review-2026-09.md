# Security review R — new core code of M1–M4 (+ M5 hand-off), 2026-09-16

Adversarial review, with fuzzing, of the C code that entered the core on
2026-09-16: the YAML config (`yamlconf.c`), zero-config materialisation
(`zeroconf.c`, `autoif.c`), the address pool (`pool.c`), invitation/join in
YAML mode (`invitation.c`, the invitation part of `protocol_auth.c`), the
transport scaffold (`transport.c`, `transport_table.c`, `transport_sf.c`, the
front dispatcher in `net_socket.c`) and the YAML-aware `tinc set/get` in
`tincctl.c`. The M5 carriers that landed on master during the review
(`obfs.c`, `https.c`, `tls.c`, `decoy.c`) were reviewed read-only.

Result in one paragraph: no memory-safety defect was found in 15 minutes of
sanitised fuzzing per parser (≈190 M executions in total); the defects are
logic and trust-boundary bugs. The two that mattered most — the YAML parser
silently truncating a file that the daemon then wrote back without the
truncated part (host records and keys gone), and the invitation propagation
wildcards that would have copied the inviter's `HttpsDecoyRoot`/
`HttpsDecoyUpstream` into every invitee — are fixed on this branch. The
findings that live in files owned by running streams (front dispatcher busy
loop, obfs key/nonce design, https pin-before-proof, decoy proxy on the main
loop) are written up here with file:line for their owners.

Everything was built and run in throwaway containers (`core/Dockerfile.build`,
`core/tincd/test/fuzz/Dockerfile`); nothing was installed on the host.

Severity scale (from PLAN.md): 🔴 P0 security hole / data at risk, 🟠 P1 real
operational risk, 🟡 P2 worthwhile fix, 🟢 P3 polish.

---

## 1. Threat model: who feeds which parser

| # | Input | Written by | Parsed by | Trust | What a hostile value can reach |
|---|-------|-----------|-----------|-------|-------------------------------|
| I1 | `tinc.yaml` | the admin, the GUI (PyYAML), the daemon's own write-back, `tinc set`, `tinc join` | `yamlconf.c` parser; `conf.c` via the `options:`/`hosts:` text | trusted author, but **the file is rewritten by the daemon**: every parser asymmetry becomes data loss | everything: keys, Name, Subnet, scripts, `InterfaceRoute` → `ip` commands |
| I2 | invitation payload | the **inviter** (any node that can run `tinc invite`) | `invitation.c` `get_line`/`split_line`, `invitation_yaml_apply`, `variables[]` filter, `PROPAGATED_OPTIONS` | authenticated (invitation key), **not** trusted: the inviter chooses every byte | the invitee's `options:` (network-wide behaviour), its interface address and routes (`autoif.c` → `system("ip ...")`), its own and the inviter's host records |
| I3 | invitation URL | pasted by the user | `invitation_url_parse` | user input | address/port to connect to; a 48-char cookie/hash |
| I4 | pending invitation files, host records (`Subnet =` lines) | the inviter's own CLI; **any authenticated peer** via ADD_SUBNET write-back | `pool.c` (`find_used`), `zeroconf_pool_parse` | semi-trusted | address allocation; pool exhaustion |
| I5 | first bytes of a TCP connection on the listen port | **anyone on the Internet** | `transport_classify_tcp`, `transport_front_dispatch` | untrusted | CPU (event loop), file descriptors, carrier selection |
| I6 | UDP datagrams on the listen port | anyone | `transport_classify_udp`, `sf_udp_receive`, `obfs_udp_try`, SPTPS | untrusted | SF session state, amplification, cold-scan budget, address bindings |
| I7 | SF frames from an accepted peer | the peer, or an on-path attacker (plain SF is unauthenticated below SPTPS) | `transport_sf.c` go-back-N | untrusted below SPTPS | meta-connection liveness (desync → SPTPS auth failure → reconnect) |
| I8 | TLS ClientHello + HTTP head | anyone; active probers | OpenSSL, `https.c` `read_head`/`cookie_sid`/`verify_client_auth`, `decoy.c` | untrusted | disk reads (host records, decoy root), Ed25519 verify, **synchronous upstream proxy** |
| I9 | `TlsFingerprint` pin / `tinc.yaml` on disk | first-use pinning writes it | `https.c verify_server_cert` | TOFU | which server a node will ever talk to over https |

Adversaries considered: (A) the Internet host that only sees the listen port;
(B) the on-path censor / middlebox; (C) an authenticated but malicious mesh
member; (D) a malicious inviter (a mesh member who can invite); (E) a local
user who can race the daemon on the config file; (F) a relay node.

## 2. Failure classes looked for

- memory safety in hand-written parsers (YAML, invitation lines, frames);
- **parser/emitter asymmetry** — anything the emitter writes that the parser
  reads back differently, because the daemon writes the file it later reads;
- silent truncation or "best effort" acceptance that drops data;
- trust-boundary leaks: options that cross from the inviter to the invitee
  without the `VAR_SAFE` filter; values that reach `system()`;
- races on the config file (read-modify-write from two processes, rename vs
  `flock` on the old inode, TOCTOU on temp files, symlinks, permissions);
- event-loop blocking or spinning from unauthenticated input;
- unauthenticated state changes (address rebinding, session teardown);
- crypto misuse in the new carriers (key derivation, nonce space, replay).

---

## 3. Findings

Status legend: **fixed** (on this branch, with proof), **open** (owner named).

### 🔴 R-1 — front dispatcher spins at 100 % CPU on one pending byte (open, owner: stream B/G, `transport.c`/`net_socket.c`)

`transport_front_dispatch()` (`core/tincd/src/transport.c:390-416`) peeks with
`MSG_PEEK` and returns `false` on `TCP_CLASS_NEED_MORE` without consuming
anything; `handle_meta_io()` (`net_socket.c:616`) is called again on the next
loop turn because `event_select.c:98` is level-triggered and the byte is still
readable. One connection that sends a single `G`, `0` or `0x16 0x03` and then
nothing pins the daemon at 100 % CPU until `timeout_handler()`
(`net.c:256-265`) reaps it after `pingtimeout` (default 5 s). Measured:
~300 loop turns per 3 s at `-d5`, reap after 5 s, and the attacker reconnects
immediately (`max_connection_burst` limits new sessions per second, not this).
Effect: trivially repeatable DoS of the event loop from any Internet host;
during the spin every other connection starves.

Fix: on `NEED_MORE`, either consume the peeked bytes into `c->inbuf` and
classify on the buffered prefix, or `io_set(&c->io, 0)` and re-arm with a
short timer; plus reject a connection that stays in the front state for more
than ~2 s instead of `pingtimeout`.

### 🟠 R-2 — invitation propagation wildcards bypassed the `VAR_SAFE` filter (fixed)

`PROPAGATED_OPTIONS[]` had `"Obfs*"`, `"Https*"`, `"Quic*"`. Master now
registers `HttpsDecoyRoot` (a directory the invitee would serve) and
`HttpsDecoyUpstream` (a URL it would proxy to) as `VAR_SERVER` *without*
`VAR_SAFE` (`tincctl.c:1749-1750` on master), yet the wildcard copied them from
the inviter's config into the invitation and the joiner wrote them into the
invitee's `options:` unfiltered. `TlsCert`/`TlsKey` were one prefix away.
Fix: `core/tincd/src/invitation.c:65-83` is an exact allow-list (Mode,
Broadcast, AddressPool, Transports, TlsFingerprint, the seven `Obfs*` shaping
knobs, HttpsSni); `invitation_option_propagated_name()` returns the canonical
spelling. Proof: `testing/security/review-r-live.sh` step 3 (an inviter with
`HttpsDecoyRoot`/`HttpsDecoyUpstream` set: the invitation carries
Mode/AddressPool/Obfs*/HttpsSni and none of the decoy options);
`fuzz_invitation` checks every document produced by a join loads again.

### 🟠 R-3 — YAML parser dropped everything after an unplaceable line; write-back deleted it (fixed)

`parse_map()` stopped at the first line it could not place (a key indented
one space too far, a line without a colon, a tab) and `parse_text()` returned
the partial document as valid. The daemon then materialised and **saved that
partial document**: the host records and keys after the bad line were gone
from disk. Input: `tinc.yaml` with `     weird: 1` between `options:` and
`hosts:` (hand edit, GUI bug, or a merge). Fix (`yamlconf.c:324-460`): a
document with a leftover line is refused (`yamlconf_parse()` → NULL, the
daemon logs `Could not parse YAML config` and does not start rather than
starting with half a config), keys are bounded (`YAML_MAX_KEY` 255), nesting is
bounded (`YAML_MAX_DEPTH` 64), duplicate keys take the last value as PyYAML
does, `---`/`...`/`%` markers and quoted keys are accepted. Proof:
`yamlconf_props.c` cases 1-3, 8; live step 1 (file refused and untouched).

### 🟠 R-4 — emitter/parser asymmetry: values that read back differently (fixed)

Found by `fuzz_yamlconf` (property `emit(parse(x))` stable and `save` ==
memory). Scalars that begin with `[`, `|`, `"`, `#`, `-`, contain `: `, have
outer blanks or control characters, and keys containing `:` (which
`set_options_text()` produces from a multi-line option value) were written
plain and parsed as something else — the next `tinc set` then rewrote a
different config. Fix: `plain_scalar_safe()`/`plain_key_safe()`/
`emit_dq_scalar()` (`yamlconf.c:693-800`): anything unsafe is double-quoted,
block scalars only when every line is safe, `{}`/`[]` for empty containers.
Regression inputs: `corpus/fuzz_yamlconf/regress-key-with-colon`;
`yamlconf_props.c` cases 4-7.

### 🟠 R-5 — join wrote a document the parser refuses (300-byte node name) (fixed)

Found by `fuzz_invitation` (artifact kept as
`corpus/fuzz_invitation/regress-long-name`). `check_id()` bounds the alphabet
of a node name but not its length; an inviter-chosen `Name = T…T` (300 bytes)
became a `hosts:` key longer than `YAML_MAX_KEY`, so the joiner saved a
`tinc.yaml` it could not load again. Fix in two layers: (1) the emitter never
writes what the parser refuses — `yamlconf_emit()` returns NULL and
`yamlconf_save()` fails with `EINVAL` for an empty or over-long key
(`yamlconf.c:782-790`, props case 9); (2) `invitation_name_ok()`
(`invitation.c:102`) bounds names to 255 bytes (NAME_MAX: a node name is also
a `hosts/<name>` file name) for the joiner's own Name, the secondary chunks,
and `tinc invite` itself. Proof: live step 5; `run.sh check` replays the
artifact.

### 🟡 R-6 — `flock` on the config file's inode did not serialise writers (fixed)

`yamlconf_save()` writes a temp file and renames it over the config, so a
lock on the config file's inode was released/invalidated by every save; a
`tinc set` racing the daemon's key write-back (learned `Ed25519PublicKey` at
invitation redemption) lost one of the updates. Fix: a stable `<path>.lock`
file (`yamlconf_lock()`/`yamlconf_unlock()`, re-entrant, `yamlconf.c:1026`),
held across the whole read-modify-write in `yamlconf_append_host_line()`,
`zeroconf_materialise()`, `tinc set/add/del` (`tincctl.c:1999`, which now
re-reads under the lock before editing) and `tinc join`. Proof: live steps 2
and 6 (`.lock` created; `tinc set` against a running daemon that has just
materialised keys keeps both).

### 🟡 R-7 — pool exhausted by one subnet wider than the pool (fixed)

`pool.c` reserved every address covered by every `Subnet` it saw. A
`Subnet = 0.0.0.0/0` or `10.0.0.0/8` in a pending invitation file or in any
host record — and host records are written from **ADD_SUBNET of any
authenticated peer** — made `tinc invite` fail with an exhausted pool. Fix:
`inside_pool()`/`find_used()` (`pool.c:250-276`) only reserve /32 subnets
inside the pool. Residual (documented, not fixed): an authenticated peer can
still announce every /32 of the pool one by one; `StrictSubnets` is the
mitigation tinc offers. Proof: live step 4 (`hosts.wide: Subnet = 0.0.0.0/0`,
invitee still gets `10.9.0.2/32`); `fuzz_pool` (3.48 M executions).

### 🟡 R-8 — `tinc join` aborted on one control byte from the inviter (fixed)

`get_line()` called `abort()` on any non-printable byte in the payload. Fix
(`invitation.c:900-930`): the line is rejected, the join fails cleanly,
`\r` and `\t` are tolerated. Regression: `corpus/fuzz_invitation/regress-ctrl-abort`.

### 🟡 R-9 — Ifconfig/Route from the inviter reached `ip` unvalidated (fixed)

The joiner turned `Ifconfig`/`Route` lines into `InterfaceAddress`/
`InterfaceRoute`, which `autoif.c` hands to `system("ip …")`. `shell_safe()`
only whitelisted characters; a value starting with `-` was still an `ip`
option, and `snprintf` truncation was unchecked. Fix: `invitation_addr_ok()`/
`invitation_route_ok()` (`invitation.c:116-160`) at the trust boundary,
`shell_safe()` rejects empty and leading `-`, `build()` checks truncation,
rejected routes are logged (`autoif.c:61-150`). The inviter can still push a
default route (`Route = 0.0.0.0/0 via …`) — that is by design (the inviter is
trusted for network topology) and is now logged on the invitee.

### 🟡 R-10 — QUIC classifier residual overlap is 2⁻¹⁷ per node, not 2⁻³⁴ (open, owner: G2/G3, `transport_table.c:227-260`)

The comment claims the overlap between a QUIC long header and an SPTPS relay
datagram whose destination id starts with `0xC0..0xFF` is 2⁻³⁴ per node.
`quic_version_known()` accepts v1, v2, v=0, **every** `0xff00xxxx` draft (2¹⁶
values) and every greased `0x?a?a?a?a` (2¹⁶ values): ≈2¹⁷ of 2³² version
words, so the overlap is 2⁻² × 2⁻¹⁵ ≈ 2⁻¹⁷ per node id. Only relevant once
`quic` is in the accept mask; then a relay datagram for one node in ~130 k is
misrouted to the QUIC path and dropped. Suggested: restrict drafts/grease to
what the carrier actually negotiates (v1, v2), or let the QUIC path fall back
to SPTPS when no QUIC connection matches the DCID.

### 🟢 R-11 — SF spoofed SYN: small amplification, bounded (informational, `transport_sf.c:352-372`)

A spoofed SYN (64-bit cid, seq 0) makes `sf_accept()` allocate a connection
and answer; the reply is one small frame per spoofed source, capped by
`max_connection_burst` (10/s). Amplification factor < 1.5, not exploitable.
A RESET for an unknown cid is rate-limited to one per second globally
(`transport_sf.c:469-473`), which an attacker can use to starve legitimate
resets — harmless (the sender retransmits and times out).

### 🟢 R-12 — SF + `UDPRebindOnWake` tears down the meta session (informational, `net.c:236`)

`rebind_udp_sockets()` after a wake changes the local port the SF session is
bound to; the peer drops frames from the new address
(`transport_sf.c:481`), the session dies and is re-dialled. Invitees default
to `UDPRebindOnWake = yes`. Acceptable (a reconnect after sleep), but worth
a note in `docs/transports.md`.

### 🟢 R-13 — temp files hold keys on Windows (`yamlconf.c:474-500`)

`yamlconf_content_fp()` writes the `options:`/`hosts:` text — and on the
`keys` path, private keys — into `%TEMP%` (`GetTempFileName`, delete-on-close).
On POSIX `tmpfile()` is unlinked immediately. Suggest an in-memory `FILE*`
(`fmemopen` where available, `open_memstream`) or `FILE_ATTRIBUTE_TEMPORARY |
FILE_FLAG_DELETE_ON_CLOSE` via `CreateFile` + `_open_osfhandle` on Windows.

### 🟢 R-14 — expired invitations stay as `.used` until the weekly sweep (`protocol_auth.c:280`, `invitation.c:636`)

Not a security issue (the cookie is single-use and the file is 0600); a
`tinc invite` on a busy inviter lists them. Cosmetic.

### 🟢 R-15 — `tincd.c:596` calls `zeroconf_materialise(true)` (note for the tincd.c owner)

One-line signature change: the daemon start path re-reads the file under
the lock; `tinc join` passes `false` because it holds unsaved changes.

### 🟢 R-16 — `tinc get Port` vs `tinc set Port` (open, owner: stream A, `tincctl.c cmd_config`)

`Port` is `VAR_HOST`, so `tinc set Port` writes `hosts.<me>`, while `tinc get
Port` returns `options.Port` when the materialiser has put one there. Both are
upstream semantics + M1 materialisation; the user-visible result is that
`set` appears not to take effect. Suggest `get` to look where `set` writes
first.

---

## 4. M5 carriers on master (read-only; owners G2 = obfs, G1 = https/tls/decoy)

Lines refer to master at `ade1876` (obfs) and `1dd187e` (https).

### 🔴 M5-1 — decoy upstream proxy blocks the event loop; a probe every 3 s freezes the node (G1, `decoy.c:277-360`, `https.c:720-741`)

`proxy_upstream()` runs synchronously inside `https_io()`: `str2addrinfo()`
(blocking DNS, unbounded), `connect()`, `send()` and a `recv()` loop with a
3 s `SO_RCVTIMEO` per call, up to 4 MiB. Every TLS connection that fails the
authenticator — i.e. **every** probe or scanner hit — takes this path when
`HttpsDecoyUpstream` is set. During it no SPTPS, no pings, no packets are
processed; with `pingtimeout` 5 s, two probes in a row drop every meta
connection. Rate needed: one TLS connection per 3 s. Fix: make the upstream
fetch asynchronous (non-blocking connect + `io_add`, or a helper thread with
a pipe), cache the upstream response per path for minutes, and never let a
decoy fetch exceed a small total budget. Until then document
`HttpsDecoyUpstream` as unsafe on a node that carries traffic.

### 🟠 M5-2 — obfs key is derived from public keys: the discriminator is a mesh-wide shared secret (G2, `obfs.c:87-116`)

`key = SHA-512("tincstack-obfs-v1\0" || lo || "|" || hi)` over the two Ed25519
**public** keys. Every mesh member holds every host record (and one leaked
`tinc.yaml` holds them all), so any member — or anyone who ever obtained an
invitation — can classify junk vs real and forge validly-tagged frames for
**every** link in the mesh, not just its own. `docs/transports.md §5`'s
"authenticated discriminator" claim holds against an outsider only; the
blast radius of one enrolled adversary is the whole mesh's obfuscation. The
seal also never rotates: one key per node pair for the lifetime of the keys.
Suggested design: keep the static key for cold start only (the first SYN
and its ACK), then switch to a per-session key derived from secret material
both ends already share after the SPTPS handshake — a fresh 32-byte seed
exchanged inside the SPTPS meta channel (a new meta request; SPTPS itself
untouched), or an exporter over the SPTPS session key. The receiver tries the
session key first, the static key second (two Poly1305 trials on the fast
path). This also bounds the nonce space per session (M5-3).

### 🟠 M5-3 — nonce reuse: 32 random bits with a magic header, 64 bits with no rotation (G2, `obfs.c:190-204`)

The nonce is the ChaCha20-Poly1305 IV and is random per datagram. With
`ObfsInitMagicHeader`/`ObfsTransportMagicHeader` set, `out[0..3]` is
overwritten (`obfs.c:194-199`) and **only 32 random bits remain**: a
collision is expected after ~2¹⁶ datagrams (seconds of traffic). A repeated
nonce under a never-rotating key gives the observer the XOR of two inner
datagrams — the SPTPS record's 4-byte cleartext seqno makes that a reliable
tinc fingerprint, which is exactly what obfs exists to hide — and Poly1305
key recovery, i.e. forgery for that nonce. Without a magic header the bound is
~2³² datagrams per node pair (~6 TB at 1500 B), reachable over a link's life
because the key never changes. Fix: never spend nonce bits on the magic (put a
plaintext prefix before the nonce instead), rotate the key per session
(M5-2) and use a counter-based nonce per direction inside the sealed region
(see M5-4).

### 🟠 M5-4 — one replayed sealed datagram from any address repoints the link (G2, `obfs.c:312-327`, `obfs.c:344-353`)

`obfs_inject()` calls `obfs_link_activate(l, addr)` **before** the inner
frame is checked by SF (address match, seq) or SPTPS. There is no
anti-replay on the seal (random nonce, no window). An attacker who captured
one sealed datagram (on-path once, or a reflected one, see M5-5) replays it
from any source: the link's remembered address becomes the attacker's, the
real peer's datagrams no longer match the fast path, and because that peer is
`udp_confirmed` the cold path skips it (`obfs.c:362-366`) — the obfs link
stalls until re-dial. Fix: update the address only after the inner layer
accepted the datagram (mirror `update_node_udp()` after SPTPS verification;
for SF only on a valid SYN or a matching session), and add a per-direction
32-bit counter inside the ciphertext with a sliding window.

### 🟡 M5-5 — same key and nonce space in both directions: reflection (G2, `obfs.c:87-116`, `transport_sf.c:523-580`)

A→B and B→A use one key with no direction binding, so a frame captured in
one direction verifies when reflected in the other. SPTPS rejects reflected
records (separate keys per direction), but a reflected SF `CLOSE`/`RESET`
with the peer's spoofed source passes `sockaddrcmp()` and
`terminate_connection()` runs (`transport_sf.c:560-569`). Plain SF has the
same exposure to anyone who sees the cid; obfs claims to remove it and does
not. Fix: derive separate keys per direction (`lo→hi`, `hi→lo` labels) or put
a direction byte in the AAD.

### 🟡 M5-6 — cold-start scan budget is global, starts at the same node every time (G2, `obfs.c:368-402`)

`scan_budget` is 25 key trials per second for the whole daemon and every
datagram restarts the walk at the first node of `node_tree`. Consequences:
(a) in a mesh with more than 25 nodes, a peer past the 25th name can
**never** be cold-classified; (b) 25 random datagrams per second from anyone
starve every legitimate cold start; (c) the dialer's own junk
(`ObfsJunkPacketCount` up to 128) burns the budget before its SYN arrives.
Fix: budget per source address, try `lookup_node_udp(addr)` and nodes with a
matching known `Address` first, rotate the start index, and skip junk-sized
datagrams that cannot hold a frame (`len < OBFS_MIN_FRAME + SF_HDR_LEN`).

### 🟠 M5-7 — https pins the server certificate before anything is proven (G1, `https.c:342-345`)

`verify_server_cert()` writes `TlsFingerprint` into the peer's host record on
first use, before the 101 and before the SPTPS handshake inside the session.
An on-path attacker at first contact pins their own certificate permanently:
they cannot complete SPTPS, but every later dial to the real server is
"fingerprint does not match; refusing" until the admin removes the pin.
Invitees get the inviter's fingerprint through the invitation (safe); every
other pair relies on TOFU. Fix: pin only once the SPTPS handshake over that
TLS session succeeded (`c->status.active`), and never write a pin on a
session that failed. Also: an invalid existing pin is treated as absent and
a second `TlsFingerprint` line is appended on every dial.

### 🟠 M5-8 — plain-HTTP decoy busy-loops on a non-reading client (G1, `decoy.c:380-395`)

`send_all()` retries on `EAGAIN` without waiting: a prober that sends a
request and never reads holds the event loop at 100 % CPU until the socket
buffer drains — for as long as the response exceeds the send buffer (a
`HttpsDecoyRoot` file up to 8 MiB, or an upstream response up to 4 MiB; the
built-in page is small enough to fit). Fix: hand the response to the normal
`io_add`/`IO_WRITE` path with a deadline, as `https.c` does for TLS.

### 🟡 M5-9 — name-existence timing oracle in the authenticator (G1, `https.c:462-563`)

Work done before serving the decoy depends on the claimed name: unknown
name → host-record lookup fails fast; known name → file parse +
`ecdsa_verify()`. Over many samples a prober can enumerate node names. The
decoy bytes themselves are identical for wrong key, replay and plain probe
(same `decoy_respond(request)`), and the stale-timestamp case returns before
any key work — so the oracle is timing only. Fix: constant-work path (verify
against a dummy key when the name is unknown; cache host public keys).

### 🟡 M5-10 — failed tinc authenticators are forwarded to the decoy upstream in the clear (G1, `decoy.c:243-275`)

`rewrite_host()` forwards the prober's request head — including the
`Cookie: sid=` of a legitimate peer whose authenticator failed (clock skew
> 90 s) — to `HttpsDecoyUpstream` over plain HTTP. The upstream and the
path to it learn "this port is a tinc node, peer name X". Fix: strip
`Cookie`, `Upgrade`, `Sec-WebSocket-*` before forwarding, or serve the static
page for any request that carried a `sid`.

### 🟢 M5-11 — misc (G1/G2)

- `tls.c:514-517` classic mode: `fopen(keypath, "w")` then `chmod(0600)` —
  the key file exists with umask permissions for a moment; use
  `open(O_CREAT|O_EXCL, 0600)`. YAML mode stores it in the 0600 `tinc.yaml`.
- `https.c:278-286`: no domain-separation prefix in the signed message. The
  formats differ in length from SPTPS's, so no cross-protocol confusion today;
  a label costs nothing and protects future formats.
- `https.c:103-133`: replay cache is only belt-and-braces (the exporter binds
  the authenticator to the TLS session; TLS 1.2 resumption and 1.3 both give
  fresh exporters); 256 slots, eviction by `now % 256` — fine.
- `decoy.c:87-120` `request_path()`: no URL decoding, so `%2e%2e` is a literal
  file name; `..` and `\` are rejected — no traversal.
- `obfs.c:476-482` `get_magic()`: negative config values wrap; cosmetic.

---

## 5. Fuzzing

Toolbox: `core/tincd/test/fuzz/Dockerfile` (debian:12-slim, clang-14,
libFuzzer, meson). The core is built with
`-Db_sanitize=address,undefined -Dc_args=-fsanitize=fuzzer-no-link`; each
harness links the real objects (`libtinc.a`/`libcommon.a`/`libtincd.a`,
`tincctl.c` with `main` renamed) — see `core/tincd/test/fuzz/Makefile`.
Binaries run under `setarch -R` (ASan vs `vm.mmap_rnd_bits=32`), which needs
`--security-opt seccomp=unconfined` on the throwaway container.

```
sh core/tincd/test/fuzz/run.sh build                     # image + core + harnesses
sh core/tincd/test/fuzz/run.sh fuzz 900                  # all five, 900 s each, in parallel
sh core/tincd/test/fuzz/run.sh check                     # replay committed corpora + yamlconf_props (CI gate)
```

Per-harness libFuzzer options (from `run.sh`): `-max_total_time=900
-rss_limit_mb=2048 -timeout=20 -print_final_stats=1 -artifact_prefix=…`,
`-max_len` 8192 (yamlconf, invitation), 1500 (classify), 4096 (pool),
16384 (sf). Seeds: `make-seeds.py` (stdlib only; placeholder keys, no real
key material).

| Harness | What it checks beyond "no crash" | Runs (900 s) | exec/s | Result |
|---------|----------------------------------|-------------:|-------:|--------|
| `fuzz_yamlconf` | `emit(parse(x))` parses and is stable; accessors; mutation API; `save`/`load` equality on a real file; `append_host_line` | 200 932 | 223 | 1 property violation (R-4, key with `:`), fixed; then clean |
| `fuzz_classify` | TCP verdict monotone in the prefix length; SF/QUIC only when accepted; `transport_parse_list` | 171 007 513 | 189 797 | no crash |
| `fuzz_invitation` | `invitation_url_parse` (byte 0 = 0) / `invitation_yaml_apply` (else); the document a join writes must emit and load | 5 423 187 | 6 019 | 1 property violation (R-5, long name), fixed; then clean |
| `fuzz_pool` | `zeroconf_pool_parse`/`first_host` invariants; `pool_allocate` over a pending-invitation file + host record | 3 480 006 | 3 862 | no crash |
| `fuzz_sf` | `sf_udp_receive` via `transport_udp_dispatch`, records `[flags][len16][frame]`, meta/teardown/sendto wrapped, session torn down per input | 8 887 268 | 9 863 | no crash |

Earlier campaigns before the fixes (same harnesses): `fuzz_classify`
8.4 M runs, `fuzz_invitation` 745 k + 863 k runs (the second found R-5),
`fuzz_sf` 905 k runs, `fuzz_yamlconf` 1 902 runs to the R-4 violation — all
without a memory-safety finding.

`fuzz_yamlconf` is slow (each input does a real save with `fsync` and a
reload); it still covered 1 281 edges of the parser/emitter.

Regression inputs kept in `core/tincd/test/fuzz/corpus/`:
`fuzz_yamlconf/regress-key-with-colon`, `fuzz_invitation/regress-ctrl-abort`,
`fuzz_invitation/regress-long-name`. `yamlconf_props.c` holds nine property
tests (strict tail, duplicate keys, nesting bound, syntax-looking scalars,
indented first block line, empty containers, options-text inverse, markers +
idempotence, refuse-to-emit).

## 6. Live proof and regression gates

- `TINCSTACK_TAG=ws-r testing/security/review-r-live.sh` — strict parser,
  writers' lock, propagation allow-list, pool vs `0.0.0.0/0`, long names,
  `tinc set` against a running daemon: all PASS on the ws-r image.
- `testing/transports/classify-test.sh` — 26 checks, 0 failures.
- `TINCSTACK_TAG=ws-r platforms/linux/docker/two-nodes.sh` — invite, join,
  ping both ways, inviter learned the invitee: PASS.
- `sh core/tincd/test/fuzz/run.sh check` — props ok, five harnesses replay
  their corpora without a crash.

## 7. Residual risks (not fixed, by decision)

- A malicious inviter still controls the invitee's network-wide options
  (`Mode`, `AddressPool`, `Transports`, obfs shaping, routes) — by design; the
  invitee now logs every address/route it applies.
- An authenticated peer can reserve pool addresses one /32 at a time via
  ADD_SUBNET; `StrictSubnets` is the mitigation.
- The `.lock` file is advisory (`flock`); a writer that bypasses
  `yamlconf_save()` (the GUI) is not serialised. The GUI should take the same
  lock file (documented in `docs/config-schema.md`).
