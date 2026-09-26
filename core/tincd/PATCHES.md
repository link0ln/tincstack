# tinc 1.1 patches — NAT-traversal resilience & relay CPU experiments

Fork of [gsliepen/tinc](https://github.com/gsliepen/tinc) branch `1.1`.
Base commit: `6707f23` ("Get more tests running in containers").
All changes live on branch `sptps-resync-fix`.

These patches were developed and tested on a real deployment: a laptop behind
Thai CGNAT, a gateway behind Russian CGNAT, and a relay node with a public IP.
The goal was to keep direct UDP tunnels alive across laptop sleep/resume and
network changes, to improve hole punching through carrier-grade NAT, and to
reduce relay CPU.

Two parallel tinc networks were used:
- **gnet** — production mesh (LAN nodes + relay + EU exit).
- **gnet2** — a throwaway test network with the same topology shape, used to
  validate every patch before touching production.

---

## 1. SPTPS: survive peer restarts without livelock-resetting (`6236a7a`)

**Problem.** After one peer restarted its tincd (or the laptop resumed from
sleep), a direct UDP tunnel would permanently fall back to the TCP/relay path.
The gateway-side logs filled with `Invalid packet seqno: N != 0` and
`Got REQ_KEY ... while we already started a SPTPS session`. Stale UDP datagrams
from the previous SPTPS session (carrying high sequence numbers) kept arriving
for several seconds after a fresh handshake started. Each one was treated as a
hard error, which escalated to `send_req_key()` and tore the in-progress
handshake down again — a livelock that never converged, pinning the tunnel to
the relay forever.

**Fix.**
- `sptps.c`: in the datagram receive path, when `!instate` (handshake phase)
  and the seqno is sharply higher than expected (`> inseqno + 64`), silently
  drop the packet as stale instead of returning an error that escalates.
- `net_packet.c` / `protocol_key.c`: raise the `send_req_key` recovery cooldown
  from 10s to 30s across all reset paths (`receive_udppacket`, `try_sptps`,
  the `SPTPS_PACKET` and `ANS_KEY` handlers), so a high-RTT handshake has time
  to finish before another reset is attempted.

Wire-compatible: patched and unpatched peers interoperate; the change only makes
the local recovery state machine more tolerant.

## 2. SPTPS/UDP: burst hole-punching through restricted-cone / CGNAT (`71c67b9`)

**Problem.** Between two cone-NAT endpoints where at least one sits behind a
CGNAT with a short inbound filtering window, a single UDP probe every
`UDPDiscoveryInterval` (2s) easily misses the window at high RTT, and the two
ends' probes are not synchronised — so direct UDP rarely establishes even
though a manual hole-puncher succeeds on the same path.

**Fix.** While a node is reachable but not yet `udp_confirmed`, `try_udp()`
sends a short *burst* of probes back-to-back instead of one. `choose_udp_address`
already rotates the destination across the reflexive address and known edges,
so the burst also fans out across candidate paths. New option
**`UDPDiscoveryBurst`** (default 5, clamp ≥1). Wire-compatible (just a few more
ordinary probe packets); deploy on both ends of the link being optimised.

## 3. net: rebind UDP sockets to fresh ports on wake-from-sleep (`53e3505`)

**Problem.** A NAT'd node uses one fixed UDP source port for its whole process
lifetime, mapping to one fixed external port in the CGNAT. After resume from
sleep (or roaming) that mapping is often left filtered/stuck, so hole punching
never re-succeeds — yet a brand new socket (fresh source port → fresh mapping)
punches through immediately. `Port = 0` gives a fresh port at process *start*,
but sleep/resume does not restart the process, so the stuck port persisted.

**Fix.** tinc already detects resume-from-sleep in the 1-second
`timeout_handler` ("Awaking from dead after N seconds") and tears down all
connections. Hook into that exact moment: if **`UDPRebindOnWake = yes`**, call
`rebind_udp_sockets()`, which closes each UDP listening socket and reopens it on
port 0 (fresh ephemeral port). Reflexive discovery (`UDP_INFO`) then
re-advertises the new external address to peers automatically.

Gating: changes the inbound UDP port, so only enable on nodes that don't rely on
a stable inbound port (NAT'd nodes reaching peers via `ConnectTo`); off by
default. Pairs naturally with `Port = 0` on the same nodes.

## 4. net: batch relay UDP forwards with sendmmsg() (`16eb7bc`) — REJECTED, removed from the tree

**Hypothesis.** A relay forwarding ~2000 pps was ~96% syscall-bound (profiled
`stime` ≫ `utime`), dominated by one `sendto()` per forwarded packet. Batching
forwards from a `recvmmsg()` burst into one `sendmmsg()` per socket should cut
syscalls.

**Implementation (was).** `tx_batch_*` helpers in `net_packet.c` queued UDP
relay-passthrough forwards during the receive loop and flushed them with
`sendmmsg()`; on short-write/error the remainder fell back to the unchanged
single-`sendto()` path (preserving `EMSGSIZE → reduce_mtu` PMTU feedback).
Static buffers, no allocation. Gated on `HAVE_SENDMMSG`; wire-identical.

**Result.** Measured on the production relay under equal controlled load:
`sendmmsg` gave **no improvement** (slightly worse: 0.041 vs 0.0376 ticks/pkt).
Cause: at the observed packet rate `recvmmsg` returns only 1–2 packets per call,
so there was nothing to batch, and the extra in-batch `memcpy` added a little
overhead. It would only help at much higher, bursty packet rates.

**Decision 2026-09-16: removed.** `HAVE_SENDMMSG` is true on every Linux host,
so the "default-off" this patch was supposed to have never existed — the
batching was built and active in every image we ship, contradicting both this
file and ARCHITECTURE.md §10. Carrying a second, slower code path with 64 ×
`MAXSIZE` of static state through the relay hot path, and a second build
configuration to test it in, buys nothing at the packet rates we measured. The
`tx_batch_*` block, its `send_sptps_data()` hook, the two receive-loop brackets
and the `sendmmsg` meson probe are gone; `git show 16eb7bc` still has the code
if a future measurement ever justifies it. The negative result above is the
point of this section.

## 5. SPTPS: REQ_KEY glare tie-break + jittered restart cooldown (tincstack, stream K)

**Problem.** Found by the M9 NAT lab (`testing/nat-sim/lab.sh glare`). When two
nodes start sending to each other in the same instant, both call
`send_req_key()` and become SPTPS *initiators*. The `REQ_KEY` handler in
`protocol_key.c` (upstream 1.1 HEAD `211e3dfa` included — no fix exists
upstream) unconditionally stops its own session and restarts as *responder*, so
after the exchange **both** sides are responders: neither will ever send a SIG,
each side's stale handshake record hits a fresh responder that expects seqno 1
(`Invalid packet seqno: 0 != 1`), and the only way out is the "No key from X
after N seconds, restarting SPTPS" timer in `try_sptps()`. Both timers were
armed in the same second, so the retry collides again; the session eventually
succeeds by accident. Measured before the fix (full-cone × full-cone, both
sides ping at once, `--rtt 50`): core 90 s **FAIL** / 32 s / 31 s to the first
key (4 / 1 / 1 restarts), upstream baseline 23 / 46 / 35 s (3 / 7 / 5 restarts).

**Fix.**
- `protocol_key.c` (`req_key_ext_h`, `case REQ_KEY`): if we already have a
  *pending initiator* session with that peer (`from->sptps.label &&
  from->sptps.initiator`), break the tie by name: the lexicographically smaller
  `Name` keeps its initiator session and ignores the incoming request; the
  larger one yields (stock behaviour: stop, restart as responder, feed the
  peer's KEX). Both sides evaluate the same `strcmp` on the same two names, so
  exactly one initiator survives. Two initiators can never complete (the SIG
  record carries the initiator flag and each side verifies the *opposite*
  flag), which is why the rule must be symmetric rather than "always keep".
- `net_packet.c` (`try_sptps`): the 30 s restart cooldown of patch 1 is
  jittered ±20 % (24–36 s, `prng`) so two nodes that armed it together do not
  retry in the same second.

**Result.** Same scenario after the fix, core × core: key in 1 s in 6/6 runs
(rtt 50 ms ×3, rtt 1 ms ×3), 0 restarts, 0 `Invalid packet seqno`; the
tie-break lines appear on both sides in 5 of the 6 runs (the 6th raced clean).

**Wire compatibility.** No new message, no changed encoding, SPTPS untouched.
An unpatched peer always tears its own session down on `REQ_KEY`, so against a
stock 1.1 node: if the patched node has the smaller name it keeps its
initiator session and the stock node answers as responder (glare resolved in
one round trip); if the patched node has the larger name it yields exactly as
stock does, both end up responders as before, and the (now jittered) timer
recovers — never worse than stock. Fully fixed only when both ends carry the
patch.

**Amended 2026-09-17 (defect G): the tie-break must not defend a session that
cannot be answered.** "Keep ours" is right when both sessions are equally
viable, which is what genuine glare means. It is wrong when ours went out over
a meta route that has since disappeared — measured in `singleflow-test.sh`
PART 2, where a node kept a key exchange sent over a direct link that was
severed one second later and discarded the peer's fresh `REQ_KEY`, which had
arrived over a relay that worked, then sat out the full 24–36 s cooldown. Two
conditions now make a pending session yield instead:

- `status.sptps_route_stale` — `sssp_bfs()` (`graph.c`) snapshots `nexthop`
  before recomputing and marks any node still waiting for a key whose route
  changed. This is the discriminator that matters: in the measured case both
  sessions really did start in the same second, so age said nothing.
  `try_sptps()` also acts on the flag, restarting the exchange at once rather
  than waiting out the cooldown. Both readers clear it; one mark per graph run.
- `SPTPS_GLARE_WINDOW` (5 s) — a session older than one relayed round trip is
  not glare any more, so a peer's request is newer information than our silence.

Real glare is decided in milliseconds and is unaffected: the lab this patch was
written for (`lab.sh glare`, `--rtt 50` and `--rtt 1`) still reports key after
1 s, 0 `Invalid packet seqno`, 0 SPTPS restarts, tie-break logged on both
sides. Still no new message and SPTPS still untouched.

## 6. Front: let a node refuse cleartext tinc meta connections — `AllowPlainMeta` (tincstack, stream Z)

**Problem.** PLAN.md Known Issues, "a node cannot refuse cleartext tinc on its
listening port". An operator who sets `Transports: [obfs]` because the node
sits behind a DPI box still answered an unadorned tinc handshake on its port,
so the node stayed fingerprintable as tinc by a probe — no man-in-the-middle
needed. Measured before the fix (`testing/transports/plain-refuse-test.sh`
PART 1): a raw TCP connection from a third address sending `0 nodea 17.7` got
`0 nodeb 17.7` back. Three places forced `plain`:

1. `transport.c transport_read_config()` OR-ed `plain` back into the accept
   mask whatever `Transports` said, with only a warning;
2. `transport.c transport_front_dispatch()`, `TCP_CLASS_TINC`: set
   `c->transport = &transports[TRANSPORT_PLAIN]` and returned `true` **without
   consulting `transport_accept_mask` at all**, unlike the `TCP_CLASS_TLS`
   branch right below it. A bug on its own terms, whatever (1) does;
3. the dialler-side mirror: `protocol_auth.c ack_h()` recorded a peer's
   advertised accept list as `mask | TRANSPORT_MASK_PLAIN`, and
   `transport.c transport_node_read_config()` did the same for a host record —
   so even a peer that refused `plain` would still be dialled on `plain`.

**Fix.** New server option **`AllowPlainMeta`** (boolean, **default `yes`**, so
every existing network behaves exactly as before, warning text included).
`no` drops `plain` from the effective accept mask, which is advertised *and*
enforced: the `TCP_CLASS_TINC` branch now checks the mask like the TLS branch,
logs the reason and tarpits the socket (indistinguishable from an unrecognised
preamble — the refusal must not itself be a signal). (3) now takes the peer's
advertised list as written; a peer that accepts `plain` says so in that very
list, so nothing changes for it.

**Loopback is exempt** from the refusal, by design. On POSIX the control
connection is a UNIX socket and never reaches the front; on Windows there is no
UNIX socket and `tinc` reaches its own daemon by connecting to this very port
with `0 ^<cookie> ...` — a tinc ID line. Refusing that would lock the operator
out of their own node and buy nothing.

**Cost.** `tinc join` against a node with `AllowPlainMeta: no` does not work:
`invitation.c` opens a raw TCP socket and sends `0 ?<key> ...` in cleartext, by
design (the invitee has no key material yet). Upstream tinc peers, and peers
whose `PreferredTransports` is the default `[plain]`, cannot reach it either.
That is the trade-off and it is why the default is `yes`. See
`docs/transports.md` §2.1.

**Wire compatibility.** No new message and no changed encoding; SPTPS
untouched. With the default `yes` the bytes on the wire are unchanged. With
`no`, the node simply refuses a connection it used to accept, and advertises
one fewer carrier in the ACK token an old peer already tolerates.

**Proof.** `testing/transports/plain-refuse-test.sh` (PART 1 before, PART 2
after + obfs still up + CLI still works + `tinc join` refused, PART 3
`tinc set` + `tinc reload` → probe answered and `tinc join` succeeds again).
No regression on the defaults: `two-nodes.sh`, `testing/smoke/run.sh`,
`obfs-test.sh`, `https-carrier-test.sh` and `classify-test.sh` all pass on
`tincstack/core:z`.

---

## 7. net: the dead-peer detection window is reloadable, and its substitutions are logged (tincstack, 2026-09-18)

**Problem.** `PingInterval` (60) and `PingTimeout` (5) decide how long a
silently dead peer stays in the routing table — measured on the field stand as
21/45/46 s of failover, a uniform draw over `[60, 65]`. Two things made that
number hard to act on:

1. both were parsed once, in `setup_network()`, and `reload_configuration()`
   never looked at them again — shortening the window took a **restart**, i.e.
   the outage the shorter window exists to avoid;
2. out-of-range values were substituted in silence. `PingInterval = 0` reads
   like "stop pinging" and means 86400 s; a `PingTimeout` above the interval, or
   the default 5 under an interval of 2, was replaced with no log line at any
   debug level.

**Fix.** The parsing moved into `setup_ping_timers(bool reloading)`
(`net_setup.c`), called from `setup_network()` and now from
`reload_configuration()` (`net.c`) as well. The substitutions are upstream's,
unchanged — a config an older build accepted must not stop a daemon from
booting — but each one now logs what was asked for and what is used, and a
reload that moves the window logs `Dead-peer detection window changed on reload:
PingInterval 60 -> 10, PingTimeout 5 -> 3 seconds.` (nothing when it does not
move).

**Scope of the runtime change.** The next one-second tick of
`timeout_handler()` uses the new values, for existing connections too. An
already-established QUIC carrier keeps the handshake and idle timeouts it
derived from `PingTimeout` at creation (`transport_quic.c`); PMTU re-probing
picks up the new `PingInterval` on its next round (`net_packet.c`).

**Wire compatibility.** None affected: no new option, no new message, no
changed encoding, SPTPS untouched. The defaults are upstream's, so an unchanged
config behaves exactly as before, log lines included (a valid pair logs
nothing).

**Proof.** `testing/config/ping-interval-test.sh` — one peer frozen with
`docker pause` (the kernel keeps ACKing, only the daemon goes quiet): 64 s
detection at the defaults, 13 s with `PingInterval: 10` / `PingTimeout: 3` in
the YAML at startup, 10 s with the same pair applied by `tinc set` + reload on a
daemon that was never restarted, plus the three substitution warnings asserted
by their exact text. No regression on the defaults: `testing/smoke/run.sh` and
`platforms/linux/docker/reload-test.sh` pass on the rebuilt core. Deployment
guidance and the costs of a short window: `docs/config-schema.md`, "Dead-peer
detection".

---

## 8. Windows: a joined node brings its own adapter up (tincstack, 2026-09-18)

Files: `src/windows/device_dispatch.c`, `src/windows/wintun_device.c`,
`src/autoif.c`, `src/autoif.h`.

Two defaults made the one-line join unusable on Windows. `select_backend()`
chose TAP-Win32 unless `DeviceType` was spelled `wintun`, and the invitation
path writes no `DeviceType` — so a node that had just joined looked for a
TAP-Win32 driver this distribution does not ship (it ships `wintun.dll`) and
died at startup:

    Using TAP-Win32 (L2) device backend
    ERROR   No Windows tap device found!
    Terminating

One layer down, `configure_ip()` assigned the adapter address only from
`WintunAddress`, although the daemon already knows its address (its `/32`
Subnet) and the prefix (`AddressPool`) — the same pair the Linux built-in
tinc-up uses. A joined node therefore needed two hand-written options before
it could run at all.

Now: with `DeviceType` unset the dispatcher asks `wintun_available()` — a
quiet probe that only loads `wintun.dll` and checks its entry points, without
either backend touching an adapter — and picks Wintun when it succeeds,
TAP-Win32 when it does not. `DeviceType` still decides outright when set, so
an existing TAP deployment is unaffected. `own_interface_address()` is now
`autoif_own_address()` (non-static, declared in `autoif.h`) and
`configure_ip()` falls back to it, logging `No WintunAddress set; using this
node's own address 10.200.250.3/24`. The backend line now says why:
`Using Wintun (L3) device backend (no DeviceType set, wintun.dll is usable)`.

Proof: `platforms/windows/build-core-win.sh` cross-builds clean; the Linux
core builds and `testing/smoke/run.sh` passes with the shared `autoif.c`
change (`tincstack/core:winfix`).

---

## 9. `tinc cert`: a real certificate for the https/quic front, via ACME + Cloudflare (tincstack, 2026-09-19)

Files: `src/acme.c`, `src/acme.h`, `src/httpc.c`, `src/httpc.h`, `src/json.c`,
`src/json.h`, `src/certcmd.c`, `src/certcmd.h`, `src/tincctl.c`,
`src/transport.c`, `src/meson.build`.

**Problem.** The node certificate the `https` and `quic` carriers present is
self-signed (`tls.c`). Peers do not care — they pin its fingerprint — but a
self-signed certificate is exactly what an observer does not expect on a port
that claims to be an HTTPS service, and nothing that validates a chain accepts
it. `TlsCert`/`TlsKey` could always point at a real certificate, but getting one
was the operator's problem.

**What was added.** An optional path from "I own a domain in Cloudflare" to a
publicly trusted certificate, in one command:

    tinc -c tinc.yaml -n net cert status | check | issue [--force] [--staging] | renew

`acme.c` implements RFC 8555 with the **DNS-01** challenge and Cloudflare as the
DNS provider: ES256 JWS with an account key it generates and stores
(`keys.acme_account`), the RFC 7638 JWK thumbprint for the key authorization,
zone discovery by walking the parent labels of `CertDomain`, a TXT record that
is always removed again, a fresh P-256 key and CSR per issuance, and the
certificate stored in `keys.tls_cert` / `keys.tls_key`. `httpc.c` is a small
blocking HTTPS client (system trust store, `SSL_set1_host`, 1 MiB cap,
dechunking); `json.c` is a bounded JSON reader (depth 32, 4096 members).

**Where it runs.** In the CLI only — `acme.c`, `httpc.c` and `json.c` are in
`src_tinc`, not `src_lib_common`, so the daemon does not even link them. A CA
takes seconds to minutes to answer and the daemon's main loop may not block;
that is defect M5-1, and this is the same mistake one layer up.

**Errors are the feature.** Fifteen distinct outcomes (`acme_rc_t`), each with a
stable name, one sentence of what happened and one of what to do: a token that
is not a token, a token that is not active, a token without `Zone:DNS:Edit`, a
token whose zones do not contain `CertDomain` (the message lists the zones it
*can* see, because that is nearly always the mistake), Cloudflare rate limiting,
a directory that is not a directory, an account the CA refuses, an order it
refuses, a challenge it cannot validate, its own rate limits, a CSR it rejects,
and the local network/crypto failures. The Windows GUI shows the code, the
sentence and the hint (`platforms/windows/gui/cert_dialog.py`).

**The fingerprint moves.** `zeroconf.c` writes `TlsFingerprint` into the node's
own host record only when it is absent, peers refuse a mismatched pin
(`https.c`), and `TlsFingerprint` is in `invitation.c`'s `PROPAGATED_OPTIONS` —
so `cert issue` rewrites that line itself and says, in as many words, that peers
holding the old pin are locked out until they learn the new one.

Two defects were found while proving it, both in this new code:

* `fail(c, rc, c->out->detail, hint)` — the "keep what the transport said, add a
  hint" idiom — printed a buffer into itself. Undefined behaviour; in practice
  glibc left the message empty, so every network failure reported nothing at
  all. Both `fail()` and `failf()` now format through a temporary.
* `httpc.c` sent `Host: <host>` without the port. Every ACME server builds its
  directory URLs from the `Host` header, so against a CA on a non-443 port the
  directory came back pointing at port 443 and the next request went nowhere.
  RFC 7230 requires the port; it is now included whenever it is not 443.

A third, older one was in the way: the https front read the certificate only at
carrier init, so a replaced certificate was served only after a restart (the
quic carrier already refreshed itself in `quic_read_config()`). `tls_init()` is
idempotent and keeps its contexts when the fingerprint is unchanged, so
`transport_read_config()` — which every `setup_myself_reloadable()` runs — now
calls it when `tls_ready`. That is what makes `cert issue` take effect without
a restart, and it closes a 🟢 known issue from M5.

And one behavioural bug in the ACME flow: Let's Encrypt caches an authorization
for 30 days, so a renewal inside that window gets a challenge that is already
`valid`, and re-triggering it is an error ("Cannot update challenge with status
valid"). `dns_challenge()` now reports an already-valid authorization and the
flow goes straight to the CSR.

Proof: `testing/acme/run.sh` — Pebble as a real ACME server, pebble-challtestsrv
as the DNS that answers the challenge, and a stdlib stand-in for the Cloudflare
API; 28 assertions covering the happy path (issue → stored cert issued by the CA,
own `TlsFingerprint` rewritten to match, account key kept, `renew` a no-op,
`renew --force` reissuing), every Cloudflare code plus `acme-challenge`, and a
running daemon serving the new certificate after the reload `cert issue` asks
for.
Nothing leaves the host and no Cloudflare account is needed.

---

## 10. `InterfaceRoute` on Windows, and the spelling that was silently dropped (tincstack, 2026-09-19)

Files: `src/windows/wintun_device.c`, `src/windows/wintun_device.h` (new),
`src/windows/device_dispatch.c`, `src/autoif.c`.

**Problem.** A node can announce a LAN (`Subnet = 192.168.1.0/24`) and every
peer then knows, in tinc's own routing table, that the LAN is behind it. The
operating system does not: `autoif.c` installs system routes only from explicit
`InterfaceRoute` entries, on purpose — a peer must not be able to edit this
machine's routing table by announcing a subnet. On Linux `InterfaceRoute` filled
that gap. On Windows nothing did: `wintun_device.c` set the adapter address and
stopped there, so a Windows node could never reach a subnet a peer announced,
whatever the config said.

**What was added.** `configure_routes()` in the Wintun backend, run right after
`configure_ip()`: each `InterfaceRoute` becomes a `CreateIpForwardEntry2` on the
adapter's LUID. Binding them to the LUID is the point — Windows removes them
with the adapter, so a route into a peer's LAN never outlives the tunnel that
was the only way to reach it, and a restart re-installs them from the config
with nothing to clean up. `SitePrefixLength = 0` is the same documented gotcha
`set_interface_mtu()` already hits.

**The defect this uncovered.** `autoif.c` split the option on the first space
and treated everything after it as the gateway, so `192.168.5.0/24 via
10.79.0.2` — the spelling anyone who knows `ip route` writes, and the one the
GUI first emitted — left the keyword attached to the gateway, failed
`shell_safe()` on the space, and was dropped with `Ignoring InterfaceRoute
'...': not a route`. A warning in a debug log, and the route silently absent.
Both spellings are now accepted, on both platforms: `"<prefix> <gateway>"` as
`tinc join` writes it from an invitation's Route line, and `"<prefix> via
<gateway>"`.

Also: `wintun_available()` was declared with a bare `extern` in
`device_dispatch.c` (a missing-prototype warning in the cross-build). It now has
a header.

Proof: `testing/config/interface-route-test.sh` — two nodes, node2 owning and
announcing 192.168.5.0/24 as a dummy interface, node1 with the `InterfaceRoute`
and no tinc-up script so the built-in path is what runs. It asserts the route
reaches the routing table in both spellings, that the LAN answers through it,
that tinc knew the subnet the whole time, and that deleting the route makes the
LAN unreachable again — the control without which the other assertions prove
nothing. The Windows half is cross-build-verified only; `platforms/windows`
carries the unit tests for what the GUI writes.

---

## 11. The node warns before its certificate expires (tincstack, 2026-09-22)

`tls.c`, `tls.h`, `net.c`.

`tinc cert issue` obtains a certificate; nothing ever renewed one. A Let's
Encrypt certificate lasts 90 days, after which the `https` front presents an
expired certificate -- which does not break the VPN at all (peers pin
`TlsFingerprint` and never look at dates) but destroys the property the
certificate was obtained for: an expired certificate on a public HTTPS port is
*more* remarkable to an observer than the self-signed one it replaced.

`tls_init()` now records the leaf's `notAfter` (via `ASN1_TIME_diff`, the same
way `tinc cert status` computes it, so the two can never disagree) and
`tls_expiry_warn()` logs once a day while fewer than `AcmeRenewDays` remain, and
once a day as an error after it has expired. It is called from `periodic_handler()`
in `net.c`, so it costs one comparison every five seconds and nothing else. A
self-signed certificate is generated with a ten-year life, so the warning stays
silent on a default node instead of becoming noise.

The Linux node image renews itself (`platforms/linux/docker/entrypoint.sh`,
`CERT_RENEW` / `CERT_RENEW_INTERVAL`); the Windows manager badges its toolbar
button. Proof: `testing/config/cert-lifecycle-test.sh` -- a real daemon given a
three-day certificate, five assertions including both negative controls (no
warning for a fresh self-signed certificate, no renewal attempt without
`CertDomain`).

## 12. A zero-config node stops choosing an address pool the machine is on (tincstack, 2026-09-22)

`zeroconf.c`, `src/meson.build`.

`zeroconf_default_pool()` was one random byte: `10.<1..254>.0.0/24`, with no
check of anything. A node whose LAN is `10.7.0.0/24` had a 1-in-254 chance per
start of putting its tunnel in front of that LAN -- silently, permanently, and
only for the user whose network it is.

It now enumerates the machine's own IPv4 networks (`getifaddrs` on POSIX,
`GetAdaptersAddresses` on Windows, nothing on a platform that has neither --
Android below API 24, where the check degrades to the old blind pick) and walks
the 65 024 `10.<x>.<y>.0/24` candidates from a random start, taking the first
that overlaps none of them. Skipped candidates are logged; a machine that is
somehow on all of 10/8 gets a warning and its first candidate, because refusing
to start would be worse than a conflict the operator can see.

`meson.build` gains `ifaddrs.h` and a dedicated `getifaddrs` check: the shared
`have_prefix` does not include `<ifaddrs.h>`, so the generic `check_functions`
loop cannot see a declaration and silently fails -- which is exactly what
happened on the first build here, and the dead-code elimination of the skip
logging is what exposed it.

Proof: `testing/config/zeroconf-pool-test.sh`, eight assertions -- a node moves
off an occupied pool, says which it skipped, survives a machine that claims all
of 10/8, and 30 consecutive runs never pick a pool overlapping four local LANs.

## 13. A renewed certificate no longer locks peers out; quic pins after SPTPS (tincstack, 2026-09-23)

`https.c`, `transport_quic.c`, `transport_quic_tls.c`, `conf.c`,
`certcmd.c`, `platforms/linux/docker/entrypoint.sh`.

Two defects, one mechanism. First: an ACME renewal makes a fresh key, so the
fingerprint every peer pinned changes, and a pin mismatch was a hard refusal on
both carriers. With `CERT_RENEW=1` (then the default) a node renewed itself
every ~60 days and every peer that knew it lost `https` and `quic` to it
until someone edited their host record. Second (review M5-7, only half fixed):
`quic` still appended `TlsFingerprint` at the end of the TLS handshake, before
SPTPS, so a server holding the wrong Ed25519 key was pinned as the peer.

The first cut (c6d7a91) let a mismatching certificate through only if a
public CA had issued it for the SNI dialled. That was the wrong layer: it
needs a trust store Windows and Android builds do not have, fails every peer
that dials by IP address, and protects nothing -- the authenticator is signed
over the session's RFC 5705 exporter and the fingerprint the client saw, the
server checks it against its own, and SPTPS then proves both keys, so a
session through anyone else's certificate never activates, CA or not.

Now a certificate that differs from the pin is handled exactly like a first
contact, on both carriers: the handshake completes with no alert (on the wire
an ordinary HTTPS/QUIC session, not a client that hangs up after the server's
certificate), and the fingerprint is written only after SPTPS set `c->edge`
over that session, replacing the old line (`replace_config_file()`, which
`tinc cert` now shares through `host_text_set_var()`) so a host record never
accumulates pins. The CA code is gone. The Linux image's `CERT_RENEW` is back
to defaulting to `1`: nothing about peers requires it off any more.
The renewal loop's first check now runs a minute after start instead of one
interval after it.

Proof: `testing/transports/cert-repin-test.sh`, twelve assertions per carrier,
A trusting no CA at all -- a server that cannot prove the key A expects is
neither connected to nor pinned (first contact, and again with a pin in
place and a new certificate); first contact pins once; a CA renewal and a
switch to a self-signed certificate each reconnect and leave exactly the new
pin. Negative controls: on the image from c6d7a91 (the CA cut) the renewal
and the self-signed switch lock A out -- what every Windows and Android peer
would have seen; on the image before that, quic pinned the wrong-key server's
certificate.

---

## 14. The https and quic fronts move to 443 (tincstack, 2026-09-23)

`transport.c`, `https.c`, `transport_quic.c`, `net_socket.c`, `conf.c`,
`tincctl.c`, `platforms/linux/docker/`.

The fingerprint audit (`testing/fingerprint/results/2026-09-23`) found TLS
and QUIC on 655 -- tinc's IANA port, so the flows were tinc to anyone
reading a port number -- and the quic dial sending *from* the node's
listening port, which no QUIC client does. Now a listening node also binds
TCP `HttpsPort` and UDP `QuicPort` (443 by default, front-only), writes the
ports it bound into its own host record so invitations and host-record
exchange carry them, and says so loudly when it cannot bind; a dial goes to
the peer's advertised port, and the quic dial uses its own ephemeral-port
socket. The UDP front socket drops `SO_REUSEADDR`: with it, Linux let the
front share UDP 443 with another server's `SO_REUSEADDR` socket and split
that server's datagrams between them. `replace_config_file()` with a NULL
value now removes the key (the advertisement is withdrawn that way).
The Linux compose files publish `FRONT_PORT` (443) TCP+UDP.

Proof: `testing/transports/front-port-test.sh` (docs/transports.md §3.1).

---

## 15. The quic carrier speaks HTTP/3 (tincstack, 2026-09-23)

`h3.c` (new), `transport_quic.c`, `meson.build`.

The fingerprint audit found a carrier that announced ALPN `h3` and was not
HTTP/3: its Initial allowed no unidirectional streams (a one-field rule in a
packet anyone can decrypt), it never opened a control stream, and a real
HTTP/3 client got nothing back. Now the tinc session is one HTTP/3 request:
both ends open control (SETTINGS) and QPACK streams; the dialler POSTs and
streams the authenticator and then the meta connection in DATA frames; the
listener answers 200 and streams back; SPTPS data rides RFC 9297 datagrams
(quarter stream id + record). Any other request gets the decoy page as an
HTTP/3 response instead of a closed connection. The dialler's transport
parameters and its empty source connection id follow curl's. QPACK is
static-table only (`h3.c`, ~450 lines). Not compatible with the quic
carrier of earlier builds: mixed pairs fall back to the next carrier.

Proof: `testing/transports/h3-interop-test.sh` (curl, Chromium and nginx
against it; docs/transports.md §9.4).

---

## 16. The decoy answers as nginx does; no tarpit on the web fronts (tincstack, 2026-09-23)

`decoy.c`, `decoy.h`, `https.c`, `transport.c`, `net.c`, `net_socket.c`,
`transport_quic.c`, `connection.h`.

The decoy imitates nginx 1.27 (`server_tokens off`): nginx's welcome page
with the stock file's dates, its header order and `Date`, `404`/`405`/`400`
with its error pages, keep-alive (pipelined requests included), TLS
`close_notify` before the FIN, and on the TLS-only `HttpsPort` its answer to
plain bytes (`400`) and to a high first byte (close). Connections on the web
fronts carry `status.web_front`: `timeout_handler` closes them after 60 s
(75 s once kept alive) instead of tarpitting them, and the accept paths skip
`check_tarpit()` and the per-second QUIC budget -- both answered a burst of
connections from one address with silence -- in favour of a cap of 256
concurrent unauthenticated clients. The tinc port keeps upstream's tarpit
and `MaxConnectionBurst`.

Proof: `testing/transports/decoy-conformance-test.sh`, the same probes to a
tinc node and to nginx side by side (docs/transports.md §8.5.1).

---

## 17. One TLS stack: OpenSSL 3.5 for both carriers (tincstack, 2026-09-23)

`transport_quic_tls.{c,h}` (rewritten), `transport_quic.c`, `tls.c`,
`https.c`, `meson.build`, `meson_options.txt`, `core/Dockerfile.build`.

The core image moves to Debian 13 and the quic carrier from ngtcp2's GnuTLS
backend to `ngtcp2_crypto_ossl` on OpenSSL 3.5, so the https and quic
carriers, client and server, run on the TLS library curl 8.14 and nginx use
there. The dialler's ClientHellos take curl's settings on top of OpenSSL's
defaults: no `session_ticket` extension on both, and on https ALPN
`h2, http/1.1` and `post_handshake_auth`. A server that selects h2 is a web
server: the https dial gives up. The quic client now checks the selected
ALPN itself (GnuTLS enforced it). The exporter the authenticator is bound to
is the same value in both stacks, so GnuTLS-era and OpenSSL nodes still
connect.

Proof: `testing/fingerprint/run.sh` (both ClientHellos' JA4, JA3 and size
equal curl's; the QUIC ServerHello's JA3S equal nginx's) and
`testing/transports/mixed-version-test.sh` (docs/transports.md §8.2, §9.1,
§9.8).

## 18. The TLS carriers on Windows (tincstack, 2026-09-23)

`core/Dockerfile.build-win`, `meson.build`, `dropin.{c,h}`, `https.c`,
`autoif.c`, `transport_quic.c`, `transport.c`, `transport_sf.c`, `obfs.c`,
`httpc.c`, `pool.c`.

The Windows core moves from libgcrypt to a static OpenSSL 3.5.7 (with zlib
and zstd, as Debian's is) and gains `https` and `quic` (static ngtcp2,
`NGTCP2_STATICLIB`). Portability fixes the carriers needed on mingw:
`memmem`/`strcasestr` fallbacks in `dropin.c`, `ioctlsocket(FIONBIO)` for the
https dial socket (there is no `O_NONBLOCK`; it had stayed blocking), no
`%zd`/`%zu` (msvcrt printf), `autoif.c`'s `WIFEXITED` path Linux-only. On
every platform: a dial to an IP now sends no SNI and `Host: <ip>[:port]`,
as curl does, instead of `localhost`.

Proof: `testing/transports/windows-wine-test.sh` (docs/transports.md §9.10).

## 19. The TLS carriers on Android; `tinc retry` keeps the carrier (tincstack, 2026-09-24)

`platforms/android/native/build-core.sh`, `net.c`, `net.h`, `net_socket.c`,
`yamlconf.c`.

The Android core links OpenSSL 3.5.7, zstd and ngtcp2 statically, as the
Windows build does, instead of LibreSSL's libcrypto (which no longer compiled
against `tls.c`), and gains `https` and `quic`. Found getting the app onto
them, both on every platform:

- `retry()` expired every connection still being set up, and the carrier
  selector read that as a failed handshake: a `tinc retry` during a TLS or
  QUIC handshake demoted the link to plain for the session. It now marks
  them, and the re-dial uses the same carrier.
- `yamlconf_content_fp()` used `tmpfile()` alone; where the fixed temporary
  directory is not writable (an Android app: bionic's `/data/local/tmp`) every
  config read failed as "Could not open configuration file". It falls back
  to a `mkstemp` file (0600, unlinked at once) next to the config.

Proof: `testing/transports/android-emulator-test.sh`,
`testing/transports/retry-carrier-test.sh`,
`platforms/android/docker/join-on-emulator.sh` with `TRANSPORT=https|quic`
(docs/transports.md §2, §9.10).

## 20. The quic dialler's Initial is curl's; datagrams negotiated inside (tincstack, 2026-09-24)

`transport_quic.c`, `h3.h`, `transport.h`, `transport_quic.h`, `net_packet.c`;
`core/ngtcp2/tincstack-wire.patch` on ngtcp2 1.25.0.

curl 8.14 on Debian 13 speaks QUIC through OpenSSL 3.5's own stack, and the
dialler's Initial -- decryptable by anyone -- was ngtcp2's. The patch adds
`ngtcp2_conn_set_openssl_client_wire()`: transport parameters in OpenSSL's
set and order (`active_connection_id_limit` written as given, even 2; no
`version_information`, no `max_datagram_frame_size`), 4-byte packet
numbers, 2-byte Length fields, the ClientHello in order instead of ngtcp2's
shuffled CRYPTO fragments; and `ngtcp2_conn_set_remote_max_datagram_frame_size()`.
The dialler also announces `disable_active_migration` and
`max_udp_payload_size 1200`, and sends 1200-byte packets at most.

Since the dialler no longer announces datagrams, a listener enables them
itself for an authenticated peer and says so with an empty reserved HTTP/3
frame (`H3_FRAME_TINC_DGRAM`); a dialler that does not get it (an older
listener) gives quic up before activation. Older diallers still announce
datagrams and ignore the frame.

Found on the way: `quic_send_datagram()` sized datagrams by the configured
UDP payload limit instead of the path's; once a peer announced 1200, a
larger datagram sat at the head of the queue for ever, and the meta stream
behind it stalled until the ping timeout. It now uses the path's limit,
reports the overshoot so tinc's MTU discovery converges in one step, and the
flush drops a queued datagram that no longer fits.

The second flight (2026-09-24, late), same mode: the datagram with the
client's Finished is written as OpenSSL writes it -- the Handshake packet
and an ACK-only 1-RTT packet first into a scratch buffer, then the Initial
(ACK + PADDING) padded to what is left, so the Initial's Length is 1051 like
curl's instead of 25; an ACK-only Initial or Handshake packet never gets
ngtcp2's ack-eliciting PING; and the client moves to the first connection
ID the server issues as soon as it has it, without retiring seq 0 -- the
Destination Connection ID is in the clear, and OpenSSL moves.

Proof: `testing/transports/quic-wire-test.sh` (the old core fails it; its
second-flight check decrypts the Initials with
`testing/transports/quic_initial.py`, because tshark loses the connection
across the connection-ID move), `quic-carrier-test.sh` (b) with a second
NAT rebind, `mixed-version-test.sh` (docs/transports.md §9.4, §9.8, §9.9).

## 21. The quic listener answers probes and requests as nginx does (tincstack, 2026-09-25)

`transport_quic.c`, `h3.c`, `h3.h`, `h3_huffman.h` (new, generated),
`test/unit/test_h3.c` (new).

Measured next to Debian 13's nginx 1.26.3 (`quic-listener-wire-test.sh`),
the listener was silent where nginx answers and answered 200 where nginx
does not. The QuicPort socket now sends Version Negotiation for any version
but 1 and a stateless reset for a short-header datagram no session claims,
with nginx's size thresholds and formats; tinc's own port does neither,
since unclaimed datagrams there are SPTPS's and obfs's. The HTTP/3 decoy
decodes the request's QPACK field section (`h3_decode_request`: static
table, literals, RFC 7541 Huffman; a dynamic-table reference fails, as our
SETTINGS forbid one) and passes the real method, path and authority to the
TCP decoy's responder, so 404, 405 and a body-less `HEAD` come out as
nginx's. Anything but a POST is answered when its HEADERS frame is whole; a
POST -- the tinc session's method -- still waits for its authenticator, and
an undecodable field section is never answered early, so a dialler's
request cannot be answered by mistake.

Proof: `quic-listener-wire-test.sh` (probes and HTTP/3 answers now equal
nginx's; the previous core fails both), `test_h3.c` (RFC 7541 vectors,
malformed input, the dialler's own request).

## 22. The quic listener's handshake is nginx's in the clear (tincstack, 2026-09-25)

`transport.h` (`TRANSPORT_QUIC_CIDLEN` 8 -> 20), `transport_quic.c`,
`transport_table.c` (comment), `testing/transports/classify_test.c`;
`core/ngtcp2/tincstack-wire.patch`: `ngtcp2_conn_set_nginx_server_wire()`.

What anyone on the path reads of the server's handshake -- connection id
lengths, long-header Length fields, datagram sizes -- was ngtcp2's. Now the
listener's ids are 20 bytes, and the new server mode writes Length in as few
bytes as it takes (`NGTCP2_PKT_FLAG_LENGTH_MIN`: 2 reserved, shrunk to 1
before encryption), one CRYPTO frame per TLS handshake message (message ends
tracked as the TLS stack submits them), and nothing in 1-RTT until the
handshake completes, so the Handshake packet, not a 0.5-RTT packet with
NEW_CONNECTION_ID, fills the datagram. The HTTP/3 control streams and the
new connection id go out after the client's Finished, as nginx's do.

Price: every dialler packet carries 12 more bytes of id; tinc's PMTU over
quic 1119 instead of 1131.

Proof: `quic-listener-wire-test.sh` (connection id length and handshake
flight PASS; `testing/fingerprint/results/2026-09-25-quic-handshake/` has
both servers' handshakes decrypted with curl's key log), `quic-wire-test.sh`
(the dialler still curl's), `mixed-version-test.sh` against four older
cores, `classify-test.sh`.

## 23. The quic listener's transport parameters and SETTINGS are nginx's (tincstack, 2026-09-25)

`transport_quic.c`, `h3.c`, `h3.h`, `test/unit/test_h3.c`;
`core/ngtcp2/tincstack-wire.patch`: `ngtcp2_transport_params_encode_nginx_server()`,
used by `ngtcp2_conn_set_nginx_server_wire()`.

Anyone who completes a handshake reads the server's transport parameters and
HTTP/3 SETTINGS. Ours were ngtcp2's defaults and the dialler's SETTINGS
(`H3_DATAGRAM`, QPACK table 0) -- no web server's. Now:

- transport parameters: nginx 1.26.3's values, in nginx's order, every
  integer written even where it equals the default, no
  `max_datagram_frame_size`, no `version_information`;
- SETTINGS: QPACK table 4096, 128 blocked streams, nothing else; a decoder
  stream and no encoder stream. The table is real: a QPACK dynamic table
  decoder (encoder-stream instructions, blocked sections, Section
  Acknowledgment, Insert Count Increment, Stream Cancellation,
  ENCODER_STREAM_ERROR / DECOMPRESSION_FAILED as nginx closes with), since
  Chromium uses it;
- datagrams without announcing them, both ways: a dialler sends the
  reserved frame `H3_FRAME_TINC_DGRAM` before its authenticator and sets
  the listener's datagram limit itself when the listener's mark arrives. A
  dialler from before sends none; the listener answers it as a web server,
  so it falls back to its next carrier instead of failing on its first
  tunnel packet and re-dialling quic for ever (measured).

Price: a node from before 2026-09-25 cannot use quic towards an upgraded
listener (other carriers unaffected).

Proof: `quic-listener-wire-test.sh` (transport parameters and SETTINGS PASS;
`testing/fingerprint/results/2026-09-25-quic-tps/`), `test_h3.c` (dynamic
table, RFC 9204 examples), `h3-interop-test.sh` (Chromium, curl, nginx),
`mixed-version-test.sh`, which now also pings through the carrier (the
old check -- "connected over quic" once -- passed the first build of this
change although an old dialler's link died on its first packet).

## 24. The quic listener's tickets, first 1-RTT packet and TLS-failure close are nginx's (tincstack, 2026-09-26)

`transport_quic.c`, `transport_quic_tls.c`; `core/ngtcp2/tincstack-wire.patch`
(`ngtcp2_conn_set_nginx_server_wire` extended).

Session tickets: nginx's 300 s lifetime and 20-byte session id context (SHA-1
of "HTTP" and the certificate's SHA-1), the cache mode of `ssl_session_cache
none`: 224-byte tickets (were 7200 s, 208 B). The first 1-RTT packet: a CRYPTO
frame per ticket, HANDSHAKE_DONE, NEW_CONNECTION_ID, then the control stream's
type byte, its SETTINGS and the decoder stream as three STREAM frames with
the Offset field even at 0 -- one 596-byte datagram; padding only for header
protection. A failed TLS handshake closes with the reason `handshake failed`.
The dialler is unchanged. Proof: `quic-listener-wire-test.sh` 9/9
(`testing/fingerprint/results/2026-09-26-quic-tickets/`), quic-wire, h3-interop,
quic-carrier, front-port, mixed-version against pre-tps and pre-deb13.

## 25. Windows elevation surface, part 2; json/httpc bounds (tincstack, 2026-09-26)

`platforms/windows/**` (`tincmgr.spec`, `management.py`, `paths.py`,
`runtime.py`, `routes.py`, `main.py`), `yamlconf.c`, `json.c`, `httpc.c`,
`certcmd.c`, unit tests `test_json.c`, `test_httpc.c`.

The logon task starts a onedir install under `%ProgramFiles%\tincmgr\app`;
the onefile is only its carrier, with a SHA-256 manifest compiled into its
PYZ, and bundled core binaries are verified against it. The config (core and
GUI) is created with a protected DACL (SYSTEM + Administrators, + the user
only when unelevated; owned by Administrators when elevated). The automatic
refresh never downgrades. JSON numbers are scanned within the buffer,
trailing garbage is refused; `httpc` refuses short and malformed bodies and
no longer overflows on a huge chunk size. Proof: `build-exe.sh` smoke 14/14
and `windows-wine-test.sh` 16/16 under Wine, unit tests under ASan/UBSan.
Real-Windows checks (UAC, icacls, schtasks) remain open (PLAN.md).

## 26. The decoy is Debian 13's nginx 1.26.3 (tincstack, 2026-09-26)

`decoy.c`, `decoy.h`, `https.c`, `tls.c`, `transport_quic.c` (the HTTP/3
decoy's upstream), `transport.c` (the Alt-Svc port), `test/unit/test_decoy.c`.

The responder is a small model of nginx's static module and filter chain:
parser, not_modified, add_header (Alt-Svc when the quic front is up), gzip,
range; its answer is a structure that HTTP/1.1 and HTTP/3 encode. The page's
dates are Debian's. `HttpsDecoyUpstream` behaves like `proxy_pass` on both
fronts. The TLS front's tickets are nginx's (SNI callback, session id
context, 300 s). Proof: `decoy-conformance-test.sh` 78/78 against
`tincstack/nginx-deb13:dev` (63 fail on the previous core),
`h3-interop-test.sh`, `testing/fingerprint/results/2026-09-26-deb13-persona/`.

## 27. Front port override and exclusive listeners (tincstack, 2026-09-26)

`transport.c` (`public_front_port()`), `tincctl.c`, `net_socket.c`
(`set_bind_policy()`), `platforms/linux/docker/*` (`compose.leaf.yml`).

`HttpsPortPublic` / `QuicPortPublic` are advertised in place of the bound
port (a router forwarding another external port); per node, not propagated.
On Windows every listener sets `SO_EXCLUSIVEADDRUSE` (upstream sets
`SO_REUSEADDR`, which lets another process bind the same port there). A
Docker leaf that only dials publishes no host ports. Proof: `front-port-test.sh`
24/24, `windows-wine-test.sh` 19/19 (UDP takeover refused), `leaf-ports-test.sh`.

## 28. obfs frame v3: header protection and random tails (tincstack, 2026-09-26)

`obfs.c`, `obfs.h`, `test/fuzz/fuzz_obfs.c`, `testing/transports/obfs_probe.py`.

nonce+clen are masked with a ChaCha20 block over a 16-byte ciphertext sample
under a per-direction header key (`tincstack-obfs-hp` / `-shp`); the tail
length is uniform per datagram, drawn from the same block, capped by the
path budget (`Obfs*HeaderJunkSize` is now its maximum). Receivers read v2 and
v3 and answer a v2-only peer in v2; `OBFS_KEY` carries the frame version as a
trailing token; no version field on the wire. Proof:
`testing/fingerprint/results/2026-09-26-obfs-v3/`, fuzz self-tests,
`mixed-version-test.sh` obfs pairs.

## 29. quic: stream bytes never move until acknowledged (tincstack, 2026-09-26)

`quic_txq.c`, `quic_txq.h`, `transport_quic.c`, `test/unit/test_quic_txq.c`.

ngtcp2 retransmits from the pointers passed to `ngtcp2_conn_writev_stream`
until `acked_stream_data_offset` covers them. The meta ring moved and
reallocated unacknowledged bytes, and so did the listener's QPACK decoder
stream: a use-after-free under loss (ASan), and quic links that died on a
lossy path. All stream data now goes through a chunk list whose chunks never
move and are freed by the acknowledged offset. Proof:
`testing/transports/quic-loss-test.sh` (fails on the previous master, passes
here), `testing/fingerprint/results/2026-09-26-quic-q/item0-loss/`.

## 30. quic: the listener decides on the request HEADERS (tincstack, 2026-09-26)

`transport_quic.c`, `h3.c`, `h3.h`, `test/unit/test_h3.c`.

The dialler sends its exporter-bound authenticator as a session cookie
(`sid=`, base64url) in the request HEADERS, and still opens the body with it
for older listeners, which read it there (a current listener compares and
skips that copy). The listener verifies the first authenticator-shaped cookie
value at HEADERS; every other request, a POST without one included, gets the
decoy at once (405 for a POST, as nginx to a static file). Price: a dialler
from before 2026-09-26 sends no cookie and falls back from quic once per
reconnect. Proof: `testing/fingerprint/results/2026-09-26-quic-q/` (post405:
12/12 -> 0/12 cells distinguishable, a head-only POST now gets 405 in ~1 RTT),
`mixed-version-test.sh` against pre-tps, pre-deb13 and the previous master.

## 31. quic: the HTTP/3 decoy, idle traffic and datagram size as nginx and curl (tincstack, 2026-09-26)

`transport_quic.c`, `h3.c`, `decoy.c`, `net_packet.c`.

- the HTTP/3 decoy gets every request field (`h3_from_http1` in nginx's
  field encoding, Huffman where shorter); its answer is HEADERS+DATA in one
  STREAM frame followed by an empty FIN frame, as nginx; `decoy.c
  rewrite_request` puts Content-Length in nginx's slot for the upstream;
- `net_packet.c carrier_datagram_path()`: over a carrier's datagram path tinc
  sends no UDP keepalive, gratuitous probe replies or PMTU re-probes once the
  path is confirmed and the MTU fixed; the dialler PINGs after 15 s idle, as
  curl waiting on nginx (200 s idle: 266 -> 55 packets);
- a DATAGRAM that fills >= 3/4 of the packet is padded to the path's full
  1200 B (`NGTCP2_WRITE_DATAGRAM_FLAG_PADDING`).

Proof: `testing/fingerprint/results/2026-09-26-quic-q/README.md`,
`quic-listener-wire-test.sh`, `decoy-conformance-test.sh` (98 PASS). The
ngtcp2 patch is unchanged.

## 32. Relay TCP-borne SPTPS packets without a key of our own (tincstack, 2026-09-26)

`net_packet.c receive_tcppacket_sptps()`.

Upstream forwarded a TCP-borne SPTPS packet for another node only if it had a
key with the destination; a relay never starts SPTPS with a TCP-only
neighbour, so two nodes that both reached a relay over the https carrier (or
with `TCPOnly = yes`, upstream too) exchanged no packets at all. Relaying
needs no key -- the record is end-to-end and `send_sptps_data()` uses only
node ids and the path, as the UDP twin always did; reachability is still
checked. Proof: `testing/nat-sim/results/2026-09-26/core-fix/`, `tcponly/`
(ping 0 -> ok), `docs/nat.md` §5.2.

---

## Building

Linux (musl/Alpine, as used on the relay containers):

    meson setup build --prefix=/usr/local --localstatedir=/usr/local/var \
        -Dbuildtype=release -Dminiupnpc=disabled -Dtests=disabled
    meson compile -C build

Windows (mingw-w64 cross-build, for the laptop):

    docker build -f core/Dockerfile.build-win -t tincstack/core-win:dev core
    # static OpenSSL 3.5 + zlib + zstd + ngtcp2, then
    # meson -Dcrypto=openssl -Dquic=enabled (§18)

`UDPDiscoveryBurst` and `UDPRebindOnWake` are added to the Linux meson
`check_functions` / option handling and registered in `tincctl.c`.

## New configuration options

| option | default | where | effect |
|---|---|---|---|
| `UDPDiscoveryBurst` | 5 | NAT'd endpoints | probes sent per round while not `udp_confirmed` |
| `UDPRebindOnWake` | no | NAT'd endpoints (not public relays) | rebind UDP to a fresh port on resume-from-sleep |
| `AllowPlainMeta` | yes | nodes that must not be fingerprintable as tinc | `no` = refuse inbound cleartext tinc meta connections (breaks `tinc join` against that node) |
| `CertDomain` | unset | nodes offering `https`/`quic` | public DNS name `tinc cert` issues a certificate for |
| `CloudflareToken` | unset | same | Cloudflare API token with `Zone:Read` + `Zone:DNS:Edit` on that domain's zone |
| `AcmeContact` / `AcmeDirectory` / `AcmeRenewDays` / `AcmePropagation` / `AcmePollTimeout` | see docs/config-schema.md | same | ACME tuning; all optional |
| `CERT_RENEW` / `CERT_RENEW_INTERVAL` | `1` / `43200` | Linux node image (env, not YAML) | run `tinc cert renew` on a timer so the front's certificate does not expire; `0` turns it off. Peers follow a renewed certificate on their own (§13) |
| `HttpsPort` / `QuicPort` | `443` on a listening node | any node offering `https`/`quic` | front-only TCP/UDP listeners, advertised in the node's own host record (§14); `0` = off |
| `FRONT_PORT` | unset (`443`) | Linux node image (env) | sets both and is the port compose publishes |
| `InterfaceRoute` | unset | any node that must reach a subnet a peer announces | `"<prefix> [via] [gateway]"`, one per route; installed on the tunnel interface by the built-in tinc-up (Linux) or the Wintun backend (Windows) |

## Recommended deployment

- Patches **1–3** on NAT'd endpoints (laptop, gateway) — these address the
  "direct UDP dies after sleep / never punches through CGNAT" problem.
- On nodes that act as a LAN listen hub, do **not** combine with `Port = 0`
  without checking that LAN neighbours can still find them.
- Patch **4** (sendmmsg): **not in the tree.** It did not help at ~2000 pps and
  was removed rather than left silently enabled; resurrect from `16eb7bc` only
  with a measurement that shows a win.
