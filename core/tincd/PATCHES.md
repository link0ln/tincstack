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

## Building

Linux (musl/Alpine, as used on the relay containers):

    meson setup build --prefix=/usr/local --localstatedir=/usr/local/var \
        -Dbuildtype=release -Dminiupnpc=disabled -Dtests=disabled
    meson compile -C build

Windows (mingw-w64 cross-build, for the laptop):

    meson setup build-win --cross-file .ci/cross/windows/amd64 \
        -Dbuildtype=release -Dminiupnpc=disabled -Dcrypto=gcrypt
    meson compile -C build-win

`UDPDiscoveryBurst` and `UDPRebindOnWake` are added to the Linux meson
`check_functions` / option handling and registered in `tincctl.c`.

## New configuration options

| option | default | where | effect |
|---|---|---|---|
| `UDPDiscoveryBurst` | 5 | NAT'd endpoints | probes sent per round while not `udp_confirmed` |
| `UDPRebindOnWake` | no | NAT'd endpoints (not public relays) | rebind UDP to a fresh port on resume-from-sleep |
| `AllowPlainMeta` | yes | nodes that must not be fingerprintable as tinc | `no` = refuse inbound cleartext tinc meta connections (breaks `tinc join` against that node) |

## Recommended deployment

- Patches **1–3** on NAT'd endpoints (laptop, gateway) — these address the
  "direct UDP dies after sleep / never punches through CGNAT" problem.
- On nodes that act as a LAN listen hub, do **not** combine with `Port = 0`
  without checking that LAN neighbours can still find them.
- Patch **4** (sendmmsg): **not in the tree.** It did not help at ~2000 pps and
  was removed rather than left silently enabled; resurrect from `16eb7bc` only
  with a measurement that shows a win.
