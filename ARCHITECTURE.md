# tincstack — architecture

**tincstack** is a self-hosted mesh VPN distribution built on a hardened tinc 1.1
fork. It consolidates prior experiments into one repository with:

- one daemon core, one config file format, shared across every platform;
- per-platform delivery: a Windows management GUI, an Android VPN client with
  per-app split routing, and a Linux `docker compose` deployment;
- optional, opt-in **circumvention transports** for use on restrictive networks:
  traffic obfuscation, an HTTPS-mimicking front with active-probing resistance,
  and a QUIC carrier — all layered *around* tinc's existing authenticated
  encryption, never replacing it.

This document records the design and the rationale. The task breakdown lives in
[`PLAN.md`](PLAN.md); the evidence behind the source decisions is in
[`docs/source-inventory.md`](docs/source-inventory.md).

---

## 1. Non-negotiable principles

These constraints are what separate this distribution from the earlier
prototypes, several of which failed by violating them.

1. **tinc's authenticated encryption (SPTPS / Ed25519 / ChaCha20-Poly1305) is
   never removed, stubbed, or bypassed.** Every circumvention transport is an
   *outer carrier* that wraps the SPTPS records; node identity remains the tinc
   Ed25519 key. A transport whose own authentication is weaker than SPTPS must
   still not weaken the tunnel, because SPTPS runs inside it. (Family-B
   prototypes deleted SPTPS and shipped plaintext or unauthenticated tunnels;
   that is the specific mistake this principle forbids.)

2. **Zero-configuration first run.** Starting the daemon against an empty or
   absent config file must succeed: the daemon writes sane defaults, generates
   keys, picks a default address pool, and is immediately able to issue
   invitations. No manual editing of config or host files is required to stand up
   the first node.

3. **One-line onboarding.** A new node joins with a single invitation string and
   nothing else. From that string it derives every parameter needed to be on the
   same network as the inviter — address from the inviter's pool, routes, connect
   target, the active transport and its parameters, and the certificate material
   for the HTTPS front — and writes its own config. The mesh works immediately.

4. **One config file, every platform.** A single YAML document is the source of
   truth on Linux, Windows and Android. The daemon reads and writes it in C
   (`yamlconf.c`), so every platform shares the exact same materialisation and
   write-back path. GUIs are editors/validators of that file, not parallel
   config engines.

5. **Everything has a working default.** Every knob added by this project ships
   with a default that keeps the daemon running. Circumvention transports are
   opt-in; with all of them off, the result is plain, fast tinc.

6. **No secrets in the repository.** No private keys, certificates, or invitation
   tokens are committed. Ever. (Prior repos violated this; see the inventory.)

---

## 2. Layered model

```
                    ┌───────────────────────────────────────────────┐
   node identity    │  tinc SPTPS  (Ed25519 auth + ChaCha20-Poly1305)│   ← never bypassed
   + payload crypto └───────────────────────────────────────────────┘
                                        │ SPTPS records (meta + data)
                    ┌───────────────────┴───────────────────────────┐
   carrier /        │  transport layer  (selectable, negotiated)     │
   obfuscation      │  • plain UDP/TCP (default, unchanged)          │
                    │  • obfuscated UDP  (junk + header shaping)      │
                    │  • HTTPS front     (TLS mimicry + probe resist) │
                    │  • QUIC            (datagrams + stream)         │
                    └───────────────────┬───────────────────────────┘
                                        │
                    ┌───────────────────┴───────────────────────────┐
   NAT traversal    │  UDP discovery burst, rebind-on-wake,          │
   resilience       │  SPTPS resync tolerance   (always on, default) │
                    └───────────────────────────────────────────────┘
```

- The **NAT-traversal resilience** layer is the field-tested Family-A work and is
  always compiled in; its knobs default to the values that were deployed.
- The **transport layer** is where obfuscation / HTTPS-front / QUIC live. Exactly
  one transport is active per link. The default is plain tinc. The others are
  selected per network and, critically, **negotiated per connection** (§4).
- The **identity/crypto layer** is untouched tinc. This is what lets us treat the
  transports as pluggable without ever trusting them for confidentiality.

---

## 3. Repository layout

```
core/
  tincd/            The daemon + CLI. tinc 1.1 fork (Family A, meson build).
                    All C feature work (obfuscation, HTTPS front, QUIC,
                    IP pool, invite/YAML integration) lands here.
  Dockerfile.build  Reproducible core build (meson → Debian slim runtime).
platforms/
  linux/docker/     docker compose + auto-init entrypoint (zero-config node).
  windows/          Management GUI (PySide6) — adopted from tinc-manager.
  android/          VPN client (Kotlin) — adopted from tincapp, CMake → core.
testing/
  nat-sim/          NAT-type lab (cone / restricted / symmetric / CGNAT).
  dpi-proof/        tcpdump-based checks that obfuscation changes the wire image.
docs/
  config-schema.md  The one YAML schema, exhaustively.
  source-inventory.md
  transports.md     Wire format & negotiation of each circumvention transport.
PLAN.md             Phased task list (the execution contract).
```

The core is vendored (not a submodule) so that all C feature work has one home
and one history. Its upstream provenance is recorded in
`docs/source-inventory.md`.

---

## 4. Transport negotiation (the piece that did not exist before)

Requirement (from the brief, point 7): a client may *request* an alternative
transport, and a willing peer *adopts it for that connection*, without both sides
being statically pre-configured for it.

Design:

- Each node advertises, in its host record, a `Transports` list — the carriers it
  is willing to speak, in preference order, e.g. `Transports = quic, https, obfs,
  plain`. This is exchanged already, because host records propagate through the
  mesh and through invitations.
- On an outgoing connection the initiator picks the **highest carrier both sides
  advertise** and dials it. Because the carrier is chosen from the intersection,
  a node that only advertises `plain` is never dialed with QUIC.
- The listener runs a **single front port** that classifies an inbound connection
  by its first bytes (TLS record vs QUIC long-header vs tinc/obfs preamble) and
  dispatches to the matching handler. This is what makes "tick QUIC on the
  Windows client and the peer answers in QUIC" work: the peer already listens for
  all carriers it advertised and routes by inspection, so no per-peer static
  config is needed.
- Selection is per connection and re-evaluated on reconnect. A carrier that fails
  handshake falls back to the next common one, ending at `plain`.

This keeps the negotiation in the transport layer and leaves SPTPS identity
unchanged: whichever carrier wins, the same SPTPS session runs inside it.

The concrete wire formats and the classifier's decision table are specified in
`docs/transports.md` (produced in the transport milestone, not before — the
classifier must be designed against the actual byte patterns).

---

## 5. HTTPS-mimicking front & active-probing resistance (point 6)

Goal: to a scanner or a probing middlebox, the listen port behaves like an
ordinary HTTPS server; to a real peer it carries the tunnel.

Design (REALITY-style, done correctly this time):

- The front terminates TLS using a certificate the operator configures
  (`tls_cert` / `tls_key` in the config — a real domain certificate). **If none
  is configured, the daemon generates a self-signed certificate at first start**
  so the service always comes up; the operator can drop in a real certificate
  later with no other change. This is the "full automation, server independent of
  settings" requirement.
- A real peer authenticates inside the TLS session using key material derived
  from the tinc node keys (an authenticator carried in the ClientHello / early
  data), so a peer is distinguishable from a scanner **without** a static bearer
  token in the clear (the vless prototype's fatal flaw was a cleartext shared
  UUID).
- An **unauthenticated** client is not told anything is wrong: it is served static
  content or transparently forwarded to a configured upstream site, so active
  probing sees a plausible web server, not a VPN. The static content and/or
  upstream are configurable; a default static page ships so the feature works out
  of the box.
- Once authenticated, the SPTPS records flow inside the TLS session — the meta and
  data channels share the one outward TLS flow (this is also point 5: a single
  outward-facing flow, no separate tinc-shaped TCP connection to fingerprint).

Certificate automation and the authenticator derivation are specified in the
HTTPS-front milestone.

---

## 6. Obfuscated UDP transport (point 6, cheaper tier; redesign of tinc-obfs)

A lightweight tier for when a full TLS front is unnecessary: shape the UDP
datagrams so they do not match tinc's SPTPS fingerprint. The redesign fixes the
four defects of the prototype:

- the junk/real discriminator is **authenticated**, derived from shared key
  material, not a cleartext flag byte anyone can forge;
- junk is emitted **around the handshake**, not on every data packet;
- cold-start identification works: the receiver can classify the first datagram
  of a new session (the prototype forced the handshake onto UDP and then could
  not identify it, deadlocking);
- **relay forwarding is prefix-aware** (the prototype double-prefixed and
  corrupted relayed records).

Config surface is kept close to the prototype's (and to AmneziaWG's vocabulary)
so the mental model transfers, but the mechanism is new.

---

## 7. IP address pool & auto-assignment (point 8)

- A node that starts a **new** network with no pool configured selects a default
  private /24 and takes the first host address.
- The pool (`address_pool`, an IPv4 /24 by default) is part of the network's
  config and is advertised to invitees.
- On **join**, the invitee is assigned the lowest free address in the inviter's
  pool — free meaning not present in the host database and not held by a pending
  invitation. The allocator is the `allocate_vpn_ip()` algorithm from the vless
  prototype, reimplemented against tinc's host DB and invitation store.
- The assigned address, subnet and routes are written into the invitee's config
  automatically, so the node is L3-reachable the moment it connects.

---

## 8. Config & onboarding flow (points 2, 3, 9)

```
first run (empty config):
    daemon → writes defaults, generates keys, picks pool, ready to invite
issue invitation:
    inviter → allocates address from pool, bundles {name, pool addr, subnet,
              routes, ConnectTo=inviter, active transport + params,
              front cert fingerprint / material} → one-line invite string
join:
    invitee → parses invite, writes its own YAML (identity + all inherited
              params), connects; inviter persists the invitee's learned key
              back into its YAML (yamlconf_append_host_line)
result:
    both nodes share identical network parameters incl. transport and cert
    material; the mesh is up with no manual editing on either side
```

The invitation payload is extended beyond upstream tinc's (which carries only
name/ConnectTo/Mode) to include the pool address, transport selection and front
material — this is what makes the joined node's config *match* the inviter's
across all the features above. This extension, and its integration with YAML mode
(so join writes the YAML, not a classic tree), is the invite/onboarding milestone
and is a prerequisite for the "one-line onboarding" principle.

---

## 9. Platform delivery

| Platform | Form | Base | Key added work |
|---|---|---|---|
| **Linux** | `docker compose` | core image | zero-config auto-init entrypoint; invite/join helper scripts |
| **Windows** | PySide6 GUI + tray | tinc-manager | invite/join UI; adopt new transports in the config editor; bug fixes (atomic save, log rotation) |
| **Android** | Kotlin VPN app | tincapp | **app-picker UI** for the existing whitelist/blacklist split routing; CMake repointed at core; build-system reconciliation |

All three consume the same `tinc.yaml`. The Windows GUI and Android app edit it;
the Linux entrypoint generates it. The daemon is the same core built for each
target (Linux x86-64, Windows mingw-w64, Android NDK ×4 ABIs).

---

## 10. What is explicitly deferred / out of scope for v1

Recorded so the plan stays honest:

- **sendmmsg relay batching** — measured *worse* by its author; kept behind a
  default-off flag or dropped, not a feature.
- **Multi-hop / onion routing** — present only as dead code in the vless
  prototype; not adopted.
- **HTTP/3 conformance for the QUIC carrier** — the goal is a working QUIC
  carrier, not a bit-exact H3 emulation; SNI/ALPN shaping is best-effort.
- **kernel-module data planes** — userspace only, per the netmaker-dev finding
  that kernel paths are too costly to operate.
