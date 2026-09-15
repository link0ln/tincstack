# PLAN.md — tincstack

**Last Updated:** 2026-09-15

A self-hosted mesh VPN distribution on a hardened tinc 1.1 core, with opt-in
circumvention transports and per-platform delivery (Linux/Windows/Android).
Read [`ARCHITECTURE.md`](ARCHITECTURE.md) first — it defines the non-negotiable
principles this plan serves. Source decisions and evidence are in
[`docs/source-inventory.md`](docs/source-inventory.md).

## How to use this plan

- Tasks are grouped into milestones **M0–M9**. Within a milestone, do items top to
  bottom; milestones are mostly sequential but the platform milestones (M6–M8) can
  proceed in parallel once M1–M5 land.
- Status marks: `[ ]` open · `[~]` in progress · `[x]` done (only when its
  **Proof** line has been produced and recorded).
- Priorities: 🔴 P0 blocker · 🟠 P1 core feature · 🟡 P2 improvement · 🟢 P3 polish.
- **A box is ticked only for work that was run and whose proof exists.** A box
  ticked on intent is worse than an unticked one.
- Every C feature lands in `core/tincd/`; keep the meson build green
  (`docker build -f core/Dockerfile.build`) after each task.
- New defects found while working go under **Known Issues** with a reproduction
  and impact, at their real priority.

---

## Milestone M0 — foundation ✅ (done in the planning session)

- [x] 🔴 Select and vendor the core. **Proof:** `core/tincd/` = `link0ln/tinc`
  branch `yaml-config` @ `47b8d54a` (crypto intact, YAML read+write-back, NAT
  fixes, Wintun). Family-B forks rejected as code (see inventory).
- [x] 🔴 Reproducible core build. **Proof:** `docker build -f core/Dockerfile.build
  -t tincstack/core:dev core/` exits 0; `tincd --version` →
  `tinc 1.1pre18 … protocol 17.7`.
- [x] 🟢 Architecture, schema, inventory docs written.

---

## Milestone M1 — zero-config daemon (principles 2 & 5) 🔴

The daemon must start against an empty/absent config and become invite-ready with
no manual editing.

- [ ] 🔴 On startup with an empty or missing YAML, materialise defaults into the
  file: a network stanza, `Name` (hostname-derived, sanitised), `Mode=router`,
  `Port=0`, `AddressPool=10.<rand>.0.0/24`, this node's `Subnet` = pool's `.1`,
  and generate the Ed25519 (and legacy RSA) keypair folded into `keys:`.
  Implement in the daemon (`net_setup.c` / `names.c` / `yamlconf.c`), so it works
  identically on every platform, not in a shell wrapper.
  **Proof:** `docker run` with an empty `tinc.yaml` mounted → daemon starts, the
  file is populated, `tinc dump nodes` lists self.
- [ ] 🔴 `AddressPool` option: parse, default-select a /24 when starting a fresh
  network, store in the network's options. **Proof:** two empty inits pick
  distinct pools; a configured pool is respected.
- [ ] 🟠 `tinc invite` works against a zero-config node with no extra setup.
  **Proof:** fresh node → `tinc invite peer1` prints a one-line string.
- **Acceptance:** a single `docker run` with no prepared config yields a running,
  invite-issuing node.

---

## Milestone M2 — invitation & one-line onboarding in YAML mode (principle 3) 🔴

Close the gap that upstream invitations bypass YAML mode and carry no pool/
transport/cert material.

- [ ] 🔴 Route `tinc join` and `finalize_join()` through the YAML writer so a
  joined node writes its `tinc.yaml` (identity + inherited options + inviter host
  record), not a classic on-disk tree. **Proof:** join produces a valid
  `tinc.yaml`; no stray `tinc.conf`/`hosts/` tree appears.
- [ ] 🔴 Extend the invitation payload beyond upstream's (name/ConnectTo/Mode) to
  carry: assigned pool address + subnet, routes, active `Transports` and their
  parameters, and the HTTPS-front certificate fingerprint/material. **Proof:** a
  joined node's `options` match the inviter's for every propagated field.
- [ ] 🟠 Inviter persists the invitee's learned Ed25519 key back into its YAML
  (`yamlconf_append_host_line`, already present) — verify it fires in YAML mode.
  **Proof:** after join, inviter's `tinc.yaml` `hosts:` contains the invitee.
- **Acceptance:** two fresh `docker run` nodes, one invite string pasted to the
  second, mesh reachable (ping across the tunnel) with **no** manual config on
  either side.

---

## Milestone M3 — IP address pool & auto-assignment (point 8) 🟠

- [ ] 🟠 Reimplement the pool allocator (`allocate_vpn_ip` algorithm from the
  vless prototype) against tinc's host DB + invitation store: lowest free address
  in `AddressPool`, skipping used and pending. Land in `invitation.c`/new file.
  **Proof:** three sequential invites get `.2/.3/.4`; a freed address is reused.
- [ ] 🟡 Collision safety: refuse to reuse an address held by a live node.
  **Proof:** unit/integration check with a pending + a live holder.
- **Acceptance:** invitees are L3-reachable immediately, no manual `Subnet`.

---

## Milestone M4 — transport layer scaffold & negotiation (point 7, prerequisite for M5) 🟠

The negotiation model does not exist in any prior work; build the frame before the
individual carriers.

- [ ] 🟠 `Transports` option: parse the willingness list; advertise it in the host
  record; propagate through invitations. Default `[plain]`. **Proof:** a peer's
  advertised list is visible in `tinc dump`/host record.
- [ ] 🟠 Outbound carrier selection: dial the highest carrier common to both
  sides; fall back down the list to `plain` on handshake failure. **Proof:**
  matrix test — each (advertised-A × advertised-B) pair dials the expected
  carrier.
- [ ] 🟠 Inbound front dispatcher: one listen port classifies a new connection by
  its first bytes and routes to the right handler (plain / obfs / TLS / QUIC).
  **Proof:** the classifier's decision table (in `docs/transports.md`) with a test
  feeding each byte pattern to the right handler.
- **Acceptance:** with only `plain` implemented behind it, the scaffold selects
  and dispatches correctly; adding a carrier is a handler registration.

---

## Milestone M5 — circumvention transports (point 6, then 5, then 7) 🟠

Each carrier wraps SPTPS; **SPTPS is never bypassed** (principle 1). Land them in
this order (cheapest / most-contained first). Full wire formats go in
`docs/transports.md` as each is built.

- [ ] 🟠 **Obfuscated UDP** (redesign of tinc-obfs). Authenticated junk/real
  discriminator (keyed, not a cleartext flag); junk around the handshake, not
  per-packet; cold-start-safe receiver classification; relay-prefix-aware.
  Config surface per schema. **Proof:** `testing/dpi-proof` shows the SPTPS
  fingerprint absent on the wire and a tunnel that comes up from cold; relay path
  intact.
- [ ] 🟠 **HTTPS-mimicking front** (point 6 + point 5). TLS terminates on the
  listen port; real peers authenticate via material derived from tinc keys inside
  the session; unauthenticated probers get static content or a proxied upstream;
  authenticated SPTPS (meta+data) rides the one TLS flow. **Cert automation:**
  use `TlsCert`/`TlsKey` if set, else generate a self-signed cert at first start
  so the service always comes up. **Proof:** `curl https://node/` from an
  unauthenticated client gets plausible web content and a valid TLS handshake; a
  peer connects and tunnels; starting with no cert configured still comes up (self
  -signed).
- [ ] 🟡 **QUIC carrier** (point 7). msquic integration (reference: tinc-quic
  wiring) carrying SPTPS records over datagrams + one stream; certificate handling
  shared with the HTTPS front; connection migration for NAT rebind. **Proof:** a
  QUIC-negotiated link tunnels; falls back to a common carrier when one side lacks
  QUIC.
- [ ] 🟡 Runtime control CLI for obfuscation (`tinc obfs status|set|…`) **with
  persistence** to the YAML (the prototype's changes were lost on reload).
  **Proof:** a `set` survives `tinc reload`.
- **Acceptance:** each carrier interoperates through the M4 negotiator; with all
  off, behaviour is identical to plain tinc.

---

## Milestone M6 — Linux delivery (point 1c) 🟠

- [ ] 🟠 `platforms/linux/docker/`: `docker-compose.yml` + auto-init entrypoint
  that relies on M1 (daemon self-configures) rather than templating config in
  shell. Env for the few deploy-time choices (netname, connect target, public
  address). **Proof:** `docker compose up` on a clean checkout brings up a node
  with a generated `tinc.yaml`; a second compose joins by invite.
- [ ] 🟠 Invite/join helper scripts (`docker compose exec … tinc invite`).
  **Proof:** two-host (or two-project) bring-up reachable end to end.
- [ ] 🟡 No secrets in the tree; keys generated at first run into a named volume.
  **Proof:** `git status` clean of key material; `.gitignore` covers runtime data.
- **Acceptance:** a Linux user gets a working node from `docker compose up` and
  onboards peers with one invite string.

---

## Milestone M7 — Windows delivery (point 1a) 🟠

Adopt `tinc-manager` (PySide6) into `platforms/windows/`, ship the M-series core.

- [ ] 🟠 Repoint the GUI at the tincstack core binaries; bundle the mingw-w64
  build of `core/tincd`. **Proof:** GUI starts a network with a core-built
  `tincd.exe`.
- [ ] 🟠 **Invite/join UI** — the top missing feature (backend exists, GUI cannot
  drive it). **Proof:** issue an invite and join from the GUI.
- [ ] 🟠 Surface the new transport options (`Transports`, obfs, HTTPS-front, QUIC)
  in the config editor. **Proof:** toggling QUIC in the GUI writes `Transports`
  and the peer negotiates QUIC (ties M5/M4).
- [ ] 🟡 Fix adoption defects: atomic `tinc.yaml` save (no truncate over keys),
  daemon-log rotation, guard malformed-YAML startup, move blocking `tinc.exe`
  calls off the Qt thread. **Proof:** each has a check or a before/after note.
- **Acceptance:** two-file deploy (`tincmgr.exe` + `tinc.yaml`) manages networks,
  invites peers, and selects transports.

---

## Milestone M8 — Android delivery (point 1b) 🟠

Adopt `tincapp` (Kotlin) into `platforms/android/`.

- [ ] 🔴 Repoint `app/CMakeLists.txt` at `core/tincd` (currently an absent
  absolute path → last build was vanilla tinc) and **reconcile the build system**
  (tincapp drives autotools; core is meson — provide an autotools-compatible build
  of the core sources for the NDK, or an NDK meson cross-build). **Proof:** debug
  APK builds against the core across the 4 ABIs (`/opt/android-sdk`, NDK 26.1).
- [ ] 🟠 **App-picker UI** for the existing whitelist/blacklist split routing
  (`AllowApplication`/`DisallowApplication` are parsed & applied; only the picker
  is missing). Enforce single-mode (Android forbids mixing). **Proof:** pick apps
  in the UI → `network.conf` reflects one list → routing honours it.
- [ ] 🟡 Verify invite/join (incl. QR, already present) writes the shared YAML
  schema. **Proof:** join on device produces a schema-conformant config.
- **Acceptance:** an Android user joins by invite/QR and chooses which apps use
  the tunnel.

---

## Milestone M9 — verification harness 🟡

- [ ] 🟡 `testing/nat-sim/`: port the netmaker NAT lab to tinc — Docker gateway
  containers with `iptables` DNAT/SNAT for cone / restricted-cone, **plus** the
  missing symmetric-NAT and two-tier-CGNAT variants and **TCP-meta handling**,
  with pass/fail exit codes. **Proof:** the burst/rebind NAT features are shown to
  punch through restricted-cone where a baseline build does not.
- [ ] 🟡 `testing/dpi-proof/`: tcpdump-based check (netns+veth skeleton from
  `awg-proof.sh`) that each obfuscation tier changes the wire image away from the
  SPTPS fingerprint. **Proof:** captured before/after byte patterns.
- [ ] 🟢 Wire the core build + a smoke `docker compose` ping test into a single
  `make check` (or script). **Proof:** one command builds core and asserts a
  cross-node ping.

---

## Known Issues / carried-over defects

Defects identified during the source audit, to fix as their milestone is reached
(kept here so they are not lost):

- 🟠 **tinc-manager save is non-atomic** over the only copy of the private keys
  (truncate-in-place). Fix in M7.
- 🟠 **tinc-manager daemon log grows unbounded** (rotation only at start; 13 MB
  observed). Fix in M7.
- 🟠 **tincapp CMake points at a missing path** → last APK was vanilla tinc, not a
  fork. Fix in M8 (blocker for M8).
- 🟡 **YAML write-back re-emits the whole file**, dropping comments/formatting;
  editors must not rely on comment round-tripping. Documented in schema.
- 🟡 **sendmmsg relay batching measured worse** by its author. Keep default-off or
  drop; do not present as a feature (Architecture §10).
- 🟢 **Family-B repos committed secrets** (keys, a real LE cert, an invite token).
  None carried over; ensure none re-enter (M6 proof).

## Guardrails (from ARCHITECTURE.md — restated so they are not skipped)

1. SPTPS/Ed25519 is never removed or bypassed; transports wrap it.
2. Empty config must start and become invite-ready.
3. One invite string fully onboards a node.
4. One YAML file, daemon-owned, across all platforms.
5. Every knob has a working default; circumvention is opt-in.
6. No secrets in the repository.
