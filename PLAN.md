# PLAN.md — tincstack

**Last Updated:** 2026-09-16 (M9 closed by stream F)

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

## Milestone M1 — zero-config daemon (principles 2 & 5) ✅ (2026-09-16)

The daemon must start against an empty/absent config and become invite-ready with
no manual editing.

- [x] 🔴 On startup with an empty or missing YAML, materialise defaults into the
  file: a network stanza, `Name` (hostname-derived, sanitised), `Mode=router`,
  `Port=655` (founding node; `0` when `ConnectTo` is present — decision 3),
  `AddressPool=10.<rand>.0.0/24`, this node's `Subnet` = pool's `.1`,
  and generate the Ed25519 (and legacy RSA) keypair folded into `keys:`.
  Implement in the daemon (`net_setup.c` / `names.c` / `yamlconf.c`), so it works
  identically on every platform, not in a shell wrapper.
  **Proof:** `core/tincd/src/zeroconf.c` (`zeroconf_materialise()`, called from
  `tincd.c` before `read_server_config`). Run 2026-09-16 with
  `docker run --cap-add NET_ADMIN --device /dev/net/tun -v <dir>:/etc/tincstack
  tincstack/core:dev tincd -c /etc/tincstack/tinc.yaml -D` against (a) a 0-byte
  `tinc.yaml` and (b) no file at all: log
  `Materialised defaults into '/etc/tincstack/tinc.yaml' [tincstack]: Name=<hostname>
  Mode=router Port=0 AddressPool=10.169.0.0/24 Subnet=10.169.0.1/32 ed25519_priv
  Ed25519PublicKey rsa_priv RSA-public` → `Ready`; file written mode 0600 with
  `options/hosts/keys`; `tinc -c …/tinc.yaml dump nodes` → `<name> id … at MYSELF`.
  Restart → no second materialisation (idempotent). An unparsable existing file
  is refused, not overwritten. Port rule re-verified 2026-09-16: empty file →
  `Port=655 … Listening on 0.0.0.0 port 655`; file with `ConnectTo: [hub]` →
  `Port=0 … Listening on 0.0.0.0 port 32857`. No `-n` → first network in the file, else
  `tincstack`. No `hosts/` tree is created in YAML mode.
- [x] 🔴 `AddressPool` option: parse, default-select a /24 when starting a fresh
  network, store in the network's options. **Proof:** parsed + validated in
  `setup_myself_reloadable()` (`address_pool` global, `net.h`), registered in the
  CLI variable table. Two empty inits (same run as above) picked `10.169.0.0/24`
  and `10.185.0.0/24`; a file pre-set to `AddressPool: 10.99.0.0/24` kept it and
  got `Subnet = 10.99.0.1/32`; log `AddressPool 10.99.0.0/24 (first host
  10.99.0.1/32)`. Invalid pool → startup error naming the option.
- [x] 🟠 `tinc invite` works against a zero-config node with no extra setup.
  **Proof:** CLI reads `Name`, own host record and `Mode`/`Broadcast` through
  `config_fopen()` (YAML-aware) instead of raw `fopen`; discovered `Address` is
  persisted through `append_config_file()` into the YAML. Fresh node →
  `tinc -c /etc/tincstack/tinc.yaml invite peer1` →
  `172.17.0.4:43941/5GiFnXYd…` (one line, exit 0); `invitations/<hash>` created;
  `Address = 172.17.0.4` appended to the node's YAML host record. See Known
  Issues for the address-discovery caveats this exposed.
- **Acceptance:** a single `docker run` with no prepared config yields a running,
  invite-issuing node. **Met** (run above). Unit check for the YAML
  read/modify/write path: load→save→load is byte-stable on the daemon-generated
  file (throwaway test run in the build-stage container).

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
- [ ] 🟠 **Runtime reconfiguration in YAML mode** (brief point 3: "tinc must read
  *and write* the config on every platform, because parameters are changed
  online"). `tinc set/add/del/get` and `tinc reload` operate on the YAML
  (`options:` for server variables, `hosts.<name>` for host variables) instead
  of the classic tree; the daemon re-reads the YAML on reload. This is the one
  path the Windows GUI, Android app and obfs/transport controls all use.
  **Proof:** `tinc -c x.yaml set UDPDiscoveryBurst 7` → YAML updated, no
  `tinc.conf` created; `tinc reload` → daemon logs the new value.
- [ ] 🟠 **Invitee NAT defaults** (brief point 4): a node that joins by invite
  materialises `Port = 0` and `UDPRebindOnWake = yes` (it always dials out, so
  a stable inbound port is not needed); the founding node keeps tinc's standard
  port 655 (done in M1). **Proof:** joined node's `options:` carry both; the
  founding node's do not.
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

- [ ] 🟠 `Transports` (accept list, default = all compiled carriers) and
  `PreferredTransports` (dial preference, default `[plain]`): parse both;
  advertise `Transports` in the host record; propagate through invitations.
  **Proof:** a peer's accept list is visible in `tinc dump`/host record; a node
  with no list is treated as `plain`.
- [ ] 🟠 Outbound carrier selection: walk own preference list, dial the first
  carrier in the peer's accept list; fall back down the list to `plain` on
  handshake failure. **Proof:** matrix test — each (preference-A × accept-B)
  pair dials the expected carrier; ticking QUIC on A alone makes A→B use QUIC.
- [ ] 🟠 Inbound front dispatcher: one listen port classifies a new connection by
  its first bytes and routes to the right handler (plain / obfs / TLS / QUIC).
  **Proof:** the classifier's decision table (in `docs/transports.md`) with a test
  feeding each byte pattern to the right handler.
- [ ] 🟠 **Single-flow mode: meta channel over the data carrier** (brief point 5,
  independent of the HTTPS front). Today tinc opens a TCP meta connection *and*
  a UDP data flow — two fingerprints. Provide a mode where the SPTPS meta
  channel rides the same UDP flow as data (the thing `tinc-obfs` attempted by
  forcing the handshake onto UDP, but with cold-start identification so a
  receiver can classify the first datagram, and with the TCP path kept as a
  fallback when UDP is blocked). The obfs, HTTPS and QUIC carriers then each
  wrap exactly one flow. **Proof:** tcpdump of a session between two nodes in
  single-flow mode shows no TCP connection on the tinc port; tunnel up from
  cold; relay path intact.
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
- [ ] 🟠 **Certificate automation, shared by HTTPS front and QUIC** (decision 1).
  `TlsCert`/`TlsKey` if set; else generate a self-signed cert at first start
  and persist it in the YAML (`keys.tls_cert`/`keys.tls_key`), reused on every
  restart, replaceable by editing the two keys. Its fingerprint travels in the
  invitation (M2). **Proof:** first start with no cert → keys present in the
  YAML; restart → same fingerprint; dropping in a real cert → served without
  any other change.
- [ ] 🟠 **Default-on decoy on the TCP listen port** (point 6, REALITY-analogue).
  A client that does not complete a tinc handshake is answered as an HTTPS
  server with the node's certificate and gets static content
  (`HttpsDecoyRoot`, a default page ships) or a proxied upstream
  (`HttpsDecoyUpstream`). No config needed. **Proof:** `curl -k https://node:655/`
  on a zero-config node returns the decoy page; `nmap -sV` identifies the port
  as https; an upstream tinc peer still connects plain.
- [ ] 🟠 **`https` carrier** (point 6 + point 5). Real peers authenticate inside
  the TLS session via material derived from tinc keys (no static bearer token
  in the clear); authenticated SPTPS (meta+data) rides the one TLS flow.
  Selected by negotiation (M4), never a global mode. **Proof:** a peer that
  prefers `https` tunnels through the front; a prober on the same port sees
  only the decoy.
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
- [ ] 🟠 **One file on Android too** (brief point 2). Today the app keeps a
  second file, `network.conf` (`Address`, `Route`, `DNSServer`,
  `AllowApplication`, `DisallowApplication`). Fold these into the network's
  YAML as ordinary `options:` keys (the daemon ignores keys it does not use;
  the app reads them from the YAML) and delete `network.conf`. The app-picker
  above writes to the YAML. **Proof:** a device with only `tinc.yaml` connects
  with split routing applied; no `network.conf` exists.
- **Acceptance:** an Android user joins by invite/QR and chooses which apps use
  the tunnel.

---

## Milestone M9 — verification harness 🟡 (2026-09-16, stream F)

All of M9 runs in Docker only (`make check`); the NAT/DPI labs live in **one
privileged container** built from `testing/image/Dockerfile` (core binaries +
upstream 1.1pre18 baseline binaries + iptables/conntrack/tcpdump/python3) and
use network namespaces + veth inside it. Docker-network gateway containers (the
netmaker shape) do not work on Docker 28+/Cilium hosts: bridged packets to
another network's addresses are dropped by the daemon's nft rules. Details:
`testing/nat-sim/README.md`.

- [x] 🟠 `testing/nat-sim/`: NAT lab with gateway namespaces implementing
  **full-cone, restricted-cone (address-dependent), port-restricted** (static
  SNAT/DNAT pairs, external port ≠ listen port), **symmetric**
  (`MASQUERADE --random-fully`), **masq** (stock Linux MASQUERADE — on kernel
  ≥ 6.7 measured as *EIM-after-first + APDF*, i.e. no longer endpoint-
  independent), **udpblock** (TCP-meta only), and a **two-tier CGNAT** (home
  masq → carrier masq with 10/30 s UDP conntrack windows). Each profile is
  validated by `udpprobe.py` before use (`lab.sh validate-nat`: 6/6 classified
  as declared, `results/2026-09-16/validate-nat.jsonl`). Pair scenarios
  (5×5 + 3 udpblock) with a public relay, pass/fail per scenario, exit code,
  matrix in `results/2026-09-16/summary.md`. **Proof (run 2026-09-16, core AND
  upstream baseline):** 56 scenarios (28 per binary), matrix exit 0. Every
  traversable pair came up direct on both sides within 6–10 s (core) /
  6–18 s (baseline); the 8 non-traversable pairs (symmetric/masq ×
  port-restricted/masq/symmetric) carried traffic via the relay for both
  binaries (baseline's masq × portrestricted came up direct by a port-sharing
  coincidence, documented); the 3 udpblock pairs carried traffic over the
  TCP meta path for both (**TCP-meta handling**).
  The restricted-cone *delta* named in the original proof line is **not**
  observed for a plain pair: with a 1 ms RTT lab both binaries punch every
  traversable pair within ~10 s; the delta shows up in the laptop regression
  below (stage c), which is where `UDPRebindOnWake` acts. A dynamic
  endpoint-independent NAT cannot be built from stock netfilter on this
  kernel, so the cone profiles are static-per-port (faithful for `Port = 655`
  nodes; the rebinding node sits behind `masq`) — recorded in the README.
- [x] 🟠 **Laptop regression** (`lab.sh laptop`, named test): L behind two-tier
  CGNAT with `UDPRebindOnWake = yes`, P behind restricted-cone, R public.
  Stages: (a) P's tincd restarted; (b) L frozen 70 s with SIGSTOP/SIGCONT
  (`docker pause` would freeze the whole lab container; for tincd's 1-second
  timer it is the same: `Awaking from dead after 71 seconds of sleep`);
  (c) frozen again while the carrier conntrack is flushed and inbound to L's
  old socket is black-holed (the field's "stuck mapping"; netfilter cannot keep
  a re-created mapping filtered, so the effect is applied by inside socket).
  Pass = direct UDP *and* a tunnel ping within 60 s per stage, same process,
  < 20 `Invalid packet seqno` / `REQ_KEY … already started` lines.
  **Proof (`results/2026-09-16/laptop/`, exit 1 = baseline failed):**
  core PASS — setup 6 s, peer-restart 8 s, sleep-resume 6 s, mapping-dropped
  4 s; log `Awaking from dead after 71 seconds` → `Rebound UDP socket 0 to a
  fresh source port` ×2, L's UDP port 655 → 45620 → 46161, probe replies from
  P resume 4 s after wake. **baseline FAIL** — setup 12 s, peer-restart 8 s,
  sleep-resume 4 s, **mapping-dropped: no recovery in 60 s**; port stays 655,
  `Awaking from dead` but no rebind, probes to P's reflexive address go out and
  no reply ever returns (`baseline/nodel.log` after the `=== stage c` marker);
  traffic falls back to the relay (ping still ok). No seqno livelock in either
  binary in this scenario (0 lines) — the livelock signature appears instead in
  the glare scenario below.
- [x] 🟡 `testing/dpi-proof/`: netns + veth + `tcpdump -w` skeleton in the lab
  container (`run.sh capture <profile>`, profiles = tinc.conf overlays for
  M5's tiers), `fingerprint.py` (stdlib pcap parser) reporting six
  fingerprints — cleartext `0 <name> 17.7` ID line, plaintext SPTPS handshake
  record `[len][0x80]` on TCP, the 6-byte null destination id, the constant
  6-byte source node id, the cleartext 32-bit seqno counter, the 51-byte probe
  size — plus the size histogram; `compare.py before after` exits 1 while any
  baseline fingerprint survives. **Proof:**
  `results/2026-09-16/plain.report.txt` — all six PRESENT on the core's plain
  wire image (84 datagrams, 16 TCP segments); `run.sh compare plain plain`
  exits 1 (harness self-test).
- [x] 🟢 `make check` = build core + baseline images, two-node docker compose
  smoke test in **YAML mode** with explicit configs (`testing/smoke/`, keys
  generated at run time, cross-node ping both ways), `validate-nat`, the NAT
  quick subset (4 pairs, core), dpi baseline; non-zero on any failure, no
  interactive step. `make lint` = shellcheck in a container (clean).
  **Proof:** `make check` run 2026-09-16 → exit 0 in ~6 min:
  `smoke: PASS (cross-node ping both ways, YAML mode)`, `validate-nat: all 6
  profiles behave as declared`, 5 quick pairs PASS, `baseline fingerprints
  present: …six…`, `make check: OK`. Note: `make check` re-runs its subset
  into `results/<today>/`, so the committed 2026-09-16 tree carries the full
  matrix plus that re-run (identical outcomes).
- **Found during M9** (core sources untouched; evidence under
  `testing/nat-sim/results/2026-09-16/`):
  - 🟠 **REQ_KEY glare has no tie-break (upstream 1.1pre18 and core).** When
    both nodes start sending to each other in the same instant, both send
    `REQ_KEY`; each side stops its own SPTPS session and becomes a responder,
    so each `ANS_KEY` hits a fresh responder expecting seqno 1 →
    `Invalid packet seqno: 0 != 1`; recovery relies on the "No key from X after
    N seconds, restarting SPTPS" timer, whose N is 30 s in the core (patch 1)
    vs 10 s upstream, and both timers were armed together so the retry can
    collide again. `lab.sh glare` (full-cone × full-cone, both sides ping at
    once): run 1 core 31 s / baseline 12 s to the first key (1 restart each);
    run 2 core 64 s (3 restarts) / baseline 45 s (7 restarts). Repro: any two
    nodes that begin exchanging traffic simultaneously (e.g. all nodes
    reconnecting after a relay restart). Impact: 30–90 s of relay-only traffic
    per glare; the 30 s cooldown triples the cost of each round. Fix
    candidates: name-based tie-break in `req_key_ext_h` (`REQ_KEY` case:
    the lexicographically smaller name ignores the incoming request while its
    own session is pending), and/or jitter on the cooldown. Owner: core.
  - 🟡 **`scripts:` stanza of `docs/config-schema.md` is not implemented** in
    `yamlconf.c` (no `scripts` key is read); in YAML mode `tinc-up` has to be
    a side-file at `<dir>/<netname>/tinc-up`. The smoke test does exactly
    that. Owner: A/C (M2/M6) or schema doc.
  - 🟡 **Linux MASQUERADE is not endpoint-independent on kernels ≥ 6.7**
    (measured: first destination keeps the source port, every later
    destination shares one other port). Any tincstack node behind a current
    Linux router behaves like a symmetric NAT towards the *first* peer it
    talks to; `UDP_INFO` learned via the relay carries the relay-facing port.
    Deployment docs (M6) should say so; the core copes because the peer learns
    the real port from the first authenticated datagram.
  - 🟢 `tinc info <peer>` reports "directly with UDP" from local state and
    keeps saying so after the peer restarted or the node slept, until a packet
    fails — a health check must send traffic (the lab pings).
  - 🟢 upstream's `tinc` CLI links the non-wide `libncurses.so.6`; the lab
    image ships both variants.
- **Acceptance:** one command (`make check`) builds and verifies; the named
  regression shows the delta between the patched core and upstream with logs
  checked in. **Met.**

---

## Execution — work streams (2026-09-16)

Priority order for the whole programme: **M2+M3 (🔴, onboarding) → M4 (🟠,
transport frame) → M5 (🟠, carriers, after M4) → M6/M7/M8 (🟠, platforms, in
parallel) → M9 (🟠 NAT lab, 🟡 rest)**. Independent streams run in parallel in
separate git worktrees and are merged into `master` in this order; each stream
ticks only its own milestone's boxes and lists defects it finds under its own
milestone as "Found during Mk" (consolidated into Known Issues at merge).

| stream | milestone(s) | area (files it owns) | depends on |
|---|---|---|---|
| A | M2, M3 | `invitation.c`, `tincctl.c` (set/add/del), `conf.c`, `yamlconf.*`, `zeroconf.*`, daemon-side invitation handling | M1 (done) |
| B | M4 | new `transport.*`, `net_socket.c`, `net.c`, `net_packet.c`, `meta.c`, option parsing; **not** `invitation.c` (A propagates `Transports` through a generic option list) | M1 |
| C | M6 | `platforms/linux/docker/` | M1; join proof needs A |
| D | M7 | `platforms/windows/` | M1; invite UI needs A's CLI |
| E | M8 | `platforms/android/` | M1 |
| F | M9 | `testing/nat-sim/`, `testing/dpi-proof/` skeleton | core as built |
| G | M5 | carriers, cert automation, decoy, obfs CLI | **B merged** |

## Decisions taken (2026-09-16, owner confirmed)

1. **Probe resistance on the listen port is default-on; the TLS carrier is
   negotiated.** One certificate per node, shared by the HTTPS front and QUIC,
   self-signed at first start and persisted in the YAML, replaceable later.
   (ARCHITECTURE §5, M5.)
2. **`Transports` = accept list (default all); `PreferredTransports` = dial
   preference (default `plain`).** One side's tick is enough. (ARCHITECTURE §4,
   M4.)
3. **Founding node keeps port 655; invitees get `Port = 0`.** (M1 done, M2.)

## Known Issues / carried-over defects

Defects identified during the source audit, to fix as their milestone is reached
(kept here so they are not lost):

- ~~🟠 `Port = 0` on the founding node breaks re-connection after its restart.~~
  **Resolved 2026-09-16** by decision 3: founding node materialises `655`,
  invitees `0` (verified: empty file → listens on 655; `ConnectTo` present →
  ephemeral).
- 🟠 **`tinc invite` phones home to `tinc-vpn.org/host.cgi`** to discover the
  external address when no `Address` is configured (upstream behaviour). For a
  circumvention product this is a network fingerprint and, on a filtered
  network, a connect stall. Found in M1. Fix in M2/M6: make discovery opt-in
  and have the Linux entrypoint set `Address` explicitly.
- 🟡 **Local-address fallback for invitations is only a hint.** M1 added a
  last-resort fallback (default-route source address) so a zero-config node can
  invite without a TTY; behind NAT it yields a private address. It prints a
  warning; M6 must set `Address` from env for real deployments.
- 🟢 **YAML emitter adds a blank line after every literal block** (pre-existing
  cosmetic quirk of `emit_scalar_value`). Parses fine; round-trip is stable.

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
