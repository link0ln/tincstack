# PLAN.md — tincstack

**Last Updated:** 2026-09-16

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

- [~] 🟠 `platforms/linux/docker/`: `docker-compose.yml` + auto-init entrypoint
  that relies on M1 (daemon self-configures) rather than templating config in
  shell. Env for the few deploy-time choices (netname, connect target, public
  address). **Proof:** `docker compose up` on a clean checkout brings up a node
  with a generated `tinc.yaml`; a second compose joins by invite.
  **(a) done 2026-09-16:** `docker compose -p wsc-single up -d --build` from the
  clean tree (compose builds `core/Dockerfile.build` as a build-only service
  and feeds it to the node image as the named context `core`) → log
  `Materialised defaults into '/etc/tincstack/tinc.yaml' [tincstack]:
  Name=2e17e9ec1961 Mode=router Port=655 AddressPool=10.87.0.0/24
  Subnet=10.87.0.1/32 ed25519_priv Ed25519PublicKey rsa_priv RSA-public` →
  `tinc-up: tincstack 10.87.0.1/24` → `Ready`; `ip -br addr` in the container:
  `tincstack UNKNOWN 10.87.0.1/24`; `tinc.yaml` mode 0600 inside the named
  volume `wsc-single_data`; `docker compose restart` → no second
  `Materialised` line (idempotent). Env mapping verified in the lab run below:
  `NODE_NAME=node_a` → `options.Name` (the materialise line then lists no
  `Name=`/`Port=`, the daemon kept the pre-set values), `PORT=655`,
  `PUBLIC_ADDRESS=wsc-a-node-1` → entrypoint log `hosts.node_a Address =
  wsc-a-node-1` and the invitation `wsc-a-node-1:655/<cookie>` with **no**
  `Trying to discover externally visible hostname` line (no phone-home, no
  guess). Nothing is templated: values go through `tincstack-yaml`, a
  stdlib-python helper in the image that edits only the requested key
  (temporary bridge until `tinc set` is YAML-aware — M2, stream A); `tinc-up`
  is a marked-removable stopgap until the core addresses the interface.
  **(b) blocked on stream A** (`two-nodes.sh`, run 2026-09-16, exit 1): the
  invitation is issued and accepted, then the join fails on both sides —
  invitee: `Connected to wsc-a-node-1 port 655... Configuration stored in:
  /etc/tincstack/tincstack` (a classic `tinc.conf`/`hosts/`/`*.priv` tree, no
  `tinc.yaml`) → `Timed out waiting for the server to reply. Invitation
  cancelled.`; inviter daemon: `Invitation … successfully sent to node_b` →
  `ERROR Error trying to create /etc/tincstack/tincstack/hosts/node_b: No such
  file or directory` → `Closing connection with node_b`. Re-run when A lands:
  `cd platforms/linux/docker && ./two-nodes.sh` (one command, cleans up).
- [~] 🟠 Invite/join helper scripts (`docker compose exec … tinc invite`).
  **Proof:** two-host (or two-project) bring-up reachable end to end.
  `invite.sh <name>` (`docker compose exec -T node tincstack-cli invite`) and
  `join.sh <invitation>` (`INVITE=… docker compose up -d`; the entrypoint joins
  on the first start only and cleans the classic-tree leftovers of a failed
  attempt so a retry is clean) exist, are shellcheck-clean and were exercised
  by `two-nodes.sh`: `invite.sh` returned `wsc-a-node-1:655/<cookie>`, `join.sh`'s
  path ran `tinc join` against it. End-to-end reachability **blocked on stream
  A** (same observation as above); the ping step of `two-nodes.sh` is in place
  and has not run.
- [x] 🟡 No secrets in the tree; keys generated at first run into a named volume.
  **Proof:** `git status` clean of key material; `.gitignore` covers runtime data.
  Run 2026-09-16: after the single-node bring-up and the two-project lab,
  `git status --porcelain` listed only the new `platforms/` sources; keys exist
  only inside `tinc.yaml` (0600) in the project-scoped volumes
  (`wsc-single_data`, `wsc-a_data`, `wsc-b_data`, all removed by `down -v`).
  Root `.gitignore` already covered `tinc.yaml`, `*.priv`, `invitations/`;
  appended `platforms/linux/docker/.env` and `platforms/linux/docker/data/`.
- **Acceptance:** a Linux user gets a working node from `docker compose up` and
  onboards peers with one invite string. **Half met:** the node, yes; the
  onboarding waits for M2.
- **Found during M6** (2026-09-16):
  - 🔴 **Daemon-side invitation acceptance is not YAML-aware** (for stream A,
    M2 box 1/3). Reproduction: zero-config node, `tinc invite node_b`, a second
    node runs `tinc -c tinc.yaml join <invitation>`. Inviter log: `Invitation …
    successfully sent` then `ERROR Error trying to create
    /etc/tincstack/tincstack/hosts/node_b: No such file or directory` and the
    connection is closed; the invitee waits and gives up (`Timed out waiting for
    the server to reply`). Impact: **every** join against a YAML-mode node fails,
    and the invitation is consumed by the failed attempt (a retry logs `tried to
    use non-existing invitation`), so the user must re-invite. Blocks M6 (b).
  - 🟠 **`tinc set/get` in YAML mode open `<rundir>/tinc.conf`** (`Could not
    open configuration file /etc/tincstack/tincstack/tinc.conf`, rc=1) — already
    an M2 box; noted here as the reason the image carries `tincstack-yaml`.
  - 🟡 **The core never addresses the tun interface on Linux** in YAML mode:
    without a `tinc-up` the interface stays `DOWN` with no address, and `tinc
    join` writes its own `tinc-up` into the run dir (overwritten by the
    entrypoint's). The compose ships a stopgap `tinc-up`; the M2 note "stream A
    adds a built-in default" is what removes it.
  - 🟢 `makedirs()` re-chmods the run dir to 0755 on every CLI call, so a 0700
    run dir cannot be kept; harmless (secrets are in `tinc.yaml` 0600 and
    `invitations/` 0700), noted so nobody "fixes" it from the entrypoint.
  - 🟢 `tinc invite` sends `reload` to the daemon (log `Got 'reload' command`
    on every invitation); the daemon does not re-read the YAML on reload
    (`yamlconf_load` is called once, in `names.c`), so a post-start file edit is
    invisible to the daemon until restart. Fine for `Address` (CLI-only field);
    matters for M2's runtime-reconfiguration box.

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

## Milestone M9 — verification harness 🟡

- [ ] 🟠 `testing/nat-sim/`: port the netmaker NAT lab to tinc — Docker gateway
  containers with `iptables` DNAT/SNAT for cone / restricted-cone, **plus** the
  missing symmetric-NAT and two-tier-CGNAT variants and **TCP-meta handling**,
  with pass/fail exit codes. **Proof:** the burst/rebind NAT features are shown to
  punch through restricted-cone where a baseline build does not.
- [ ] 🟠 **The laptop scenario is a named regression test** (brief point 4 says
  "resolved", not "vendored"): node behind two-tier CGNAT, direct UDP up, then
  (a) peer restarts, (b) the node's clock jumps ≥ 30 s (sleep/resume path that
  triggers `rebind_udp_sockets`), (c) its NAT mapping is dropped by the lab.
  Pass = direct UDP re-established within 60 s with no process restart and no
  `Invalid packet seqno` livelock in the log. Run against the core and against
  upstream tinc 1.1 to show the delta. **Proof:** the lab's exit code + both
  logs checked in under `testing/nat-sim/results/`.
- [ ] 🟡 `testing/dpi-proof/`: tcpdump-based check (netns+veth skeleton from
  `awg-proof.sh`) that each obfuscation tier changes the wire image away from the
  SPTPS fingerprint. **Proof:** captured before/after byte patterns.
- [ ] 🟢 Wire the core build + a smoke `docker compose` ping test into a single
  `make check` (or script). **Proof:** one command builds core and asserts a
  cross-node ping.

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
