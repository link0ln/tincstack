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

## Milestone M7 — Windows delivery (point 1a) 🟠 — stream D, 2026-09-16

Adopt `tinc-manager` (PySide6) into `platforms/windows/`, ship the M-series core.
All Python/Qt/mingw work ran in throwaway Docker containers on a Linux host;
nothing below was run on Windows (no Windows host in the lab) — each box says
what that leaves open.

- [x] 🟠 Repoint the GUI at the tincstack core binaries; bundle the mingw-w64
  build of `core/tincd`. **Proof:** `core/Dockerfile.build-win` (Debian 12,
  mingw-w64, `--cross-file .ci/cross/windows/amd64`, `-Dcrypto=gcrypt`,
  miniupnpc/zlib/lzo/lz4/curses/readline disabled, static) exits 0 →
  `tincd.exe`/`tinc.exe`: `file` = `PE32+ executable (console) x86-64, for MS
  Windows`; imports only `ADVAPI32 IPHLPAPI KERNEL32 msvcrt USER32 WS2_32`
  (`wintun.dll` is loaded at runtime); `wine64 tincd.exe --version` in a
  throwaway `debian:12-slim` + wine64 container → `tinc version 1.1pre18 (…
  protocol 17.7) Features: libgcrypt legacy_protocol`, rc=0.
  `platforms/windows/build-core-win.sh` drops them into
  `platforms/windows/resources/` (gitignored); `backend/paths.py` resolves
  `resources/` → `$TINCSTACK_BIN_DIR` → `$PATH` (this also fixes the broken
  Linux path of `cli.py`). "GUI starts a network with a core-built tincd",
  Linux half, same `Runtime`/`TincControl` the GUI uses: in `tincstack/core:dev`
  + python3 (`--cap-add NET_ADMIN --device /dev/net/tun`), `cli.py -c
  /etc/tincstack/tinc.yaml up lab` against a 0-byte file → `up lab: ok —
  started`; daemon log `Materialised defaults into … [lab]: Name=c213f7a5c3ef
  Mode=router Port=655 AddressPool=10.35.0.0/24 … Ready`; `peers lab` → self
  `10.35.0.1`; `invite lab peer1` → `172.17.0.6:655/1e41LZ…` (one line, rc 0);
  `down lab` → stopped; `<yaml dir>/lab/{cache,invitations}` + rotating
  `lab-tincd.log`, no `hosts/` tree. **Not run on Windows:** `tincd.exe` +
  Wintun adapter under the GUI — `tests/selftest_runtime.py` is the manual
  check for a Windows box (its last pre-adoption run is quoted in the file).
- [x] 🟠 **Invite/join UI.** `gui/dialogs.py`: `InviteDialog` runs `tinc -n NET
  -c tinc.yaml invite NAME` on a worker thread, shows the one-line string
  (copy button; QR left out), stderr panel; `JoinDialog` validates the paste,
  runs `tinc [-n NET] -c tinc.yaml join STRING`, shows stdout+stderr, and on
  rc 0 the main window re-reads `tinc.yaml` and selects the new network.
  Coded against the M2 CLI contract (stream A) with the subprocess mocked.
  **Proof:** `tests/test_gui.py::test_invite_dialog_offscreen` (result line,
  stderr surfaced, copy, empty-name refusal, runner thread ≠ Qt thread) and
  `::test_join_dialog_offscreen` (single-token check, duplicate-name refusal,
  CLI error surfaced, success → network read back from the file and selected).
  `cli.py invite|join` expose the same calls headless. **Open until A lands:**
  today's `tinc join` in YAML mode writes a classic tree, so the dialog's
  success path only shows the new network once M2 makes `join` YAML-native.
- [x] 🟠 Surface the new transport options in the config editor —
  **editor half**. `backend/transports.py` (Qt-free schema: `Transports`
  accept list default all, `PreferredTransports` dial preference default
  `[plain]`, `Obfs*`, `HttpsFront*`, `TlsCert`/`TlsKey`, `HttpsDecoy*`,
  `QuicPort`, per `docs/config-schema.md`; validation; `changes()` = only the
  keys the user changed, absent-and-default keys stay absent);
  `gui/transports_panel.py` + a *Transports* tab with a "prefer QUIC" knob
  (decision 2). The generic options table also knows the keys and validates
  them. **Proof:** `tests/test_transports.py` (defaults, 11 validation
  errors, change-set rules) and
  `tests/test_gui.py::test_transports_tab_tick_quic_writes_only_changed_keys`:
  tick QUIC → save → file is byte-for-byte the original plus
  `PreferredTransports: [quic, plain]`; reload → editor shows it; untick →
  `[plain]` written explicitly. `::test_transports_tab_validation_blocks_save`
  (cert without key + empty accept list refused; then only `Transports`,
  `TlsCert`, `TlsKey` written).
- [ ] 🟠 **Peer negotiates QUIC after the tick** — end-to-end proof belongs to
  M4/M5 (the carriers do not exist yet); nothing to run here.
- [x] 🟡 Fix adoption defects — each with its check:
  - **atomic `tinc.yaml` save**: `yaml_config.atomic_write_text` (temp in the
    same dir + fsync + `os.replace` + dir fsync, mode preserved); `save()`
    re-reads the file and applies only the diff against the loaded baseline
    (the daemon is a concurrent writer), refuses to overwrite an unparsable
    file. Before: `open(path, "w")` truncate-in-place of the only key copy.
    **Check:** `tests/test_yaml_config.py::test_atomic_save_never_truncates`
    (rename fails → original byte-identical, no temp left),
    `::test_concurrent_writer_merge` (daemon adds `AddressPool` + a learned
    peer while the GUI edits → exact expected YAML keeps both; a no-op save
    does not rewrite), `::test_save_refuses_to_overwrite_unparsable_file`,
    `::test_atomic_save_keeps_mode`, and `test_gui.py::test_network_tab_save_uses_merge`.
  - **daemon-log rotation while running**: `runtime.LogSink` pumps the
    daemon's stdout pipe into `<net>-tincd.log`, rotating at 2 MB with two
    backups (the GUI owns the handle, so it works on Windows where a file
    held open by the child cannot be renamed). Before: rotate-at-start only
    (13 MB observed). **Check:** `tests/test_runtime.py::test_logsink_rotates_while_writing`
    (35 KB through a 10 KB limit → 3 files ≤ 10 KB, whole lines) and
    `::test_start_stop_with_fake_core` (real `Runtime.start` path with a fake
    `tincd` that logs 30 KB → `.1` exists while the daemon is still running).
  - **malformed-YAML startup**: `yaml_config.load` raises `ConfigError` (parse
    error or wrong shape, with file + line); `MainWindow` opens with an error
    banner (Open raw YAML… / Reload), autostart suppressed. Before: uncaught
    `yaml.YAMLError` in `MainWindow.__init__`. **Check:**
    `tests/test_gui.py::test_window_opens_with_malformed_yaml` (banner text,
    no networks; fixing the file via the raw-YAML save clears it) and 4
    parametrised cases in `test_yaml_config.py::test_malformed_raises_config_error`.
  - **blocking `tinc.exe` calls off the Qt thread**: `gui/workers.py`
    (`WorkerPool` of `QThread`s, tag de-duplication); the peer sampler,
    start/stop/restart, autostart, tray toggle, genkeys, invite and join all
    run there; running state is cached from the sampler instead of a
    subprocess per list refresh. Before: 3 subprocesses per network per 2.5 s
    tick plus every action on the GUI thread. **Check:**
    `test_gui.py::test_sampler_runs_off_qt_thread_and_updates_running_state`
    and `::test_start_stop_do_not_block_qt_thread` (a 0.6 s start returns to
    the event loop in < 0.3 s; worker thread id ≠ Qt thread). Remaining
    synchronous call: `Runtime.stop_all()` on Exit (exit path, deliberate).
  - Also removed: the dead classic-tree modules (`config_store.py`,
    `service_control.py`, the `sc`/`C:\Program Files\tinc` paths in
    `management.py`/`tinc_control.py`), the materialiser references in the
    README, and the three self-tests were rewritten to the current APIs as a
    pytest suite (38 tests; `selftest_runtime.py` kept as the manual Windows
    check).
- [x] 🟡 Two-file deploy story documented: `tincmgr.spec` (PyInstaller onefile,
  `uac_admin`, bundles `tincd.exe`/`tinc.exe`/`wintun.dll` from `resources/`,
  refuses to build without them) + `build-windows.md` with the exact
  commands (core in Docker on Linux, exe on a Windows host). `README.md`
  (platform + root paragraph) rewritten for the adopted layout.
- [ ] 🟡 **Build the actual `tincmgr.exe`** — not runnable here (PyInstaller
  cannot produce a Windows onefile from Linux; needs the Windows box from
  `build-windows.md` §2). Same for `tests/selftest_runtime.py` on real Wintun.
- **Acceptance:** two-file deploy (`tincmgr.exe` + `tinc.yaml`) manages
  networks, invites peers, and selects transports — **met at the code/test
  level** (38 headless tests, 30 backend + 8 offscreen GUI, all passing in
  `python:3.12-slim` + PySide6 6.7.3); the on-Windows run is the open box above.

**Test/proof commands (all Docker, nothing on the host):**
`docker build -f core/Dockerfile.build-win -t tincstack/core-win:dev core/`;
`docker run --rm -v "$PWD/platforms/windows/resources:/out" tincstack/core-win:dev`;
`docker run --rm -v "$PWD/platforms/windows:/w" -w /w <python:3.12-slim + libgl1
libegl1 … + pip PySide6-Essentials==6.7.3 pyqtgraph pyyaml pytest> env
QT_QPA_PLATFORM=offscreen python -m pytest -q tests` → `38 passed`.

**Found during M7:**
- 🟡 **Original `Runtime.start` refused to start a network without keys**
  ("generate keys first") and `＋ Add network` seeded `Port: 0` for a founding
  node — both contradict M1 zero-config / decision 3. Fixed: a new network is
  an empty stanza and the daemon materialises everything on first Start.
- 🟡 **`tinc invite` phone-home re-confirmed** from the Windows backend path
  (`Trying to discover externally visible hostname...` in the CLI proof; then
  the M1 local-address fallback). Same defect as in Known Issues; the GUI
  surfaces the warning in the Invite dialog's stderr panel. Fix stays in M2/M6.
- 🟢 **Core cross-build warnings**: `src/tincctl.c:2931-2932` `cmd_verify`
  `-Wuse-after-free` (pointer used after `xrealloc`) — upstream code, builds
  fine with mingw-w64 GCC 12; not touched by stream D (core is not in D's area).
- 🟢 **`wintun_mtu` is a GUI-only per-network YAML key** (not in
  `docs/config-schema.md`). The daemon's writer is a generic tree
  (`yamlconf.c`), so it survives daemon write-back (verified by reading the
  emitter); schema doc could list it. Left as is.
- 🟢 **`Compression`/curses/readline are compiled out of the Windows core**
  (no mingw packages, offline build). `tinc top` and `Compression > 0` are
  unavailable on Windows until the wraps are vendored.

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
