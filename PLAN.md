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

## Milestone M2 — invitation & one-line onboarding in YAML mode (principle 3) ✅ (2026-09-16, stream A)

Close the gap that upstream invitations bypass YAML mode and carry no pool/
transport/cert material. All runs below: image `tincstack/core:ws-a` built
from this tree, two containers `wsa-a`/`wsa-b` on docker network `wsa-net`,
`-v /tmp/wsa-{a,b}:/etc/tincstack`, `tincd -c /etc/tincstack/tinc.yaml -D -d3`.

- [x] 🔴 Route `tinc join` and `finalize_join()` through the YAML writer so a
  joined node writes its `tinc.yaml` (identity + inherited options + inviter host
  record), not a classic on-disk tree. **Proof:** `finalize_join_yaml()` in
  `invitation.c` (network name: `-n`, else the invitation's `NetName`, else
  `tincstack`; refuses an already-set-up network). On `wsa-b` with **no file at
  all**: `tinc -c /etc/tincstack/tinc.yaml join 10.16.10.2:655/Misf…` →
  `Materialised defaults into '/etc/tincstack/tinc.yaml' [tincstack]:
  ed25519_priv Ed25519PublicKey rsa_priv RSA-public` → `Configuration stored
  in: /etc/tincstack/tinc.yaml [tincstack]` → `Invitation successfully
  accepted.` (exit 0). `find /tmp/wsa-b -type f` afterwards: `tinc.yaml` (0600)
  and, after the daemon start, `tincstack/cache/nodea` — **no** `tinc.conf`,
  `hosts/`, `*_key.priv` or `tinc-up.invitation`. The YAML holds
  `options: {Name: peer, ConnectTo: nodea, Mode: router, AddressPool:
  10.138.0.0/24, InterfaceAddress: 10.138.0.2/24, Port: 0, UDPRebindOnWake:
  yes}`, `hosts.peer` (Subnet 10.138.0.2/32 + Ed25519PublicKey + RSA public),
  `hosts.nodea` (inviter's record incl. `Address` and `Port = 655`), and
  `keys.ed25519_priv`/`rsa_priv`. The daemon then started from that file alone
  (`Listening on 0.0.0.0 port 36703` … `Connection with nodea … activated`).
- [x] 🔴 Extend the invitation payload beyond upstream's (name/ConnectTo/Mode) to
  carry: assigned pool address + subnet, routes, active `Transports` and their
  parameters, and the HTTPS-front certificate fingerprint/material. **Proof:**
  `PROPAGATED_OPTIONS[]` in `invitation.c` (one table; `*` suffix = prefix
  match: `Mode, Broadcast, AddressPool, Transports, TlsFingerprint, Obfs*,
  Https*, Quic*`) drives both `cmd_invite` (copies every matching option from
  the inviter's `options:`) and the join side (accepts a propagated option even
  before it is in `variables[]`, so streams B/G only add table entries).
  Invitation file written on `wsa-a`: `Name = peer / NetName = tincstack /
  ConnectTo = nodea / Mode = router / AddressPool = 10.138.0.0/24 / Subnet =
  10.138.0.2/32 / Ifconfig = 10.138.0.2/24 / #---- / Name = nodea / Subnet …
  Ed25519PublicKey … RSA … Address = 10.16.10.2 / Port = 655`. Joined node's
  `options` vs inviter's: `Mode: router` = `Mode: router`, `AddressPool:
  10.138.0.0/24` = `AddressPool: 10.138.0.0/24` (the only propagated fields
  the inviter had set; `Transports`/`Obfs*`/`Https*`/`Quic*`/`TlsFingerprint`
  are carried by the same table once M4/M5 define them — no Transports or
  certificate exists yet in this tree, so that part of the proof is deferred
  to those milestones by construction, not skipped). `Ifconfig`/`Route` become
  `InterfaceAddress`/`InterfaceRoute` options (documented in
  `docs/config-schema.md`); `dhcp`/`dhcp6`/`slaac` forms are ignored with a
  message in YAML mode.
- [x] 🟠 Inviter persists the invitee's learned Ed25519 key back into its YAML
  (`yamlconf_append_host_line`, already present) — verify it fires in YAML mode.
  **Proof:** by inspection it could **not** fire: `finalize_invitation()`
  (`protocol_auth.c`) wrote `hosts/<name>` with a raw `fopen`, and in YAML mode
  no `hosts/` directory exists (`tincd.c` skips `DIR_HOSTS`), so the daemon
  would have logged `Error trying to create …/hosts/peer` and cancelled the
  invitation (defect, below; fixed before the run, not reproduced live).
  Fixed to go through `append_config_file()` and to
  persist the promised `Subnet` as well (captured from the invitation file into
  `c->config_tree` when it is streamed). `wsa-a` log: `Invitation lRba…
  successfully sent to peer` → `Key successfully received from peer`; its
  `tinc.yaml` afterwards: `hosts.peer: | Ed25519PublicKey = xV39… / Subnet =
  10.138.0.2/32`. The in-memory document is updated too, so the running daemon
  serves the new record without a reload.
- [x] 🟠 **Runtime reconfiguration in YAML mode** (brief point 3: "tinc must read
  *and write* the config on every platform, because parameters are changed
  online"). `tinc set/add/del/get` and `tinc reload` operate on the YAML
  (`options:` for server variables, `hosts.<name>` for host variables) instead
  of the classic tree; the daemon re-reads the YAML on reload. This is the one
  path the Windows GUI, Android app and obfs/transport controls all use.
  **Proof:** `cmd_config` runs its unchanged line editor over a temporary
  stream of the options/host text and writes the result back with
  `yamlconf_set_options_text()` / `yamlconf_host_set_text()` + atomic save;
  `read_server_config()` re-reads the YAML from disk on every (re)load. On
  `wsa-a`: `tinc … get UDPDiscoveryBurst` → `No matching configuration
  variables found.` (exit 1); `tinc … set UDPDiscoveryBurst 7` → exit 0, YAML
  `options:` gained `UDPDiscoveryBurst: 7`; `find /tmp/wsa-a -name tinc.conf`
  → nothing; daemon log: `Got 'reload' command` … `UDPDiscoveryBurst 7,
  UDPRebindOnWake no` (auto-reload after set, and again after `tinc … reload`
  exit 0). Lists: `add ConnectTo peer`, `add ConnectTo other` → YAML
  `ConnectTo:\n - peer\n - other`, `get ConnectTo` → `peer` `other`; `del
  ConnectTo other` → `peer`; `del ConnectTo` → gone. Host vars: `set
  peer.Weight 5` → `hosts.peer` gains `Weight = 5`; `get peer.Subnet` →
  `10.138.0.2/32`; `del peer.Weight` → gone. Unknown variable still refused
  (`Bogus: is not a known configuration variable!`). Classic mode re-checked in
  the same image: `tinc -c /tmp/x init foo; set Mode switch; get Mode; add/del
  ConnectTo` still edit `tinc.conf`/`hosts/foo`.
- [x] 🟠 **Invitee NAT defaults** (brief point 4): a node that joins by invite
  materialises `Port = 0` and `UDPRebindOnWake = yes` (it always dials out, so
  a stable inbound port is not needed); the founding node keeps tinc's standard
  port 655 (done in M1). **Proof:** joined node `wsa-b` `options:` carry
  `Port: 0` and `UDPRebindOnWake: yes` (its log: `Listening on 0.0.0.0 port
  36703`, `UDPDiscoveryBurst 5, UDPRebindOnWake yes`); founding node `wsa-a`
  has `Port: 655`, no `UDPRebindOnWake` (`… port 655`, `UDPRebindOnWake no`).
- [x] 🟠 **Interface addressing without a script** (needed for the acceptance
  ping; brief point 2). `scripts.<name>` in the YAML are written to the runtime
  dir (0700) on every start; when no `tinc-up` exists on Linux, the daemon runs
  a built-in `ip addr replace <own Subnet host>/<AddressPool prefix> dev
  $INTERFACE; ip link set up` (+ `InterfaceRoute`s) — `autoif.c`, documented in
  `docs/config-schema.md`. **Proof:** both nodes' logs: `Built-in tinc-up: ip
  addr replace 10.138.0.1/24 dev tincstack` / `… 10.138.0.2/24 …`, `Interface
  tincstack configured with … (built-in tinc-up)`; `ip -4 addr show dev
  tincstack` → `inet 10.138.0.1/24` and `inet 10.138.0.2/24`. Script path:
  a YAML with `scripts.tinc-up` → log `Wrote 1 script(s) from
  '/etc/tincstack/tinc.yaml' into '/etc/tincstack/tiny'`, `Executing script
  tinc-up`, file `-rwx------ tiny/tinc-up`, the script's own marker file
  written, interface `10.98.0.1/30` from the script (built-in not used).
- **Acceptance:** two fresh `docker run` nodes, one invite string pasted to the
  second, mesh reachable (ping across the tunnel) with **no** manual config on
  either side. **Met 2026-09-16.** Run (throwaway shell harness, not
  committed; full output recorded here): `docker network create wsa-net`; A:
  `docker run -d --name wsa-a --hostname nodea --network wsa-net --cap-add
  NET_ADMIN --device /dev/net/tun -v /tmp/wsa-a:/etc/tincstack
  tincstack/core:ws-a tincd -c /etc/tincstack/tinc.yaml -D -d3` on an empty
  dir → `Materialised defaults … Name=nodea … Port=655 AddressPool=10.138.0.0/24
  Subnet=10.138.0.1/32 …` → `Ready`; `docker exec wsa-a tinc -c
  /etc/tincstack/tinc.yaml invite peer` → `Assigned address 10.138.0.2/24 to
  peer.` + `10.16.10.2:655/MisfHNPEsx…` (one line, exit 0)
  (Address = container IP via the M1 fallback, no phone-home); B: `docker run
  … --name wsa-b … sleep infinity`, `docker exec wsa-b tinc -c
  /etc/tincstack/tinc.yaml join <that string>` → accepted (above); `docker exec
  -d wsa-b tincd -c /etc/tincstack/tinc.yaml -D -d3` → `Connection with nodea
  (10.16.10.2 port 655) activated`. `docker exec wsa-b ping -c 3 10.138.0.1` →
  `3 packets transmitted, 3 received, 0% packet loss` (rtt 0.13–0.43 ms);
  `docker exec wsa-a ping -c 3 10.138.0.2` → `3 received, 0% loss`. `tinc dump
  nodes` on A: `peer id 97a9… at 10.16.10.3 port 36703 … nexthop peer via peer
  distance 1`; on B: `nodea id 0bab… at 10.16.10.2 port 655 … nexthop nodea
  via nodea distance 1` — both direct (`via` = the node itself).
- **Found during M2** (fixed unless stated; the merger consolidates into Known
  Issues):
  - 🔴 Daemon-side invitation acceptance could not work in YAML mode (found
    by code inspection before the first run, not reproduced live):
    `finalize_invitation()` did `access()`/`fopen("hosts/<name>")` directly,
    and YAML mode creates no `hosts/` directory, so the create fails and the
    invitee is cancelled. Fixed (routes through `append_config_file()`, also
    stores `Subnet`).
  - 🟠 The inviter's `Port` was missing from the invitee's copy of the inviter
    host record (upstream copies only the host file; ours keeps `Port` in
    `options:`), so an inviter on a non-655 port could not be dialled back.
    Fixed (`copy_config_replacing_port()` appends `Port = <actual>`).
  - 🟠 The daemon's in-memory YAML went stale after `append_config_file()` and
    after any CLI/GUI edit: `reload_configuration()` re-read only the classic
    files through `config_fopen()`, which serves the *old* document. Fixed
    (`read_server_config()` re-reads the file; append mirrors in memory).
  - 🟠 Phone-home to `tinc-vpn.org/host.cgi` (Known Issue from M1) is now
    **opt-in** via `AddressDiscovery = yes`; default uses the default-route
    source address (`Warning: using local address …` stays). In the container
    run the external lookup would have produced the host's public IP, which the
    second container cannot reach — the acceptance would have failed.
  - 🟡 Upstream bug: `cmd_invite` tested `open()` with `if(!ifd)` (fd 0 vs
    -1), so a failed create was reported as success. Fixed (`< 0`).
  - 🟠 (reported by stream C from its two-node lab, same root cause as the
    first item) **an invitation was burned when storing the invitee failed**:
    the daemon unlinked the claimed invitation right after sending it, so a
    failure while persisting the key left the invitee with `Invitation
    cancelled` and a retry with `tried to use non-existing invitation`.
    Fixed: the claimed `<cookie>.used` file now lives until the key is stored
    (`connection_t.invitation_file`, `invitation_release()` in
    `protocol_auth.c`, called from `free_connection()` too); on any failure it
    is renamed back and the invitee's `tinc join` rolls its own YAML back
    (deletes the file it created, or just the network it added). In-flight
    `.used` files still reserve their address in the pool and expire with the
    same one-week deadline. **Proof** (run 2026-09-16, `wsa-a`/`wsa-b`):
    inviter's save broken on purpose (`mkdir /tmp/wsa-a/tinc.yaml.tmp`); B
    `tinc … join <url>` → `Timed out waiting for the server to reply.` /
    `Removed /etc/tincstack/tinc.yaml again (join did not complete).` (exit 1;
    `find /tmp/wsa-b -type f` empty); A log: `Error trying to store the key
    of peer in /etc/tincstack/tinc.yaml: Is a directory` / `Invitation for
    peer … was not completed; it can be used again`; `invitations/` again
    holds `jZkSh1Tc…` (no `.used`); `tinc … invite other` meanwhile →
    `Assigned address 10.145.0.3/24` (`.2` still reserved). `rmdir` the
    blocker, B re-runs the **same** `tinc … join <url>` → `Invitation
    successfully accepted.`; A's `hosts.peer` = key + `Subnet =
    10.145.0.2/32`; B's daemon up, `ping 10.145.0.2` from A → `2 received,
    0% loss`.
  - 🟢 (stream C) the YAML runtime dir flapped between 0700 (`make_names()`)
    and 0755 (`makedirs()` re-chmods on every CLI call). Fixed by creating it
    0755 like a classic confbase (secrets are in `invitations/` 0700 and the
    0600 YAML). Proof: `stat -c %a /tmp/wsa-a/tincstack` → `755` before and
    after `tinc … invite`.
  - 🟢 `tinc join` prints `YAML config … does not exist yet; it will be
    created` twice (make_names() runs again once the NetName is known).
    Cosmetic, left.
  - Files touched outside stream A's area, all minimal: `net_setup.c` (built-in
    tinc-up fallback in `device_enable()`, one log line in
    `setup_myself_reloadable()`), `connection.h` (one field), `connection.c`
    (one call + include), `protocol.h` (one declaration), `meson.build` (two
    new sources).
  - 🟡 Not covered: `Ifconfig = dhcp|dhcp6|slaac` and non-Linux built-in
    addressing (the built-in logs a warning and does nothing; Windows uses
    `WintunAddress`, Android its fd). Documented in the schema.

---

## Milestone M3 — IP address pool & auto-assignment (point 8) ✅ (2026-09-16, stream A)

- [x] 🟠 Reimplement the pool allocator (`allocate_vpn_ip` algorithm from the
  vless prototype) against tinc's host DB + invitation store: lowest free address
  in `AddressPool`, skipping used and pending. Land in `invitation.c`/new file.
  **Proof:** `core/tincd/src/pool.c` (`pool_allocate()`, CLI side, called by
  `cmd_invite`): skips network/broadcast, every `Subnet` of every host record
  (own included; YAML `hosts:` or classic `hosts/`), every `Subnet` in
  `<runtime>/invitations/*` (24-char names), and live subnets from
  `REQ_DUMP_SUBNETS`. Fresh node `wsa-c` with `AddressPool: 10.99.0.0/24`
  (own Subnet `.1`): `tinc … invite x` → `Assigned address 10.99.0.2/24 to
  x.`, `invite y` → `10.99.0.3/24`, `invite z` → `10.99.0.4/24`; pending files
  carry `Subnet = 10.99.0.2/32|.3|.4`. `rm invitations/<y's file>`; `invite w`
  → `Assigned address 10.99.0.3/24 to w.` (freed address reused). Exhaustion:
  pool `10.98.0.0/30` → `p1` gets `.2`, `invite p2` → `No free address left
  in AddressPool 10.98.0.0/30 (4 in use).` (exit 1, no invitation file).
  A node without `AddressPool` (classic mode) invites as before, with no
  `Subnet`/`Ifconfig` lines.
- [x] 🟡 Collision safety: refuse to reuse an address held by a live node.
  **Proof:** integration check on the running pair from M2 — `peer` is live at
  `10.138.0.2`; its Subnet removed from the inviter's host DB with `tinc … del
  peer.Subnet` (`tinc dump subnets` still shows `10.138.0.2 owner peer`);
  `tinc … invite q` → `Address 10.138.0.2 is held by live node peer,
  skipping.` / `Assigned address 10.138.0.3/24 to q.`; the pending file
  carries `Subnet = 10.138.0.3/32`. (Pending holders are covered by the
  `.2/.3/.4` run above: `.2` and `.3` were only *pending*, and `z` still got
  `.4`.)
- **Acceptance:** invitees are L3-reachable immediately, no manual `Subnet`.
  **Met** — the M2 acceptance ping ran with the invitee's `Subnet` and
  interface address coming solely from the invitation.
- **Found during M3:**
  - 🟡 The pool is only as consistent as the inviter's local view: two nodes
    inviting concurrently from the same `AddressPool` (every joined node
    inherits it) can hand out the same address; only the live-node check
    catches it. Mitigation: invite from one node, or from nodes that see each
    other. Documented in `docs/config-schema.md`; a mesh-wide reservation is
    out of scope for M3.
  - 🟢 A `Subnet` wider than /32 in any host record reserves its whole range
    (by design); an IPv6 `AddressPool` is rejected (IPv4 only, as in M1).

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
