# PLAN.md — tincstack

**Last Updated:** 2026-09-16 (M9 closed by stream F; Port classification fixed in the consolidation pass; REQ_KEY glare fixed by stream K)

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

- [x] 🟠 `Transports` (accept list, default = all compiled carriers) and
  `PreferredTransports` (dial preference, default `[plain]`): parse both;
  advertise `Transports` in the host record; propagate through invitations.
  **Proof:** implemented in `core/tincd/src/transport.{h,c}` (registry + names +
  hooks), `transport_table.c` (pure names/parse/classifier). Parsed in
  `setup_myself_reloadable()` via `transport_read_config()`; registered in
  `tincctl.c variables[]` (`Transports`, `PreferredTransports`, `SingleFlow`).
  Advertised two ways: `zeroconf.c` writes `Transports = plain, sf` into the
  node's own YAML host record (minimal hook, reported below), AND the accept
  list rides a trailing token on the ACK (`protocol_auth.c send_ack`/`ack_h`),
  so a peer learns it without host records and an upstream peer that sends
  nothing is treated as `plain`. Run 2026-09-16, two docker nodes: `tinc info
  nodea` on the peer → `Transports:   plain,sf`; `tinc dump nodes` → each node
  line ends `transports plain,sf`. (`n->transports==0` prints `plain`.)
- [x] 🟠 Outbound carrier selection: walk own preference list, dial the first
  carrier in the peer's accept list; fall back down the list to `plain` on
  handshake failure. Selection is per connection, re-evaluated on reconnect
  (`transport_current`/`transport_next_candidate` in `transport.c`, driven from
  `do_outgoing_connection` in `net_socket.c` for immediate dial failure and from
  `terminate_connection` in `net.c` for handshake-phase failure; reset on ACK).
  **Proof:** `testing/transports/matrix-test.sh` (two docker nodes, needs
  `-Dtransport_test=true` which compiles the `test` stub carrier whose dial
  always fails). Run 2026-09-16: node B log →
  `via test` → `test carrier: simulated dial failure` →
  `Carrier test failed for nodea, falling back to plain` → `via plain` →
  `Connection with nodea … activated`. `PASS`.
- [x] 🟠 Inbound front dispatcher: one listen port classifies a new connection by
  its first bytes and routes to the right handler (plain / obfs / TLS / QUIC).
  `transport_classify_tcp`/`transport_classify_udp` in `transport_table.c`;
  dispatch in `transport_front_dispatch` (TCP, `net_socket.c handle_meta_io`
  peek path) and `transport_udp_dispatch` (UDP, `net_packet.c
  handle_incoming_vpn_packet`). HTTP probers get a minimal decoy `200 OK` (M5
  fills the real decoy); a client that sends nothing is reaped by the auth
  timeout. Decision table in `docs/transports.md` §3. **Proof:**
  `testing/transports/classify-test.sh` (compiles the classifier standalone in a
  container, feeds each byte pattern). Run 2026-09-16: `26 checks, 0 failures`.
- [x] 🟠 **Single-flow mode: meta channel over the data carrier** (brief point 5,
  independent of the HTTPS front). `SingleFlow = yes|no` (default **no** —
  documented in `docs/transports.md` §2: it trades tinc's independently-recovering
  TCP meta channel for one UDP flow, so it is opt-in until it has field mileage;
  `yes` = dial `sf` first). Carrier in `transport_sf.c`: an ordered, reliable
  byte stream (go-back-N, cumulative ACK, RTO, fast retransmit) over the UDP data
  socket carrying the SPTPS meta records; SPTPS itself is unchanged. Cold-start
  identification: the first datagram is a `DATA|SYN, seq 0` frame with a fixed
  6-byte magic in the destination-node-id position, so the receiver classifies it
  with no prior state (the mistake `tinc-obfs` made — fixed here). TCP `plain`
  stays as the negotiated fallback when UDP is blocked. Relay datagrams keep the
  existing SPTPS relay format and are classified as `SPTPS`, so relaying is
  prefix-aware and uncorrupted. **Proof:** `testing/transports/singleflow-test.sh`.
  Run 2026-09-16, two `SingleFlow=yes` nodes: cold ping `3/3 received`; tcpdump
  (throwaway `nicolaka/netshoot` sharing the node netns) on the tinc port →
  `TCP segments=0  UDP datagrams=13`. Three-node A–R–B with A↔B direct severed by
  an `iptables` DROP → relayed ping `4/4 received` (relay path intact). `PASS`.
- **Acceptance:** met. With only `plain`/`sf` behind it, the scaffold selects and
  dispatches correctly; adding a carrier is one `transports[]` row plus its hooks
  (contract in `docs/transports.md` §5). With all defaults, behaviour is plain
  tinc (accept `plain,sf`, dial `plain`; ID/ACK wire-compatible with upstream).

### Found during M4

- 🟢 The relayed SPTPS key exchange (A–R–B, no direct path) can take ~20 s to
  establish on a cold start because of the 30 s SPTPS reset cooldown and the
  UDP-discovery retry cadence; not a regression (pre-existing timing), but the
  single-flow relay test retries for it. Blast radius: first-packet latency on a
  freshly relayed pair; steady state unaffected.
- 🟢 Files touched outside the stream-B area, all minimal and reported here:
  `connection.h`/`node.h` (added `transport`/`transport_data` and `transports`
  fields + a `front_pending` status bit), `node.c` (append transports to the node
  dump), `info.c` (print `Transports:`), `zeroconf.c` (the one host-record
  advertisement hook), `meson_options.txt` (the `transport_test` option). No
  changes to `invitation.c`, `yamlconf.*`, or `sptps.c`.

---

## Milestone M5 — circumvention transports (point 6, then 5, then 7) 🟠

Each carrier wraps SPTPS; **SPTPS is never bypassed** (principle 1). Land them in
this order (cheapest / most-contained first). Full wire formats go in
`docs/transports.md` as each is built.

- [x] 🟠 **Obfuscated UDP** (redesign of tinc-obfs). Authenticated junk/real
  discriminator (keyed, not a cleartext flag); junk around the handshake, not
  per-packet; cold-start-safe receiver classification; relay-prefix-aware.
  Config surface per schema. **Done (G2, 2026-09-16):** new `obfs.c`/`obfs.h`
  carrier built on the single-flow engine; every UDP datagram of the link (SF
  meta frames + SPTPS data datagrams) sealed as `nonce(8)|clen(2)|ChaCha20-
  Poly1305(inner)|tail-junk`, keyed from `SHA-512("tincstack-obfs-v1\0" ||
  sorted Ed25519 public keys)`. The Poly1305 tag *is* the discriminator (no
  cleartext flag; junk and forgeries fail it). Junk (`ObfsJunkPacketCount`,
  `Min/MaxSize`) emitted only at dial/accept. Cold-start classification is the
  keyed check in `transport_udp_dispatch` (fast path by source address; rate-
  limited node-key scan otherwise), re-injecting the inner without re-dispatch.
  Relay: `obfs_wrap_send` re-seals per hop and the receiver strips before the
  relay logic, so no double-prefix. `obfs` registered compiled in
  `transport_table.c` (default accept list). SPTPS untouched. Registered UDP
  classifier ranges unchanged (obfs is keyed, not pattern-matched); docs updated
  (`docs/transports.md` §5, `docs/config-schema.md`).
  **Proof** (`testing/transports/obfs-test.sh`, image `ws-g2`, run 2026-09-16):
  - cold two-node obfs tunnel up **both ways** (A→B and B→A `0% packet loss`
    from cold, dialer `PreferredTransports: [obfs, plain]`);
  - **fingerprint gone**: the single-flow magic `9f747366` appears `1×` on the
    wire in a `SingleFlow`(sf) reference capture but `0×` under obfs (sealed);
    the SPTPS relay/direct datagram structure (leading `dst|src` ids, SF magic)
    is inside the ciphertext, so the leading bytes are the random nonce;
  - **junk around the handshake only**: `16` junk datagrams (distinctive
    600–650 B window, `ObfsJunkPacketCount 8` × both directions) during the cold
    handshake, `0` during a 30-packet steady ping flood;
  - **relay A–R–B intact** with A↔B direct DROP'd: `4/4 received` through R,
    each hop sealed with its own key (no double-prefix corruption);
  - **defaults byte-identical**: obfs compiled but not selected +
    `ObfsJunkPacketCount 0` → tunnel up, `0×` SF magic, plain SPTPS UDP on the
    wire; `classify-test.sh` (26/0) and `singleflow-test.sh` still pass on ws-g2.
  - *(the stream-F `testing/dpi-proof` harness is not on master yet, so the
    before/after tcpdump comparison is done in obfs-test.sh instead, as the brief
    allows.)*
- [x] 🟠 **Certificate automation, shared by HTTPS front and QUIC** (decision 1).
  `TlsCert`/`TlsKey` if set; else generate a self-signed cert at first start
  and persist it in the YAML (`keys.tls_cert`/`keys.tls_key`), reused on every
  restart, replaceable by editing the two keys. Its fingerprint travels in the
  invitation (M2). Done in `core/tincd/src/tls.{c,h}` (P-256 self-signed X.509v3,
  generic `localhost` subject so a scanner cannot tie the port to a node,
  10-year validity, SAN present); generated + persisted in `zeroconf.c`
  (`keys.tls_cert/tls_key`, classic mode: `tls_cert.pem/tls_key.pem`); loaded
  and contexts built in `tls_init()` (run from the https carrier's init, rebuilt
  on reload only if the material changed). Fingerprint exposed in `tinc
  info`/dump (`node.c`/`info.c`, back-compatible trailing token) and written as
  `TlsFingerprint` into the node's own host record for M2 propagation.
  **Proof:** `testing/transports/tls-front-test.sh` (2026-09-16, image ws-g1):
  first start → `keys.tls_cert`/`keys.tls_key` + `TlsFingerprint` present;
  restart → same fingerprint; `openssl s_client` served-cert fingerprint ==
  persisted `TlsFingerprint`; `HttpsDecoyUpstream` reload → served content is the
  upstream's. `PASS`.
- [x] 🟠 **Default-on decoy on the TCP listen port** (point 6, REALITY-analogue).
  A client that does not complete a tinc handshake is answered as an HTTPS
  server with the node's certificate and gets static content
  (`HttpsDecoyRoot`, a default page ships) or a proxied upstream
  (`HttpsDecoyUpstream`). No config needed. Done in `core/tincd/src/decoy.{c,h}`
  (built-in generic page, `HttpsDecoyRoot` file serving with traversal guard,
  `HttpsDecoyUpstream` proxy with Host rewrite) and the front dispatch in
  `transport.c`: a TLS ClientHello → real TLS handshake (`https_accept`) →
  decoy if it does not authenticate; a plain-HTTP prober → the same content over
  HTTP (`decoy_serve_plain`, replaces the M4 stub 200). `https` is compiled and
  accepted by default on OpenSSL builds, so this needs no option. No response
  path emits a tinc string (grep-checked in the test). **Proof:**
  `testing/transports/tls-front-test.sh` (2026-09-16): `curl -k https://node:655/`
  returns the decoy over a valid TLS handshake; `openssl s_client` shows the
  cert; `nmap -sV -p655` (throwaway `nicolaka/netshoot`) reports `http nginx`,
  never tinc; `curl http://node:655/` returns the page too; with
  `HttpsDecoyUpstream` set the response is the upstream's; an upstream-format
  tinc peer still connects `plain` (see the https-carrier test's fallback path).
  `PASS`. *(Note: nmap reports the port as `http (nginx)` rather than `https`
  because the port also answers cleartext HTTP; either way it fingerprints as an
  ordinary web server, not a VPN — the anti-probing goal.)*
- [x] 🟠 **`https` carrier** (point 6 + point 5). Real peers authenticate inside
  the TLS session via material derived from tinc keys (no static bearer token
  in the clear); authenticated SPTPS (meta+data) rides the one TLS flow.
  Selected by negotiation (M4), never a global mode. Done in
  `core/tincd/src/https.c`: TLS client dial with a plausible SNI, peer-cert
  pinning by `TlsFingerprint` (accept-on-first-use then pin), an Ed25519
  authenticator over `server-cert-fp || RFC5705 exporter || nonce || timestamp`
  carried in a WebSocket-upgrade `Cookie`, verified by the server against the
  node's `Ed25519PublicKey`; success answers `101 Switching Protocols` and the
  tinc meta byte stream runs inside TLS, with the link marked TCP-only-equivalent
  so SPTPS data frames ride the same flow (single outward TLS flow, no UDP).
  Registered compiled in `transport_table.c` and wired in `transport.c`. SPTPS
  untouched. Wire format + authenticator in `docs/transports.md` §8. **Proof:**
  `testing/transports/https-carrier-test.sh` (2026-09-16, image ws-g1): node A
  `PreferredTransports: [https, plain]` tunnels to B, ping both ways `0% loss`;
  `tinc dump connections` on both shows `transport https`; tcpdump on the port →
  `UDP datagrams: 0`, no cleartext tinc ID line, no cleartext key material; a
  live `curl -k` prober during the session gets the decoy; a forged and a
  replayed authenticator each get the decoy (no `101`). `PASS`.
- [x] 🟡 **QUIC carrier** (point 7). ngtcp2 integration (msquic rejected by
  stream Q, see below) carrying SPTPS records over datagrams + one stream;
  certificate handling shared with the HTTPS front; connection migration for NAT
  rebind. **Proof:** a QUIC-negotiated link tunnels; falls back to a common
  carrier when one side lacks QUIC.
  - **Done (G3, 2026-09-16):** `transport_quic.c` + `transport_quic_tls.c`
    (ngtcp2 1.25.0 + GnuTLS on tinc's own UDP socket and event loop), the §8.3
    authenticator factored into `authn.c` and sent as the first bytes of stream
    0, SPTPS data in DATAGRAM frames via the new `send_datagram` hook,
    v1-only + keyed-CID classifier rows, `-Dquic=auto|enabled|disabled`,
    ngtcp2 folded into `core/Dockerfile.build` (`ARG QUIC`), `QuicPort` /
    `QuicSni` / `QuicAlpn`. Mechanism: docs/transports.md §9. All proofs from
    `testing/transports/quic-carrier-test.sh` (image ws-g3, run 2026-09-16,
    `PASS`):
    - (a) A `PreferredTransports: [quic, plain]`, B default: `A -> B ping 0%
      loss`, `B -> A ping 0% loss`; `dump connections` on both shows
      `transport quic`; `tinc info nodea` on B lists quic; B log `quic:
      authenticated peer nodea`; tcpdump on the port: `288 UDP datagrams`,
      header sequence `LLLSSSS…` (3 long headers = Initial/Handshake, then 285
      short), `fixed bit clear (SPTPS-shaped): 0`, `0 SYN-ACK, 0 with payload`
      (no TCP meta connection; the only 2 TCP segments are B's autoconnect SYN
      before A was up and A's RST).
    - (b) NAT rebind: SNAT in A's netns maps its source port to 40000, flipped
      to 40001 mid-session + conntrack flushed → B log `quic: path validated
      for nodea, remote now 10.44.9.10 port 40001`; `quic: connection from`
      count 1 before and after (no re-handshake); ping `0% loss` both ways
      after the flip; B `dump connections: nodea now at port 40001`; A never
      re-dialled or fell back.
    - (c) fallback: B `Transports: [plain]` and B built without QUIC
      (`--build-arg QUIC=disabled`, image ws-g3-noquic) → A log `Carrier
      candidates for nodeb: plain`, tunnel on plain, ping 0% loss; UDP to B
      DROP'd → A log `Carrier quic failed for nodeb, falling back to plain`
      (handshake timeout = PingTimeout 5 s), tunnel on plain, ping 0% loss.
    - (d) A running with another node's Ed25519 key → B log `quic:
      authenticator from 10.44.9.10 port 655 rejected`, never `authenticated
      peer`; A log `Carrier quic failed for nodeb, falling back to plain`,
      then dials plain where SPTPS rejects it too. Replay: the same
      `authn_verify` replay cache as https (proven there with a replayed
      cookie); over QUIC a captured authenticator is dead on arrival anyway
      because the exporter differs per session — no QUIC-level replay injector
      exists (docs §9.11).
    - (e) regressions on ws-g3: `classify-test.sh` `37 checks, 0 failures`;
      `singleflow-test.sh` PASS; `https-carrier-test.sh` PASS;
      `tls-front-test.sh` PASS; `platforms/linux/docker/two-nodes.sh`
      (`TINCSTACK_TAG=ws-g3`, needs bash) PASS; `obfs-test.sh` at this branch's
      base fails on its fixed sleeps (the timing flake master fixed with
      polling) — master's polling version run against ws-g3: obfs tunnel `0%
      loss` both ways, relay A–R–B up, plain-wire part PASS, only the junk log
      marker missing because master's obfs.c log-level change is not in this
      branch (merge resolves it).
    - (f) relay A–R–B, A–R on quic, R–B plain, A↔B DROP'd: `R: A's link is
      quic`, `R: B's link is plain`, `A -> B relayed through R 0% loss`, `B ->
      A relayed 0% loss`, direct A↔B confirmed severed.
    - QUIC-less build stays green: ws-g3-noquic `tincd` links neither ngtcp2
      nor GnuTLS, `Transports accept=plain,sf,obfs,https`.
  - Stream Q (2026-09-16): dependency + spike. Library decided: **ngtcp2 1.25.0
    + GnuTLS backend**, not msquic (msquic owns its sockets/threads and cannot
    take datagrams from the M4 front's UDP socket; comparison in
    docs/transports.md §9.1). `core/Dockerfile.build-quic` builds it from a
    sha256-pinned tarball: build stage 60 s (ngtcp2 16 s of it), runtime image
    +5.4 MB (100.3 vs 94.9 MB); pkg-config resolves `libngtcp2` and
    `libngtcp2_crypto_gnutls` 1.25.0. Spike `testing/quic-spike/run.sh`, three
    consecutive runs `ALL PASS` (9/9): handshake with PEM EC P-256 cert + SHA-256
    pin (`PIN ok sha256=…`, `alpn=h3 sni=cdn.example.net TLS1.3`), wrong pin
    rejected (TLS alert 42), datagrams 5/5 both ways, one bidi stream both ways,
    NAT rebind (server `PATH_VALIDATION success remote=127.0.0.1:<new port>`,
    traffic continues), explicit migration with a fresh CID, clean close; wire
    capture: first packet `c3 00 00 00 01 08 …` (long header, fixed bit, Initial,
    version 1, 1200 bytes). Design for G3 in docs/transports.md §9. Found: the §3
    UDP classifier only catches long headers; 1-RTT short-header packets need a
    keyed CID lookup (§9.6) before the carrier can work; `active_connection_id_limit`
    must be > 2 (spike: 8) or the second migration fails. Carrier integrated by
    G3 (above).
- [x] 🟡 Runtime control CLI for obfuscation (`tinc obfs status|set|…`) **with
  persistence** to the YAML (the prototype's changes were lost on reload).
  **Done (G2, 2026-09-16):** `cmd_obfs` in `tincctl.c` implements
  `tinc obfs status|enable|disable|set <key> <value>|get <key>|tag <spec>` on
  top of the YAML-aware `cmd_config` path (M2); the `Obfs*` keys are registered
  in `variables[]`. **Proof** (single node, ws-g2, run 2026-09-16):
  `tinc obfs enable` → YAML `PreferredTransports: [obfs]` (+`plain`);
  `tinc obfs set junkcount 5` / `jmin 600` / `jmax 650` → YAML gains
  `ObfsJunkPacketCount: 5`, `ObfsJunkPacketMinSize: 600`,
  `ObfsJunkPacketMaxSize: 650`; the daemon auto-reloads (`Got 'reload' command` …
  `Transports accept=plain,sf,obfs prefer=obfs,plain`); an explicit
  `tinc reload` re-reads the same; after a **daemon restart** the YAML still
  carries the values and `tinc obfs status` (which connects the control socket
  as its live check) reports them — the set survived reload and restart, the
  exact defect the prototype had.
- **Acceptance:** each carrier interoperates through the M4 negotiator; with all
  off, behaviour is identical to plain tinc.

- **Found during M5 (G2):**
  - 🟠 `zeroconf.c` advertised a hard-coded `Transports = plain, sf` in each
    node's own host record (an M4 stopgap), so once `obfs` was compiled in a
    peer still never learned this node accepts it and the carrier could not be
    negotiated. Fixed to advertise `plain, sf, obfs` (the compiled set; the
    file's own comment already declared it "kept in sync with
    transport_compiled_mask()"). File outside G2's area — reported. When
    `https`/`quic` are compiled (G1/QUIC), that literal must be extended the
    same way.
  - 🟢 Ed25519 public keys are read lazily (`load_all_nodes` creates the node
    but not `n->ecdsa`), so obfs had to call `node_read_ecdsa_public_key()`
    before deriving a link key on dial and in the cold-start scan. Fixed in
    `obfs.c` (within area).

- **Found during M5 (G3):**
  - 🟠 `net.c terminate_connection()` computed `activated = c->edge != NULL`
    *after* the edge had been deleted, so it was always false and every
    reconnect — including one after a long-lived, authenticated link dropped —
    advanced the carrier candidate walk instead of retrying the preferred
    carrier (an M4 defect that only showed once a carrier that can drop
    mid-session existed). Fixed by evaluating the flag first. File outside
    G3's area — reported.
  - 🟡 Review R-10 was right: the classifier's "known QUIC version" set (~2¹⁷
    words) put the SPTPS-relay overlap at ~2⁻¹⁷ per node, not the documented
    2⁻³⁴. Fixed by matching v1 only (the carrier speaks nothing else) → 2⁻³⁴,
    plus `quic_udp_try` only consumes a packet ngtcp2 confirms (live CID or a
    ≥ 1200-byte Initial); docs §3/§9.5 carry the arithmetic, unit test rows
    added.
  - 🟢 `dump connections` did not follow a NAT rebind (the session peer moved,
    `c->address`/`hostname` did not); fixed in the path-validation callback.
  - 🟢 The two-node lab `platforms/linux/docker/two-nodes.sh` uses `set -o
    pipefail` and must be run with bash, not `sh` (not changed; noted).
  - Files touched outside the G3 area: `tls.c`/`tls.h` (`tls_current_pem()`
    accessor for the one node certificate), `net.c` (the defect above),
    `tincctl.c` (`QuicPort`/`QuicSni`/`QuicAlpn` in `variables[]`; master also
    changed this file — merge). `https.c` changed only to call the factored
    `authn.c`.
  - Decision: ngtcp2 folded into `core/Dockerfile.build` (`ARG QUIC=enabled`),
    `Dockerfile.build-quic` removed — the compose lab and every default node
    image now carry the carrier, which decision 2 needs; `QUIC=disabled` proves
    the plain build.
### Found during M5 (G1)

- 🟢 **`nmap -sV` labels the port `http (nginx)`, not `https`.** The listen port
  answers cleartext HTTP as well as TLS (both serve the decoy), so nmap's plain
  probe wins the service-version race. Either way it fingerprints as an ordinary
  web server, never as tinc, so the anti-probing goal holds; noted because the
  M5 proof line said "identifies https". Blast radius: cosmetic (the scanner's
  label). No fix planned.
- 🟢 **The decoy upstream proxy fetches synchronously with a 3 s timeout**
  (`decoy.c proxy_upstream`), briefly blocking the event loop for one prober,
  rather than an async TCP splice. Acceptable for a low-volume decoy that is torn
  down immediately; documented in `docs/transports.md` §8.5. If a busy public
  decoy ever needs it, convert to an async splice. Blast radius: up to 3 s of
  loop latency per unauthenticated TLS prober when `HttpsDecoyUpstream` is set.
- 🟢 **TLS certificate hot-reload is partial.** A new `TlsCert`/`TlsKey` or an
  edited `keys.tls_*` is picked up on daemon restart, not on `tinc reload`
  (`tls_init` runs from the carrier init, not `setup_myself_reloadable`). The
  decoy config (`HttpsDecoyRoot`/`HttpsDecoyUpstream`) *is* reload-aware. Blast
  radius: an operator swapping in a real cert must restart the daemon. Fix would
  be one `tls_init()` call on reload.
- 🟢 Files touched outside the stream-G1 area, all minimal and reported here:
  `node.{c,h}` (the `tls_fingerprint` field + the fingerprint dump token),
  `connection.c` (the carrier dump token), `info.c` (print the fingerprint),
  `net_setup.c` (set own fingerprint after `transport_init`), `tincctl.c` (new
  variables + connection-dump parse). No changes to `net_packet.c`,
  `invitation.c` or `sptps.c`.

---

## Milestone M6 — Linux delivery (point 1c) ✅ (2026-09-16; 🟢 cleanup closed by stream H)

- [x] 🟠 `platforms/linux/docker/`: `docker-compose.yml` + auto-init entrypoint
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
  **(b) done 2026-09-16 after merging stream A** (`47b4bbb`): `LAB=mrg
  TINCSTACK_TAG=dev ./two-nodes.sh` → invitee `Connected to mrg-a-node-1 port
  655...` → `Materialised defaults … ed25519_priv … RSA-public` → `Ready` →
  `Connection with node_a (10.16.8.2 port 655) activated`; ping b→a and a→b
  `3 packets transmitted, 3 received, 0% packet loss`; inviter's `tinc.yaml`
  gained `hosts.node_b` with the invitee's Ed25519 key; `PASS: two-node tunnel
  up`, exit 0.
- [x] 🟠 Invite/join helper scripts (`docker compose exec … tinc invite`).
  **Proof:** two-host (or two-project) bring-up reachable end to end.
  `invite.sh <name>` (`docker compose exec -T node tincstack-cli invite`) and
  `join.sh <invitation>` (`INVITE=… docker compose up -d`; the entrypoint joins
  on the first start only and cleans the classic-tree leftovers of a failed
  attempt so a retry is clean) exist, are shellcheck-clean and were exercised
  by `two-nodes.sh`: `invite.sh` returned `wsc-a-node-1:655/<cookie>`, `join.sh`'s
  path ran `tinc join` against it. End-to-end reachability proven on merged
  master 2026-09-16 (run (b) above): tunnel addresses 10.176.0.1 / 10.176.0.2,
  ping both ways 0% loss.
- [x] 🟡 No secrets in the tree; keys generated at first run into a named volume.
  **Proof:** `git status` clean of key material; `.gitignore` covers runtime data.
  Run 2026-09-16: after the single-node bring-up and the two-project lab,
  `git status --porcelain` listed only the new `platforms/` sources; keys exist
  only inside `tinc.yaml` (0600) in the project-scoped volumes
  (`wsc-single_data`, `wsc-a_data`, `wsc-b_data`, all removed by `down -v`).
  Root `.gitignore` already covered `tinc.yaml`, `*.priv`, `invitations/`;
  appended `platforms/linux/docker/.env` and `platforms/linux/docker/data/`.
- **Acceptance:** a Linux user gets a working node from `docker compose up` and
  onboards peers with one invite string. **Met** on merged master 2026-09-16
  (`two-nodes.sh` exit 0). Follow-ups: replace `tincstack-yaml` with the now
  YAML-aware `tinc set` and drop the stopgap `tinc-up` (the core's built-in
  Linux addressing from M2 covers it) — tracked as a 🟢 cleanup below.
- [x] 🟢 Cleanup after M2 landed: route the env mapping through `tinc set`
  (YAML-aware since M2) and delete `tincstack-yaml`; delete the stopgap
  `tinc-up` (the core's built-in Linux interface addressing covers it) and
  verify `two-nodes.sh` still passes. **Proof:** both files gone, run exit 0.
  **Done 2026-09-16 (stream H):** `tincstack-yaml`, `tinc-up` and the
  `python3-minimal` install are gone from `platforms/linux/docker/`; the
  entrypoint uses `tinc -c tinc.yaml set Name`, `set <Name>.Address`,
  `set <Name>.Port` (an absent file is first created empty, since the CLI
  refuses a missing document; a stopgap `tinc-up` left in an old volume is
  removed). `LAB=wsh TINCSTACK_TAG=ws-h ./two-nodes.sh` → a: `entrypoint:
  hosts.node_a Address = wsh-a-node-1` → `Materialised … Port=655` → `Ready`;
  invitation `wsh-a-node-1:655/<cookie>`; b: `entrypoint: hosts.node_b Port =
  656` → `Ready` → `Connection with node_a … activated`; both logs `Interface
  tincstack configured with 10.250.0.{1,2}/24 (built-in tinc-up)`, `ip -br
  addr show dev tincstack` → `tincstack UNKNOWN 10.250.0.1/24 …` / `… 10.250.0.2/24 …`,
  no `tinc-up` in either runtime dir (asserted by the script); ping both ways
  `3 received, 0% packet loss`; `PASS: two-node tunnel up`, exit 0.
  shellcheck (koalaman/shellcheck:stable, `-x`) clean on all five scripts;
  `docker compose config` clean with and without the lab overlay.
  **Core gap found (bridged at the time, bridge removed in the consolidation
  pass — see Known Issues, resolved):** tinc's
  variable table marked `Port` host-only, so `tinc set Port` can only write
  `hosts.<Name>`, while the daemon materialises `options.Port`; with both
  present `config_compare` (conf.c) picks by line number — measured: a joined
  node with `Port = 656` in its host record and materialised `Port: 0`
  listened on an ephemeral port (38055). The entrypoint therefore also passes
  `tincd -o Port=$PORT` (command-line options rank first in the same
  comparator); verified on real containers: founding node without
  `NODE_NAME` + `PORT=700` → `Listening on … port 700`, invitation
  `…:700/`, invitee with `PORT=656` → `Listening on … port 656`, connection
  activated, restart keeps identity and port. Fix belongs to the core
  (`Port` as `VAR_SERVER|VAR_HOST` in `variables[]`, or YAML-mode routing of
  host-only variables to `options:`), then the `-o` line goes.
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
- [x] 🟠 **Peer negotiates QUIC after the tick** — proven by M5 G3
  (`testing/transports/quic-carrier-test.sh` (a), image ws-g3, 2026-09-16):
  `PreferredTransports: [quic, plain]` on one node only, the peer at defaults →
  `tinc dump connections` shows `transport quic` on both sides (ping 0% loss,
  wire QUIC-only). The GUI writes exactly that line, so the tick is sufficient.
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

Adopt `tincapp` (Kotlin) into `platforms/android/`. Stream E, 2026-09-16,
branch `worktree-agent-a9d089facc77a096c` (commits `afe0775..`). Everything
below ran in containers (`ws-e-android-build` image, `wse-*` volumes), the
host SDK/NDK mounted read-only; no core source or meson change was needed.

- [x] 🔴 Repoint `app/CMakeLists.txt` at `core/tincd` (currently an absent
  absolute path → last build was vanilla tinc) and **reconcile the build system**
  (tincapp drives autotools; core is meson — provide an autotools-compatible build
  of the core sources for the NDK, or an NDK meson cross-build). **Proof:** debug
  APK builds against the core across the 4 ABIs (`/opt/android-sdk`, NDK 26.1).
  **Done:** CMake/`main.c` dropped; `platforms/android/native/build-core.sh`
  does an NDK **meson cross-build** of `../../core/tincd` per ABI (cross file
  with `system = 'android'`, API 21, `-Dcrypto=openssl` against a static
  LibreSSL 3.7.3 libcrypto cross-compiled by its own configure, zlib from the
  NDK sysroot, lzo/lz4/curses/readline/systemd/miniupnpc disabled), strips into
  `jniLibs/<abi>/libtincd.so|libtinc.so`; Gradle task `buildTincCore` runs it
  before `preBuild`, `useLegacyPackaging` so the executables are extracted.
  Proof (from-scratch build, `app/build` deleted first):
  `docker build -t ws-e-android-build -f platforms/android/docker/Dockerfile.build platforms/android/docker`;
  `docker run --name wse-clean-build -v "$PWD":/src -v /opt/android-sdk:/opt/android-sdk:ro -v wse-gradle:/root/.gradle -v wse-m2:/root/.m2 -w /src/platforms/android ws-e-android-build ./gradlew --no-daemon assembleDebug testDebugUnitTest`
  → `BUILD SUCCESSFUL in 2m 7s`, `EXIT=0`; `unzip -l app/build/outputs/apk/debug/app-debug.apk | grep libtinc`
  lists `lib/{arm64-v8a,armeabi-v7a,x86,x86_64}/libtincd.so` and `libtinc.so`
  (8 files, 1.06–1.37 MB each; APK 12.6 MB); `llvm-strings` of
  `x86_64/libtincd.so` contains `1.1pre18` and `tincd %s (%s %s) starting`;
  `llvm-readelf -d` shows PIE executables needing only libm/libz/libc/libdl.
  Trade-off: LibreSSL is what tincapp already shipped; `--crypto nolegacy`
  builds without it (SPTPS-only, no RSA legacy protocol) if the extra 1 MB per
  ABI is unwanted.
- [x] 🟠 **App-picker UI** for the existing whitelist/blacklist split routing
  (`AllowApplication`/`DisallowApplication` are parsed & applied; only the picker
  is missing). Enforce single-mode (Android forbids mixing). **Proof:** pick apps
  in the UI → `network.conf` reflects one list → routing honours it.
  **Done:** Configure → Tools → "Choose which apps use the VPN" →
  `AppPickerActivity` (mode radio: only-selected / all-except-selected, search,
  multi-select list with icon/label/package). `SplitRouting.write` puts exactly
  one key into `tinc.yaml` and removes the other; a file with both is refused.
  Proof (no emulator on this host; unit + Robolectric instead): `SplitRoutingTest`
  (5: round trip, one key only, mode switch removes the other, both → refused,
  empty selection removes the key), `VpnServiceBuilderTest.blacklistWrittenByThePickerIsApplied`
  (picker output → real `VpnService.Builder` with `disallowedApplications`
  set and `allowedApplications` null). `testDebugUnitTest`: 23 tests, 0 failures.
  The screen itself was only compiled, not tapped — awaits a device.
- [ ] 🟡 Verify invite/join (incl. QR, already present) writes the shared YAML
  schema. **Proof:** join on device produces a schema-conformant config.
  **Blocked on stream A** (core in YAML mode): with the master core
  (`tincstack/core:dev`) `tinc -c b/tinc.yaml -n mynet join <url>` prints
  "Configuration stored in: /etc/tincstack/mynet" and writes a **classic tree**
  (`tinc.conf` with `Name/ConnectTo/Mode`, `hosts/nodeA`, `hosts/nodeB`,
  `invitation-data`, `*_key.priv`), no `tinc.yaml`, then "Timed out waiting for
  the server to reply. Invitation cancelled." (exit 1; the inviter's `tincd`
  was up and had accepted the TCP connection). `tinc init` in YAML mode also
  writes a classic tree. The app side is done and waits for that: it runs
  `tinc --config networks/<net>/tinc.yaml --net <net> join <url>` (QR scanner
  feeds the same path), then folds the invitation's `Ifconfig`/`Route` from
  `invitation-data` into the YAML options (`VpnInterfaceConfigurationTest.invitationDataAddressingIsFoldedIntoTheYaml`).
  On-device proof `[ ]` until the core's join emits YAML.
  **Update 2026-09-16 (after merging stream A, `47b4bbb`):** the core's
  `tinc join` is YAML-native on master — it writes only `tinc.yaml`
  (`InterfaceAddress`/`InterfaceRoute` options, own + inviter host records,
  keys) and leaves **no** `invitation-data` file. The app's fold-in of
  `invitation-data` is therefore dead code, and its `Ifconfig`/`Route` keys do
  not match the core's `InterfaceAddress`/`InterfaceRoute` (see Known Issues,
  schema naming). It still works because the app derives the address from
  own `Subnet` + `AddressPool` when `Ifconfig` is absent. The on-device proof
  remains open only for lack of a device.
  **Update 2026-09-16 (stream H):** the app now reads `InterfaceAddress`
  (one or more) and `InterfaceRoute` (list, "prefix [gateway]" as
  `finalize_join_yaml` writes it; only the prefix is used) as its primary
  keys, the `invitation-data` fold-in (`TincApp.importInvitationAddressing`,
  `VpnInterfaceConfiguration.fromInvitation`/`writeAddressing`,
  `AppPaths.invitationFile`) and its test are deleted; the own `Subnet` +
  `AddressPool` fallback stays. Cross-check against the real core
  (`tincstack/core:ws-h`, docker network `wsh-fixture`): founding node
  `node_a` (`tinc set Name/AddressPool/node_a.Address`, daemon `Ready`, an
  `invitation-created` hook adding `Route = 10.99.0.0/24` and `Route =
  172.16.0.0/12 10.165.0.1` to the invitee chunk) → `tinc invite phone` →
  on a second container `tinc -c tinc.yaml -n phonenet join <url>` →
  `Invitation successfully accepted`, only `tinc.yaml` + an empty `phonenet/`
  written, options `InterfaceAddress: 10.165.0.2/24`, `InterfaceRoute:
  [10.99.0.0/24, "172.16.0.0/12 10.165.0.1"]`. That exact file (keys replaced
  by dummy PEMs) is `app/src/test/resources/joined-tinc.yaml`;
  `VpnServiceBuilderTest.joinedDocumentFromTheCoreReachesTheBuilder` asserts
  the real `VpnService.Builder` gets `10.165.0.2/24` and routes
  `10.99.0.0/24`, `172.16.0.0/12`. `./gradlew --no-daemon testDebugUnitTest
  assembleDebug` in the `ws-e-android-build` container: `BUILD SUCCESSFUL in
  2m 35s`, EXIT=0, 25 tests / 0 failures (TincYamlTest 9, SplitRoutingTest 5,
  VpnInterfaceConfigurationTest 6, VpnServiceBuilderTest 5), APK 12.7 MB.
  Still open here: only the on-device run.
- [x] 🟠 **One file on Android too** (brief point 2). Today the app keeps a
  second file, `network.conf` (`Address`, `Route`, `DNSServer`,
  `AllowApplication`, `DisallowApplication`). Fold these into the network's
  YAML as ordinary `options:` keys (the daemon ignores keys it does not use;
  the app reads them from the YAML) and delete `network.conf`. The app-picker
  above writes to the YAML. **Proof:** a device with only `tinc.yaml` connects
  with split routing applied; no `network.conf` exists.
  **Done:** `network.conf`, `tinc.conf` reading, `res/raw/network.conf`,
  commons-configuration and the key-passphrase machinery are gone; the app
  reads `Ifconfig`/`Route`/`DNSServer`/`SearchDomain`/`AllowApplication`/
  `DisallowApplication`/`AllowFamily`/`AllowBypass`/`Blocking`/`MTU`/
  `ReconnectOnNetworkChange` from `networks/<net>/tinc.yaml` `options:`
  (`Ifconfig`/`Route` = the keys tinc invitations already carry; `Address`
  would collide with the host `Address`). Without them: address = own
  `Subnet` + `AddressPool` prefix, route = `AddressPool`, so a zero-config node
  connects with nothing Android-specific in the file. Writes are a key-level
  textual splice (everything else byte-identical) + atomic temp/rename.
  Documented in `docs/config-schema.md` ("Android interface options").
  Proof: `VpnServiceBuilderTest` (Robolectric, SDK 34): a directory holding
  only `tinc.yaml` (asserted: `dir.list() == [tinc.yaml]`) yields a
  `VpnService.Builder` with the expected addresses, routes, DNS, search
  domain, MTU and exactly one app list; a zero-config daemon document yields
  `10.165.0.1/24` + route `10.165.0.0/24`; mixed lists throw before the
  builder. `TincYamlTest` (9) splices a daemon-materialised document
  byte-for-byte. Cross-check against the real daemon (`tincstack/core:dev`):
  a daemon-written `tinc.yaml` spliced with the app keys still starts
  (`Ready`), `tinc get AllowApplication|Route|Ifconfig` return the values (with
  "not a known configuration variable" warnings), and the file keeps all keys
  after the daemon stops. Real `establish()` on a device not run here.
- **Acceptance:** an Android user joins by invite/QR and chooses which apps use
  the tunnel. **Status:** the picker and the one-file config are proven on the
  JVM; the APK is built from the core for all 4 ABIs. Awaits a device: install +
  `VpnService.establish()`, `tincd` subprocess start via the fd socket, QR scan,
  and end-to-end join (core side unblocked by stream A; see the update above).
- **Found during M8:**
  - 🟠 (core, stream A) `tinc join` and `tinc init` in YAML mode
    (`-c x/tinc.yaml`) write a classic `tinc.conf`/`hosts/` tree next to the
    YAML and never the YAML itself; the inviter times out the invitation. Until
    fixed, joining from the app cannot produce a schema-conformant config.
  - 🟡 tincapp's `applyIgnoringException` silently dropped the second app list
    when both `AllowApplication` and `DisallowApplication` were present; the
    app now refuses such a file (documented in the schema).
  - 🟡 (core, cosmetic) `tinc get <AndroidKey>` warns "not a known
    configuration variable" for the Android keys; harmless, but a schema-aware
    `tinc get` would be cleaner.
  - 🟢 tincapp's key-passphrase feature (encrypted `*.priv` + unlock dialog)
    has no equivalent with keys embedded in the YAML; removed, not ported.
  - 🟢 `app_doc_url_format` / website strings still point at
    `tincapp.euxane.net`; the crash-report e-mail was emptied (button hidden).
  - 🟢 The app's Kotlin package is still `org.pacien.tincapp` (applicationId
    is `net.tincstack.android`); a rename is churn without benefit for now.

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
  - 🟢 **Lab evidence is committed in full** (`testing/**/results/`, ~20 MB of
    per-node tincd logs, 700+ files for one run; `make check` writes a new
    `results/<today>/` tree on every run). Impact: repository bloat grows
    with every recorded run, and `make check` in a checkout overwrites the
    committed evidence of the same day (stream K hit this: 63 modified
    files after one run). Consolidation: keep `summary.md`, `result.json`
    and the laptop/glare logs that the proof lines cite, gitignore the rest
    (or move full logs to a release artifact), and have `make check` write
    to a run-scoped directory.
  - 🟢 `testing/transports/singleflow-test.sh` uses fixed container/network
    names (`wsbsf-*`) and removes the `wsbsf` network on start: two
    concurrent runs kill each other (stream K). Parametrise the prefix like
    `two-nodes.sh` (`LAB=`).
  - ~~🟠 **REQ_KEY glare has no tie-break (upstream 1.1pre18 and core).**~~
    **Resolved 2026-09-16 (stream K, core patch 5 — `core/tincd/PATCHES.md`
    §5, `docs/source-inventory.md`).** Upstream 1.1 HEAD (`211e3dfa`) has the
    same unconditional tear-down in the `REQ_KEY` handler and no fix in its
    history, so the tie-break is ours: in `req_key_ext_h` a node whose own
    SPTPS session with that peer is *pending as initiator* keeps it and ignores
    the peer's `REQ_KEY` when its `Name` is lexicographically smaller, and
    yields as responder otherwise (both sides evaluate the same rule, so exactly
    one initiator survives — two initiators can never finish, the SIG record
    carries the initiator flag); the 30 s "No key after N seconds" cooldown in
    `try_sptps` is jittered ±20 % (24–36 s). Wire-compatible: no new message.
    **Measured** (`lab.sh glare`, full-cone × full-cone, both sides ping at
    once; `--rtt 50` makes the collision near-certain; evidence
    `testing/nat-sim/results/2026-09-16/glare-fix/summary.md` + cited logs):
    *before* (core at fef10b9, rtt 50, 3 runs) 90 s **FAIL** / 32 s / 31 s
    to the first key, 4 / 1 / 1 SPTPS restarts, 6 / 2 / 2 `Invalid packet
    seqno`; baseline 23 / 46 / 35 s, 3 / 7 / 5 restarts (rtt 1 ms: core 32 s
    with 1 restart when the pings collided, 1 s when they did not).
    *After*, core × core, 6 runs (rtt 50 ×3, rtt 1 ×3): **1 s in 6/6, 0
    restarts, 0 seqno errors**, the tie-break logged on both sides in 5/6
    runs (the 6th did not collide). *Mixed pairs* (rtt 50, 3 runs each):
    core × baseline (patched node has the smaller name, wins) 1 s / 0
    restarts ×3; baseline × core (patched node yields exactly as stock) 13 /
    12 / 13 s with 1 restart each — the residual both-responder case is
    recovered by the stock 10 s timer and is never worse than
    baseline × baseline (23–46 s). Fully fixed only when both ends carry the
    patch. Regression on the same image (`ws-k`): `make check` exit 0 (smoke
    PASS, validate-nat 6/6, quick matrix 5/5 PASS, dpi baseline six
    fingerprints), `lab.sh laptop --image both` core PASS 6/8/6/4 s and
    baseline FAIL at mapping-dropped exactly as recorded above (0 seqno / 0
    glare lines in both), `singleflow-test.sh` PASS, `two-nodes.sh` PASS.
    Lab: `natlab glare --image-b core|baseline` runs nodeb on the other
    binary; the "glare lines" column now also counts the tie-break message.
    Original finding (stream F): When
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
| H | M6 consolidation | Linux compose vs schema naming | C merged |
| Q | M5 QUIC design | `docs/transports.md` §9, ngtcp2 spike | — |
| G1 / G2 / G3 | M5 | https carrier / obfs tier / QUIC carrier | G design, Q |
| R | security | adversarial review + fuzz of M1–M4, read-only over M5 (`core/tincd/test/fuzz/`, `docs/security-review-2026-09.md`) | A–E merged |
| K | M9 finding | REQ_KEY glare tie-break (patch 5, `protocol_key.c`, `net_packet.c`) | F merged |
| L | review R | R-1, M5-1, M5-7…M5-11, L-1 (`transport.c` front, `decoy.*`, `https.c`, `tls.c`) | R merged |
| O | review R | M5-2…M5-6, R-10 (`obfs.c`, `transport_sf.c`) | R, G2 merged |

Merged into master, in order: A, B, C, D, E, H, G2, Q, G1, F, R, G2 (test
hardening), K, L, G3. Running: O.

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

- ~~🟠 **Two names for the interface address in the schema.**~~ Stream A's core
  writes `InterfaceAddress`/`InterfaceRoute` into the joined node's `options:`
  (and `autoif.c` reads them on Linux); stream E's Android app read
  `Ifconfig`/`Route` from the same `options:` and still looked for the
  `invitation-data` side-file that the YAML-native join no longer produces.
  Found 2026-09-16 at merge. **Resolved 2026-09-16 (stream H):** the app
  reads `InterfaceAddress`/`InterfaceRoute` (fallback own `Subnet` +
  `AddressPool` kept), the `invitation-data` path and its test are gone,
  docs/config-schema.md §"Android interface options" lists the top-level
  spellings only. Proof: a real `tinc invite` → `tinc join` with
  `tincstack/core:ws-h` produced `InterfaceAddress: 10.165.0.2/24` +
  `InterfaceRoute: [10.99.0.0/24, "172.16.0.0/12 10.165.0.1"]`; that file
  (keys redacted) is a Robolectric fixture and
  `VpnServiceBuilderTest.joinedDocumentFromTheCoreReachesTheBuilder` sees
  address `10.165.0.2/24` and routes `10.99.0.0/24`, `172.16.0.0/12` on the
  real `VpnService.Builder`; `testDebugUnitTest assembleDebug` → 25 tests,
  0 failures, EXIT=0 (details in M8).
- ~~🟠 **`Port` is classified host-only in the CLI, so `tinc set Port` and the
  materialised `options.Port` disagree.**~~ **Resolved 2026-09-16
  (consolidation):** `Port` is `VAR_SERVER | VAR_HOST` in `variables[]`
  (unprefixed → tinc.conf/`options:`, `<node>.Port` → host record);
  `net_setup.c` reads the server-config `Port` *before* merging the own host
  record, so `options.Port` wins; `get_my_hostname` (invitation.c) uses the
  same order (`Address host port` on the host record still wins, tinc.conf
  `Port` next, host-record `Port` last). Linux entrypoint: `tinc set Port`,
  the `-o Port=` bridge and the host-record copy are gone. Proof: two-nodes
  lab on the rebuilt `dev` image — invitee `entrypoint: options.Port = 656`
  → `Listening on 0.0.0.0 port 656`, tunnel PASS; with `node_b.Port = 700`
  added to the host record `tinc invite` still emits `…:656/`; classify
  26/0, singleflow, tls-front, https-carrier PASS. Original finding by stream
  H (2026-09-16):
  `variables[]` in tincctl.c marks `Port` as `VAR_HOST` without `VAR_SERVER`,
  so `cmd_config` always writes it into `hosts.<Name>`, while zeroconf/join
  write `options.Port` (655/0). With both present `config_compare` picks by
  line number — measured: invitee with `Port = 656` in its host record and
  `Port: 0` in options listened on ephemeral 38055. The Linux entrypoint
  bridges it with `tincd -o Port=$PORT` (command line wins). Fix in the
  consolidation pass: make `Port` `VAR_SERVER | VAR_HOST`, route the
  unprefixed form to `options:` in YAML mode, and have `tinc set Port` update
  the host record copy that `tinc invite` reads; then drop the `-o` bridge.
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

## Security review R (2026-09-16)

Adversarial review + fuzzing of the M1–M4 C code and a read-only pass over
the M5 carriers that landed during the review. Full write-up with threat
model, reproduction and fuzz commands: `docs/security-review-2026-09.md`.
Harnesses: `core/tincd/test/fuzz/` (`run.sh build|fuzz|check`, all in a
throwaway container). Live proof of the fixes:
`TINCSTACK_TAG=<tag> testing/security/review-r-live.sh`.

Fuzzing, 900 s per harness, ASan+UBSan, no memory-safety finding:
`fuzz_classify` 171.0 M runs, `fuzz_sf` 8.9 M, `fuzz_invitation` 5.4 M
(1 property violation → R-5, fixed), `fuzz_pool` 3.5 M, `fuzz_yamlconf`
201 k (1 property violation → R-4, fixed). Regression inputs are committed
under `corpus/`; `run.sh check` is the gate.

| # | Sev | Where | Finding | Repro | Status |
|---|-----|-------|---------|-------|--------|
| R-1 | 🔴 | `transport.c:390-416`, `net_socket.c:616` | front dispatcher returns on NEED_MORE without consuming; level-triggered select → 100 % CPU from one pending byte (`G`, `0`, `16 03`) for `pingtimeout`, repeatable | `printf G \| nc host 655` while watching `-d5` log rate | **fixed** (L, 2026-09-16: undecided front connection is parked, re-peeked every 200 ms, closed+tarpitted after 2 s; `tls-front-test.sh` R-1 case: one pending `G` cost **443 → 0** CPU ticks in a 6 s probe, closed at 2 s instead of never; fuzz_classify now also proves a full 8-byte peek always decides) |
| R-2 | 🟠 | `invitation.c:65-83` | `Obfs*/Https*/Quic*` propagation wildcards bypassed VAR_SAFE; on master would copy `HttpsDecoyRoot/Upstream` into every invitee | inviter with `HttpsDecoyRoot` set → `tinc invite` → file | **fixed** (exact allow-list; live step 3) |
| R-3 | 🟠 | `yamlconf.c:324-460` | parser silently truncated at an unplaceable line; write-back deleted hosts/keys | misindented `weird: 1` in tinc.yaml, start daemon | **fixed** (strict parser; props 1-3, live step 1) |
| R-4 | 🟠 | `yamlconf.c:693-800` | emitter wrote scalars/keys the parser read back differently (`[`, `\|`, `#`, `: `, key with `:`) | `fuzz_yamlconf` regress-key-with-colon | **fixed** (quoted scalars/keys; props 4-7) |
| R-5 | 🟠 | `invitation.c:102`, `yamlconf.c:782-790` | inviter-chosen 300-byte Name → YAML key the parser refuses → joiner wrote an unloadable config | `fuzz_invitation` regress-long-name | **fixed** (name ≤ 255; emit/save refuse; props 9, live step 5) |
| R-6 | 🟡 | `yamlconf.c:1026`, `tincctl.c:1999` | flock on the config inode lost across rename → `tinc set` vs daemon write-back lost updates | concurrent `tinc set` + invitation redemption | **fixed** (`<path>.lock`, held across read-modify-write; live steps 2, 6) |
| R-7 | 🟡 | `pool.c:250-276` | `Subnet = 0.0.0.0/0` (pending file or any peer's ADD_SUBNET) exhausted the pool | host record with `0.0.0.0/0`, `tinc invite` | **fixed** (only /32 inside the pool count; live step 4). Residual: per-/32 reservation by a peer — `StrictSubnets` |
| R-8 | 🟡 | `invitation.c:900-930` | `get_line` `abort()` on one control byte from the inviter | regress-ctrl-abort | **fixed** |
| R-9 | 🟡 | `invitation.c:116-160`, `autoif.c:61-150` | Ifconfig/Route from inviter → `ip` unvalidated; `-` option injection; unchecked snprintf | `Ifconfig = -x` in payload | **fixed** (syntax checks at the boundary, logged) |
| R-10 | 🟡 | `transport_table.c:227-260` | QUIC/SPTPS-relay overlap is 2⁻¹⁷ per node (drafts + grease), comment says 2⁻³⁴ | arithmetic | **open** — stream O (with G3) |
| R-11 | 🟢 | `transport_sf.c:352-372` | spoofed SYN amplification < 1.5×, bounded by MaxConnectionBurst | — | informational |
| R-12 | 🟢 | `net.c:236`, `transport_sf.c:481` | UDPRebindOnWake kills an SF session (re-dial) | sleep/wake | informational, doc note |
| R-13 | 🟢 | `yamlconf.c:474-500` | Windows temp files hold keys in `%TEMP%` | — | **open** — stream D |
| R-14 | 🟢 | `protocol_auth.c:280` | expired invitations stay `.used` until the weekly sweep | — | cosmetic |
| R-15 | 🟢 | `tincd.c:596` | one-line call change `zeroconf_materialise(true)` | — | note for tincd.c owner |
| R-16 | 🟢 | `tincctl.c cmd_config` | `tinc get Port` reads options while `tinc set Port` writes hosts.<me> | live step 6 (first version) | **fixed** in the consolidation pass (fef10b9: `Port` is `VAR_SERVER \| VAR_HOST`, options.Port authoritative for daemon, CLI and invite) |
| M5-1 | 🔴 | `decoy.c:277-360` | decoy upstream proxy is synchronous on the main loop (DNS unbounded, 3 s per recv, 4 MiB): one failed TLS probe per 3 s freezes the node | set `HttpsDecoyUpstream`, `openssl s_client` twice | **fixed** (L: upstream fetch is event-driven with a 3 s total deadline and 1 MiB cap, address resolved once at (re)load; `tls-front-test.sh` M5-1 case, black-holed upstream: a second probe's TLS handshake **2.52 s → 2.8 ms**; `https-carrier-test.sh` M5-1 case: tunnel ping A→B during three probes against B's black-holed upstream **0 % loss, max RTT 0.285 ms**; on the pre-fix build the case could not run at all, see L-1) |
| M5-2 | 🟠 | `obfs.c:87-116` | obfs key from public keys = mesh-wide shared secret; any member classifies/forges every link; never rotates | — | **open** — stream O (session-derived key after handshake) |
| M5-3 | 🟠 | `obfs.c:190-204` | magic header leaves 32 random nonce bits → reuse at ~2¹⁶ datagrams; 2³² without rotation | — | **open** — stream O |
| M5-4 | 🟠 | `obfs.c:312-327,344-366` | replayed sealed datagram from any address repoints the link before SF/SPTPS checks; no anti-replay | replay one captured datagram | **open** — stream O |
| M5-5 | 🟡 | `obfs.c:87-116` | same key both directions → reflected CLOSE/RESET | — | **open** — stream O |
| M5-6 | 🟡 | `obfs.c:368-402` | cold-scan budget global, restarts at node 1: > 25 nodes never classified; 25 pps starves it | — | **open** — stream O |
| M5-7 | 🟠 | `https.c:342-345` | TlsFingerprint pinned on first use before SPTPS proves anything → persistent MITM pin / DoS | MITM first dial | **fixed** (L: no pin is written on an unauthenticated contact; the pin is written once SPTPS activated the link over that TLS session; `https-carrier-test.sh` M5-7 cases: socat TLS bump on the first dial → **no pin**, https fails without a 101; legitimate first dial → exactly B's fingerprint pinned after `SPTPS authenticated nodeb`; malformed pin no longer re-appended) |
| M5-8 | 🟠 | `decoy.c:380-395` | plain-HTTP decoy `send_all` busy-loops on EAGAIN for a non-reading client | large decoy file + zero-window client | **fixed** (L: plain-HTTP decoy is an event-driven state machine, writes on IO_WRITE readiness, reaped by the authentication timeout; `tls-front-test.sh` M5-8 case, 8 MB decoy to a non-reading client: **800 → 2** CPU ticks over 8 s and the connection is dropped) |
| M5-9 | 🟡 | `https.c:462-563` | name-existence timing oracle (verify only for known names) | timing | **fixed** in shape (L: unknown name still parses a host record (own) and runs a full Ed25519 verify against the own key, freshness folded into the final AND; measured time-to-first-byte over TLS, 400 samples each: known/unknown **107/108 µs before, 100/102 µs after** — the oracle was below the noise of this lab both times, so the proof is structural) |
| M5-10 | 🟡 | `decoy.c:243-275` | failed tinc authenticators forwarded to the upstream in clear HTTP | clock-skewed peer | **fixed** (L: `Cookie`, `Upgrade`, `Sec-WebSocket-*`, `Authorization` and the client's `Host`/`Connection` are stripped before the request reaches `HttpsDecoyUpstream`; `tls-front-test.sh` M5-10 case: an authenticator-shaped request with `Cookie: sid=LEAKMARK…` — before the upstream logged all of it, after it sees none of those headers) |
| M5-11 | 🟢 | `tls.c:514`, `https.c:278` | key file chmod race (classic mode); no domain separation in signed message | — | **fixed** (L: key file `open(O_CREAT\|O_EXCL, 0600)`; authenticator **v2** signs `"tincstack-https-auth-v2\0" \|\| …` (docs/transports.md §8.3), both sides on this build; a v1-shaped forged authenticator gets the decoy — `https-carrier-test.sh` forged/replayed cases) |
| L-1 | 🔴 | `https.c:598-622` (`https_send`) | found by stream L while proving M5-1: a peer that closes its https link cleanly (close_notify — `tinc reload`, restart) made `terminate_connection()`'s DEL_EDGE broadcast call `https_send` on the dying link, whose `SSL_write` failure called `terminate_connection()` again → unbounded recursion → **SIGSEGV** (exit 139, 3 040 nested "Closing connection with nodeb" lines) on master and on the pre-fix stream-L build | `tinc reload` on B while A is connected via https | **fixed** (L: a failed send marks the session dying and a zero-delay reaper terminates it outside the send path; `https-carrier-test.sh` M5-1 case now reloads B under an https link and checks both nodes are still running) |
| L-2 | 🟡 | `net.c terminate_connection` / outgoing selection | observed by stream L in the same lab: after B's `tinc reload` closed an **activated** https link, A reconnected over **`plain`** (`dump connections` → `transport plain`), although a dropped activated link is meant to keep its carrier; a peer or on-path party that can reset the link once may therefore downgrade it. Not investigated further (outgoing selection is stream G's area) | `tinc reload` on B while A is connected via https, then `tinc dump connections` on A | **open** — for the negotiation owner (G) |

Re-run at the end of the review: `testing/transports/classify-test.sh` 26/0,
`TINCSTACK_TAG=ws-r platforms/linux/docker/two-nodes.sh` PASS.
