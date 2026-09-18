# PLAN.md — tincstack

**Last Updated:** 2026-09-17 (**defect G is closed: a severed direct path used
to cost 31-61 s of blackout, and `singleflow-test.sh` PART 2 -- written off as
flaky for weeks -- was measuring exactly that.** Three causes, none of them a
flake: sf spent its whole 24 s retransmission budget on a path where every
`sendto` returned `EPERM`; the REQ_KEY glare tie-break then defended a key
exchange that had gone out over that dead path; and nothing noticed when the
route changed under a pending exchange. 4 of 8 runs took 35-61 s before, 61 of
62 took 2-5 s after the fixes, and the residual is now closed too: **250
sequential runs on the shipped build, 0 slow, worst case 9 s** against a 31 s
signature, which rejects the old 1-in-62 rate at ~98 % (95 % upper bound
1.19 %). No slow run occurred, so the closure is statistical and no cause was
named; that is written down rather than dressed up. The proof prints the number
and separates "slow" from "never". The NAT lab the tie-break was written for is
unchanged: key after 1 s, 0 seqno errors, 0 restarts.
Earlier -- stream AE: **defect E is closed -- two nodes
behind one NAT now form a direct meta connection instead of retrying for
ever.** Their data path was already direct (that NAT hairpins UDP) while their
meta connection was relayed abroad and each node logged an ERROR every backoff
round. Three separable fixes: the give-up ERROR is quieted after three rounds
instead of repeating for ever; a meta connection may now fall back onto the
peer's **confirmed direct UDP flow** over the `sf` carrier when every address
the graph knows has refused (`UdpMetaFallback`, default `yes`,
`docs/transports.md` §2.2); and a peer's accept mask now reaches a node that
already holds its key, by re-asking the same REQ_PUBKEY an upstream tinc
already answers. New harness `testing/transports/same-nat-meta-test.sh` (four
containers, three networks, a hairpinning-UDP/TCP-deaf NAT) reproduces the
defect (`--expect-defect`), asserts the fix by default, and carries a negative
control (`SET_OPTS='UdpMetaFallback no' --expect-relayed`). "Advertise your LAN
address" was deliberately **not** implemented: it does not fix this pair and
the lab asserts why. See the Known Issues entry.
Earlier -- **defect F is fully closed: obfs can finally be
switched on in a network that is already running, and a peer that restarts can
still dial it.** It had two independent causes. The second was mine to find:
the obfs replay window is anchored to the *bootstrap* keyset, which is derived
from the two public keys and outlives both daemons, while the sender's counter
is re-randomised on every start -- so a restarted peer began below the
acceptor's high-water mark more often than not and every frame of its dial was
dropped **with no log line at any debug level**. Measured 1 of 6 restarts
recovering obfs before, **6 of 6 after** (`testing/transports/obfs-restart-test.sh`,
new); the drop is now logged, and stream AD's own test -- which was still
FAILing on the merged tree -- passes. Stream AD's half, the first cause:
`obfs_udp_try()` skipped its keyed check
for any source address bound to a node with `udp_confirmed`, so an obfs dial
between two peers that had ever exchanged UDP data was dropped on the acceptor
as `unknown source and/or destination ID` and timed out in authentication --
obfs worked only between nodes that had never talked, i.e. never in the field.
Found on the stand 2026-09-17, reproduced in a three-node lab
(`testing/transports/obfs-confirmed-peer-test.sh`, `--expect-defect`), fixed by
asking whether the SPTPS path would actually claim the datagram before leaving
it to it. `sf` and `quic` were measured with the same harness on the pre-fix
image and are **not** shadowed. See the Known Issues entry.
Earlier -- stream AC: **defects C and D are closed** -- two
nodes invited by the same third node now peer directly instead of being
relayed through their inviter forever, and a node's carrier accept mask now
travels over the meta graph. Measured against upstream tinc 1.1pre18 and
against classic `tinc.conf` + `hosts/` on the same binary: **all three
symptoms of defect C are upstream tinc 1.1 behaviour, none is YAML-specific.**
New harness `testing/transports/invitee-mesh-test.sh` reproduces the defect on
demand (`--expect-defect`) and asserts the fix by default. Earlier: stream W
merged and verified live; the
`pipefail` + `grep -q` defect that made seven proofs report the opposite of
what they measured is fixed; the transport proofs no longer silently test a
stale stream image. Stream Z **merged**: `AllowPlainMeta` — a node can finally
refuse cleartext tinc on its listening port; default `yes`, so nothing changes
until an operator asks for it. See the struck Known Issues entry. The first
release tag is cut from this tree.)

**Stream AE re-verification**, 2026-09-17, on `tincstack/core:ae` (master +
the defect-E fixes), each exit 0: the new `same-nat-meta-test` (`PASS`;
`PASS(repro)` on `tincstack/core:ae-pre` with `--expect-defect`;
`PASS(control)` with `SET_OPTS='UdpMetaFallback no' --expect-relayed`),
`obfs-test` (PART 2 is flaky -- see the note below: it failed once in the batch
run and passed twice on each image afterwards), `obfs-mtu-test`,
`obfs-confirmed-peer-test` (precondition held, 6 of 6 samples),
`carrier-switch-test`, `invitee-mesh-test`,
`plain-refuse-test`, `matrix-test` (on `:ae-test`, `-Dtransport_test=true`),
`quic-carrier-test` (second image `:ae-noquic`, `-Dquic=disabled`),
`singleflow-test`, `testing/smoke/run.sh` under bash, and `make lint`
(26 scripts). **Not run:** `classify-test.sh`, `tls-front-test.sh`,
`https-carrier-test.sh` -- the first for the same reason stream AD gave (it
`apt-get install`s a compiler in a throwaway container and this host has no DNS
in plain `docker run`), the other two because nothing in this stream touches the
TCP front or the https carrier.

**The two "sever a live link, require the relay" proofs are flaky, and this
stream measured both rather than assuming.** `singleflow-test.sh` PART 2 severs
a *fresh* A<->B link and gives the pair ~40 s to fall back to the relay, which
is close to both recovery paths' own timers (one `sf` retransmission round is
~36 s, `udp_discovery_timeout` is 30 s); `obfs-test.sh` PART 2 is the same
scenario with a 120 s window. Measured:

| proof | `:ae-pre` | first cut of AE | shipped AE |
|---|---|---|---|
| `singleflow-test` PART 2 | 3/3 (always the 4th of 5 attempts) | **1/3** | 3/3 (attempts 4, 4, 1) |
| `obfs-test` PART 2 | 2/2 (relay up after 38 s, 38 s) | -- | 2/2 (39 s, 9 s), plus one failure in the batch run above |

The `obfs-test` failure in the batch run happened while an unrelated pytest
suite was saturating the host; re-run twice on each image afterwards it passed
every time, with `:ae-pre` taking the same 38 s. A single green run of either
proves little; read them together with the attempt count / "relay up after N s"
line. The first cut of AE's `try_tx()` kick was a genuine regression here and
was narrowed because of these numbers -- see defect E point (2).

**Reviewer's own count, 2026-09-17, because 3 runs cannot separate a 0 % rate
from a 20 % one.** `singleflow-test.sh` on the merged tree (`tincstack/core:ae`)
vs the same tree without AE (`tincstack/core:epoch2`), same host, sequential,
no other lab running:

| build | runs | PART 2 failures |
|---|---|---|
| master + AE (`:ae`) | 18 | **2** (11 %) |
| master without AE (`:epoch2`) | 15 | **0** |

One-sided Fisher exact on 2/18 vs 0/15 is p ≈ 0.29 — **the two are not
distinguishable**, and this is not evidence that AE is clean, only that 33 runs
cannot see a difference of this size. Both failures are the already-tracked 🟡
slow plain-path reconvergence (`MISS: relayed A<->B ping failed`, 5 of 5
attempts), not a new symptom. **Followed up the same day and it was not a
flake at all — it was three defects, now fixed; see the PART 2 entry under
Known Issues.** The `try_tx()` watch item stands but is no longer the leading
suspect: with the reconvergence fixed the proof is 2-5 s in 61 of 62 runs on
the merged tree, and 250 of 250 within 9 s on the shipped build. `obfs-confirmed-peer-test.sh`
was measured the same way after it failed once in the batch run: 3/3 on `:ae`
and 3/3 on `:epoch2`, i.e. that failure was the harness's own retry logic (it
needs the acceptor to hold `udp_confirmed` through the dial), not AE.

**Stream AD re-verification**, 2026-09-17, on `tincstack/core:ad` (master +
the obfs guard fix), each exit 0: the new `obfs-confirmed-peer-test` (`PASS`;
`PASS(repro)` on `tincstack/core:ad-pre` with `--expect-defect`), the same
harness with `CARRIER=sf` and `CARRIER=quic` on **both** images, `obfs-test`,
`obfs-mtu-test`, `carrier-switch-test`, `invitee-mesh-test`,
`plain-refuse-test`, `matrix-test` (on a `-Dtransport_test=true` image),
`quic-carrier-test` (with a `QUIC=disabled` second image), `testing/smoke/run.sh`
under bash, and `make lint` (25 scripts). **Not run:** `classify-test.sh` --
it `apt-get install`s a compiler inside a throwaway container and this host has
no DNS in plain `docker run` (`Temporary failure resolving 'deb.debian.org'`);
it compiles `transport_table.c`, which stream AD does not touch.

**Regression state of `master`**, all 2026-09-16, each exit 0. On
`tincstack/core:w` (the merged tree: streams X, Y and W): `obfs-test` **three
times** — 0 of 1176 and 0 of 1172 steady frames readable with the public-key
bootstrap key on an idle host, and 0 of 1182 under a parallel 6-harness fuzz
campaign (host load ≈ 8); worst session-key window 1 s, 0 of 10 replacements
stuck in every run. `obfs-rekey-test` (held back until W merged): **PASS** —
session keys a=5 b=5 symmetric, a=10 b=10 one-sided, 0 % packet loss in both
phases. `two-nodes`, `yaml-scripts`, `reload-test`: PASS, re-run after the
`grep -q` harness fix. The fuzz gate (`run.sh check`: `yamlconf_props` + 6
harnesses, all ok — which also executes `selftest_close_preserves_session`) and
a 900 s campaign over all six harnesses: no crash, no new artifact. `make lint`
(shellcheck, 24 scripts), `make secrets` ("no leaks found"), `actionlint`, and
GitHub Actions `check` green on the pushed head `5f68245`.
Re-verified on `tincstack/core:zz` (the tree with stream Z merged), in the
coordination pass, not by the stream: the new `plain-refuse-test` **PASS**
(cleartext probe answered by default; with `AllowPlainMeta: no` the probe gets
nothing while an obfs link to the same node still carries traffic, `tinc dump
nodes` still works, and `tinc join` fails — the documented cost; `tinc set
AllowPlainMeta yes` + `tinc reload` restores both without a restart),
`smoke` PASS, `two-nodes` PASS, `classify` 37 checks 0 failures, and
`https-carrier` PASS (it exercises the `ack_h` change: a peer's advertised
accept list is now taken as written).

On `tincstack/core:nosendmmsg` (the same tree before W, which differs only in
`obfs.c`, so these are unaffected by the merge and were not re-run):
`classify` (37 checks, 0 failures), `singleflow` ("relay path intact"),
`tls-front`, `https-carrier`, `quic-carrier` (with a `QUIC=disabled` second
image), `matrix` (needs `-Dtransport_test=true`), `smoke`, the Windows
cross-build and `tincmgr.exe` end to end, and the Android `assembleRelease`.

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
- [x] 🟡 **Build the actual `tincmgr.exe`** — **built on Linux, in Docker,
  2026-09-16** (stream X). The old note ("PyInstaller cannot produce a Windows
  onefile from Linux") was only true of running PyInstaller *natively* on Linux:
  `platforms/windows/Dockerfile.build-exe` runs the official python.org Windows
  CPython 3.12.7 under `winehq-stable=11.0.0.0~bookworm-1`, so PyInstaller
  executes as a Windows process and takes its own `win_amd64` bootloader — not
  a cross-build. Everything pinned (installer SHA-256 checked; wheels incl.
  transitive: PySide6-Essentials/shiboken6 6.7.3, pyqtgraph 0.13.7, numpy
  1.26.4, PyYAML 6.0.2, pyinstaller 6.11.1, hooks-contrib 2026.7, pefile
  2023.2.7, pywin32-ctypes 0.2.3, altgraph 0.17.5, packaging 26.3, setuptools
  84.0.0). The i386 Wine runtime is required — `python-3.12.7-amd64.exe` is a
  PE32 bootstrapper. **One command** (after `build-core-win.sh` + `wintun.dll`):
  `platforms/windows/build-exe.sh` (= `docker build -f
  platforms/windows/Dockerfile.build-exe -t tincstack/win-exe:dev
  platforms/windows/`; `docker run --rm -e SMOKE=1 -v
  "$PWD/platforms/windows:/work" tincstack/win-exe:dev`), rc 0 from a cold
  cache in ~4 min image + ~40 s build. **Artefact** (gitignored,
  `platforms/windows/dist/`): `tincmgr.exe`, **57 665 248 B**, SHA-256
  `4c3725d98592a92b67d1cca2fcd2ca72c8b17e53276cb32de74fe1b7175a53e6` — the size
  is stable across runs but PyInstaller is **not** bit-reproducible (a second
  run of the same command gave `31a440c8024586b9a34119be64e889413e124996d0ef01d3168cecd61f6c0c1b`
  at the identical size), so that digest pins one artefact, not the recipe;
  `file` →
  `PE32+ executable (GUI) x86-64, for MS Windows, 6 sections`; `objdump -p`
  imports only `USER32 COMCTL32 KERNEL32 ADVAPI32 GDI32`. **Starts under
  Wine + Xvfb** (`TINCMGR_SELFTEST_MS`, the app's own headless probe — the exe
  is `console=False`/`uac_admin` so it has no `--help` to print): `SELFTEST OK /
  frozen=True / admin=True / config=Z:\tmp\smoke\tinc.yaml / networks=[] /
  load_error='' / tincd=…\_MEI2802\tincd.exe / tincd_exists=True`, rc 0 — i.e.
  the onefile unpacks, Qt builds the main window, the YAML is created and the
  bundled core is found. **Real two-file deploy, not a stub:** the unpacked
  `_MEI*` holds `tincd.exe` `ba2ccf73…d527`, `tinc.exe` `fc148d23…0680` (both
  byte-identical to `core/Dockerfile.build-win`'s output) and `wintun.dll`
  0.14.1 `e5da8447…afce`; run from there, `wine tincd.exe --version` → `tinc
  version 1.1pre18 (built Sep 16 2026 10:12:02, protocol 17.7) Features:
  libgcrypt legacy_protocol` and `wine tinc.exe --version` → the same version.
  Bonus: the suite also passes with the *Windows* interpreter under Wine —
  `wine python.exe -m pytest -q tests` → `36 passed, 2 skipped` (the two skips
  are the tests' own POSIX guards: POSIX-shell fake binaries, POSIX file modes).
  **Limits (Wine is not Windows, `build-windows.md` §2b):** no Wintun driver /
  adapter / MTU clamp, so `tests/selftest_runtime.py` is still the manual
  on-Windows check; `uac_admin` untested (Wine reports elevated
  unconditionally); Scheduled-Task autostart, tray/shell integration,
  SmartScreen and code signing untested; Wine's Qt platform plugin is not the
  Windows one, so nothing here is a rendering check. Also measured:
  `www.wintun.net` stalls at 12 288 B from this lab (5/5 tries killed by a 90 s
  `timeout`, rc 124; HEAD returns 200 with the full 750 540 B length), so the
  bundled `wintun.dll` came from the repo group's existing copy, verified by
  its version resource (`WireGuard LLC`, `0.14.1`, 427 552 B) rather than by a
  fresh download.
- **Acceptance:** two-file deploy (`tincmgr.exe` + `tinc.yaml`) manages
  networks, invites peers, and selects transports — **met at the code/test
  level** (38 headless tests, 30 backend + 8 offscreen GUI, all passing in
  `python:3.12-slim` + PySide6 6.7.3, rc 0; 36+2-skipped with the Windows
  interpreter under Wine) **and the `tincmgr.exe` half of the deploy now
  exists and starts** (box above). What is still unrun is on-Windows
  behaviour: the Wintun adapter, UAC, autostart and an interactive session.

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
- ~~🟡 **`tinc invite` phone-home re-confirmed** from the Windows backend path
  (`Trying to discover externally visible hostname...` in the CLI proof; then
  the M1 local-address fallback).~~ **Resolved 2026-09-16 by M2 + M6, verified
  in the consolidation pass.** The lookup is opt-in
  (`invitation.c get_my_hostname` reads `AddressDiscovery`, registered
  `VAR_SERVER` in `tincctl.c`; unset means no HTTP at all), and an operator who
  knows the address no longer relies on any fallback: the Linux entrypoint
  writes `hosts.<Name>.Address` from `PUBLIC_ADDRESS` (`entrypoint.sh`, v4 /
  `[v6]:port` / `host:port` forms) and `tinc invite` reads it. What remains is
  deliberate and documented, not a defect: with neither `PUBLIC_ADDRESS` nor
  `AddressDiscovery` the invitation carries the default-route source address
  and prints `Warning: using local address …`. The GUI still shows that warning
  in the Invite dialog's stderr panel, which is the intended surface.
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
- [x] 🟡 Verify invite/join (incl. QR, already present) writes the shared YAML
  schema. **Proof:** join on device produces a schema-conformant config.
  **Done 2026-09-16 (stream Y)** on a real Android runtime — the emulator run
  at the end of this box. The "blocked on stream A" paragraph that follows is
  the historical record of why the box sat open; it stopped being true when
  stream A merged (`47b4bbb`) and the only thing left was a runtime to run it
  on.
  **Was blocked on stream A** (core in YAML mode): with the master core
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
  **Proof 2026-09-16 (stream Y) — a real Android runtime, no device, nothing
  on the host.** A headless emulator in Docker
  (`platforms/android/docker/Dockerfile.emulator` + `emulator.sh`: SDK
  command-line tools, platform-tools, `system-images;android-34;google_apis;
  x86_64` and a baked AVD, booted `-no-window -gpu swiftshader_indirect
  -no-snapshot` with `--device /dev/kvm`; Android 14 / API 34, the app's
  `targetSdk`). One command, exit 0:
  `platforms/android/docker/join-on-emulator.sh` → Linux inviter `node_a`
  (`tincstack/node:wsy`, `PUBLIC_ADDRESS=10.44.77.10`, `AddressPool
  10.239.0.0/24`) on docker network `wsy-lab`, emulator attached to it (the
  guest reaches the inviter through the emulator's user-mode NAT), APK
  installed clean, `appops set net.tincstack.android ACTIVATE_VPN allow`,
  `tinc invite phone` → **the invitation driven through the UI**
  (`docker/ui-join.sh`, `uiautomator dump` + taps: Configure → "Join network
  via invitation URL or QR code" → the string typed into the `invitation_url`
  field, i.e. exactly what `JoinNetworkToolDialogFragment.onActivityResult`
  writes when the QR scanner returns → the dialog's Join button →
  `Tinc.join`). The file the core wrote,
  `/data/data/net.tincstack.android/files/networks/phonenet/tinc.yaml`
  (keys redacted), is the shared schema: `networks.phonenet.options` (`Name:
  phone`, `ConnectTo: node_a`, `Mode: router`, `AddressPool: 10.239.0.0/24`,
  `InterfaceAddress: 10.239.0.2/24`, `Port: 0`, `UDPRebindOnWake: yes`),
  `hosts.phone` / `hosts.node_a` (the inviter's `Address`, `Subnet`,
  `Transports`, `TlsFingerprint`, keys), `keys.ed25519_priv`; no side-file,
  no classic tree. Then the app's own CONNECT intent → `VpnService.establish()`
  → `tun0 10.239.0.2/24` with `libtincd.so` running as the app's child, and
  traffic both ways: guest → `10.239.0.1` 3/3 packets (0% loss), inviter →
  `10.239.0.2` 3/3 (0% loss), inviter log `Connection with phone ... activated`.
  The whole thing, from no emulator container to a torn-down lab, is
  `real 1m27s`, EXIT=0, and leaves nothing behind. Unit tests alongside:
  `./gradlew --no-daemon -PtincAbis=x86_64 -PtincCrypto=nolegacy assembleDebug
  testDebugUnitTest` → `BUILD SUCCESSFUL`, EXIT=0, 25 tests / 0 failures
  (TincYamlTest 9, SplitRoutingTest 5, VpnInterfaceConfigurationTest 6,
  VpnServiceBuilderTest 5). Getting there needed three app-side fixes (TMPDIR
  for the core subprocess, creating `networks/<net>/` before the join, the
  manifest's intent action names) and turned up one core-side defect left for
  the core stream; the `-PtincCrypto=openssl` default does not build at all —
  all four in "Found during M8".
  Not covered by this run: a physical device (ARM ABIs, real radio/NAT, sleep
  and `UDPRebindOnWake`, the actual camera QR scan) and the app-picker screen,
  which is still only compiled and unit-tested.
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
  JVM; the APK is built from the core for all 4 ABIs. Install,
  `VpnService.establish()`, the `tincd` subprocess over the fd socket and the
  end-to-end join are proven on an emulator (API 34, x86_64; stream Y, see the
  box above). Still awaits a physical device: the ARM ABIs, a real radio and
  NAT (sleep/`UDPRebindOnWake`), the camera QR scan, and the app-picker screen.
- **Found during M8:**
  - 🟠 (build, stream Y, 2026-09-16) **the documented Android build is
    broken**: `-Dcrypto=openssl` against the LibreSSL 3.7.3 that
    `native/build-core.sh` cross-compiles no longer compiles the core, because
    `core/tincd/src/tls.c` (M5/G1, the TLS front) uses OpenSSL 3.0-only API —
    `tls.c:165 EVP_EC_gen("P-256")` (undeclared → int-to-pointer) and
    `tls.c:327 SSL_OP_NO_RENEGOTIATION` (undeclared). Measured:
    `./gradlew -PtincAbis=x86_64 assembleDebug` → `3 errors generated`,
    `:app:buildTincCore` non-zero, `BUILD FAILED in 1m 38s`, EXIT=1 (all three
    errors land in `app/build/core/build/<abi>.build.log`, which the next build
    overwrites). No LibreSSL release fixes it:
    4.1.0 has `SSL_OP_NO_RENEGOTIATION` but still no `EVP_EC_gen` (checked by
    grepping its headers). A second gap in the same path:
    `build-core.sh` builds and installs only LibreSSL's **libcrypto** and its
    fabricated `openssl.pc` requires only `libcrypto`, so even a compiling
    `tls.c` would not link (`SSL_*` lives in libssl). Blast radius: every
    Android build with the default crypto backend, i.e. the release APK; the
    `https`/`quic` carriers on Android as a consequence. Workaround used for
    the M8 proof: `-PtincCrypto=nolegacy` (SPTPS/Ed25519 only), which builds
    and interoperates with an OpenSSL inviter over the `plain` carrier. Fix
    belongs to the core stream (an OpenSSL-1.1/LibreSSL fallback in `tls.c`)
    plus a libssl build here.
  - 🟠 (core, stream Y, 2026-09-16) **the core cannot write keys inside an
    Android app sandbox**: `zeroconf.c` serialises PEMs through
    `capture_pem()` → `yamlconf_content_fp()` → `tmpfile(3)`, and bionic's
    `tmpfile()` uses `$TMPDIR` or falls back to `/data/local/tmp`, which an app
    UID cannot write. Measured on the emulator: the very first `tinc join`
    fails with `Could not serialise Ed25519 private key` / `Could not write
    .../tinc.yaml` / `Invitation cancelled` (exit 1) while the inviter logs
    `Invitation ... successfully sent` then `was not completed`; the identical
    command with `TMPDIR=<app cache>` exported succeeds
    (`Invitation successfully accepted`). Worked around app-side (below), but
    any other embedder without a writable `$TMPDIR` hits the same wall — the
    core should fall back to a temp file in its own config/run directory.
  - 🟡 (app, stream Y, fixed) the app never created `networks/<net>/` before
    handing the path to `tinc join`, and the core does not create it either:
    join died with `Could not lock .../tinc.yaml: No such file or directory`.
    `Tinc.join` now creates the directory and removes it again if it is still
    empty after a failed join.
  - 🟡 (app, stream Y, fixed) `TMPDIR` is now set for every core subprocess
    (`Executor.run` → the app's `cache/run`), which is what makes the join
    above work.
  - 🟡 (app, stream Y, fixed) the exported intent API was dead: the manifest
    declared `org.pacien.tincapp.intent.action.CONNECT`/`.DISCONNECT` while
    `intent/Actions.kt` builds the action names from `BuildConfig.
    APPLICATION_ID` (`net.tincstack.android...`), so a matching external
    intent launched `StartActivity` but its action never equalled
    `Actions.ACTION_CONNECT` and nothing happened. The manifest now uses
    `${applicationId}`; measured before/after on the emulator (nothing in the
    app log vs. `Starting tinc daemon for network "phonenet"`).
  - 🟢 (app, stream Y) after a successful join the "Join network" dialog is
    re-shown when its `ConfigureActivity` is resumed, still holding the old
    invitation. Cosmetic; not fixed.
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
  interactive step. `make lint` = shellcheck in a container (clean; since
  stream U at shellcheck's default severity for every script, the transport
  proofs included).
  **Proof:** `make check` run 2026-09-16 → exit 0 in ~6 min:
  `smoke: PASS (cross-node ping both ways, YAML mode)`, `validate-nat: all 6
  profiles behave as declared`, 5 quick pairs PASS, `baseline fingerprints
  present: …six…`, `make check: OK`. Since stream T every lab step writes into the git-ignored
  `results/run/<run-id>/` (one `RUN` id per `make` invocation) and the
  committed `results/2026-09-16/` trees are the curated subset
  (`make promote RUN=…` / `lab.sh promote`), so a re-run never overwrites the
  evidence. CI: `.github/workflows/check.yml` (stream T) runs `make lint`,
  the core build (QUIC stage, buildx layer cache in GHA), the smoke test and
  `validate-nat` + the quick matrix on push/PR — validated with actionlint
  and by running each step's command locally in order; **not yet observed
  running on GitHub**.
- **Found during M9** (core sources untouched; evidence under
  `testing/nat-sim/results/2026-09-16/`):
  - ~~🟢 **Lab evidence is committed in full** (`testing/**/results/`, ~20 MB of
    per-node tincd logs, 700+ files for one run; `make check` writes a new
    `results/<today>/` tree on every run). Impact: repository bloat grows
    with every recorded run, and `make check` in a checkout overwrites the
    committed evidence of the same day (stream K hit this: 63 modified
    files after one run). Consolidation: keep `summary.md`, `result.json`
    and the laptop/glare logs that the proof lines cite, gitignore the rest
    (or move full logs to a release artifact), and have `make check` write
    to a run-scoped directory.~~ **Resolved 2026-09-16 (stream T):**
    `testing/{nat-sim,dpi-proof}/results/` in git went from **767 files /
    17.7 MiB to 112 files / 0.83 MiB** (kept: every `summary.md` and
    `result.json`, `validate-nat*.jsonl`, `laptop/*/nodel.log` +
    `nodel-udp-port.txt` + the conntrack snapshot, every `glare-fix/` log,
    `plain.report.txt` + `.fingerprint.json` + `.pcap`, and the two `gw-*.txt`
    the README cites by path); `lab.sh` / `dpi-proof/run.sh` / `make check`
    write to the git-ignored `results/run/<run-id>/`; `.gitignore` refuses
    node logs, dumps and gateway dumps under `results/`; `lab.sh promote`
    (`make promote RUN=…`) copies the curated subset into `results/<date>/`.
  - ~~🟢 `testing/transports/singleflow-test.sh` uses fixed container/network
    names (`wsbsf-*`) and removes the `wsbsf` network on start: two
    concurrent runs kill each other (stream K). Parametrise the prefix like
    `two-nodes.sh` (`LAB=`).~~ **Resolved 2026-09-16 (stream T):**
    `singleflow`, `tls-front`, `https-carrier`, `quic-carrier` and `matrix`
    source `testing/transports/lab-env.sh` and take `LAB=` (names, `/tmp`
    dir) plus a `LAB`-derived or explicit `SUBNET=` (two runs also collided
    on the docker `/24`); defaults unchanged. Proof on `tincstack/core:dev`:
    `LAB=wst1` and `LAB=wst2` singleflow runs started together, both PASS
    (exit 0); tls-front, https-carrier, matrix (`ws-b-test`) and
    quic-carrier PASS with `LAB=wst*`.
    `two-nodes.sh` now refuses `sh` with a message (it needs bash).
    **`obfs-test.sh` followed 2026-09-16 (stream U)** once stream O was merged:
    it sources `lab-env.sh` too (`DEFAULT_LAB=wso`, `DEFAULT_SUBNET=10.37.90`),
    so `LAB=` moves the five container names, the `<LAB>obfs` network, the
    `/tmp/<LAB>-obfs*` data and pcap directories, the lab `/24` **and** the two
    off-path attacker addresses of the replay/reflection checks (`$SUBNET.50`,
    `.51`) — the historical names are the defaults. Its EXIT trap now also
    removes the network (it only removed containers, so with `LAB=` every run
    would have leaked one docker network; `reset_lab()` between parts still
    keeps it). **Proof** on
    `tincstack/core:dev`: `LAB=wsu1` (10.37.157.0/24) and `LAB=wsu2`
    (10.37.54.0/24) started together, **both exit 0**, both `PASS: obfs
    cold-start works, fingerprint gone, junk per-handshake, relay intact,
    defaults plain; … (M5-2/4/5/6)`, no `MISS` line, and after the pair no
    `wsu*obfs` network is left behind; `singleflow-test.sh` `LAB=wsu1`/`wsu2`
    concurrently, both exit 0.
    **Collision retry added 2026-09-16 (this session).** The derived octet has
    only 200 values, so two non-default `LAB`s can hash to the same `/24`
    (`wsu1` and `wso` both give `.157`) and the second run died on docker's
    `Pool overlaps with other one on this address space`. `lab-env.sh` now
    reads the docker network list and, when the first candidate is held by a
    network that is not this lab's own, takes the lowest free octet in
    `20..219` and says so on stderr; an explicit `SUBNET=` still wins, an
    unreachable docker daemon falls back to the old unconditional choice, and
    a leftover `<LAB>*` network from a killed run does not push the lab off its
    documented `/24` (a name whose prefix is ours but continues with a digit,
    `wso` vs `wso1obfs`, is a different lab and does count). It reads the list,
    it is not a lock: two labs started in the same second can still both pick
    the same `/24`. **Proof** on `tincstack/core:dev`: `LAB=wsu1` and `LAB=wso`
    `testing/smoke/run.sh` overlapping — the first took `172.31.157.0/24`, the
    second logged `172.31.157.0/24 is held by another lab, taking
    172.31.20.0/24`, **both `smoke: PASS`, both exit 0**. Unit checks against
    real docker networks: default `wso` keeps `10.37.90` under its own leftover
    `wsoobfs`; `wsu2` shifts off a foreign `wsu23x`; `wsu2` keeps `.20` under
    its own `wsu2front`; `SUBNET=` overrides all of it.
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
  - ~~🟡 **`scripts:` stanza of `docs/config-schema.md` is not implemented** in
    `yamlconf.c` (no `scripts` key is read); in YAML mode `tinc-up` has to be
    a side-file at `<dir>/<netname>/tinc-up`. The smoke test does exactly
    that. Owner: A/C (M2/M6) or schema doc.~~ **Resolved 2026-09-16 (stream
    S).** The key *was* read (M2: `yamlconf_script_names()`, written once at
    start by `zeroconf_materialise()`), but not on reload, not atomically, and
    a deleted key left its file behind. Now `zeroconf_sync_scripts()`
    (`zeroconf.c`) runs from `setup_myself_reloadable()` — start and every
    reload, before the tinc-up decision: each `scripts.<name>` is written
    atomically (temp in the same dir, 0700, fsync, rename; unchanged content
    is not rewritten), a key deleted from the YAML has its file removed (only
    files this daemon wrote), a side file not in the YAML is left alone and
    reported once; `scripts.tinc-up` wins over the built-in `autoif.c` (the
    built-in is skipped), documented in `docs/config-schema.md` "Scripts".
    ~~`tinc set scripts.<name>` is not implemented (edit the file + `tinc
    reload`; the CLI's variable table is for options/hosts).~~ **Implemented
    2026-09-16 (stream U)**, see the entry below. Property 10 in
    `yamlconf_props.c` (scripts block round-trip incl. a trailing-space
    line). **Proof** (`LAB=wss TINCSTACK_TAG=ws-s
    platforms/linux/docker/yaml-scripts.sh`, exit 0): both nodes `built-in
    tinc-up`; `scripts.host-up` appended to b's YAML + `tincstack-cli reload`
    → ``Wrote script `host-up' … into `/etc/tincstack/tincstack'``, file `700
    root`, no `.tmp` left, no marker yet; a restarted → marker
    `/etc/tincstack/marker-node_a` = `node_a 10.16.6.2`; hand-made
    `tinc-down` → ``Script `…/tinc-down' is a side file … left alone`` once
    across two reloads, `host-up` not rewritten; key deleted + reload →
    ``Removed script `…/host-up'``, file gone, `tinc-down` still there. The
    smoke test now ships its `tinc-up` as `scripts.tinc-up` and asserts
    `Wrote script`, no `built-in tinc-up`, mode 0700 → PASS on `ws-s`.
  - ~~🟡 **`tinc set scripts.<name>` is missing**: in YAML mode a script can
    only be installed by hand-editing `tinc.yaml`, which races the daemon's own
    write-back of learned keys on a running node (the CLI takes the writers'
    lock, an editor does not).~~ **Resolved 2026-09-16 (stream U).**
    `tinc -c <file>.yaml get|set|del scripts.<name>` (`cmd_config_script()` in
    `tincctl.c`, `yamlconf_script_set_text()`/`yamlconf_script_del()` in
    `yamlconf.c`) writes `networks.<net>.scripts.<name>` through the same
    lock → re-read → atomic save → `REQ_RELOAD` sequence the options/hosts path
    uses, so stream S's `zeroconf_sync_scripts()` materialises it with no
    restart and no explicit `tinc reload`. **The body comes from a file**
    (`set scripts.tinc-up @./tinc-up`); an inline value is refused with a
    message naming the `@file` form, because `cmd_config()` concatenates argv
    with single spaces into one 4096-byte buffer and splits it on `[ \t=]`
    (a script would be mangled *and* silently truncated — and a truncated
    script still runs as root), and stdin is already `tinc`'s own command
    stream in shell/batch mode, so `@-` is not accepted either. `get` prints
    the text + a newline (a byte-for-byte round trip of a file ending in one
    newline, since the emitter writes a literal block and the parser chomps);
    the name must be a plain file name, so `scripts.` is a reserved prefix in
    the CLI's `<node>.<variable>` namespace; deleting the last entry drops the
    `scripts:` key (an empty map would be emitted as `{}` and read back as a
    scalar); outside YAML mode the CLI says a script is a file in the confbase.
    Documented in `docs/config-schema.md` "Editing a script from the CLI".
    **Proof** (`LAB=wsu5 TINCSTACK_TAG=ws-u
    platforms/linux/docker/yaml-scripts.sh`, exit 0 — step 6 added to that
    script): `set scripts.host-up @/tmp/host-up.new` with the daemon running →
    ``Wrote script `host-up'`` (2nd write), `700 root`, `get` diffs clean
    against the source file, an inline body refused with "read from a file",
    a restarted → marker `/etc/tincstack/marker2-node_a` = `node_a via-cli`
    (the CLI-installed script really ran), `del scripts.host-up` →
    ``Removed script `…/host-up'``, file gone, key gone from the YAML, a second
    `del` exits 1, the hand-made `tinc-down` side file untouched.
    Regression on `ws-u`: `review-r-live.sh` ALL PASSED (exit 0),
    `two-nodes.sh` PASS (exit 0), fuzz gate `run.sh build && run.sh check`
    exit 0 (yamlconf_props + 6 harnesses, `fuzz_invitation`/`fuzz_pool` link
    `tincctl.c`).
  - ~~🟢 **`testing/smoke/` uses a fixed compose project, network and `/24`**
    (`wsf-smoke`, `172.31.77.0/24`, `testing/smoke/run/`): two concurrent
    `make smoke` runs tear each other's containers down and fight over the
    docker subnet.~~ **Resolved 2026-09-16 (stream U).** `testing/smoke/run.sh`
    sources `testing/transports/lab-env.sh` (`DEFAULT_LAB=wsf`,
    `DEFAULT_SUBNET=172.31.77`) and exports `SMOKE_PROJECT` (`<LAB>-smoke`,
    both the compose project and the network name), `SMOKE_SUBNET` and
    `SMOKE_RUN` (`run` for the default LAB, `run-<LAB>` otherwise) into
    `compose.yml`, which keeps the historical values as its own defaults so a
    bare `docker compose -f testing/smoke/compose.yml down` still targets the
    default lab. `make smoke LAB=…` passes it through (`LAB ?= wsf`), `make
    clean` also removes `testing/smoke/run-*`, `.gitignore` covers them.
    **Proof** on `tincstack/core:dev`: `LAB=wsua` (172.31.114.0/24) and
    `LAB=wsub` (172.31.105.0/24) started together, **both exit 0**, both
    `smoke: PASS (cross-node ping both ways, YAML mode)`; then
    `TAG=dev make -o build-core smoke` with the default LAB → exit 0,
    project/network `wsf-smoke` on `172.31.77.0/24` as before.
  - ~~🟢 **The transport proofs are linted at `-S warning`** (`TEST_SCRIPTS` in
    the Makefile, stream T): dozens of pre-existing SC2086/SC2015 findings kept
    `make lint` from running them at the default severity the rest of the tree
    gets, so a real quoting defect in a proof could hide among them.~~
    **Resolved 2026-09-16 (stream U).** 117 SC2086 (unquoted `${PFX}-…`
    container names, `[ $i -lt … ]`, `[ $case = … ]`), 51 SC2015
    (`cond && note … || miss …`, which runs `miss` when `note` fails) and 20
    SC2329 were cleaned up mechanically — quoting via `shellcheck -f diff`,
    every `A && B || C` rewritten as `if A; then B; else C; fi`, the
    indirect-dispatch false positives silenced with one justified directive per
    site (a file-level one in `quic-carrier-test.sh`, whose sections are all
    dispatched as `sec_"$sec"`), and one genuinely dead helper (`wait_log` in
    `tls-front-test.sh`) deleted. No assertion changed. `TEST_SCRIPTS` is gone:
    one `SHELL_SCRIPTS` list, one severity, and `obfs-test.sh` (never linted
    before) is in it. **Proof:** `make lint` exit 0 at the default severity;
    every touched script re-run on `tincstack/core:dev` — `singleflow` ×2
    concurrent, `obfs` ×2 concurrent, `tls-front`, `https-carrier`,
    `quic-carrier`, all exit 0.
  - ~~🟡 **Linux MASQUERADE is not endpoint-independent on kernels ≥ 6.7**
    (measured: first destination keeps the source port, every later
    destination shares one other port). Any tincstack node behind a current
    Linux router behaves like a symmetric NAT towards the *first* peer it
    talks to; `UDP_INFO` learned via the relay carries the relay-facing port.
    Deployment docs (M6) should say so; the core copes because the peer learns
    the real port from the first authenticated datagram.~~ **Documented
    2026-09-16 (stream S):** `platforms/linux/docker/README.md` "NAT: a Linux
    router in front of a node" — the first peer (relay) sees the stable port,
    every other peer sees a symmetric NAT; what to do: `PORT` +
    `PUBLIC_ADDRESS` with a port-forward (no mapping involved), keep one
    public relay as everyone's first peer, or an EIM `SNAT` recipe on a
    router you control (`testing/nat-sim/natprofile.sh` `fullcone`). The
    measurement itself stays in `testing/nat-sim/README.md` (profile `masq`).
  - 🟢 `tinc info <peer>` reports "directly with UDP" from local state and
    keeps saying so after the peer restarted or the node slept, until a packet
    fails — a health check must send traffic (the lab pings).
  - 🟢 upstream's `tinc` CLI links the non-wide `libncurses.so.6`; the lab
    image ships both variants.
- **Acceptance:** one command (`make check`) builds and verifies; the named
  regression shows the delta between the patched core and upstream with logs
  checked in. **Met.**

---

## Milestone M10 — publishing & releases 🟠 (2026-09-16, owner request)

The tree now has a public home: `git@github.com:link0ln/tincstack.git`. Owner's
requirements, verbatim in intent: build and publish **only on a tag**, so a
normal commit never builds images; images go to the GitHub Container Registry
for Linux hosts; the release carries Android and Windows builds as assets;
Linux gets the archived repository instead of a binary, because Linux nodes run
through docker compose; and the compose file people run must reference the
registry image.

- [x] **Repository pushed.** `origin` = `git@github.com:link0ln/tincstack.git`,
  `master` at `ed9b325`, 126 commits. Before pushing, gitleaks (in a throwaway
  container) scanned the whole history: **12 findings, all benign** — WebSocket
  handshake nonces in two carrier proofs, `AAAA…`/`c2VjcmV0`/`REDACTED…`
  placeholders in the fuzz corpus, the Android unit-test fixtures, the schema
  docs and a help string, plus the one real blob already recorded in Known
  Issues (upstream tinc's public ED25519 test vector in
  `core/tincd/test/integration/cmd_sign_verify.py`). No node key, token or
  certificate is in the tree.
- [x] **`.github/workflows/release.yml`**, triggered by `push: tags: v*` and
  nothing else. Jobs:
  - `images` — builds `core/Dockerfile.build` (QUIC included) and the node
    image with buildx, **loads them locally**, runs `testing/smoke/run.sh`
    against the core image and a zero-config start against the node image, and
    only then logs in to `ghcr.io` and pushes
    `ghcr.io/<owner>/tincstack/{core,node}:<tag>` plus `:latest`. Publishing an
    image nobody ran is exactly the failure this ordering removes.
  - `windows` — `core/Dockerfile.build-win` cross-build, asserts `PE32+
    executable` on both exes, zips them with their `SHA256SUMS`.
  - `android` — the repository's own `platforms/android/docker/Dockerfile.build`
    with the runner's SDK/NDK mounted, `./gradlew assembleRelease`. Signing is
    optional: four `ANDROID_*` repository secrets materialise
    `keystore.properties` (never committed, removed in an `always()` step); with
    no secrets the asset is named `-unsigned` so nobody mistakes it for signed.
  - `release` — `git archive` of the tag as the Linux artefact, then
    `gh release create` with every artefact and notes that spell out the pull
    commands.
  - A `meta` job decides the version and whether anything leaves the run, so
    **"Run workflow" from the Actions tab is a dry run**: everything builds and
    is tested and the artefacts are attached to the workflow run, but no image
    is pushed and no release is created. That is how the pipeline gets proven
    before the first real tag, without publishing one.
- [x] **`platforms/linux/docker/compose.release.yml`** — the same node service
  with **no build section**, image
  `ghcr.io/link0ln/tincstack/node:${TINCSTACK_VERSION:-latest}`
  (`TINCSTACK_IMAGE` overrides the whole reference). `invite.sh` / `join.sh`
  honour `COMPOSE_FILE`, so the release flow uses the same two helpers. The
  building `docker-compose.yml` stays for development; a single file cannot do
  both, because compose still builds when a service has a `build:` section.
- [x] **`check.yml` no longer runs on tags** (`push: branches: '**'`), so one
  tag does not build everything twice.
- [x] Both workflows pass `actionlint` (which runs shellcheck over every `run:`
  block); `compose.release.yml` passes `docker compose config`.
- [x] **Top-level `LICENSE.md`.** The repository is public and carries GPL v2
  (tinc core and everything derived from it) and GPL v3 (the Android app,
  descended from tincapp) code, with no top-level statement of either. The file
  records what applies where and does not relicense anything. **Open question
  for the owner:** `platforms/windows/`, `platforms/linux/docker/`, `testing/`
  and the docs were written for tincstack and carry no per-file header;
  `LICENSE.md` currently says "treat as GPL v2 or later, matching the core",
  which is the safe reading, not a decision.
- [x] **`make secrets` / `.gitleaks.toml`, wired into `check.yml`.** The
  allowlist enumerates each known key-shaped string (placeholder bodies, the
  `Sec-WebSocket-Key` handshake nonces, upstream's public ED25519 test vector)
  instead of silencing the rule, so a genuinely new secret still fails. Current
  state: `no leaks found` over 105 commits.
- [x] **Three of the four jobs were run step by step on the dev host**, which is
  how both android failures and the Windows exec-bit failure above were found —
  the first tag is not their first execution:
  - `images`: core built and `tincd --version` answered; the node image built
    with `--build-arg CORE_IMAGE=…` and a container from it reached ` Ready`,
    answered `tincstack-cli pid` and had materialised a `Name` from an empty
    volume; `testing/smoke/run.sh` passes here on every build.
  - `windows`: `build-core-win.sh` → both exes, `build-exe.sh` → `tincmgr.exe`
    57 665 247 B, `PE32+ executable (GUI) x86-64`, Wine smoke `SELFTEST OK`;
    `file` reports `PE32+` for all three binaries (the workflow asserts the
    count is exactly 3). Only the `wintun.dll` download is untested here —
    wintun.net is unreachable from this host — but the check it feeds
    (`osslsigncode verify` → `O=WireGuard LLC`) was exercised against the copy
    the repo group already had.
  - `android`: `assembleRelease` in the repository's own build container with
    the host SDK mounted → `BUILD SUCCESSFUL`, a 4.5 MB APK with all four ABIs.
- [x] **A tag has now been pushed: `v0.1.0`, 2026-09-16 — and two of the four
  jobs failed on the first attempt.** Recorded in full because the point of the
  exercise was to find exactly this, and because neither failure could be seen
  in the logs (the Actions log API answers 403 "Must have admin rights" to the
  token available here; only *annotations* are readable, which is why every
  fragile step now re-emits its tail as an `::error::` annotation).
  - 🔴 **`images` died in "Build node":** `buildx failed ... failed to resolve
    source metadata for docker.io/tincstack/core:rel: pull access denied`.
    `docker/build-push-action` runs buildx in its own container, so
    `FROM ${CORE_IMAGE}` was resolved against Docker Hub, not against the core
    image the previous step had just `load`ed into the runner's daemon. The
    local proofs never caught it because a developer's `docker build` *is* the
    daemon builder. **Fixed:** the node image is built with plain `docker
    build --build-arg CORE_IMAGE=tincstack/core:rel` (the core build stays on
    buildx for the gha cache; it pulls only public bases). Verified on this
    host with `CORE_IMAGE=tincstack/core:w`: image built, container started
    from an empty volume, log `QUIC carrier ready … Interface tincstack
    configured with 10.225.0.1/24 (built-in tinc-up) … Ready`,
    `tincstack-cli get Name` answered.
  - 🟠 **`android` died inside `android-actions/setup-android@v3` itself**, in
    the action, before any of our steps. **Fixed by removing the action:** the
    ubuntu runner image already ships the Android SDK and its cmdline-tools,
    and the build itself runs in this repository's own container with that SDK
    mounted, so the job now locates `sdkmanager` under `$ANDROID_SDK_ROOT`,
    accepts licences, installs the three packages, and prints which binary it
    used — with an `::error::` annotation naming the SDK contents if it cannot
    find one. Untestable from here; the next tag is the test.
  - 🟡 **The workflow carried the `pipefail` + `grep -q` trap too** (GitHub runs
    every `run:` under `bash -eo pipefail`): `docker logs relnode | grep -q
    ' Ready$'` as an assertion would have failed the job *because* the node was
    ready, once the log grew. Fixed the same way as the scripts.
  - ✅ **What the tag did prove**, in the parts that ran: `meta` (version and
    publish gating), and in `windows` the two steps no local run could cover —
    the wintun.net download and the Authenticode gate on it (`O=WireGuard LLC`,
    `Signature verification: ok`) both passed on the runner.
  - Nothing was published: `release` needs all three build jobs, so no image
    reached ghcr.io and no GitHub release was created. The tag is re-pointed at
    the fix rather than burned, since no artefact ever carried it.
- [x] **The `android` job would have failed on its first run.** `assembleRelease`
  with no flags takes `app/build.gradle`'s default `-PtincCrypto=openssl`,
  which does not compile (see the `tls.c` entry in Known Issues). The job now
  passes `-PtincCrypto=nolegacy` explicitly, with the reason in a comment and
  in the release notes: **the released APK speaks SPTPS/Ed25519 only and cannot
  talk to a tinc 1.0-era peer.** The gradle default is deliberately left as
  `openssl`, because it documents the intended configuration and
  `platforms/android/readme.md` already warns that it is broken; flipping it
  would hide the defect instead of fixing it.
- [x] **The `android` job would have failed a second time, in R8.** The
  `release` build type has `minifyEnabled true`, and the release variant had
  never been built by anyone — stream Y proved the join with `assembleDebug`.
  `minifyReleaseWithR8` died on *Missing class java.beans.BeanInfo …
  (referenced from org.yaml.snakeyaml.introspector.PropertyUtils)* and four
  more: SnakeYAML's introspector references `java.beans`, which Android does
  not have. Fixed in `app/proguard-rules.pro` with `-dontwarn java.beans.**`
  and a whole-package keep for SnakeYAML, matching how commons/logback/slf4j
  are already kept (it resolves node types reflectively). **Proof** on this
  host, in the repository's own build container with the host SDK mounted:
  `./gradlew --no-daemon -PtincCrypto=nolegacy assembleRelease` →
  `BUILD SUCCESSFUL in 4m 30s`, exit 0,
  `app/build/outputs/apk/release/app-release-unsigned.apk` 4 558 685 B carrying
  `libtincd.so` + `libtinc.so` for all four ABIs (arm64-v8a, armeabi-v7a, x86,
  x86_64).
- [x] **The pipeline has now produced a release: `v0.1.1`, 2026-09-16.**
  <https://github.com/link0ln/tincstack/releases/tag/v0.1.1> — assets
  `tincstack-v0.1.1-source.tar.gz` (1 223 884 B),
  `tincstack-v0.1.1-unsigned.apk` (4 561 589 B) and
  `tincstack-v0.1.1-windows-x86_64.zip` (58 803 268 B); images pushed as
  `ghcr.io/link0ln/tincstack/{core,node}:v0.1.1` and `:latest`. Verified after
  publication: the source archive holds 1053 files and its
  `platforms/linux/docker/compose.release.yml` names
  `ghcr.io/link0ln/tincstack/node:${TINCSTACK_VERSION:-latest}`, so the release
  notes' first instruction works from the archive alone.
  - 🟠 **The third defect the tag found, after the buildx and setup-android
    ones:** the `release` job pulled **every** artefact of the run with a
    single `actions/download-artifact@v4` and died with `Unable to download
    artifact(s) ... after 5 retries` — with all three build jobs green and the
    images already pushed to ghcr, so the run left the registry ahead of the
    repository. The same blanket download would also have attached buildx's
    `<owner>~<repo>~XXXX.dockerbuild` record blob to the release as an asset.
    **Fixed:** `DOCKER_BUILD_RECORD_UPLOAD: false` on the core build so the
    blob never exists, two downloads **by name** (`windows`, `android`), an
    explicit error when `assets/` comes out empty, and an `::error::`
    annotation around `gh release create`. Proven by the v0.1.1 run: three
    assets, no blob.
  - **`v0.1.0` stays as a tag with no release.** Its run pushed
    `ghcr.io/link0ln/tincstack/{core,node}:v0.1.0` before the release job
    failed, so those image tags exist and point at a core without stream Z.
    Delete them in the package settings if that bothers you; nothing references
    them.
- [x] 🟡 **CI now builds the Android app — but only when the app changes.**
  Both of the android job's failures above were found by running it by hand on
  a tag, not by `check.yml`, which builds only the core image and the Linux
  labs. The owner asked for less building per commit, and GitHub has no
  per-job path filter (`on.push.paths` is per workflow), so this is its own
  workflow: `.github/workflows/android.yml` runs
  `testDebugUnitTest assembleRelease` in the repository's own build container
  with the runner's SDK, on a push or PR that touches `platforms/android/**`
  or that file, and nothing otherwise. Roughly ten runner-minutes on an
  Android change, zero on every other commit. It is deliberately the same
  three steps as the release job's android leg (same SDK discovery, same
  `-PtincCrypto=nolegacy`, same container), so a red run here means the
  release would be red too. **Proof:** the workflow file matches its own path
  filter, so pushing it was its first real run —
  <https://github.com/link0ln/tincstack/actions/runs/35139673064>, every step
  green (SDK discovery, build container, `testDebugUnitTest assembleRelease`),
  on a runner, without the `android-actions/setup-android` action that failed
  on the v0.1.0 tag. `actionlint` clean.
- [x] **The one manual step is done (owner, 2026-09-16): both ghcr packages are
  Public.** A package Actions creates is private even when the repository is
  public, and nothing in the workflow can change that — the API needs a token
  with `packages` scope that `GITHUB_TOKEN` does not carry. **Verified
  anonymously, end to end, on this host:**
  - anonymous ghcr token (`ghcr.io/token?scope=repository:…:pull`) then
    `GET /v2/link0ln/tincstack/{node,core}/manifests/{v0.1.1,latest,v0.1.0}` →
    **HTTP 200** for all six;
  - `docker --config <empty dir> pull ghcr.io/link0ln/tincstack/node:v0.1.1`
    (no credentials at all) → `Status: Downloaded newer image`, digest
    `sha256:7399543eabc84780adde9f662717a99a98cb425c1936909898cdda29ed33e618`;
  - the release notes' own instruction, from the published source archive:
    `COMPOSE_FILE=compose.release.yml TINCSTACK_VERSION=v0.1.1 docker compose
    up -d` → `Ready`, `tincstack-cli pid` answers, `tincstack-cli invite` issues
    an invitation; a second container started from the same pulled image with
    that `INVITE` joined (`Carrier candidates … plain (peer accepts
    plain,sf,obfs,https,quic)` → `Connection … activated`) and both ends pinged
    through the tunnel, **0 % packet loss both ways** (10.50.0.1 ↔ 10.50.0.2),
    both containers running image
    `sha256:8aea9b07c32c37112a040efb306e0a37caf830ebb6a44db6bbd6ecd6a7372f42`.
  - Note for the record: a bare `GET /v2/…/manifests/…` with no token returns
    401 from ghcr for **public** images too, so that response alone says nothing
    about visibility — an earlier check in this session read it as "private".
- [ ] **arm64 images.** Deliberately not in the first pipeline: the ngtcp2 +
  GnuTLS stage under QEMU is roughly 10x slower, and an arm64 runner is the
  better answer. Add as a matrix leg with a manifest merge once a first release
  has gone out on amd64. Home SBC nodes are the obvious users, so this is a real
  gap, not a cosmetic one.
  **Measured 2026-09-16, and the gap is now a lived one.** The whole arm64
  image was cross-built here under `tonistiigi/binfmt` qemu
  (`docker buildx --platform linux/arm64 -f core/Dockerfile.build`, then
  `docker build --platform linux/arm64 --build-arg CORE_IMAGE=tincstack/core:arm64`)
  and the emulated build cost **978 s of build stages end to end** (~16 min),
  of which tinc's own compile is only **154 s** -- the bulk is the emulated
  `apt-get` layers (301 + 228 + 166 s), which a cached base image removes
  entirely. (An earlier revision of this entry said "about 11 minutes of
  compile"; that was a guess from a partial log, and the split matters: the
  thing to optimise is the base image, not the compiler.) So the "roughly 10x,
  wait for an arm64 runner" reasoning above is too pessimistic -- a matrix leg
  is affordable on an ordinary runner today. Proof that the artefact is real, not just
  built: `tincstack/node:arm64` (130 MB, `Architecture: arm64`) was shipped to
  the home router with `docker save | gzip | ssh root@192.168.1.1 docker load`
  and started there from
  `/mnt/usb-8ba4d39c/storage/tincstack/` (compose v2.32.4 already on its
  flash, `network_mode: host` because that dockerd runs `--iptables=false`).
  It came up as a full node -- `QUIC carrier ready (ngtcp2 1.25.0, GnuTLS)`,
  `Interface tincstack configured with 10.170.0.4/24`, joined ruvds2 by
  invitation on the first try, `router -> ruvds2` 26.7 ms, 0% loss over the
  tunnel -- on an aarch64 OpenWrt-ish firmware with a 32 MB read-only rootfs.
  The existing `gnet` tinc on that box (container `tinc`, `tap5`,
  10.200.240.7) was untouched and still carries 8.8.8.8 at 69 ms.
  Until the matrix leg exists, an SBC owner has to do that cross-build by
  hand, which is exactly the "real gap" this item claims.
- [x] **`tincmgr.exe` is in the Windows asset** (stream X merged). The job runs
  the repository's own `platforms/windows/build-core-win.sh` and
  `build-exe.sh`, so CI and a developer run the same two commands. `wintun.dll`
  is fetched from wintun.net and gated on its **Authenticode signature**
  verifying to `O=WireGuard LLC` rather than on a checksum pinned in the
  workflow — a hash in the file is only as trustworthy as whoever typed it, and
  this host cannot reach wintun.net to obtain one honestly. The observed
  SHA-256 is printed for the record. Verified here with the copy the repo group
  already had: `osslsigncode verify` → signer `O=WireGuard LLC`, chain to
  DigiCert EV Code Signing, timestamped 2021-10-17, `Signature verification:
  ok`, `Succeeded`. The ZIP carries `tincmgr.exe`, the standalone
  `tincd.exe`/`tinc.exe` and `SHA256SUMS`; everything is **unsigned**, which
  the release notes say.
- [x] **`platforms/windows/build-core-win.sh` was committed non-executable**
  (mode 100644), so the documented one-command build died with exit 126,
  "Permission denied". Found by running it on merged master — stream X never
  ran that script, it reproduced its steps by hand. Fixed with
  `git update-index --chmod=+x`; the whole chain then ran clean here:
  `build-core-win.sh` → `tincd.exe`/`tinc.exe`, `build-exe.sh` → 57 665 247 B
  `dist/tincmgr.exe`, `PE32+ executable (GUI) x86-64`, Wine smoke test
  `SELFTEST OK`.

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

| N | review L-2 | carrier retention across link drops (`transport.c` candidates, `net.c`) | L, G3 merged |
| S | M2/M9 findings | `scripts:` stanza sync, MASQUERADE note, R-13/R-14 | R merged |
| T | M9 infra | run-scoped lab results, curated evidence, `LAB=` for proofs, CI workflow | F, K merged |
| U | M9 infra | `LAB=` for obfs-test and the smoke lab, full-severity shellcheck, `tinc set scripts.<name>` | O, S, T merged |

Merged into master, in order: A, B, C, D, E, H, G2, Q, G1, F, R, G2 (test
hardening), K, L, G3, S, T, N, O. No stream running.

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

- 🟠 **An already-running network could never be switched to obfs**
  (stream AD, found on the real stand 2026-09-17, **fixed** in the same
  stream). Two nodes with a confirmed UDP data path could not bring up an
  obfs link in either direction: the dial timed out in authentication and
  fell back to plain. Field log, `laptop` (NATed) dialling `euvds` (public
  VPS), both on the then-current master *with* stream AB's MTU fix, and with
  no `Message too long` anywhere, so this is **not** the EMSGSIZE defect —
  dialler:

      00:14:48 INFO  Dialling euvds (88.218.122.166 port 655) via obfuscated single-flow UDP
      00:14:48 INFO  Connected to euvds (88.218.122.166 port 655)
      00:14:53 WARNING Timeout from euvds (88.218.122.166 port 655) during authentication
      00:14:53 INFO  Dial to euvds ... via obfs abandoned before the connection was activated
      00:14:53 INFO  Carrier obfs failed for euvds before activation (1/3) but worked before, retrying it

  acceptor, at `-d5`, at exactly those seconds:

      00:14:59 WARNING Received UDP packet from laptop (79.139.184.85 port 1181) with unknown source and/or destination ID
      00:15:00 WARNING Received UDP packet from laptop (79.139.184.85 port 1181) with unknown source and/or destination ID
      00:15:13 WARNING Received UDP packet from laptop (79.139.184.85 port 1181) with unknown source and/or destination ID

  **Cause.** `obfs_udp_try()` (obfs.c), cold-start branch:

      node_t *known = lookup_node_udp(&addr);
      if(known && known->status.udp_confirmed) {
              return false; /* an established plain peer: leave it to the SPTPS path */
      }

  The dialler's source address is already bound to a node with
  `udp_confirmed` — the normal state of any pair that has been carrying
  traffic — so the keyed check was skipped exactly when an existing network
  switched to obfs. The sealed frames fell through to `process_sptps_udp()`,
  which found the whitened nonce where a node id should be and dropped them.
  Blast radius: obfs was unusable in the one scenario it exists for.

  **Why every lab passed.** They dial obfs from cold containers, before any
  UDP path is confirmed. `carrier-switch-test.sh` does wait for
  `udp_confirmed` and still passes, because it has only **two** nodes: `tinc
  disconnect nodea` removes the last edge to the dialler, so on the acceptor
  the dialler becomes unreachable and `graph.c`'s reachability block clears
  `udp_confirmed` before the obfs frames arrive. A real network has a third
  node, and nothing clears it.

  **Reproduction** (new, `testing/transports/obfs-confirmed-peer-test.sh`,
  in `SHELL_SCRIPTS`): three nodes, `nodea` founder/acceptor at `-d5`,
  `nodeb` dialler, `nodec` keeping `nodeb` reachable through the mesh; come
  up on plain, wait for `udp_confirmed` **on the acceptor**, then
  `set PreferredTransports obfs` + `reload` + `disconnect nodea` on the
  running dialler. The acceptor's `udp_confirmed` for `nodeb` is asserted in
  six consecutive samples from the instant of the disconnect — that is the
  precondition the two-node test destroys, and a run that loses it to mesh
  reconvergence retries instead of reporting. PART 4 is the control: remove
  `nodec`, restart the dialler with the same configuration, and obfs comes up
  **even on the pre-fix image**. Against `tincstack/core:ad-pre`
  (`--expect-defect`): link stayed on `plain`, acceptor dropped 8 datagrams
  as `unknown source and/or destination ID`, dialler hit 1 authentication
  timeout, control reached `obfs` — `PASS(repro)`. Against the fixed build:
  `obfs`, 0 dropped, 0 timeouts — `PASS`.

  **Fix.** Ask whether the SPTPS path would actually claim the datagram
  before leaving it alone, instead of assuming it would. New
  `sptps_udp_addresses_known_nodes()` (net_packet.c, declared in net.h) runs
  exactly the identification `process_sptps_udp()` runs and nothing else: for
  a relay-capable peer (protocol option version ≥ 4 — every build that can
  speak obfs), an all-zero destination id means a direct datagram, otherwise
  both ids must resolve to known nodes. An obfs frame starts with its
  whitened nonce, so its destination id is neither zero nor a node we know
  and it falls through to the keyed check. `obfs_udp_try()`'s guard becomes
  `known && known->status.udp_confirmed && sptps_udp_addresses_known_nodes(...)`.
  **Steady-state cost, per datagram from a confirmed plain peer:** one
  six-byte `memcmp` for a direct datagram (the overwhelming majority), plus
  two O(log N) node-id splay lookups for a relayed one. No crypto, no
  per-node keyed trial, no change to the unknown-source path. The rejected
  alternative — keying the skip on an obfs dial being in flight — does not
  work, because the side that drops the frames is the **acceptor**, which has
  no dial of its own to key on. Residual: one frame in 2^48 whose first six
  bytes are zero is still handed to the SPTPS path and dropped; the handshake
  retries. Mis-claiming is not a hazard here — the keyed check is
  authenticated, so a real data packet cannot be taken for an obfs frame.

  **Neighbouring carriers, measured not argued.** The same harness with
  `CARRIER=sf` and `CARRIER=quic` passes on the **pre-fix** image
  (`tincstack/core:ad-pre`), so neither is shadowed by a confirmed plain
  peer: `transport_classify_udp()` claims an sf frame on its magic prefix and
  a quic packet on its version word or a live connection id, and neither ever
  calls `lookup_node_udp()`. `grep -rn udp_confirmed core/tincd/src` finds
  exactly one carrier-side use, the one fixed here.

- 🟡 **Rebuilding a plain path right after a single-flow link was torn down
  can take minutes** (stream AD, observed while building the harness above,
  **not investigated, not fixed**). With the link on obfs, `set
  PreferredTransports plain` + `reload` + restart of the dialler left the two
  nodes reconverging for **over three minutes** (measured once, at `-d5`):
  the acceptor kept sealing data to the restarted peer (`Cold-classified an
  obfs datagram from <acceptor> as nodea` on the dialler right after its
  restart), the dialler logged `Got ADD_EDGE from nodea for ourself which
  does not match existing entry`, and `udp_confirmed` did not come back on
  either side until the meta connection was re-established 3 min later. The
  reverse direction (plain → obfs) is fast. `carrier-switch-test.sh` does the
  same transition and passes inside its 90 s, so this is not a hard failure
  and may be a narrower race; it is recorded here because the new harness had
  to route around it (PART 4 restarts into the carrier rather than dancing
  back through plain). **Not proven:** whether the acceptor's obfs link state
  survives a peer restart when it should not, and whether the delay is
  bounded.

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
- ~~🟠 **`tinc invite` phones home to `tinc-vpn.org/host.cgi`** to discover the
  external address when no `Address` is configured (upstream behaviour).~~
  **Resolved 2026-09-16:** discovery is opt-in (`AddressDiscovery = yes`,
  `invitation.c get_my_hostname`, M2) and the Linux entrypoint writes
  `Address` from `PUBLIC_ADDRESS` (M6). Without both, `tinc invite` uses the
  local-address hint below and warns.
- ~~🟠 **The obfs session key did not rotate unless both peers happened to
  rekey together.**~~ **Found and resolved 2026-09-16 (coordination pass,
  verifying stream O's merged work):** `obfs_key_h()` cleared `ack_sent` only in
  the initiator, so a peer that had acknowledged the previous round never
  answered a fresh offer; the effective rotation period was the *larger* of the
  two nodes' `KeyExpire`. Measured (compose lab, obfs carrier, 80 s of 1 Hz
  ping, `obfs session key established` per side): `KeyExpire` 10 s / 3600 s →
  **1, 1** before, **5, 5** after; 10 s / 10 s → **5, 5** before, **12, 12**
  after; 0 % packet loss in every run. Fix: an offer (flag 0) re-arms the
  answer. Regression test: `platforms/linux/docker/obfs-rekey-test.sh` (new,
  in `make lint`). Note for the record: the documented rotation had **no test**
  before this — stream O's proofs covered the key's secrecy, nonces, replay and
  cold scan, but never that the key actually changes.
- ~~🟠 **The obfs link can fall back to the mesh-wide bootstrap key *after* the
  per-link session key was established, and stay there for up to one 30 s
  self-heal tick.**~~ **Resolved 2026-09-16 (stream W).** Found in the
  coordination pass, on master with streams O, U and P merged, while the host
  was loaded (three labs running): `obfs-test.sh` PART 4 reported `obfs session
  key established` on **both** ends yet the steady capture was **174 of 174
  datagrams decryptable** with the public-key bootstrap key (idle host: 0 of
  176). Root cause: `obfs_close()` decided whether to reset the shared per-node
  link from `node->connection`, but `terminate_connection()` (`net.c`) clears
  `node->connection` **before** it calls the carrier close hook — so when the
  owner is being closed `node->connection` is NULL, `superseded` is false, and
  the reset wiped the session a replacement connection had just negotiated (or
  was about to), leaving the link on the bootstrap key until the 30 s tick.
  **Fix (inside `obfs.c` only):** (a) the reset condition now scans the live
  `connection_list` for any *other* connection to the node (`superseded` is true
  whenever one survives), so a superseded/late close cannot wipe the survivor's
  session; (b) the send path self-heals — sealing under the bootstrap key on an
  active, authenticated link arms a 1 s one-shot timer (`OBFS_SELFHEAL_DELAY`,
  rate-limited one offer/s/link) that re-issues the `OBFS_KEY` exchange, so any
  link that did revert is back on a session key in ≈1 s, not up to 30 s (the
  30 s tick is kept as a backstop). Considered and **rejected** refusing to
  *send* under the bootstrap key once a session existed: it would black-hole the
  link during renegotiation to protect obfuscation only (SPTPS still encrypts
  the payload; the bootstrap leak is classification + transport-header
  forgeability, an availability-vs-unlinkability trade where availability wins).
  **Proof — deterministic before/after:** `core/tincd/test/fuzz/fuzz_obfs.c`
  self-test `selftest_close_preserves_session` reproduces the exact
  `terminate_connection()` ordering (owner closed with `node->connection` NULL
  while a sibling is on the list); it **aborts on the pre-fix `obfs_close()`
  condition** and **passes with the fix** (`run.sh check`, EXIT 1 → 0).
  Integration guard: `obfs-test.sh` PART 8 forces ≥ 10 connection replacements
  (both nodes `ConnectTo` each other) and asserts every replacement re-
  establishes a session key on both ends and that steady traffic is 0-of-N
  bootstrap-decryptable. **Live before/after, same lab, same idle host,
  2026-09-16** (obtained by accident: the proof silently defaulted to the
  pre-fix stream image, see the image-selector defect below, which turned the
  run into the "before" arm stream W had said it could not reproduce):
  `tincstack/core:ws-o` (pre-fix) → **6 of 10 replacements stuck on the
  bootstrap key for the full 120 s deadline, 673 of 1099 steady frames
  decryptable with the public-key bootstrap key, worst window 120 s, FAIL**;
  `tincstack/core:w` (post-fix), immediately after, same host, same lab names
  → **0 stuck, 0 of 1172 steady frames decryptable, worst window 1 s, PASS**.
  An earlier idle run of the post-fix image gave 0 / 1176, worst window 1 s.
  The deterministic unit before/after (`selftest_close_preserves_session`,
  aborts pre-fix, passes post-fix) still stands as the mechanism proof; the
  numbers above are the live confirmation, so stream W's "could not reproduce
  the live symptom, closure rests on the unit test" caveat is withdrawn — the
  symptom reproduces on demand on an idle host, 6 times in 10, on the pre-fix
  build.
- ~~🟢 **`testing/smoke/run.sh` silently tested whatever `tincstack/core:ws-f`
  happened to be.**~~ **Resolved 2026-09-16 (coordination pass):** it took
  `CORE_IMAGE`/`WSF_TAG` while every other proof takes `TINCSTACK_TAG`, so an
  invocation in the house style ran the stale stream-F image and failed on
  `scripts.tinc-up` — a feature that image predates — which reads exactly like
  a regression in the merged core (it cost one false alarm during the P/U
  merge). It now accepts `TINCSTACK_TAG`, defaults to `dev` instead of a
  stream tag, and fails loudly when the image does not exist. Proof:
  `LAB=dbg3 TINCSTACK_TAG=dev testing/smoke/run.sh` → `smoke: PASS … tincstack/core:dev`,
  exit 0.
- 🟡 **Local-address fallback for invitations is only a hint.** M1 added a
  last-resort fallback (default-route source address) so a zero-config node can
  invite without a TTY; behind NAT it yields a private address. It prints a
  warning; M6 must set `Address` from env for real deployments.
- 🟢 **YAML emitter adds a blank line after every literal block** (pre-existing
  cosmetic quirk of `emit_scalar_value`). Parses fine; round-trip is stable.

- ~~🟠 **`tinc reload` in YAML mode bounces every meta connection**~~ (observed
  by stream S, 2026-09-16, in the scripts lab): each reload logged `Host config
  file of <peer> has been changed` and closed the link. **Resolved 2026-09-16
  (stream P):** the upstream check `stat()`s `<confbase>/hosts/<peer>` and
  closes the link when the file is newer than `last_config_check`; in YAML mode
  that tree does not exist at all (`config_fopen()` materialises the record as
  text on every read), so the `stat()` failed and *every* peer looked changed on
  *every* reload. `reload_configuration()` (`net.c`) now compares the record's
  **content** in YAML mode: `yamlconf_host_digest()` (SHA-512/256 of the host
  text) against a per-connection snapshot (`connection_t.host_digest`) taken
  when the record is read (`id_h`) and refreshed through `config_host_written_cb`
  whenever the daemon appends to it itself (learned `Ed25519PublicKey`,
  `TlsFingerprint` pin — otherwise our own write read back as an operator edit).
  Classic mode keeps the upstream mtime behaviour unchanged. Note the defect was
  wider than "`tinc set` followed by a reload": `tinc set/add/del` sends
  `REQ_RELOAD` to the running daemon itself (`tincctl.c:2236,2272`), so a bare
  `tinc set` dropped every link. Proof `TINCSTACK_TAG=ws-p LAB=wsp
  platforms/linux/docker/reload-test.sh` (new, two-project lab, b on
  `PreferredTransports: [https, plain]`), same script on the pre-fix build
  (a1d60ad, `TINCSTACK_TAG=ws-p-pre LAB=wspre`): **before** — 3 no-op reloads +
  `tinc set PingInterval` + reload logged `Host config file of node_a has been
  changed` 3× and closed the link to node_a 3× (a closed its link to node_b 2×),
  tunnel ping **70 % packet loss**; **after** — `has been changed` 0×, `Closing
  connection with node_a` 0×, same socket (10) on b and (14) on a throughout,
  tunnel ping **0 % packet loss**, carrier still `https` on both ends. A real
  change (`tinc add node_a.Address <a-ip> 655` + reload) still logs exactly one
  `Host config file of node_a has been changed`, closes that one link and brings
  it back on `https`, tunnel PASS. Run twice, EXIT=0 both times.
- ~~🟠 **Windows cross-build broken by `decoy.c`**~~ **Resolved 2026-09-16
  (consolidation):** stream L's event-driven decoy included `<sys/socket.h>`
  directly, used `fcntl(O_NONBLOCK)` unguarded and `memmem()` (not in mingw);
  found by stream S. Fixed (system.h, `ioctlsocket(FIONBIO)` under
  `HAVE_WINDOWS`, local `mem_has()`); `core/Dockerfile.build-win` builds
  `tincd.exe`/`tinc.exe` again (PE32+, DLLs: ADVAPI32, IPHLPAPI, KERNEL32,
  msvcrt, USER32, WS2_32); Linux `tls-front-test.sh` PASS after the change.
- ~~🟠 **tinc-manager save is non-atomic** over the only copy of the private keys
  (truncate-in-place).~~ **Resolved in M7** (`yaml_config.atomic_write_text`,
  merge against the daemon's concurrent writes; tests listed in M7).
- ~~🟠 **tinc-manager daemon log grows unbounded** (rotation only at start; 13 MB
  observed).~~ **Resolved in M7** (`runtime.LogSink`, 2 MB × 2 backups while
  running; tests listed in M7).
- ~~🟠 **tincapp CMake points at a missing path** → last APK was vanilla tinc, not a
  fork.~~ **Resolved in M8:** CMake dropped, `platforms/android/native/build-core.sh`
  does an NDK meson cross-build of `core/tincd` per ABI (proof in M8).
- 🟠 **`tls.c` needs OpenSSL 3.0, so the documented Android `openssl` build does
  not compile.** Found by stream Y, verified in the consolidated tree:
  `core/tincd/src/tls.c:165` calls `EVP_EC_gen("P-256")` and `tls.c:327`
  `SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION)`. Neither exists in the
  LibreSSL 3.7.3 that `platforms/android/native/build-core.sh` cross-builds, so
  `-PtincCrypto=openssl` fails with *3 errors generated* / `BUILD FAILED`.
  LibreSSL 4.1.0 adds `SSL_OP_NO_RENEGOTIATION` but still not `EVP_EC_gen`, so
  bumping the dependency is not the fix. Second half of the same gap:
  `build-core.sh` builds and installs only **libcrypto**, and its generated
  `openssl.pc` requires only libcrypto, so a `tls.c` that did compile would not
  link. **Impact:** the Android APK can only be built `--crypto nolegacy`
  (SPTPS/Ed25519, no legacy RSA protocol), which is what stream Y's proof used;
  a device that needs the legacy protocol has no working build. Fix belongs to
  the core: an OpenSSL-1.1/LibreSSL fallback in `tls.c` plus a libssl build in
  `build-core.sh`. Details and measurements under M8 "Found during M8".
- 🟠 **The core cannot write keys where `tmpfile(3)` has nowhere to go.**
  `zeroconf.c` → `capture_pem()` → `yamlconf_content_fp()` → `tmpfile()`
  (`yamlconf.c:593`). bionic's `tmpfile()` uses `$TMPDIR` and otherwise
  `/data/local/tmp`, which an Android app UID cannot write, so `tinc join`
  failed with *Could not serialise Ed25519 private key* / *Invitation
  cancelled* while the inviter logged the invitation as sent. Measured by
  stream Y: the same command with `TMPDIR=<app cache>` succeeds. Worked around
  app-side (`Executor.run` sets `TMPDIR`), but the core should fall back to its
  own config or run directory instead of depending on an environment variable —
  the same trap waits on any sandboxed or read-only-/tmp deployment.
- 🟢 **`tincmgr.exe` is not bit-reproducible.** PyInstaller stamps timestamps
  into the PE and its archive, so two identical runs give the same size and
  different SHA-256 (stream X measured 57 665 248 B with two distinct digests;
  a third run here produced 57 665 247 B). A published digest pins one
  artefact, never the recipe — do not present it as a reproducibility claim.
- ~~🟠 **A node cannot refuse cleartext tinc on its listening port.** Found in the
  consolidation pass while writing up stream P's carrier ranking; no fix
  attempted, because the answer is a design decision, not a patch.
  Two independent places force it:
  1. `transport_read_config()` (`transport.c`) adds `plain` back to the accept
     mask whatever `Transports` says, with only a warning: *"Transports omits
     `plain'; it is always accepted (upstream peers and the control connection
     need it)"*.
  2. Even without that, the front classifier's `TCP_CLASS_TINC` branch sets
     `c->transport = &transports[TRANSPORT_PLAIN]` and returns `true` **without
     consulting `transport_accept_mask` at all**, unlike the `TCP_CLASS_TLS`
     branch right below it, which does check the mask for `https`.

  **Impact.** Secrecy is unaffected: every carrier wraps SPTPS and SPTPS is
  never bypassed, so a plain meta connection is still authenticated and
  encrypted. What is lost is the thing this project exists for. An operator who
  configures `Transports: [obfs]` because the node sits behind a DPI box still
  answers an unadorned tinc handshake on its port, so the node stays
  fingerprintable as tinc by anyone who can reach it — a probe, not a
  man-in-the-middle, is enough. "Circumvention is opt-in" (guardrail 5) is not
  the same as "cleartext is mandatory".

  **Reproduction.** Set `Transports: [obfs]` on a node, restart, watch the
  warning, then open a plain tinc meta connection to its port from a peer whose
  own `PreferredTransports` is `plain`: it is accepted and activated.

  **Options, for the owner to choose between:** (a) keep `plain` forced but
  scope the force to the control connection and to peers that advertise no
  carrier set, so the *listening socket* can still refuse it; (b) add an
  explicit `AllowPlainMeta = no` so refusing is a deliberate act rather than a
  side effect of an accept list; (c) leave it and document the limit loudly in
  `docs/transports.md`. Whichever is chosen, the `TCP_CLASS_TINC` branch has to
  consult the mask like the TLS branch does — that asymmetry is a bug on its
  own terms.~~ **Resolved 2026-09-16 (stream Z): option (b), `AllowPlainMeta`,
  default `yes`.** Core patch 6 in `core/tincd/PATCHES.md`; option documented in
  `docs/config-schema.md` and `docs/transports.md` §2.1.

  **What was implemented.** A new server option **`AllowPlainMeta`** (boolean,
  **default `yes`**, so every existing network behaves exactly as before,
  warning text included; parsed in `transport_read_config()`, registered in
  `tincctl.c variables[]` as `VAR_SERVER`, re-read by
  `setup_myself_reloadable()` like `Transports`/`SingleFlow`). It is
  deliberately **not** `VAR_SAFE` and **not** in `PROPAGATED_OPTIONS`: a
  per-node listener policy must not be settable by an inviter. `no` drops
  `plain` from the effective accept mask. All three forcing sites were fixed,
  not just the two the entry named:
  1. `transport_read_config()` no longer forces `plain` unconditionally;
  2. the `TCP_CLASS_TINC` branch now consults `transport_accept_mask` exactly
     like `TCP_CLASS_TLS`, logs the reason and **tarpits** the socket, so the
     refusal is indistinguishable from an unrecognised preamble (no RST, no
     banner). **Loopback is exempt**: on Windows the tinc CLI reaches its own
     daemon over TCP to this port with `0 ^<cookie>`, and locking the operator
     out would buy nothing;
  3. the dialler-side mirror, found while fixing the above: `ack_h()`
     (`protocol_auth.c`) stored a peer's advertised list as
     `mask | TRANSPORT_MASK_PLAIN` and `transport_node_read_config()` did the
     same for a host record, so a peer that refuses `plain` was still dialled
     on `plain`. Both now take the list as written.

  **Measured** (2026-09-16, `tincstack/core:z`, new proof
  `testing/transports/plain-refuse-test.sh`, `make lint` clean):
  - *before / default*: the plain link comes up, `Transports
    accept=plain,sf,obfs,https,quic`, and a raw TCP prober on a third address
    sending `0 nodea 17.7` gets `0 nodeb 17.7` back — the fingerprint this
    entry described, reproduced;
  - *after*, nodeb with `AllowPlainMeta: no`: `Transports
    accept=sf,obfs,https,quic`; the same prober gets **nothing**; nodeb logs
    `WARNING Front: refusing cleartext tinc meta connection from
    10.37.155.50 port 60508: `plain' is not in this node's Transports accept
    list (AllowPlainMeta = no)`; an `obfs` link from nodea to the same node
    activates and pings **0 % loss (4/4)**; nodea's view of nodeb's accept list
    is `sf,obfs,https,quic` (no plain); `tinc dump nodes` on the refusing node
    still works;
  - *the trade-off, measured on the same lab*: `tinc join` against nodeb while
    it refuses plain →
    `Timed out waiting for the server to reply. / Cannot read greeting from
    peer / Could not connect to inviter.`, with the refusal line in nodeb's
    log;
  - *reload*: `tinc set AllowPlainMeta yes` + `tinc reload` puts `plain` back,
    the prober is answered again **and the same `tinc join` now succeeds**
    (`Invitation successfully accepted.`), without a restart;
  - *no regression on the defaults*: `platforms/linux/docker/two-nodes.sh`
    (`LAB=wsz TINCSTACK_TAG=z`) → `PASS: two-node tunnel up` (so `tinc join`
    over plain is unaffected by the default); `testing/smoke/run.sh` → `smoke:
    PASS (cross-node ping both ways, YAML mode, tincstack/core:z)`;
    `testing/transports/obfs-test.sh tincstack/core:z` → see below.

  **Trade-off the owner needs to see: `tinc join` against a node that sets
  `AllowPlainMeta: no` does not work.** `invitation.c` opens a raw TCP socket
  and sends `0 ?<key> ...` in cleartext — it has to, the invitee holds no key
  material yet — so it is classified `TCP_CLASS_TINC` and refused like any
  other cleartext meta connection. Same for upstream (unmodified) tinc peers
  and for any tincstack peer whose `PreferredTransports` is the default
  `[plain]`: a peer must opt into a wrapped carrier of its own to reach such a
  node. Invite from a node that still allows plain, or flip the option off for
  the duration of the join. This is why the default is `yes`, and it is the
  reason option (b) is a switch and not the new default behaviour.

  **Residual, not fixed:** the node's *own host record* still says
  `Transports = plain, sf, obfs, ...` (written by `zeroconf.c` at creation), so
  `tinc dump nodes` prints that for `MYSELF` and a peer that has only the host
  record tries `plain` once before learning the truth from an ACK. Set
  `Transports` to match if the first attempt matters. Documented in
  `docs/transports.md` §2.1.
- 🟢 **Carrier ranking lets a peer impose more wrapping than you asked for**
  (`transport_outranks_connection`, fixed order `plain < sf < obfs < https <
  quic`). A node whose `PreferredTransports` is `plain` keeps an inbound `quic`
  link instead of its own dial. This is deliberate ("more wrapping wins, and
  both ends compile the same table so nothing is negotiated") and it is bounded:
  the dialer's candidates are filtered by the mask the target advertises, so
  removing a carrier from `Transports` does stop it — for every carrier except
  `plain`, which is the item above. Recorded so the asymmetry is not rediscovered
  as a defect: local preference loses to a remote peer's, silently.
- 🟡 **YAML write-back re-emits the whole file**, dropping comments/formatting;
  editors must not rely on comment round-tripping. Documented in schema.
- ~~🟡 **sendmmsg relay batching measured worse** by its author. Keep default-off or
  drop; do not present as a feature (Architecture §10).~~ **Resolved 2026-09-16
  (this session): dropped.** The "default-off" was fiction — the batching was
  gated on `HAVE_SENDMMSG`, which meson finds on every Linux host, so it was
  built and live in every image. Its own measurement is 0.041 vs 0.0376
  ticks/pkt, i.e. ~9 % *worse* at ~2000 pps, because `recvmmsg()` returns 1–2
  packets per call at that rate and the in-batch `memcpy` is pure cost. Keeping
  it would mean a second code path with 64 × `MAXSIZE` of static state in the
  relay hot path plus a second build configuration to test. Removed:
  `tx_batch_*`, the `send_sptps_data()` hook, the two receive-loop brackets and
  the `sendmmsg` meson probe (`core/tincd/PATCHES.md` §4 keeps the negative
  result and the `16eb7bc` reference).
- ~~🟠 **`set -o pipefail` + `| grep -q` made seven test scripts report the
  opposite of what they measured.**~~ **Found and resolved 2026-09-16
  (coordination pass, chasing the red `obfs-rekey-test` after stream W).**
  `grep -q` exits on its first match, the producer on the left of the pipe gets
  SIGPIPE, and under `pipefail` the whole pipeline then fails *because* the
  pattern was found. It only bites once the producer's output is large enough
  that it is still writing when grep leaves, which is why these scripts worked
  for weeks and then "broke". Reproduction, on a real 8061-byte compose log
  containing two matching lines: `docker compose -p <p> logs node | grep -q
  ' Ready$'` → **exit 255**, `... | grep -c ' Ready$' >/dev/null` → **exit 0**.
  Impact by site: `obfs-rekey-test.sh` `wait_ready()` could never return after a
  restart, so the test failed as soon as the pre-restart log passed a few KiB —
  the *whole* red result attributed to host load was this, and stream W's "load"
  explanation for it was wrong; `two-nodes.sh`, `reload-test.sh` and
  `yaml-scripts.sh` carried the identical `wait_ready` and were one log-growth
  away from the same false failure; `testing/smoke/run.sh` (the CI gate) had it
  in two *assertions*, where it can produce both a **false FAIL** (line 113,
  `Wrote script \`tinc-up'` present but reported missing) and a **false PASS**
  (line 114, `built-in tinc-up` present but the guard swallowed by the SIGPIPE
  exit); `platforms/android/docker/emulator.sh` and `join-on-emulator.sh` had it
  on `docker ps` / `docker logs` / `adb shell`. **Fix:** every presence test in a
  `pipefail` script is now `| grep -c PATTERN >/dev/null` — `grep -c` reads to
  EOF, so no SIGPIPE, and still exits non-zero only when the count is zero — with
  a comment in each file naming the trap. `obfs-rekey-test.sh` additionally
  counts `Ready` lines *before* restarting and waits for `n+1`, so it can no
  longer be satisfied by the previous boot's log, and its failure path prints the
  count, the CLI error and the container state instead of nothing. Audit:
  `grep -ln pipefail $(git ls-files '*.sh')` × `| grep -q` → zero remaining
  sites. `make lint` (shellcheck, 24 scripts) exits 0.
- ~~🟠 **The transport proofs silently tested the stream image they were written
  against, not the core you asked for.**~~ **Found and resolved 2026-09-16
  (coordination pass).** `obfs-test.sh`, `singleflow-test.sh` and
  `matrix-test.sh` took the image only as `$1` (`IMG=${1:-tincstack/core:ws-o}`
  and friends) and ignored `TINCSTACK_TAG`, the selector every other proof and
  both Linux labs take; `tls-front`, `https-carrier` and `quic-carrier` honoured
  the variable but still fell back to `ws-l` / `ws-g3`. Reproduction and impact:
  `TINCSTACK_TAG=w LAB=wso2 ./obfs-test.sh` ran **`tincstack/core:ws-o`**, a
  months-old build, and returned FAIL on PART 8 — reported against a core that
  passes it. This is the same papercut as the `testing/smoke/run.sh`
  `CORE_IMAGE` one below, and it is worse than a wasted run: a stale image can
  also report a *pass* for a regression the current tree has. **Fix:** every
  proof is now `IMG=${1:-tincstack/core:${TINCSTACK_TAG:-dev}}`
  (`matrix-test.sh`: `dev-test`, it needs `-Dtransport_test=true`), with the
  reason in each header and `testing/transports/README.md` updated to build
  `dev` / `dev-test` / `dev-noquic`. The accidental run was not wasted: it is
  the pre-fix arm of the live before/after now recorded against stream W above.
- ~~🔴 **`tinc disconnect` killed the re-dial it had just started, so the carrier
  of a running node could not be changed.**~~ **Found 2026-09-16 (owner),
  resolved 2026-09-16 (stream AA).**
  **Reproduction** (two node-image containers on one docker network, `a`
  founding with `PORT=655`, `b` joined by invitation, both on the released
  v0.1.1 build and on a locally built one):

      docker exec b tincstack-cli set PreferredTransports obfs
      docker exec b tincstack-cli reload
      docker exec b tincstack-cli disconnect node_a

  b logged, all inside one second, at `-d5`:

      INFO  Carrier candidates for node_a: obfs,plain (… last activated plain)
      INFO  Dialling node_a (10.77.3.2 port 655) via obfuscated single-flow UDP
      INFO  Connected to node_a (10.77.3.2 port 655)
      DEBUG Sending ID to node_a: 0 node_b 17.7
      NOTICE Closing connection with node_a      <-- no error line, at any level
      INFO  Carrier obfs failed for node_a, falling back to plain

  and settled on `transport plain`; `sf`, `https` and `quic` behaved the same.
  The control — `docker restart b`, the *same* configuration read at startup —
  came up on `transport obfs` at once.
  **Root cause** (not the reload path, which was measured innocent: with the
  same config already reloaded, closing the link from the *other* node's side
  put b straight onto obfs). `control.c` `REQ_DISCONNECT` walked
  `connection_list` while `terminate_connection()` was appending to it:
  terminating an outgoing connection re-dials on the spot
  (`do_outgoing_connection()`), `connection_add()` puts the replacement at the
  tail of the very list the loop is walking, `list_each` reaches it, the name
  matches a second time — and the fresh dial is terminated before its ID line
  is answered. Never activated, so `transport_next_candidate()` read it as a
  carrier failure and fell back. It bit only when the address cache could
  serve an address immediately (`get_recent_address()`, i.e. after a
  confirmed UDP path); otherwise the re-dial was deferred 5 s to
  `retry_outgoing()`, outside the loop, and the switch appeared to work —
  which is why this looked like a reload defect.
  **Fix** (`core/tincd/src/control.c`): snapshot the matching connections,
  then terminate the snapshot, skipping any that an earlier termination
  already freed. Plus two hardening changes: `terminate_connection()`
  (`net.c`) now logs *"Dial to X (…) via <carrier> abandoned before the
  connection was activated"* at DEBUG_CONNECTIONS, so "Carrier X failed" is
  never unexplained, and `disconnect` names itself
  (*"Disconnecting X (…) on operator request"*); and
  `transport_read_config()` (`transport.c`) now runs the `init` hook of a
  carrier that a reload has just added to `Transports` (they used to run once,
  at startup, for the startup accept mask only — a latent gap found while
  checking the suspects, dropping the carrier from the accept mask with an
  error if its init fails rather than taking the daemon down).
  **Measurements** (`tincstack/core:aa`, containers `wscs-*`):
  `testing/transports/carrier-switch-test.sh` — new, in `SHELL_SCRIPTS`,
  shellcheck-clean — restarts b on `plain`, waits for `udp_confirmed` (the
  precondition that makes the re-dial immediate, without which the bug cannot
  bite and the test would pass vacuously), then does `set` + `reload` +
  `disconnect`: **PASS** for `plain→obfs`, `plain→sf`, `plain→https`,
  `plain→quic` and `obfs→plain`, each activated on the requested carrier with
  a 0 %-loss tunnel ping, `disconnect` logging its reason 5×. The same script
  on a core built from `master` (988b8bd, `tincstack/core:aa-master`):
  **FAIL** — `plain→obfs`, `plain→sf`, `plain→https` each `got 'plain'` and
  `1x 'Carrier <c> failed'`, and `disconnect` logged nothing. The new
  diagnostic shown in a live failing case (UDP to a DROP'd with iptables):
  `Dial to node_a (…) via obfs abandoned before the connection was activated`
  → `Carrier obfs failed … (1/3) but worked before, retrying it`.
  Regressions re-run against the same image, all PASS:
  `platforms/linux/docker/reload-test.sh`, `two-nodes.sh`,
  `testing/smoke/run.sh`, `testing/transports/obfs-test.sh`,
  `testing/transports/quic-carrier-test.sh` (with `tincstack/core:aa-noquic`),
  `make lint`.
  **Three things this fix does not prove, kept here rather than in a report
  nobody will re-read:**
  1. The `transport.c` change that runs a carrier's `init` hook when a reload
     *widens* `Transports` is **reasoned, not measured** — it compiles and
     regresses nothing, but no test starts a node with a narrow `Transports`
     and widens it, so the failure it guards (https/quic dialling with
     uninitialised TLS state) has never been observed or reproduced.
  2. `carrier-switch-test.sh` restarts the invitee and waits for
     `udp_confirmed` before each switch, because the defect only bites when
     `get_recent_address()` can hand the re-dial an address immediately;
     without that wait the re-dial is deferred 5 s to `retry_outgoing()`,
     outside the offending loop, and **the test passes on the broken tree** —
     the first version of the script did exactly that. If the wait times out
     the case reports MISS rather than a pass, and on the master control run
     one case (`plain→quic`) did time out, so the FAIL on master rests on
     three carriers plus the missing diagnostic, not four.
  3. `disconnect` against a peer holding two simultaneous connections (the
     `ack_h()` "second connection" case) is unmeasured; the snapshot plus
     liveness check is written for it.
- ~~🟠 **Defect C — two invitees of the same node never peer directly; every
  leaf-to-leaf packet is relayed through the inviter, forever.**~~ Found
  2026-09-16 on the real three-host stand (ruvds2 = founder,
  `laptop` = NATed workstation, `euvds` = public VPS, all
  `ghcr.io/…/node:v0.1.1`, each joined with an invitation issued by ruvds2;
  a fourth node, the aarch64 `router` at 10.170.0.4, reproduced it too and gave
  the sharpest number: the router is the workstation's own LAN gateway — both
  appear to the founder as 79.139.184.85 — and their tunnel traffic was still
  relayed through a VPS in another country, **33.4 ms** where the wire is
  sub-millisecond; router→euvds 61.3 ms, router→ruvds2 (its only direct link)
  26.7 ms. **Closed 2026-09-16 (stream AC).**

  **Reproduced in the lab, then measured against three controls.** The new
  harness `testing/transports/invitee-mesh-test.sh` stands up the same topology
  in three containers (founder invites both leaves; neither leaf is ever given
  a host record for the other — the script asserts that before it starts) and
  has two modes: `--expect-defect` asserts the pre-fix behaviour, the default
  asserts the fix.
  - `LAB=wsacimd testing/transports/invitee-mesh-test.sh tincstack/core:ac-base
    --expect-defect` → `PASS(repro)`, with the field log lines verbatim:
    `ERROR Cannot open config file /etc/tincstack/tincstack/hosts/leaf2: No
    such file or directory` → `ERROR Peer 10.33.19.12 port 53702 had unknown
    identity (leaf2)` → `WARNING Timeout from leaf2 (…) during authentication`
    → `ERROR Could not set up a meta connection to leaf2` repeating on every
    retry, and `dump nodes` on both leaves ending at
    `nexthop founder … distance 2 … transports plain`.
  - **Control 1 — same binary, classic `tinc.conf` + `hosts/` + `tinc invite` /
    `tinc join`, no YAML:** identical, line for line
    (`Cannot open config file /usr/local/etc/tinc/tincstack/hosts/leaf2` →
    `Peer 10.45.9.12 port 39720 had unknown identity (leaf2)` →
    `Timeout … during authentication` → `Could not set up a meta connection`,
    `distance 2` both ways).
  - **Control 2 — upstream tinc 1.1pre18 (`tincstack/baseline:ws-f`), classic
    config, same topology:** identical again (`Peer 10.46.9.12 port 56584 had
    unknown identity (leaf2)`, backoff 5→10→15→20 s, `distance 2`).
  **Verdict: none of the three symptoms is YAML-mode-specific.** All three are
  upstream tinc 1.1 behaviour; YAML mode only changes the text of the path in
  the message, because `config_fopen()` (conf.c) returns `ENOENT` for a node
  with no `hosts:` section exactly as the filesystem does for a missing file.
  Source diff confirms it: `address_cache.c` differs from upstream only in the
  splay/`init_configuration` API churn and a `free(ai->ai_addr)` leak fix, and
  `do_outgoing_connection()` / `setup_outgoing_connection()` / `id_h()`'s
  `unknown identity` branch are upstream's.

  **Three independent causes, all upstream, all fixed here:**
  1. *The acceptor rejects a name it knows from the graph* — `id_h()`
     (`protocol_auth.c`) required `read_host_config()` to succeed. A host
     record is not what authenticates a peer; the Ed25519 key is. `id_h()` now
     falls back to the key the graph gave us (`ecdsa_from_graph()`, fed by
     ANS_PUBKEY over already-authenticated meta links) and lets the SPTPS
     handshake prove possession of it — **SPTPS/Ed25519 is not bypassed, it is
     the gate**: a node whose key we do not have is still refused, and the
     version-rollback check is untouched. When the key is missing we now ask
     for it over the graph (`send_req_pubkey()`, rate-limited to one request
     per node per 5 s so an unauthenticated stranger cannot use this to flood
     a relay) and log the refusal at `DEBUG_CONNECTIONS`/`LOG_INFO` instead of
     `LOG_ERR`, because it is an expected transient, not an operator error.
  2. *The dialler silently downgrades to legacy RSA* — `send_id()`
     (`protocol_auth.c`) reads the peer's host record and, when it is absent,
     announces protocol **17.1** instead of 17.2, i.e. drops the meta
     connection from SPTPS/Ed25519 to legacy RSA, for which it has no key
     either. This is the second half of the field observation `Connected to
     euvds (88.218.122.166 port 655)` immediately followed by `Cannot open
     config file …/hosts/euvds` — the dialler path needs the record too, not
     just the ID handler. `send_id()` now takes the key from the graph by the
     same `ecdsa_from_graph()` and stays on 17.2; a `nolegacy` build could not
     even have tried the downgrade.
  3. *The address cache is single-shot* — `get_recent_address()` consumes the
     persisted cache, then the addresses the graph advertises, then the
     `Address` statements, and rewinds only on a *successful* connection
     (`pong_h`) or when the carrier walk moves on. A peer known only from the
     graph has no `Address` statement, so after its single graph-derived
     candidate is spent every retry logs `Could not set up a meta connection`
     **without opening a socket** — which is why the AutoConnect backoff
     (5→10→15→20→25→30 s) ran out with nothing to show. `retry_outgoing()`
     (`net_socket.c`) now rewinds the cache; the backoff it just extended is
     what bounds the attempt rate, so this is a handful of addresses per retry,
     not a storm.
  Plus two things that follow from them: `setup_outgoing_connection()` defers a
  dial to a peer whose key it does not have (that dial is provably unauthenticable)
  and asks for the key instead — **bounded**: only while the backoff is under
  30 s, after which it dials anyway rather than stalling the `outgoing_t`
  silently; and the "host record is absent" message, which `read_host_config()`
  already marks non-verbose, moved from `LOG_ERR` at `DEBUG_CONNECTIONS` (i.e.
  visible at the default `-d1`, several lines per dial attempt, forever) to
  `LOG_DEBUG` at `DEBUG_PROTOCOL`. `node_read_ecdsa_public_key()`
  (`net_setup.c`) is a lazy probe and now reads quietly for the same reason;
  every verbose caller (fsck, `tinc export`, the explicit key reads) is
  unchanged.

  **Proof (`LAB=wsacimz testing/transports/invitee-mesh-test.sh
  tincstack/core:ac`, EXIT 0):**
  `l1: leaf2 is DIRECT (distance 1, nexthop leaf2)`,
  `l2: leaf1 is DIRECT (distance 1, nexthop leaf1)`,
  `dump edges` carries `leaf1 to leaf2` and `leaf2 to leaf1`, and — the part
  that rules out a relay — **with the founder container stopped** both pings
  are `3 packets transmitted, 3 received, 0% packet loss` (0.117–0.230 ms).
  Neither leaf logs `unknown identity`, `Could not set up a meta connection to
  <peer>` or `Timeout from <peer> … during authentication`; the only ERROR left
  in either log is the founder we deliberately killed. Convergence is one relay
  round trip: `Deferring the dial to leaf2 until its Ed25519 key arrives over
  the graph` → `Learned Ed25519 public key from leaf2` →
  `Connection with leaf2 … activated`, all in the same second.
  Carriers and onboarding re-checked on the same build:
  `testing/transports/matrix-test.sh tincstack/core:ac-test` PASS,
  `testing/transports/plain-refuse-test.sh tincstack/core:ac` PASS,
  `CORE_IMAGE=tincstack/core:ac testing/smoke/run.sh` PASS,
  `TINCSTACK_TAG=ac platforms/linux/docker/two-nodes.sh` PASS.
- ~~🟡 **Defect D — `Transports` is not propagated past one hop.**~~ Same
  stand, same `dump nodes`: ruvds2 listed both leaves as
  `transports plain,sf,obfs,https,quic`, but each leaf listed the *other* leaf
  as `transports plain` — the accept mask is learned from the ACK of a *direct*
  meta connection (`ack_h()`) and from the node's own host record, and nothing
  carried it over the graph, so the first direct leaf-to-leaf dial could only
  ever offer `plain`. **Closed 2026-09-16 (stream AC)**, because it did fall
  out cleanly once C was fixed and needed no new request type: the mask now
  rides on **ANS_PUBKEY** as one extra, space-free token
  (`protocol_key.c`, `transport_accept_string()` /`transport_parse_list()`).
  Upstream's parser is `sscanf(request, "%*d %*s %*s %*d " MAX_STRING, pubkey)`,
  which stops at the first whitespace, so an upstream or older-tincstack peer
  ignores the extra token and nothing on the wire changes for it; relays
  forward the request verbatim (`send_request(to->nexthop->connection, "%s",
  request)`), so an old node in the middle is transparent. The mask is
  **advisory, never a permission**: the acceptor still enforces its own
  `Transports`/`AllowPlainMeta`, so the worst a lying relay can do is provoke a
  dial the other end refuses — no worse than today's unconditional `plain`.
  Proof: in the fixed run both leaves show
  `transports plain,sf,obfs,https,quic` for the other leaf, and the dialling
  leaf logs `Carrier candidates for leaf1: plain (peer accepts
  plain,sf,obfs,https,quic)` **before** `Trying to connect to leaf1` — i.e.
  the mask was known at first-dial time, not learned afterwards from the ACK.
  `plain-refuse-test.sh` (which is the test for "a peer that refuses plain")
  still passes on the same build.
- 🟢 **First burst on a fresh relayed path loses its first two packets** —
  not part of defect C, and **not tincstack's**: measured 2026-09-16 (stream
  AC) on three builds, same lab, 5-packet bursts on a never-used path.
  `tincstack/core:ac-base` (pre-fix, relayed): `icmp_seq` 1 and 2 lost,
  **40 % of 5**, second burst on the same path 0 %.
  **Upstream tinc 1.1pre18** (`tincstack/baseline:ws-f`, classic config, same
  topology, tun addressed by hand): `icmp_seq` 1 and 2 lost, **40 % of 5**,
  second burst 0 % — byte-for-byte the same symptom, so it is upstream
  behaviour (`try_sptps()` in `net_packet.c` requests the SPTPS key on the
  first packet that needs it and nothing is queued while the handshake runs;
  tincstack differs there only in the documented 30 s ± jitter cooldown vs
  upstream's fixed 10 s). It matches the field numbers (2 of 5 on the router,
  2 of 10 on the three-host stand). Fixing defect C removes it for an invitee
  pair as a side effect: on `tincstack/core:ac` the same first burst over the
  now-direct path is **0 % of 5**, `icmp_seq=1` at 0.226 ms, because the meta
  connection and its keys are already up before any traffic. It would still
  show on a genuinely new relayed path; queueing the first packets is a
  separate change and is **not** made here.
- ~~🔴 **obfs emits datagrams larger than the path MTU: the dial hangs and falls
  back to plain, and PMTU discovery never converges.**~~ **Found 2026-09-16
  between two real hosts over the internet (a VPS at 80.87.200.39 and a NATed
  laptop), resolved 2026-09-17 (stream AB).**
  *Symptom:* with `PreferredTransports: obfs` the dial hung ~5 s and fell back to
  plain; the acceptor logged
  `WARNING Error sending obfs datagram to laptop (...): Message too long`.
  *Reproduction (now deterministic and local):* put the pair on a docker network
  with `--opt com.docker.network.driver.mtu=1400`. With
  `ObfsInitHeaderJunkSize: 1400` the released core logs four
  `Error sending single-flow frame: Message too long` (the SF SYN and its three
  retries, 0.5 + 1 + 2 s) and then `Carrier obfs failed for nodeb, falling back
  to plain`. `testing/transports/obfs-mtu-test.sh` is that lab; run against
  `tincstack/core:aa-master` (= the v0.1.1 release code) it reports
  `MISS: the obfs carrier failed and fell back (the defect)`, 8 EMSGSIZE lines,
  and `PMTU discovery did not converge on the 1500-byte lab`.
  *Root cause:* tinc sets `IP_MTU_DISCOVER`, so an oversized datagram is refused
  with EMSGSIZE rather than fragmented, and **every** obfs size was clamped
  against a constant instead of the path. Three components pushed datagrams over
  the path, and the third was broken on **every** path, 1500-byte docker bridges
  included:
  (a) `ObfsInit/TransportHeaderJunkSize` — tail padding clamped only to
  `OBFS_MAX_JUNK` (1400), so a handshake frame could reach 24 + 1200 + 30 + 1400
  = 2654 bytes and no SF frame of a dial could ever go out;
  (b) `ObfsJunkPacketMaxSize` — standalone junk up to 1400 + 28 = 1428 bytes on
  the wire, over a 1400-byte path, and `obfs_send_junk()` broke out of its loop
  on the error *without a log line*;
  (c) the 26/30-byte seal itself on a full-size SPTPS datagram —
  `choose_initial_maxmtu()` sizes a tinc packet so the datagram is *exactly* the
  path MTU and knows nothing about a carrier, so the seal always overshot by 26,
  and `obfs_wrap_send()` swallowed the EMSGSIZE (logged at `DEBUG_TRAFFIC`,
  never fed to `reduce_mtu()`), so every top-end PMTU probe was lost silently
  and discovery never converged. Measured on a plain 1500-byte lab with the
  release image: 2-4 `Message too long` lines and **no** `Fixing MTU` line at
  all within the observation window.
  *Fix (stream AB):* a per-link **path budget** — the kernel's route MTU toward
  the peer (`getsockopt(IP_MTU)`/`IPV6_MTU` on a throwaway connected socket, the
  same source `choose_initial_maxmtu()` uses, so it also follows an ICMP-learned
  PMTU), cached 10 s, falling back to 1280 (the IPv6 minimum) when the kernel
  will not say. Junk is sized to fit rather than dropped: `obfs_max_inner()`
  reserves the configured junk *before* the payload and `transport_sf.c` chunks
  the meta stream against it, so shaping costs one extra segment, not a lost
  datagram; junk yields only below a 256-byte payload floor. The data path
  cannot chunk, so `obfs_wrap_send()` now returns `OBFS_SEND_TOOBIG` with the
  exact overshoot and `send_sptps_data()` feeds it to `reduce_mtu()` — the same
  contract the quic carrier already had, except the overshoot is exact, so
  discovery converges in one probe. A kernel EMSGSIZE that still happens is
  logged at `DEBUG_ALWAYS` with the size and the re-queried budget; an SF frame
  the path refuses fails the session at once (`sf_send_frame`) so the carrier
  fails over immediately instead of after 3.5 s of apparent hang. Obfuscation is
  not weakened: junk is made to fit, never removed, and SPTPS/Ed25519 is
  untouched.
  *Measurements (tincstack/core:ab):* `obfs-mtu-test.sh` PASS — 1400-byte path
  with junk at the ceiling: obfs carrier up, 0%/0% loss, 0 EMSGSIZE, junk still
  emitted, largest datagram on the wire **1372 bytes = exactly the budget**,
  `Fixing MTU ... to 1273 after 1 probes`; 1280-byte path: up, 0%/0% loss, 0
  EMSGSIZE; 1500-byte path: 0 EMSGSIZE, `Fixing MTU ... to 1413` (below the 1443
  a plain link reaches — the seal accounted for). Regression: `obfs-test.sh`
  8/8, `classify-test.sh`, `testing/smoke/run.sh`, `two-nodes.sh`, fuzz
  `build`+`check` (incl. `fuzz_obfs` self-tests) all pass.
  *Residual:* on a platform without `IP_MTU`/`IPV6_MTU` (Windows) the budget is
  the 1280-byte assumption, so junk there is capped lower than the path could
  carry — safe, but conservative. A middlebox that drops oversized datagrams
  without sending ICMP is invisible to the kernel's route MTU; tinc's own PMTU
  probing (which now converges) covers the data path, and the meta path relies on
  a sealed SF frame being at most 1254 bytes, i.e. any path of >= 1282 bytes.
- 🟡 **`quic` never emits an oversized datagram, but tinc's PMTU discovery over
  it does not converge on a reduced-MTU path.** Measured 2026-09-17 (stream AB)
  on the same lab, `PreferredTransports: [quic, plain]`, `tincstack/core:ab`:
  - MTU 1500: ping 0%/0% loss, 0 EMSGSIZE, `Fixing MTU ... to 1367 after 1
    probes` within ~11 s.
  - MTU 1400 (three runs): 0 EMSGSIZE — `quic_send_datagram()` bounds every
    datagram by `ngtcp2_conn_get_max_tx_udp_payload_size()` and never hands an
    oversized one to the socket, so the obfs defect above has no quic analogue.
    But **zero** `Fixing MTU` lines in ~2.5 minutes on either node, and the
    tunnel took 58 s to reach a clean 4-packet run (20-100% loss before that,
    with connection churn: "Established a second connection ... closing old
    connection", "Could not set up a meta connection").
  *Cause:* the hook returns a bare `false`, and `send_sptps_data()` answers with
  `reduce_mtu(relay, origlen - 1)` — one byte per failed probe. `maxmtu` starts
  at `choose_initial_maxmtu()` (1343 on a 1400-byte path) while QUIC's
  conservative initial datagram ceiling is ~1165, so discovery needs ~180
  single-byte steps. Traffic still flows (records below the ceiling go through),
  so this is slow/never-finishing discovery, not a dead tunnel.
  *Not fixed here, deliberately:* the fix is the same one obfs just got — report
  the overshoot instead of a bare boolean — but that changes the shared
  `send_datagram` hook signature in `transport.h`/`transport.c` while stream AA
  is working in `transport.c`. Small, but not safely concurrent. Owner: whoever
  picks up the quic carrier next.
  *How much churn is quic's own and how much was the loaded host* (several other
  streams' labs were running) was not separated; the 1500-byte control run on the
  same host was clean, which is the reason for reporting it at all.
- ~~🟠 **Defect G — a severed direct path costs 31-61 s of blackout, and the
  "flaky" proof was measuring it.**~~ **Closed 2026-09-17.** `singleflow-test.sh`
  PART 2 (three nodes A-R-B; A and B get a direct link, then `iptables DROP`
  severs it and the pair must reroute through R) failed intermittently for
  weeks and was written off as a flake. It was not. Measured with 1-second
  granularity instead of the test's five 11-second attempts:

  | build | seconds to the relayed path, 8 runs |
  |---|---|
  | before (`tincstack/core:ae`) | 2, 2, 2, **37**, **36**, 2, **61**, **35** |

  Four runs in eight took 35-61 s. The old proof's budget was ~55 s, so it
  passed three of those four and failed the fourth — a defect with a
  probability attached, presented as noise. **Three independent causes, each
  found by measuring rather than guessing:**

  1. **sf burned its whole retransmission budget on a path the kernel had
     already refused.** After the sever, every `sendto` returned `EPERM`
     (`iptables -j DROP` on OUTPUT) — synchronous, local, unambiguous — and
     `transport_sf.c` logged it at `DEBUG_TRAFFIC` and carried on: 8
     retransmissions at RTO 0.5/1/2/4/4/4/4/4 = **27 s** during which the graph
     still believed the edge existed and routed `REQ_KEY` into it. Silence and
     refusal are not the same evidence. New `sockunreachable()` (`utils.h`:
     EPERM, EACCES, ENETUNREACH, EHOSTUNREACH, ENETDOWN, EADDRNOTAVAIL, and the
     WSA* equivalents); `sf_send_raw()` now returns *why* it failed, and after
     `SF_MAX_HARD_ERRORS` (3) **consecutive** refusals the session is declared
     dead — about 3.5 s. Consecutive on purpose: any send the kernel accepts
     and any frame that arrives resets the count, so a route that flaps and
     comes back is forgiven. Measured: the link now dies **1 s** after the
     sever instead of 27 s.
  2. **The REQ_KEY glare tie-break defended a session that had gone out over
     the dead path.** With (1) fixed the pair still took 31-35 s, and the log
     said why: `Got REQ_KEY from nodeb while our SPTPS session is pending;
     keeping ours (glare tie-break: we win)` — while B's request had arrived
     over the relay, which worked. The tie-break (stream K, patch 5) is correct
     for genuine glare and is unchanged for it; what was missing is that it
     assumed both sessions were equally viable. `SPTPS_GLARE_WINDOW` (5 s) now
     bounds it to real simultaneity.
  3. **Nothing noticed when the route changed under a pending key exchange** —
     and this, not age, was the real discriminator: both sides really did start
     within the same second, so (2)'s window did not fire. A key exchange rides
     the meta channel, i.e. whatever `nexthop` was when it started; when that
     route disappears the records went nowhere and no one retransmits them.
     `sssp_bfs()` now snapshots `nexthop` and, for a node still waiting for a
     key whose route changed, sets `status.sptps_route_stale`. The flag states
     one fact and nothing more; two places act on it and both clear it:
     `try_sptps()` restarts the exchange at once instead of waiting out the
     24-36 s cooldown, and the tie-break stops defending it. One mark per graph
     run, so a flapping edge costs one restart per flap, not a storm.

  **Result, same lab, same host:**

  | build | runs | 2-5 s | one cooldown (~31 s) |
  |---|---|---|---|
  | before (`:ae`) | 8 | 4 | **4** |
  | + fix 1 (`:sf2`) | 8 | 6 | 2 |
  | + fixes 2 and 3 (`:sf3`) | 62 | 61 | 1 |
  | `:sf4` | 12 | **12** | 0 |
  | shipped (`:sf5`) | 12 | **12** | 0 |

  Two corrections to my own fix 3, both found by reviewing the diff and the
  field, not by a test:
  - `:sf4` — `prev_nexthop` could name a node `net.c` had already deleted
    (`node_del` reaps unreachable nodes between graph runs) and the log line
    followed it. The snapshot is now taken only for nodes reachable as of the
    previous run, the pointer is compared and never dereferenced, and the field
    is cleared after use.
  - `:sf5` — after deploying `:sf4` to the four-host stand the router showed
    `status 20da` permanently: the mark survived the key exchange it described
    and stayed visible in `dump nodes`. Harmless in practice (`send_req_key()`
    clears it before every new exchange, and the flag is only read while
    `waitingforkey`, which implies that call ran), but a flag that outlives
    what it describes is a trap for the next reader. Both places that set
    `validkey` now clear it.

  Everything was re-measured on each build rather than carried over.

  **The residual was real and is now closed on the shipped build, 2026-09-17.**
  One run in 62 on `:sf3` still spent one SPTPS cooldown, and it could not be
  reproduced on demand (32 probe runs and 20 further test runs after the one
  that caught it were all 2-5 s), so its cause was never named. `:sf4` and
  `:sf5` were 12 of 12 fast each, which was **not** enough to claim it was gone
  -- 12 runs cannot see a 1-in-60 event -- so it stayed open.

  It was then measured properly: **250 sequential runs of PART 2 on
  `tincstack/core:sf5` (master e497541), zero slow runs.**

  | elapsed | 2 s | 3 s | 4 s | 5 s | 8 s | 9 s | >10 s |
  |---|---|---|---|---|---|---|---|
  | runs | 105 | 15 | 107 | 20 | 1 | 2 | **0** |

  250 of 250 PASS, worst case 9 s against a 31 s signature. Sequential on
  purpose (the quantity measured is a timing stall, so parallel labs must not
  contend for CPU) and at the harness's own `-d2`, the level the 62-run
  baseline was taken at; raising it would change the timing, which had already
  produced one wrong answer in this defect's history.

  **What that does and does not prove.** Zero events in 250 trials puts the 95 %
  upper bound on the rate at **1.19 %**, below the 1.61 % (1 in 62) that was
  observed; if the residual were still occurring at its old rate, the chance of
  250 clean runs is **1.7 %**. So the rate is rejected at roughly the 98 %
  level. It is *not* a named cause: no slow run occurred, so there was nothing
  to dissect. The closure is statistical, and it is recorded as such.

  **The most likely mechanism, stated as a hypothesis and not as a finding.**
  The residual was seen on `:sf3`, which carried a use-after-free in this
  change's own `graph.c` snapshot: `prev_nexthop` could name a node `net.c` had
  already reaped. A stale read there makes the route-change detection miss,
  and a miss is exactly a fall-through to the 24-36 s cooldown -- the ~31 s
  that was measured. `:sf4` fixed that read, and nothing has been seen since,
  over 274 runs on the two builds after it. Consistent with every measurement,
  and still only a hypothesis.

  PART 2 keeps the shape this investigation gave it: it *measures* the time,
  prints it on success, and distinguishes the two failures -- "came up, but
  only after Ns" from "never reached B", which is the relay path itself being
  broken. A budget of 20 s with a 120 s hard limit; both env-overridable. With
  the residual gone the budget no longer costs a failure per ~62 runs.
  `KEEP_LOGS` was added to the harness (d42a069) so that a future slow run is
  diagnosable: its advice was to read nodea's log, and cleanup used to delete
  the container first.

  **Regression** on `tincstack/core:sf3`: the NAT lab the tie-break was written
  for, `lab.sh glare --rtt 50` and `--rtt 1`, core arm **PASS key after 1 s, 0
  `Invalid packet seqno`, 0 SPTPS restarts, tie-break logged on both sides** —
  byte-for-byte the numbers stream K recorded, so (2) and (3) did not weaken
  it. (The `baseline` arm of that lab fails at `--rtt 1` and passes at
  `--rtt 50`; it is upstream 1.1pre18 with no tie-break at all and has nothing
  to do with this change — `lab.sh glare` exits non-zero whenever the control
  arm fails, which is what it is for.) Plus `singleflow-test` x3, `obfs-test`,
  `obfs-mtu-test`, `obfs-confirmed-peer-test`, `carrier-switch-test`,
  `invitee-mesh-test`, `plain-refuse-test`, `same-nat-meta-test`,
  `obfs-restart-test`, `smoke`, `make lint`.

  **`obfs-confirmed-peer-test.sh` failed once in that suite and it is not this
  change**, measured rather than assumed: 3 of 4 PASS on `:sf4`, 3 of 4 on
  `:ae` (the build before any of these fixes), and 4 of 4 on `:sf5`. It is the
  harness's own precondition -- it needs the acceptor to hold `udp_confirmed` through the
  dial and says so itself ("this attempt proves nothing, retrying") -- at a
  rate of roughly 1 run in 4. Worth tightening in that harness one day; it is
  not a daemon defect.
- **CPU and memory at 100 Mbit/s, against upstream tinc 1.1pre18, 2026-09-18**
  (`testing/perf/`, result in `testing/perf/results/2026-09-18-100mbit.csv`).
  Both daemons in one image, two netns on a veth pair, UDP load with a fixed
  datagram size, 0.433 Mpkt per 45 s run, `-d0`, cpuset 0-3, i9-10900K, 14
  paired repeats. **Every row records the carrier actually negotiated and all
  84 ran on the carrier their arm asked for.** Per node:

  | arm | data path | CPU, % of one core | peak RSS | vs upstream |
  |---|---|---|---|---|
  | upstream 1.1pre18 | raw SPTPS/UDP | 23.7 | 6.8 MB | reference |
  | tincstack `plain` | raw SPTPS/UDP | 21.1 | 11.8 MB | **-8.0 %** [-12.9, -3.2], p = 0.002 |
  | tincstack `sf` | SPTPS/UDP, meta in the same flow | 21.9 | 11.8 MB | -4.3 %, **not significant** |
  | tincstack `obfs` | sealed datagrams | 26.7 | 11.9 MB | **+13.6 %** [+9.1, +30.2], p = 0.002 |
  | tincstack `https` | one TLS/TCP flow carries meta **and** data | 26.6 | 11.7 MB | **+18.0 %** [+6.3, +31.7], p = 0.002 |
  | tincstack `quic` | data inside QUIC datagrams | 29.6 | 12.3 MB | **+26.3 %** [+18.5, +46.6], p = 0.013 |

  **Memory is the firm number: +5 MB per node** (`quic` +5.5), in every run,
  the groups never overlapping. **`quic` is the expensive carrier** -- +26 %
  against upstream, about +37 % against our own `plain` -- and it is the only
  carrier with a `send_datagram` hook, so the tunnel's data really rides inside
  QUIC datagrams rather than beside them. `https` is a different data path
  again: `become_established()` marks the link `TCPONLY|INDIRECT` so one TLS
  flow carries meta and data, which is the point (bare UDP beside a connection
  pretending to be HTTPS would give the cover away).

  The CPU figures come from a *paired* comparison -- arms are interleaved inside
  each repeat, so the repeat index pairs them -- because unpaired nothing
  resolves: the same arm varies by 45 % of its median between repeats.

  **Four measurement mistakes are recorded because each produced a confident
  wrong answer first.** (a) Under a TCP load the same arm came out at 23.7 %,
  10.6 % and 23.9 % of a core: TCP does not hold the packet count still, the tun
  device coalesces segments. The load is UDP with a fixed datagram size now, and
  the packet count is printed with every row. (b) With the packet count nailed
  down CPU still ranged 7-26 % for provably identical work: raw CPU seconds are
  not a unit of work under `intel_pstate`/`powersave`, since a boosted core does
  the same work in a third of them. Every run is calibrated against a fixed busy
  loop that reports its own CPU time. (c) The obvious explanation for "our build
  is cheaper" -- meson release at -O3 against autotools' default -g -O2 -- was
  tested with an upstream arm rebuilt at -O3 and killed: -0.1 %, indistinguishable.
  (d) **The first published sweep had no `quic` or `https` arm at all, and no way
  to tell what any arm ran on.** Both nodes dialled each other and no host file
  carried a `Transports` line, so a cold dialler assumed the peer took `plain`
  only and the `sf` and `obfs` arms measured the plain data path while reporting
  themselves as `sf` and `obfs`. Those results were deleted rather than kept with
  a caveat. The harness now uses one dialler and one acceptor, puts the accept
  mask in the host file, records the carrier on every row, and both analysers
  warn when a row's carrier is not its arm's.

  **The ~8 % `plain` wins against upstream still has no established mechanism**
  and is recorded as a measurement, not a claim. The first guess, batched
  `recvmmsg`, is wrong: it is in both binaries, because it is upstream's code.

- **Full regression on the shipped build, 2026-09-17** (`tincstack/core:sf5` /
  `tincstack/node:sf5`, master 3bff008) -- wider than the batch run that closed
  defect G, which covered 12 proofs and skipped five. **29 of 29 PASS:**

      classify matrix singleflow x3 tls-front https-carrier quic-carrier
      obfs obfs-mtu obfs-restart plain-refuse carrier-switch invitee-mesh
      same-nat-meta confirmed-peer x4 two-nodes yaml-scripts obfs-rekey
      reload smoke glare(--rtt 50) glare(--rtt 1) nat-quick dpi-baseline
      lint secrets

  `confirmed-peer` was 4 of 4 this time, the first clean sweep of the four; its
  own precondition flake (roughly 1 run in 4, the harness's, not the daemon's)
  stays on the list because four clean runs do not retire it.

  **Three arms failed on the first pass and none of them was the daemon**, which
  is worth writing down because two were my own mistakes and one was a real
  defect in the stand:
  - `nat-quick` and `dpi-baseline` were invoked with arguments those scripts do
    not take (`lab.sh quick` instead of `lab.sh matrix --quick --image core`,
    `dpi-proof/run.sh` with none instead of `baseline`). Both printed their
    usage and exited non-zero. Re-run correctly: PASS.
  - `smoke` could not create its network and said nothing useful. Two defects
    behind it, both now fixed (c91ac1a): `run.sh` sent compose's stderr to
    /dev/null and then printed `compose logs`, which is empty when the failure
    happens before any container exists -- so the whole diagnosis was one blank
    line. And `lab-env.sh`'s free-subnet check compared the first three octets
    **as text**, so a network that *encloses* the candidate /24 did not count
    as taken: an unrelated compose stack on `172.31.0.0/16` left the smoke lab
    on its documented `172.31.77.0/24`, docker refused the pool, and the
    self-healing walk never ran. It now compares the first min(len, 24) bits and
    can leave a base that is entirely covered. This would have hit any host
    whose docker has a /16 overlapping a lab default, silently, forever.
- **The shipped commit is what the field runs, 2026-09-17.** All four real hosts
  were moved onto `tincstack/node:sf5`, built from master f5c6856 (defect G's
  three fixes plus the route-stale flag clearing); the router onto
  `tincstack/node:sf5-arm64`, again refreshed with the 968 KB in-place rebuild
  `FROM tincstack/node:abc-arm64` rather than a 130 MB `docker load` onto its USB
  flash. The mesh came back full: every node reports the other three at
  `distance 1`, and the ping matrix is clean --

      router -> ruvds2 10.170.0.1  0% loss  30.6 ms
      router -> laptop 10.170.0.2  0% loss   0.8 ms
      router -> euvds  10.170.0.3  0% loss  45.5 ms
      laptop -> ruvds2 10.170.0.1  0% loss  22.7 ms
      laptop -> euvds  10.170.0.3  0% loss  47.8 ms
      laptop -> router 10.170.0.4  0% loss   0.7 ms

  The flag-clearing fix is visible too: node statuses across the stand are
  `00da` / `08da` / `0858` / `0058`, none carrying the `sptps_route_stale` bit
  that was found stuck as `20da` on the router on `:sf4`.
- **Field re-test of defects E and F on the same four real hosts, 2026-09-17**,
  every node redeployed on `tincstack/node:aef` built from master 926d346
  (defect F's epoch fix + stream AE merged). **The router's image was refreshed
  without writing 130 MB to its USB flash**: only the two aarch64 binaries and
  the two shell helpers changed, so a 968 KB context was shipped and the image
  was rebuilt in place there `FROM tincstack/node:abc-arm64` — the flash that
  dropped off the USB bus during the previous 130 MB `docker load` was written
  once, with about a megabyte. Its ext4 is clean since the reboot
  (`dmesg | grep -c "EXT4-fs error"` = 0, 106 GB free).

  **Defect E is closed in the field.** Before the rollout the pair was in
  exactly the documented half-state:

      laptop: router ... nexthop ruvds2 via router distance 2 ... transports plain
      router: laptop ... nexthop ruvds2 via laptop distance 2 ... transports plain

  i.e. data direct, meta relayed through a VPS in another country, and the
  accept mask never propagated. After the rollout, all three of AE's fixes are
  visible, in order:

      laptop  04:36:38 WARNING Could not set up a meta connection to router (4 times in a row; further attempts are logged at -d3 until one succeeds)
      laptop  04:38:45 DEBUG   Could not set up a meta connection to router (8 times in a row)
      laptop  04:38:04 INFO    Carrier candidates for router: plain (peer accepts plain,sf,obfs,https,quic)
      router  04:39:22 INFO    No address of laptop accepts a meta connection, but its UDP data path is direct: dialling laptop (79.139.184.85 port 1181) via sf
      router  04:39:22 INFO    Dialling laptop (79.139.184.85 port 1181) via single-flow UDP
      router  04:39:22 NOTICE  Connection with laptop (79.139.184.85 port 1181) activated

  — point (1) (the ERROR is quieted after three rounds), point (3) (the peer's
  mask now reads `plain,sf,obfs,https,quic` where it read `plain` for hours),
  and point (2) (the fallback). 35 s and three failed plain dials from daemon
  start to a direct link; both sides then show `distance 1`, `transport sf`.

  **And the fallback turned out to be a bootstrap, not a crutch** — a field
  finding AE could not have had. Within seconds of the `sf` meta connection
  coming up the router cached the address that connection's UDP flow actually
  uses and dialled it over ordinary TCP:

      router  04:48:52 INFO    Trying to connect to laptop (192.168.1.200 port 6552) via plain
      router  04:48:52 NOTICE  Connection with laptop (192.168.1.200 port 6552) activated

  The pair is now direct on **plain**, at the laptop's LAN address, which
  neither node advertises and neither could have dialled before (the router only
  ever had the shared public address). So the fallback's real value here is that
  it lets `Caching recent address` learn a working address at all; AE's "the
  fallback is not remembered across reconnects" caveat matters less than it
  looks, because after one round the pair no longer needs it. This does **not**
  retire the fallback: the address cache can only cache an address that a meta
  connection already succeeded at.

  **Defect F's second cause is closed in the field, and the fix earned its
  keep.** With `laptop` switched to `PreferredTransports obfs` the link to the
  hub came up and carried traffic (0 % loss, 22.2 ms to `ruvds2`, 45.8 ms to
  `euvds`), and the node was then restarted five times:

      RESULT: obfs re-established after 5 of 5 restarts; hub replay-window restarts +2; hub obfs accepts +5

  Two of those five restarts drew a counter below the hub's high-water mark and
  were saved by the new epoch restart — on the pre-fix build those two dials
  would have been silent black-outs:

      ruvds2  04:48:27 INFO    Restarting the obfs replay window for laptop at counter 131700747468804: this frame opens a new single-flow session under the bootstrap key, so the peer has restarted
      ruvds2  04:48:41 INFO    Restarting the obfs replay window for laptop at counter 107849511272841: ...

  2 of 5 is consistent with the ~38 %/62 % split measured in the lab. The stand
  was put back on `PreferredTransports plain` afterwards.

  **Two of my own measuring mistakes, recorded because both produced a green
  result that meant nothing.** (a) The first two cuts of the field restart
  script checked `docker logs --since 3m` and then `grep -c >= 1`; `docker logs`
  keeps the whole history across a compose restart, so both were satisfied by
  the *previous* run's line and reported "obfs back after 0 s" five times in a
  row. Only a before/after **count delta** answers this question. (b) The lab
  harness `obfs-restart-test.sh` used `status != 0` as its "activated" test.
  Status bit 8 (0x100) is `mst`, "part of the minimum spanning tree"
  (connection.h) — in a two-node lab that coincides with "up", on the four-node
  field stand a live obfs link outside the MST reports `status 0`. The predicate
  now asks for the obfs carrier in `dump connections` **and** `distance 1` in
  `dump nodes`, and both arms of the harness were re-calibrated after the
  change.
- **Field re-test of streams AA, AB and AC, 2026-09-17, four real hosts**
  (`ruvds2` hub / `laptop` NATed workstation / `euvds` public VPS / `router`
  aarch64 home gateway, all redeployed on a locally built `tincstack/node:abc`
  from master a48d0ca; the router on its own cross-built arm64 image):
  - **Defect C is fixed in the field, and proven the hard way.** `laptop` and
    `euvds` now show each other at `distance 1` with the other leaf as
    `nexthop`, and the pair keeps working **with the hub's container stopped**:
    8 packets, 0 % loss, 46.0 ms, while `dump nodes` shows `ruvds2` and
    `router` at `distance -1`. Before the fix the same pair was
    `nexthop ruvds2 … distance 2`.
  - **Latency is not the win, and saying so would be dishonest.** The direct
    path measures 46.1 ms against 45.7 ms relayed: these two hosts are far
    apart either way, and the relay hop through the hub was almost free. What
    changed is that the hub no longer carries their traffic and no longer takes
    them down with it.
  - **The first-burst packet loss is gone for this pair** (10/10 both ways,
    where the relayed pair lost its first two), exactly as stream AC's
    three-build measurement predicted: the keys are up before any traffic.
  - **Defect D works where its request fires and not otherwise:** `laptop` and
    `euvds` now list each other as `plain,sf,obfs,https,quic`, but `router` and
    `laptop` still list each other as `plain` — see defect E, point 3.
  - **Stream AB's fix removed the field EMSGSIZE**: no `Message too long` in
    any log on the stand, on any host, in any of the obfs dials attempted.
    **The obfs dial still fails**, for a different reason that this re-test
    found and traced — defect F below.
  - **Stream AA's diagnostic earns its keep**: every failed dial on the stand
    now says `Dial to X (host) via <carrier> abandoned before the connection
    was activated`, which is how defects E and F were read off the logs in
    minutes rather than guessed at.
- ~~🟠 **Defect F — obfs can never be turned on for a pair that already has a
  working UDP path.**~~ **Closed 2026-09-17**, and it had TWO independent
  causes; fixing the first one alone left the dial still hanging. Found on the
  four-node stand while re-testing
  streams AA/AB/AC in the field, and traced to the line that causes it.
  `obfs_udp_try()` (obfs.c) skips its keyed check when the datagram's source
  address belongs to a node that already has `udp_confirmed`:

      node_t *known = lookup_node_udp(&addr);

      if(known && known->status.udp_confirmed) {
              return false; /* an established plain peer: leave it to the SPTPS path */
      }

  That is the normal state of every working pair, so the sealed handshake
  frames fall through to `process_sptps_udp()` and are dropped as unparseable.
  Measured, dialler (`laptop` → `euvds`, both on master with stream AB's MTU
  fix, so there is **no** `Message too long` anywhere in this trace):

      00:14:48 INFO    Dialling euvds (88.218.122.166 port 655) via obfuscated single-flow UDP
      00:14:48 INFO    Connected to euvds (88.218.122.166 port 655)
      00:14:53 WARNING Timeout from euvds (88.218.122.166 port 655) during authentication
      00:14:53 INFO    Carrier obfs failed for euvds before activation (1/3) but worked before, retrying it

  acceptor at `-d5`, same seconds:

      00:14:59 WARNING Received UDP packet from laptop (79.139.184.85 port 1181) with unknown source and/or destination ID
      00:15:00 WARNING Received UDP packet from laptop (79.139.184.85 port 1181) with unknown source and/or destination ID

  Every obfs lab passes because every lab dials obfs from fresh containers,
  before any UDP path is confirmed — the one state in which the guard lets the
  scan run. Impact: obfs is unusable in exactly the scenario it exists for, an
  already-running network turning covert under censorship; a node can only get
  an obfs link by never having had a plain one. This is also the second cause
  stream AB said it could not find ("if your pair had junk at 0, the dial hang
  has a second cause I have not found") — it was right to flag it: AB's fix
  removed the EMSGSIZE symptom, and the dial still hung. **Dispatched as
  stream AD** (merged c36599a): the skip is now qualified by
  `sptps_udp_addresses_known_nodes()` — it only stands when the datagram's
  SPTPS header actually names nodes we know, which a sealed obfs frame never
  does. New test `testing/transports/obfs-confirmed-peer-test.sh`.

  **Second cause — the replay window outlives the daemon. Found and fixed by
  me, 2026-09-17,** because AD's own new test still failed on the merged tree
  (`MISS: the obfs dial still ran into 1 authentication timeout(s)`) and I do
  not accept "flaky" as a diagnosis. An instrumented build (`tincstack/core:dbg`)
  printed the decisive line on the acceptor:

      DBG obfs replay-window rejected seq 79590043557285 (window max 173021181478996, started 1)

  `keyset_build()` (obfs.c) starts each sender counter at a **random 48-bit
  value**, while the **bootstrap** keyset is derived from the two nodes'
  Ed25519 public keys and therefore **outlives both daemons**. A peer that
  restarts draws a fresh start; it lands below the acceptor's remembered
  high-water mark with probability `mark / 2^48`, and the mark only ever moves
  up — here 1.7e14 of 2.8e14. Every frame of that peer's dial then decrypts
  correctly, is counted as classified, and is **dropped with no log line at
  any debug level**. The daemon's own comment in `keyset_build()` claimed the
  random start prevented exactly this; it was wrong, and the comment is now
  corrected in place rather than deleted.

  Fix: `obfs_epoch_restart()` — a frame that opens a **new single-flow
  session** (`SF_TYPE_DATA` + `SF_FLAG_SYN`, `seq == 0`) under the *bootstrap*
  key may start a new key epoch, resetting that window to its counter, at most
  once per 5 s per link (`OBFS_EPOCH_MIN_INTERVAL`); the *session* keyset's
  window is never restarted this way. Plus a `DEBUG_TRAFFIC` line on every
  out-of-window drop, so this class of failure can never again be silent.
  **Trade-off, stated rather than buried:** a recorded old SYN can be replayed
  to reset the bootstrap window once per 5 s and feed stale frames from around
  that counter. It buys the attacker nothing — those frames land in a *new*
  single-flow session whose tinc ID exchange runs under SPTPS and fails closed
  without the peer's private key, `sf_accept()`'s `max_connection_burst` bounds
  how many such sessions a flood can create, and the live session's window is
  untouched. M5-4 (a replay must not re-point the link's address) and M5-5 are
  unaffected and still asserted green.

  **Measurement, same stand, two builds differing only in this patch**
  (`testing/transports/obfs-restart-test.sh`, new):
  `tincstack/core:abcd` → `RESULT: obfs re-established after 1 of 6 restarts`;
  `tincstack/core:epoch` → `RESULT: obfs re-established after 6 of 6
  restarts`, with the acceptor logging `Restarting the obfs replay window for
  nodeb at counter 71709580590509 ...` → `Connection from 10.62.7.11 port 656
  (obfuscated single-flow UDP)` → `activated`. The new harness also asserts
  the *pre-fix* behaviour (`--expect-defect`), and its header records that a
  broken build passes that arm by luck with p ≈ 0.38^6 ≈ 0.3 %.

  **Why no existing test caught it, which is the part worth keeping:** every
  obfs lab dials from containers that have never spoken obfs, so the window is
  unstarted and the first dial always works. `carrier-switch-test.sh` and
  `obfs-confirmed-peer-test.sh` switch a *running* node, which also works the
  first time; the latter restarts the dialler only on a retry, which is why it
  looked flaky (1 run in 4 for its author, 3 of 3 for the reviewer) rather
  than broken. **Flakiness that tracks a coin flip is a defect with a
  probability attached, not noise.** Regression on the fixed build, all green:
  obfs (incl. M5-2/M5-4/M5-5/M5-6), obfs-mtu, obfs-confirmed-peer (which was
  FAILing before this fix), carrier-switch, invitee-mesh, singleflow, smoke,
  lint.
- 🟠 **Defect E — two nodes behind the same NAT never form a meta connection,
  and retry forever** (found on the four-node stand 2026-09-17; reproduced in a
  four-container lab and **fixed** in stream AE). `router` (the LAN gateway) and
  `laptop` (a node in a docker bridge on a machine inside that LAN) both know
  each other and both dial -- stream AC's fix made the dials happen -- and both
  fail for ever, because each dials the only address the other advertises, the
  shared public one, and that NAT's TCP hairpin does not work:

      00:11:52 INFO    Trying to connect to router (79.139.184.85 port 655) via plain
      00:11:57 WARNING Timeout while connecting to router (79.139.184.85 port 655)
      00:11:57 INFO    Dial to router (79.139.184.85 port 655) via plain abandoned before the connection was activated
      00:11:57 ERROR   Could not set up a meta connection to router

  and symmetrically on the router (dialling `laptop` at port 6552, the
  invitee's *internal* port, for which no forward exists). Their **data** path
  meanwhile is direct and healthy -- UDP hairpin *does* work on this NAT: 10
  packets, 0 % loss, 5.7 ms each way. So the pair sat in a half-state: packets
  took the short path, the meta connection was relayed through a VPS abroad
  (`nexthop euvds … distance 2`), and each node logged an ERROR every backoff
  round.

  **The lab** (`testing/transports/same-nat-meta-test.sh`, in `SHELL_SCRIPTS`,
  `make lint` clean). Four containers on three docker networks: `relay` (public
  founder), `natgw`, and `nodea`/`nodeb` each in its **own** inside segment. The
  separate segments are the point and they are what makes this defect E rather
  than "advertise your LAN address": the gateway does not route between them, so
  -- exactly as in the field, where `laptop` is at `10.16.8.2` inside a docker
  bridge and `router` advertises its own upstream side `192.168.0.2` -- the only
  address either node has for the other is the shared public one. The gateway is
  a port-preserving cone NAT for UDP *including hairpin* and a black hole (DROP,
  not REJECT, so the dialler times out rather than being refused) for TCP to the
  public address in either direction. The relay stays up for the whole run: a
  two-node lab does not reproduce mesh-dependent behaviour (stream AD paid for
  that lesson). Five preconditions are asserted, none of them through tinc:
  TCP `nodea → relay:655` connects, TCP `nodea → public:6552` times out, UDP
  `nodea → public:7552` reaches a listener in nodeb's namespace, *neither*
  protocol reaches nodeb's private address, and both nodes already hold the
  other's Ed25519 key. Docker 28+ installs a `! -i br-X -o br-X -j DROP` rule per
  bridge that black-holes exactly this lab's traffic, so the networks are created
  with `gateway_mode_ipv4=nat-unprotected`; the relaxation lives and dies with
  them.

  Pre-fix image, `--expect-defect`, both nodes, after the keys are on disk and
  the daemons restarted (which is what stops AC's mask propagation from firing,
  see (3) below):

      nodeb … nexthop relay via nodeb distance 2 … transports plain rtt 0.113
      01:27:24 ERROR   Could not set up a meta connection to nodeb      [every round]
      PASS(repro): the pair's data path is direct, its meta path is relayed for ever

  Fixed image, same lab, same settle time:

      nodeb … nexthop nodeb via nodeb distance 1 … transports plain,sf,obfs,https,quic rtt 0.100
      dump connections:  nodeb at 10.34.9.66 port 6552 … transport sf
      ERROR lines about the peer: nodea 1, nodeb 0
      PASS: two nodes behind one NAT peer directly over a UDP carrier, with no ERROR loop

  Three things were wrong and all three are now fixed, in this order:

  1. **The give-up ERROR repeated for ever at the default `-d1`.** Corrected
     measurement, against the first field write-up: the backoff *does* widen --
     the lab shows `Trying to re-establish outgoing connection in 10 seconds`,
     then 15, then 25 -- up to `MaxTimeout` (900 s). So the steady state was one
     `ERROR Could not set up a meta connection to X` per peer per 15 minutes,
     not one every 45 s; the 45 s in the field report was a snapshot of a
     still-growing backoff, not a cap. It was still an ERROR, for ever, for a
     condition the operator cannot act on. `net_socket.c` now counts consecutive
     give-ups per `outgoing_t`: the first three are as loud as before, the fourth
     says where the rest went, and the rest go to `-d3`. The counter is reset
     the moment *any* link to that peer activates, so a peer that goes away and
     comes back is loud again. Deliberately **quieted, not stopped**: a NAT
     mapping or a route can start working at any time, so the dial keeps
     happening on the same backoff.
  2. **A meta connection can now use the peer's confirmed UDP path**
     (`UdpMetaFallback`, default `yes`; `docs/transports.md` §2.2). When
     `do_outgoing_connection()` has walked every address the graph and the config
     know for a peer and every one of them refused, it asks
     `transport_udp_meta_fallback()` for one more address: the one the peer's
     **confirmed direct UDP flow** already uses, and dials there over `sf`. Same
     path, same 5-tuple, same NAT mapping the data packets are already using.
     Conditions, none of them a guess: the option is on; `sf` is compiled,
     dialable and in *our* `Transports`; `sf` is in the *peer's advertised*
     accept list; the peer is reachable and `status.udp_confirmed`; `n->via == n`
     (the UDP path goes to the peer, not through a relay); once per reconnect
     cycle. Where it lives is a deliberate answer to "carrier walk or
     outgoing-connection logic": the walk decides *which wrapper goes around
     SPTPS* over a given address, and what is different here is the **address** --
     the only reachable endpoint for this peer is a UDP flow, and only a UDP
     carrier can use it. So it sits outside the walk, at the exact point where
     the code used to give up. Nothing is weakened: `sf` hands the same ID
     exchange and the same SPTPS session to the same code, and the acceptor still
     enforces its own `Transports`/`AllowPlainMeta`. `n->address` is only ever
     updated from an authenticated UDP probe reply (`net_packet.c`, "It's a valid
     reply"), so the fallback cannot be pointed at an attacker-chosen address,
     and a wrong one would simply fail the ID exchange.
     Because the fallback needs a *confirmed* path and confirmation is normally
     driven by traffic, `setup_outgoing_connection()` also calls `try_tx()` for a
     reachable peer that has none -- the same call ordinary traffic makes, rate
     limited by `try_udp`/`try_sptps` and by the growing backoff. Without it a
     pair with nothing to say to each other would never qualify.
     **Only for a peer we have already failed to dial at least once**, and that
     restriction is measured, not cosmetic. Kicking `try_tx()` on the *first*
     dial as well confirms the UDP path of a peer that is about to connect
     normally -- and a node whose **confirmed** path is then black-holed falls
     back to the relay only after `udp_discovery_timeout`, where a node that
     never confirmed it notices in one `sf` retransmission round (~36 s).
     `singleflow-test.sh` PART 2 (sever a fresh A<->B link, require the relayed
     path inside ~40 s) measured the difference: **1 of 3 passes** with the
     unconditional kick, against **3 of 3** both on the pre-fix image and with
     the kick narrowed. A's log showed exactly the mechanism -- `Caching recent
     address for nodeb` three seconds after activation (UDP confirmed) and then
     nothing, instead of `Single-flow link to nodeb: no acknowledgement after 8
     retransmissions`.
  3. **The accept mask now reaches a peer whose key we already have.** Stream
     AC's mask rides on `ANS_PUBKEY`, and `ANS_PUBKEY` only ever answers a node
     that does not have the key yet -- and a key is cached for ever. The field
     pair had each other's keys, so the mask never travelled and each still saw
     `transports plain`, which is exactly the pair that needs a non-plain carrier.
     `send_req_transports()` (protocol_key.c) asks again over the graph, using
     **the same REQ_PUBKEY request as before** rather than a new one: an upstream
     tinc answers it whether or not it has our key, and answers with a plain
     `ANS_PUBKEY` we already parse, so nothing new goes on the wire that an
     upstream peer could choke on. It is called from
     `setup_outgoing_connection()` only while the list is unknown, rate limited
     to one per node per 60 s, and an answer *without* the extra token now records
     `plain` -- so a peer that does not speak the extension is asked once, not
     once a minute for ever.

  **Negative control**, which also isolates (3) from (2): the same lab with
  `SET_OPTS='UdpMetaFallback no' --expect-relayed` on the **fixed** image puts
  the pair straight back into the half-state --
  `nodeb … nexthop relay via nodeb distance 2` -- while now showing
  `transports plain,sf,obfs,https,quic`, i.e. (3) works on its own and (2) is
  what closes the distance. `PASS(control): with the UDP meta fallback off the
  pair stays in the half-state`.

  **Regression, all against `tincstack/core:ae` unless noted** (2026-09-17):
  `same-nat-meta-test.sh` (fixed, defect on `:ae-pre`, control), `obfs-test.sh`,
  `obfs-mtu-test.sh`, `obfs-confirmed-peer-test.sh` (its flaky precondition
  **held**: "acceptor still reports udp_confirmed for nodeb in 6 of 6 samples
  during the dial" -- a run where it does not hold proves nothing and must be
  repeated), `carrier-switch-test.sh`, `invitee-mesh-test.sh`,
  `plain-refuse-test.sh`, `matrix-test.sh` (`:ae-test`, built with
  `-Dtransport_test=true`), `quic-carrier-test.sh` (second image `:ae-noquic`,
  `-Dquic=disabled`, exercised: "B built without QUIC"), `testing/smoke/run.sh`
  (run with **bash**), `make lint`. All PASS.

  **Deliberately left undone, and why:**
  - **"Use the graph's `local_address` when it is on our own subnet" is not
    implemented.** It would be correct in general and it does **not** fix this
    pair: neither node's advertised local address is reachable by the other
    (`router` advertises its upstream `192.168.0.2`, `laptop` a docker-bridge
    `10.16.8.2`). The lab asserts that property explicitly -- "neither UDP nor
    TCP reaches nodeb's private address" -- so a future change of this kind
    cannot quietly be credited with closing defect E.
  - **The fallback is not remembered across reconnects.** When an `sf` link that
    the fallback dialled drops, `transport_candidate_activated()` has cleared the
    walk and the next cycle dials `plain` first, wasting one `pingtimeout` (5 s)
    before falling back again. Remembering it would mean putting the fallback
    into `last_ok_mask`, whose contract today is "a candidate at a *known*
    address"; conflating the two would let a stale UDP address outrank a working
    TCP one. Cost measured: one 5 s dial per reconnect.
  - **Only `sf` is used as the fallback carrier.** `obfs` would additionally need
    that peer's obfs key material to be right, and `quic` a TLS handshake over a
    path we have confirmed in one direction. Neither is blocked; neither was
    done.
  - **The retry is quieted, not bounded.** One dial per `MaxTimeout` per
    unreachable peer remains, on purpose (see (1)).
  - **`send_req_transports()` costs one relayed request per minute per peer whose
    list is still unknown and never answers.** Bounded, not zero.

  **Reviewer's note on (3), found while merging and not a blocker.** Recording
  `plain` for an `ANS_PUBKEY` that carries no carrier token makes the
  plain-only verdict *sticky*: a relay in the middle that strips the token now
  pins the peer as plain-only for the node's lifetime, where before it stayed
  "unknown" and could be re-asked. This grants an attacker nothing new — the
  re-ask travels through that same relay, so re-asking buys nothing, and
  `ack_h()` overwrites `n->transports` unconditionally from the ACK of any
  direct meta connection, which is the moment the mask actually matters. It is
  a carrier downgrade, never a crypto one: SPTPS is unchanged and the acceptor
  enforces its own accept list. Worth knowing when reading a node that
  stubbornly shows `transports plain` for one peer.
- 🟢 **Family-B repos committed secrets** (keys, a real LE cert, an invite token).
  None carried over; ensure none re-enter (M6 proof).
- 🟢 **One private-key blob is in the tree by design**: `core/tincd/test/integration/cmd_sign_verify.py`
  carries upstream tinc's ED25519 test key (verified 2026-09-16 byte-identical
  to `gsliepen/tinc` `test/integration/cmd_sign_verify.py`), used as a
  deterministic signature vector. It is public upstream material and no node
  uses it, but secret scanners (GitHub push protection, gitleaks) will flag it
  on the first push — expect that and allow-list the path rather than
  rewriting history. Every other key-shaped string in the tree is a
  placeholder (`AAAA…`, `REDACTED…`).

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
| R-10 | 🟡 | `transport_table.c:227-260` | QUIC/SPTPS-relay overlap is 2⁻¹⁷ per node (drafts + grease), comment says 2⁻³⁴ | arithmetic | **fixed** (G3, 2026-09-16): the long-header rule matches the v1 version word only (`00 00 00 01`), so the residual is 2⁻³⁴ per node as documented; v2/drafts/grease/VN fall through to SPTPS. Proof: `classify-test.sh` 37 checks, 0 failures; arithmetic in `docs/transports.md` §3/§9.5 |
| R-11 | 🟢 | `transport_sf.c:352-372` | spoofed SYN amplification < 1.5×, bounded by MaxConnectionBurst | — | informational |
| R-12 | 🟢 | `net.c:236`, `transport_sf.c:481` | UDPRebindOnWake kills an SF session (re-dial) | sleep/wake | informational, doc note |
| R-13 | 🟢 | `yamlconf.c:474-500` | Windows temp files hold keys in `%TEMP%` | — | **fixed** (S, 2026-09-16: `yamlconf_content_fp()` on Windows creates the temporary next to the config — the directory that already holds the keys — with a DACL for the calling user + SYSTEM only, no sharing, `FILE_ATTRIBUTE_TEMPORARY \| FILE_FLAG_DELETE_ON_CLOSE`; `%TEMP%` only when there is no config path (no key material then). POSIX unchanged: `tmpfile()`, 0600 and unlinked. `write_atomic()` already wrote its temp next to the target. Verified: mingw cross-compile of `yamlconf.c` clean (the Windows image build as a whole currently stops at `decoy.c` `<sys/socket.h>` — pre-existing, stream L's file, not touched); Linux `run.sh check` green (props + 5 harnesses), `review-r-live.sh` 18/18, smoke PASS) |
| R-14 | 🟢 | `protocol_auth.c:280` | expired invitations stay `.used` until the weekly sweep | — | **fixed** (S, 2026-09-16: an expired invitation a peer presents is `unlink()`ed right after the "tried to use expired invitation" log instead of staying renamed `.used`; nobody can redeem it, so nothing is lost. The `tinc invite` sweep is unchanged (older than one week, `.used` included) — it still covers a `.used` left by a redemption that crashed mid-way) |
| R-15 | 🟢 | `tincd.c:596` | one-line call change `zeroconf_materialise(true)` | — | note for tincd.c owner |
| R-16 | 🟢 | `tincctl.c cmd_config` | `tinc get Port` reads options while `tinc set Port` writes hosts.<me> | live step 6 (first version) | **fixed** in the consolidation pass (fef10b9: `Port` is `VAR_SERVER \| VAR_HOST`, options.Port authoritative for daemon, CLI and invite) |
| M5-1 | 🔴 | `decoy.c:277-360` | decoy upstream proxy is synchronous on the main loop (DNS unbounded, 3 s per recv, 4 MiB): one failed TLS probe per 3 s freezes the node | set `HttpsDecoyUpstream`, `openssl s_client` twice | **fixed** (L: upstream fetch is event-driven with a 3 s total deadline and 1 MiB cap, address resolved once at (re)load; `tls-front-test.sh` M5-1 case, black-holed upstream: a second probe's TLS handshake **2.52 s → 2.8 ms**; `https-carrier-test.sh` M5-1 case: tunnel ping A→B during three probes against B's black-holed upstream **0 % loss, max RTT 0.285 ms**; on the pre-fix build the case could not run at all, see L-1) |
| M5-2 | 🟠 | `obfs.c:87-116` | obfs key from public keys = mesh-wide shared secret; any member classifies/forges every link; never rotates | — | **fixed** (stream O): obfs v2 keeps the public-key key as cold-start bootstrap only; peers exchange fresh seeds over the authenticated SPTPS meta channel (`OBFS_KEY`) and switch to a per-link session key, re-keyed with `KeyExpire`. Proof: `obfs-test.sh` PART 4(a) — a third party holding both public keys (`obfs_probe.py`) decrypts cold frames but `decryptable=0` on steady traffic |
| M5-3 | 🟠 | `obfs.c:190-204` | magic header leaves 32 random nonce bits → reuse at ~2¹⁶ datagrams; 2³² without rotation | — | **fixed** (stream O): per-direction 64-bit counter nonce (whitened on the wire, random 48-bit start), magic is now a separate plaintext prefix that costs no nonce entropy. Proof: `fuzz_obfs` self-test asserts unique wire nonces over a 100 k-frame flood incl. a magic header |
| M5-4 | 🟠 | `obfs.c:312-327,344-366` | replayed sealed datagram from any address repoints the link before SF/SPTPS checks; no anti-replay | replay one captured datagram | **fixed** (stream O): per-direction sliding replay window; the peer address is moved only after a datagram verifies AND is fresh. Proof: `obfs-test.sh` PART 5(b) — a replay flood from a 3rd address leaves A↔B pinging `0%` |
| M5-5 | 🟡 | `obfs.c:87-116` | same key both directions → reflected CLOSE/RESET | — | **fixed** (stream O): direction-separated keys (`l2h`/`h2l`). Proof: `fuzz_obfs` reflection self-test + `obfs-test.sh` PART 6(c) — reflecting a frame to its sender does not close the session |
| M5-6 | 🟡 | `obfs.c:368-402` | cold-scan budget global, restarts at node 1: > 25 nodes never classified; 25 pps starves it | — | **fixed** (stream O): per-peer round-robin cursor persisting across ticks, budget scales with peer count (floor 25/s, cap 512/s). Proof: `obfs-test.sh` PART 7(e) — A's link comes up with 35 extra peers in the tree |
| M5-7 | 🟠 | `https.c:342-345` | TlsFingerprint pinned on first use before SPTPS proves anything → persistent MITM pin / DoS | MITM first dial | **fixed** (L: no pin is written on an unauthenticated contact; the pin is written once SPTPS activated the link over that TLS session; `https-carrier-test.sh` M5-7 cases: socat TLS bump on the first dial → **no pin**, https fails without a 101; legitimate first dial → exactly B's fingerprint pinned after `SPTPS authenticated nodeb`; malformed pin no longer re-appended) |
| M5-8 | 🟠 | `decoy.c:380-395` | plain-HTTP decoy `send_all` busy-loops on EAGAIN for a non-reading client | large decoy file + zero-window client | **fixed** (L: plain-HTTP decoy is an event-driven state machine, writes on IO_WRITE readiness, reaped by the authentication timeout; `tls-front-test.sh` M5-8 case, 8 MB decoy to a non-reading client: **800 → 2** CPU ticks over 8 s and the connection is dropped) |
| M5-9 | 🟡 | `https.c:462-563` | name-existence timing oracle (verify only for known names) | timing | **fixed** in shape (L: unknown name still parses a host record (own) and runs a full Ed25519 verify against the own key, freshness folded into the final AND; measured time-to-first-byte over TLS, 400 samples each: known/unknown **107/108 µs before, 100/102 µs after** — the oracle was below the noise of this lab both times, so the proof is structural) |
| M5-10 | 🟡 | `decoy.c:243-275` | failed tinc authenticators forwarded to the upstream in clear HTTP | clock-skewed peer | **fixed** (L: `Cookie`, `Upgrade`, `Sec-WebSocket-*`, `Authorization` and the client's `Host`/`Connection` are stripped before the request reaches `HttpsDecoyUpstream`; `tls-front-test.sh` M5-10 case: an authenticator-shaped request with `Cookie: sid=LEAKMARK…` — before the upstream logged all of it, after it sees none of those headers) |
| M5-11 | 🟢 | `tls.c:514`, `https.c:278` | key file chmod race (classic mode); no domain separation in signed message | — | **fixed** (L: key file `open(O_CREAT\|O_EXCL, 0600)`; authenticator **v2** signs `"tincstack-https-auth-v2\0" \|\| …` (docs/transports.md §8.3), both sides on this build; a v1-shaped forged authenticator gets the decoy — `https-carrier-test.sh` forged/replayed cases) |
| L-1 | 🔴 | `https.c:598-622` (`https_send`) | found by stream L while proving M5-1: a peer that closes its https link cleanly (close_notify — `tinc reload`, restart) made `terminate_connection()`'s DEL_EDGE broadcast call `https_send` on the dying link, whose `SSL_write` failure called `terminate_connection()` again → unbounded recursion → **SIGSEGV** (exit 139, 3 040 nested "Closing connection with nodeb" lines) on master and on the pre-fix stream-L build | `tinc reload` on B while A is connected via https | **fixed** (L: a failed send marks the session dying and a zero-delay reaper terminates it outside the send path; `https-carrier-test.sh` M5-1 case now reloads B under an https link and checks both nodes are still running) |
| L-2 | 🟡 | `net.c terminate_connection` / outgoing selection | observed by stream L in the same lab: after B's `tinc reload` closed an **activated** https link, A reconnected over **`plain`** (`dump connections` → `transport plain`), although a dropped activated link is meant to keep its carrier; a peer or on-path party that can reset the link once may therefore downgrade it. Not investigated further (outgoing selection is stream G's area) | `tinc reload` on B while A is connected via https, then `tinc dump connections` on A | **fixed** (N, 2026-09-16). Re-checked on 7ac5f90 first: the *reload*, *TCP reset* (`ss -K`) and *UDP black-hole* drops already came back on https/quic (G3's `activated`-before-edge-delete fix, 6416dd7, covered the reported path), but **one refused re-dial still downgraded**: `kill -9` of B's tincd kept down 8 s (past A's 5 s backoff) → A: `https: connect to nodeb … Connection refused` → `Carrier https failed for nodeb, falling back to plain` → `dump connections` → `transport plain` until the next drop. Fix in `transport.c`/`net.h`/`protocol_auth.c ack_h` (docs/transports.md §2 steps 3-6): the walk always starts from the operator's first preference after an activated link drops; the carrier that last activated a link *we dialled* is retried, with the normal backoff, until it has failed **3** times in a row (`Carrier https failed for nodeb before activation (1/3) but worked before, retrying it`), only then `… failed 3 times in a row for nodeb, no longer preferred` → next candidate; an exhausted list restarts from the top. Proof `TINCSTACK_TAG=ws-n testing/transports/https-carrier-test.sh` L-2 cases: reload / TCP reset / kill -9 + restart → `A is back on https, tunnel 0% packet loss` each, the kill case logging the `(1/3) … retrying it` line; three refused dials in a row → plain (as designed), and the next drop of that plain link → https again. `quic-carrier-test.sh` (l): reload / UDP black-hole / kill -9 + restart → `A is back on quic (both ends), tunnel 0% packet loss`, `A never fell back to plain`. R-12 note in docs/transports.md §4 (`UDPRebindOnWake` tears the link down through the same activated-drop path, so the re-dial keeps the carrier). ~~**Residual (new, 🟡):**~~ the dialler chooses the carrier and tinc keeps the *newer* of two connections (`id_h`): a peer with the default `PreferredTransports: [plain]`, `AutoConnect` on and our address in its host record brought a restarted link back as `plain` before our re-dial (seen in the L-2 lab after B's `kill -9`: B's autoconnect reached A over plain at once, A's own https re-dial then found `Already connected`). **Closed 2026-09-16 (stream P):** acceptor-side rule, docs/transports.md §2 step 7 — when a link the *peer* opened runs on a carrier ranked below the candidate our `outgoing` would dial, we dial ours anyway instead of logging `Already connected` (`net_socket.c setup_outgoing_connection`; `protocol_auth.c ack_h` arms the dial when our `outgoing` had been parked on the inbound link), and the existing `id_h` dedup drops the older connection once ours activates, so neither end is ever left with zero connections. The ranking is **not** each node's preference list (mirrored lists would oscillate) but the fixed carrier order `plain < sf < obfs < https < quic` (`transport_outranks_connection()`), which every build compiles identically: only one of the two nodes can ever want to re-dial, and a re-dial moves the surviving link strictly *up* a bounded order, so the rule terminates. It is bounded on the failure side too (only carriers the peer advertises are dialled; after `TRANSPORT_STICKY_FAILURES` the walk moves on and the rule disengages) and it never fires on default settings. Proof `TINCSTACK_TAG=ws-p testing/transports/https-carrier-test.sh` new case "L-2 residual": B with `AutoConnect: yes` + A's `Address` + default `[plain]`, `kill -9` and restart → A logs `Connected to nodeb over plain, which we rank below https: dialling https as well` → `dump connections` **https on both ends**, then a 60 s polled window with **0 off-carrier samples, A closes 2→2, B closes 4→4**, tunnel 0 % loss. Side effect of stream P's reload fix: the L-2 reload cases of `https-carrier-test.sh` and `quic-carrier-test.sh` no longer see a drop (a reload leaves an unchanged host record's link alone), so they now assert exactly that and the drop-and-recover path is carried by the reset / black-hole / `kill -9` cases. |

Re-run at the end of the review: `testing/transports/classify-test.sh` 26/0,
`TINCSTACK_TAG=ws-r platforms/linux/docker/two-nodes.sh` PASS.
