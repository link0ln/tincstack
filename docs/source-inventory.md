# Source inventory — what each prior experiment contributed

This document is the consolidated result of a full read of every prior tinc
experiment in `/opt/gitrepo/vpn-experiments` and the five GitHub repositories
under `github.com/link0ln`. It exists so that an implementer does not have to
re-audit the history: it records, per source, what is **reusable as code**, what
is **reusable only as a reference design**, and what is **rejected**, with the
evidence for each verdict.

Terminology used throughout follows the censorship-circumvention / pluggable-transport
literature (Tor pluggable transports, obfs4, Shadowsocks, VLESS/REALITY, AmneziaWG):
*obfuscation*, *traffic-analysis resistance*, *protocol mimicry*, *active-probing
resistance*, *transport negotiation*. The product is a self-hosted mesh VPN with
optional circumvention transports; the circumvention features are opt-in.

---

## The one decision that shapes everything

The prior work splits into **two incompatible families**:

| Family | Repos | Build | tinc crypto (SPTPS/Ed25519) | Verdict |
|---|---|---|---|---|
| **A — hardening fork** | `link0ln/tinc` (branches `sptps-resync-fix`, `yaml-config`) | **meson**, tinc 1.1 git HEAD | **intact** | **Adopt as core** |
| **B — transport prototypes** | `tinc-obfs`, `tinc-quic`, `tinc-vless-reality` | autotools, tinc 1.1pre18 tarball | **removed or bypassed** | **Reference only** |

Family B repos each **delete or stub tinc's authenticated-encryption layer**
(SPTPS, Ed25519, ChaCha20-Poly1305) and replace it with a transport whose own
authentication is incomplete. Concretely:

- `tinc-vless-reality`: `src/stub/sptps_stub.c` returns `false` from
  `sptps_start`/`sptps_send_record`; key exchange is skipped
  (`protocol_auth.c:478-493`); payload is sent via raw `send()`. **Result: VPN
  traffic is plaintext and the only credential is a static UUID sent in the
  clear.** The REALITY handshake, fallback proxy, DPI-evasion, domain-fronting
  and multi-hop modules are all present but **never called** (`vless_init()` has
  no call sites).
- `tinc-quic`: deletes `sptps.c`, `ed25519/`, `chacha-poly1305/`,
  `protocol_key.c`; relies solely on QUIC TLS 1.3, but certificate chain
  validation is stubbed (`quic.c:279-347` accepts any self-signed cert, and with
  `QUICTrustPublicCerts` any CA cert), with **no binding between the certificate
  and the tinc node identity**. Stream multiplexing, keepalives, SNI rotation
  and padding are dead or non-conformant. The only recorded end-to-end run
  reported **0/6 connectivity** while `summary.log` falsely printed "ALL TESTS
  PASSED".
- `tinc-obfs`: keeps SPTPS but its obfuscation is semantically broken — the
  junk/real discriminator is a **single unauthenticated cleartext flag byte**;
  enabling it **forces the handshake onto UDP** which the receiver cannot
  identify on a cold start (`net_packet.c:985-991` + unmodified
  `handle_incoming_vpn_packet`), so a fresh tunnel deadlocks; junk is emitted
  **per data packet** (3× packet-rate amplification), not per handshake; and
  **relay forwarding double-prefixes** and corrupts the record.

Therefore: **the core daemon is Family A. Every Family-B feature is rebuilt on
top of the intact-crypto core rather than imported.** Importing Family B would
import the security regressions above. Their value is as *reference designs* —
they show the config surface, the msquic wiring, and the IP-pool algorithm — not
as merge sources.

Also note both families additionally committed live private keys and (in
`tinc-quic`) a real Let's Encrypt cert + CA key + a live invitation token into
git, against `AGENTS.md` policy. None of that material is carried over.

---

## Per-source detail

### `link0ln/tinc` — **CORE** (Family A)

Base commit of `yaml-config`: `47b8d54a`. Base of `sptps-resync-fix`: forked from
tinc 1.1 at `6707f23b`. meson build; Windows via mingw-w64 cross file
`.ci/cross/windows/amd64`. No Android, no Dockerfile.

Reusable **as code** (this is the adopted core):

| Feature | Files / symbols | Config | Maturity |
|---|---|---|---|
| SPTPS stale-sequence tolerance + 30 s reset cooldown | `src/sptps.c:561`, `src/net_packet.c`, `src/protocol_key.c` | none (hardcoded) | Field-deployed on the author's "gnet" mesh |
| UDP discovery burst (restricted-cone / CGNAT traversal) | `src/net_packet.c:95,1348-1400`, `net_setup.c:399` | `UDPDiscoveryBurst` (default 5) | Field-deployed, tagged release |
| UDP rebind on wake-from-sleep | `src/net_socket.c:417` `rebind_udp_sockets()`, `net.c:220` | `UDPRebindOnWake` (default no) | Field-deployed, tagged release |
| Wintun (L3) Windows device backend | `src/windows/wintun_device.c`, `device_dispatch.c` | `DeviceType=wintun`, `WintunAddress`, `WintunInterface` | Built & shipped in the Windows GUI; take the **yaml-config** variant (adapter-name-collision fix) |
| Single-file YAML config — daemon **read** | `src/yamlconf.c` (own parser, no libyaml), `conf.c:config_fopen()`, `keys.c`, `names.c` | `-c tinc.yaml` | Works via ad-hoc harness; no unit test yet |
| Single-file YAML config — daemon **write-back** of learned peer keys | `yamlconf_append_host_line()`, `append_config_file()` (`conf.c:443`) | — | Works; re-emits whole file (loses comments) |
| sendmmsg() relay TX batching | *removed 2026-09-16* (`git show 16eb7bc`) | — | **Measured slightly worse by its author** and `HAVE_SENDMMSG` made it active in every Linux build, so it was dropped rather than kept as a phantom default-off switch (`core/tincd/PATCHES.md` §4) |
| REQ_KEY glare tie-break + jittered restart cooldown (tincstack patch 5, `core/tincd/PATCHES.md` §5) | `src/protocol_key.c` (`req_key_ext_h`, `REQ_KEY` case), `src/net_packet.c` (`try_sptps`) | none (hardcoded) | Added 2026-09-16 by stream K after the M9 lab measured 30–90 s of relay-only traffic per simultaneous SPTPS start. When both peers are pending initiators the lexicographically smaller `Name` keeps its session and ignores the peer's `REQ_KEY`, the larger one yields as responder; the 30 s "No key after N seconds" cooldown (patch 1) gets ±20 % jitter. Wire-compatible: no new message; against an unpatched peer it is either resolved in one round trip (patched side has the smaller name) or identical to stock (larger name), never worse. Proof: `testing/nat-sim/results/2026-09-16/glare-fix/` |

Reference-only / to finish:
- Invitations are **stock upstream** (`src/invitation.c`, untouched). `tinc invite`
  emits `Name`, `NetName`, `ConnectTo=<inviter>`, `Mode`, `Broadcast`, the
  inviter host block, and `Ifconfig`/`Route` → a `tinc-up.invitation` script.
  **No auto-IP, no pool, no extra fields.** The extension hook is the
  `invitation-created` script. Invitations are **not** integrated with YAML mode
  (they read/write a classic tree in the runtime dir) — this is the single most
  important gap to close for one-line onboarding (points 3 & 9).

### `tinc-manager` (`/opt/gitrepo/vpn-experiments/tinc-manager`) — **Windows platform, adopt**

PySide6 GUI + headless `cli.py`, single `tinc.yaml`. Talks to the daemon by
shelling `tinc.exe`/`tincd.exe -c tinc.yaml`. The bundled binaries are the
Family-A `sptps-resync-fix` fork built with mingw-w64; **the YAML→config
materialisation is done inside the daemon in C (`yamlconf.c`), not in Python** —
so the config path is already cross-platform and shared.

Reusable as code: `backend/yaml_config.py` (schema model), `backend/tinc_control.py`
(dump-nodes parser + direct/relay detection), `cli.py`, `backend/runtime.py`
(process spawn), `backend/netmtu.py` (Wintun MTU clamp), `management.py`
(elevation, Scheduled-Task autostart, firewall rule). GUI: peer table + throughput
graph (pyqtgraph), key generate/import, host add/import/export, raw-YAML editor.

Known defects to fix during adoption: unbounded daemon log growth (rotation only
at start; a 13 MB log observed); non-atomic `tinc.yaml` save (truncate-in-place
over the only copy of the private keys); GUI startup dies on malformed YAML;
blocking `tinc.exe` calls on the Qt thread; **the Linux path of `cli.py` is broken**
(only Windows binaries in `resources/`); all three self-tests reference removed
APIs; README describes a materialiser that no longer exists. Invite/join has **no
UI** — the daemon can do it, the GUI cannot drive it. That is the top missing UX.

### `tincapp` (`/opt/gitrepo/vpn-experiments/tincapp`, fork of pacien/tincapp) — **Android platform, adopt**

Kotlin, GPLv3, minSdk 21, no JNI — `tincd`/`tinc` are shipped as
`libtincd.so`/`libtinc.so` and run as subprocesses; the TUN fd is handed to the
daemon over an abstract `LocalSocket` (`Device=@…`). Native deps built per-ABI by
CMake: lzo 2.10 + LibreSSL 3.7.3, four ABIs. Toolchain present on this host
(`/opt/android-sdk`, NDK 26.1); a debug APK was built.

**Per-app split routing already exists** (point 1's whitelist/blacklist):
`AllowApplication` / `DisallowApplication` keys in the per-network `network.conf`
(`data/VpnInterfaceConfiguration.kt:40-53`, applied at
`extensions/VpnServiceBuilder.kt:63-67`). **But there is no app-picker UI** — the
only way to set them is hand-editing `network.conf` via a file manager, and
mixing both lists silently fails (Android forbids it). Invite/join **is**
supported incl. QR scanning (`JoinNetworkToolDialogFragment`).

Two local uncommitted edits: `app/CMakeLists.txt` repoints the tinc source at a
**missing** absolute path `/opt/gitrepo/vpn-experiments/tinc-1.1pre18` (so the
last build used *vanilla* 1.1pre18, not any fork), and `build.gradle` disables the
Play-publish plugin. Adoption = repoint CMake at `core/tincd`, add the app-picker
UI, verify the fork builds under `--disable-curses --disable-readline` + LibreSSL
across 4 ABIs (the fork uses meson upstream but tincapp drives autotools —
**reconcile the build system**, see the plan's Android milestone).

### `docker/` + `tinc-docker` (`link0ln/tinc-docker`) — **Linux platform, reference + partial reuse**

`tinc-docker@alter/init-tinc.sh` is the closest thing to the desired first-run
auto-init: `tinc init`, key generation, subnet add, `tinc.conf` templating,
public-IP discovery via ipinfo.io, then `exec tincd`. Bugs to fix: `tinc-up`
hardcodes `10.200.210.1/24` ignoring the env vars; the `tinc.conf` heredoc
discards what `tinc init` wrote; it is master-only (no `tinc join` path).
`tinc-vless/docker/scripts/entrypoint.sh` has the cleanest **env→config mapping**
incl. `CONNECT_TO` comma-list → `ConnectTo` lines and auto VPN-IP from node
number — good template. The local `docker/` tree builds two obfs-enabled nodes but
commits private keys and leaves node3 with mismatched keys/ports; regenerate.

### `netmaker-dev/sim-*.sh` + `awg-proof.sh` — **NAT test harness, reference**

A NAT lab built from Docker bridge networks + dual-homed gateway containers doing
`iptables` DNAT/SNAT: `sim-cone.sh` (full-cone, non-port-preserving),
`sim-restricted.sh` (restricted-cone via conntrack-state FORWARD filter). The
"external port ≠ listen port" design is exactly the case tinc must survive.
`awg-proof.sh` is a netns+veth+`tcpdump -X` skeleton that proves handshake packet
shaping — directly reusable to prove tinc's obfuscation. **Reusable structure;
the netmaker/WireGuard specifics (`sim-setup.sh`, `wg show`, AWG binaries) are
discarded.** Missing pieces to add: a symmetric-NAT variant, a two-tier CGNAT
variant, TCP handling (tinc keeps a TCP meta channel), and pass/fail exit codes.

### `tinc-obfs` / `tinc-quic` / `tinc-vless-reality` — **reference designs only** (Family B, see the decision above)

What to mine from each, without importing code:

- **obfs**: the *config surface* (`ObfsJunkPacket{Count,MinSize,MaxSize}`,
  `Obfs{Init,Response,Transport}{HeaderJunkSize,MagicHeader}`, `ObfsHandshakeTag`
  pattern DSL `<b>/<c>/<t>/<r>/<rc>/<rd>`) and the runtime-control CLI shape
  (`tinc obfs status|enable|disable|set|tag`). Rebuild the *mechanism* with an
  authenticated marker, per-handshake (not per-packet) junk, cold-start-safe
  identification, and relay-awareness.
- **quic**: the msquic wiring (`--with-msquic`, `MsQuicOpen2`, datagrams for the
  data path, a bidirectional stream for meta, connection migration for NAT
  rebind) as an integration reference. Rebuild transport **negotiation** (does
  not exist anywhere — all forks are static both-sides-configured) and keep SPTPS
  *inside* the QUIC carrier so identity/crypto is unchanged.
- **vless-reality**: the **IP-pool allocator** algorithm (`allocate_vpn_ip()` in
  `invitation.c`: scan the subnet, skip IPs used in the host DB or pending
  invitations) and the HTTP-invitation-endpoint idea. Rebuild the REALITY-style
  front (real active-probing resistance: forward unauthenticated clients to a
  real upstream, present the upstream's certificate) properly — the fork's
  version sends a cleartext 302 to google and a self-signed cert named
  `tinc-vless`, which is the opposite of the goal.
