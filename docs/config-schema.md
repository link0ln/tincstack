# tincstack config schema — the one YAML file

A single YAML document is the source of truth on every platform. The daemon reads
and writes it in C (`core/tincd/src/yamlconf.c`); GUIs edit and validate it. This
document is the contract that file conforms to.

Design rules:

- **Every field is optional.** An empty file (or none) is valid; the daemon fills
  defaults on first run (ARCHITECTURE.md §1, principle 2).
- **`options` maps 1:1 to tinc.conf lines.** A scalar becomes one line, a list
  becomes repeated lines. This mirrors the existing `yamlconf.c` behaviour and
  keeps every current and future tinc option expressible without schema changes.
- **New tincstack features are expressed as ordinary `options` keys** so they flow
  through the same parser, the same write-back, and the same invitation
  propagation as native tinc options. No parallel config surface.

```yaml
# ── top level ────────────────────────────────────────────────────────────────
workdir: tincmgr-data          # optional; where runtime side-files go. Default:
                               # <dir of this file>/<netname>/
networks:
  <netname>:                   # == `tinc -n <netname>`; multiple networks allowed
    autostart: true            # bring this network up on daemon/GUI launch

    # ── options → tinc.conf (scalar = one line, list = many) ─────────────────
    options:
      Name: node-a             # this node's name; must match a hosts: key
      Mode: router             # router | switch | hub      (default router)
      Port: 0                  # 0 = OS-assigned ephemeral (good behind NAT)
      AddressFamily: ipv4      # ipv4 | ipv6 | any
      ConnectTo: [node-b]      # list → one ConnectTo line each

      # device backend (per platform; the daemon picks a sane default)
      DeviceType: wintun       # wintun (Windows) | tun (Linux) | tap | fd (Android)
                               # unset on Windows = wintun when wintun.dll loads
      WintunAddress: 10.210.0.1/24   # Windows: adapter IP, set without netsh
                                     # unset = own Subnet at the pool's prefix
      WintunInterface: gnet          # Windows: adapter name (collision-safe)

      # ── NAT-traversal resilience (Family-A; safe defaults, keep on) ────────
      UDPDiscoveryBurst: 5     # probes per discovery round while unconfirmed
      UDPRebindOnWake: yes     # rebind UDP to a fresh port after sleep/resume.
                               # daemon default is *no*; invitees get *yes* (M2)
      LocalDiscovery: yes

      # ── dead-peer detection / failover window (see the section below) ─────
      PingInterval: 60         # seconds of silence from a peer before it is
                               # pinged. Default 60.
      PingTimeout: 5           # seconds to wait for the PONG before the link is
                               # dropped. Default 5, must be 1..PingInterval.
                               # A silently dead peer is noticed somewhere in
                               # [PingInterval, PingInterval + PingTimeout]:
                               # measured 64 s at the defaults, 13 s at 10 / 3.
                               # Server-scoped, re-read on `tinc reload' (no
                               # restart), NOT carried by invitations.

      # ── address pool (point 8) ────────────────────────────────────────────
      AddressPool: 10.210.0.0/24   # network the inviter assigns invitee IPs from
                                   # default when starting a NEW network: 10.<rnd>.0.0/24
      AddressDiscovery: no         # `tinc invite`: ask tinc-vpn.org for our public
                                   # address when no Address is set. Off by default
                                   # (fingerprint + stall on filtered networks); the
                                   # default-route source address is used instead.

      # ── interface addressing (built-in tinc-up, see below) ────────────────
      InterfaceAddress: 10.210.0.3/24  # address/prefix for the tun interface.
                                   # Set by `tinc join` from the invitation's
                                   # Ifconfig; default = own Subnet + AddressPool prefix
      InterfaceRoute: [10.220.0.0/24]  # extra routes via the interface (from the
                                   # invitation's Route lines); "net gw" form allowed

      # ── transport selection & negotiation (points 5, 6, 7) ────────────────
      Transports: [plain, obfs, https, quic]   # ACCEPT list: what this listener
                               # answers. Default: every carrier compiled in.
      PreferredTransports: [plain]   # DIAL preference, in order; the first one
                               # present in the peer's accept list is used
                               # (ARCHITECTURE.md §4). Default: [plain].
      AllowPlainMeta: yes      # may the LISTENER take an inbound CLEARTEXT tinc
                               # meta connection? Default yes (what tinc has
                               # always done). `no' drops `plain' from the
                               # effective accept mask, so the front refuses an
                               # unwrapped tinc ID line (and tarpits it, like an
                               # unrecognised preamble) instead of answering with
                               # its own ID line. Use it when the node must not
                               # be fingerprintable as tinc by a probe.
                               # Costs, before you set it (docs/transports.md
                               # §2.1): `tinc join' AGAINST this node stops
                               # working (join sends "0 ?<key>" in cleartext);
                               # upstream tinc peers and peers whose
                               # PreferredTransports is the default [plain]
                               # cannot reach it at all. It does NOT change
                               # secrecy -- SPTPS protected the payload either
                               # way -- and it does not affect the UDP data path,
                               # outbound dialling, or the local tinc CLI (the
                               # control connection is a UNIX socket; on Windows
                               # it is a loopback TCP connection, and loopback is
                               # exempt from the refusal).
                               # Server-scoped, re-read on `tinc reload'.
                               # Deliberately NOT carried by invitations: it is a
                               # per-node listener policy, not a network-wide one.

      # obfuscated-UDP tier (point 6, cheap tier; redesigned mechanism).
      # Active only when `obfs' is selected (PreferredTransports: [obfs, plain]);
      # with obfs unselected and ObfsJunkPacketCount 0 the wire is plain tinc.
      # All keys are server-scoped, propagate through invitations, and are
      # re-read on `tinc reload'. Full mechanism in docs/transports.md §5.
      ObfsJunkPacketCount: 0        # junk datagrams emitted around each handshake
                                    # (0 = off); never per data packet
      ObfsJunkPacketMinSize: 40     # min junk datagram size (bytes), 1..1400
      ObfsJunkPacketMaxSize: 200    # max junk datagram size (bytes), 1..1400
      ObfsInitHeaderJunkSize: 0     # random tail bytes on handshake-phase frames
                                    # (AmneziaWG S1), 0..1400
      ObfsTransportHeaderJunkSize: 0 # random tail bytes on steady-state frames
                                    # (AmneziaWG S2), 0..1400
      ObfsInitMagicHeader: 0        # if set, force the first 4 nonce bytes of
                                    # handshake-phase frames to this value so the
                                    # leading bytes mimic another protocol
                                    # (AmneziaWG H1); 0 = random nonce
      ObfsTransportMagicHeader: 0   # same for steady-state frames (H2)
      # Runtime CLI: tinc obfs status | enable | disable |
      #              set <key> <value> | get <key> | tag <c>/<min>/<max>[/<s1>[/<h1>]]
      # (aliases: junkcount/jc jmin jmax initjunk/s1 transportjunk/s2
      #           initmagic/h1 transportmagic/h2). Changes persist to this YAML.

      # HTTPS front & the `https` carrier (point 6; active-probing resistance).
      # M5 (G1): the decoy is DEFAULT-ON on the tinc listen port whenever tinc is
      # built against OpenSSL -- no option enables it, and `https' is in the
      # default accept list. There is no separate front port: a TLS ClientHello
      # on the normal listen port gets a TLS handshake with the node's cert and
      # then either the `https' carrier (authenticated peer) or the decoy.
      TlsCert: /etc/tincstack/fullchain.pem   # real cert (PEM, leaf + chain); optional
      TlsKey:  /etc/tincstack/privkey.pem     # matching private key (PEM). If either
                                              # is unset a self-signed P-256 cert is
                                              # generated at first start into
                                              # keys.tls_cert/tls_key below and reused
                                              # on every restart; shared with QUIC.
      HttpsSni: www.example.com               # SNI the `https' DIAL presents; default =
                                              # the peer's Address if it is a hostname,
                                              # else none (an IP gets no SNI, as curl
                                              # sends none; `localhost' until 2026-09-23)
      HttpsDecoyRoot: /var/www/decoy          # static files served to probers, with
                                              # nginx's answers (404/405/400, dates,
                                              # ETag); unset = nginx's welcome page
      HttpsDecoyUpstream: "example.com:80"    # or transparently proxy probers here
                                              # (host:port; Host header rewritten)

      # QUIC carrier (point 7; M5 G3). Compiled when tinc is built with ngtcp2 +
      # OpenSSL >= 3.5 (the Docker image is, on Debian 13); then `quic' is in the
      # default accept list and is dialled only when a node lists it in
      # PreferredTransports ([quic, plain]). Meta rides one QUIC stream, SPTPS
      # data rides DATAGRAM frames; the node certificate (keys.tls_cert) and the
      # https authenticator are shared. Mechanism: docs/transports.md §9.
      HttpsPort: 443                # TCP listener for the https front only
                                    # (docs/transports.md 3.1). Default 443 on a
                                    # listening node, none with Port = 0; 0 = off.
                                    # The node writes the port it bound into its
                                    # own host record; that is where peers dial.
      QuicPort: 443                 # UDP listener for the quic front only; same
                                    # default and advertisement as HttpsPort.
      QuicSni: cdn.example.net      # SNI the quic DIAL presents; default = HttpsSni,
                                    # else the peer's Address if it is a hostname,
                                    # else none
      QuicAlpn: h3                  # ALPN offered by the dial and required by the
                                    # listener; default h3

    # ── embedded identity (self-contained config) ───────────────────────────
    keys:
      ed25519_priv: |          # PEM; generated by the daemon/GUI if absent
        -----BEGIN ED25519 PRIVATE KEY-----
        ...
      rsa_priv: |              # legacy; optional
        -----BEGIN RSA PRIVATE KEY-----
        ...
      tls_cert: |              # self-signed, generated at first start if no
        -----BEGIN CERTIFICATE-----      # TlsCert/TlsKey; replace freely
        ...
      tls_key: |
        -----BEGIN PRIVATE KEY-----
        ...

    # ── per-network scripts (optional) ───────────────────────────────────────
    scripts:                   # each entry is materialised by the daemon as
      host-up: |               # <runtime dir>/<name> (mode 0700, atomic write)
        #!/bin/sh              # on every start and on every reload, and run by
        echo "$NODE up" >> /var/log/mesh   # tinc as the script of that name
      tinc-up: |               # (tinc-up, tinc-down, host-up, host-down,
        ...                    # subnet-up, subnet-down, invitation-created,
                               # invitation-accepted). Deleting a key removes
                               # the file on the next reload. tinc-up is rarely
                               # needed: see "Built-in interface setup" below.

    # ── peer host records (the host database) ────────────────────────────────
    hosts:
      node-a: |                # this node's own host file
        Ed25519PublicKey = ...
        Subnet = 10.210.0.1/32
        TlsFingerprint = 6316...e2d3       # SHA-256 of this node's TLS cert;
                                           # written at first start, propagated
                                           # in invitations, pinned by peers
      node-b: |
        Address = 198.51.100.7
        Port = 443
        Ed25519PublicKey = ...
        Subnet = 10.210.0.2/32
        Transports = quic, https, plain   # peer's advertised carriers
        TlsFingerprint = 6776...64f2      # pinned; the `https' and `quic' dials
                                          # verify the peer cert against it
                                          # (accept-on-first-use then pin if absent)
        HttpsPort = 443                   # written by the peer itself: dial its
        QuicPort = 443                    # https / quic front here instead of Port
```

## Dead-peer detection (`PingInterval`, `PingTimeout`)

These two options are the failover window, and they are the reason a node that
has to fail over fast needs anything more than the defaults.

**Mechanism** (`core/tincd/src/net.c`, `timeout_handler()`; the values are
parsed in `net_setup.c`, `setup_ping_timers()`):

- a meta connection that has been silent for `PingInterval` seconds gets a
  `PING`;
- if no `PONG` arrives within `PingTimeout` seconds, the connection is closed,
  the edge is withdrawn and the routing table reconverges.

A peer that dies *silently* — power cut, frozen VM, a path that starts dropping
everything — dies at a moment uncorrelated with the ping cadence, so detection
is a uniform draw over `[PingInterval, PingInterval + PingTimeout]`. A peer that
dies *loudly* (process exit, TCP RST, interface down) is noticed at once; the
window is irrelevant to it.

**Measured** (`testing/config/ping-interval-test.sh`, one node frozen with
`docker pause` so the kernel still ACKs and only the daemon goes quiet):

| window | detection (two runs) |
|---|---|
| defaults, 60 / 5 | 64 s, 65 s |
| 10 / 3, set at startup in the YAML | 13 s, 12 s |
| 10 / 3, applied by `tinc reload` on the running daemon | 10 s, 10 s |

The field stand ran the defaults and reconverged in 21 / 45 / 46 s over three
trials (PLAN.md, defect G in the field) — three draws from the same 60–65 s
window, not a regression.

**Costs of a short window**, in the order they bite:

- a false disconnect on a link that merely stalls. `PingTimeout` is a hard
  deadline on a single round trip over a meta connection that may be running on
  `https` or `quic` (TLS records, head-of-line blocking) through a congested
  path. A 1 s timeout on a satellite or a loaded mobile link will tear down a
  perfectly good tunnel and, on reconnect, cost more than the failover it was
  meant to shorten;
- meta traffic and wakeups scale with `1 / PingInterval` per connection —
  irrelevant on a server, measurable on a battery-powered Android node;
- PMTU re-probing uses `PingInterval` as its idle cadence
  (`net_packet.c`), so shortening it also re-probes more often.

Start at `PingInterval: 20`, `PingTimeout: 5` for a stand that wants sub-30 s
failover, and only go lower with a measurement of the actual round-trip
distribution of that path.

**Scope and lifetime:**

- server-scoped (they live under `options:`, not in a host record), and
  **not** in the invitation allow-list — each node keeps its own window, so
  shortening it on the node that must notice a failure does not push the cost
  onto every invitee;
- re-read on every reload, including the implicit one that `tinc set` performs,
  so `tinc -c tinc.yaml set PingInterval 10` changes the window of a running
  daemon. The daemon logs the change (`Dead-peer detection window changed on
  reload: PingInterval 60 -> 10, PingTimeout 5 -> 3 seconds.`) and says nothing
  when a reload does not move them;
- an established QUIC carrier keeps the handshake and idle timeouts it derived
  from `PingTimeout` when it was created (`transport_quic.c`: handshake
  `PingTimeout`, idle `3 × PingTimeout`); the new value applies to QUIC
  connections made after the reload.

**Out-of-range values are substituted, and the substitution is logged.** The
substitutions are upstream's (configs that rely on them keep working), the
logging is not:

| written | used | logged |
|---|---|---|
| `PingInterval: 0` (or any value < 1) | 86400 s | `PingInterval 0 is out of range (minimum 1), using 86400 seconds instead: a peer that stops answering stays reachable in the routing table for up to a day.` |
| `PingTimeout` < 1 or > `PingInterval` | `PingInterval` | `PingTimeout 99 is out of range (1..PingInterval = 10), using 10 seconds instead.` |
| `PingInterval` below the default timeout, no `PingTimeout` | `PingInterval` | `The default PingTimeout of 5 seconds is longer than PingInterval 2, using 2 seconds instead.` |
| a non-integer value | the default | `Integer expected for configuration variable PingInterval in …` |

`PingInterval: 0` reads like "stop pinging" and means "ping once a day", i.e. a
day-long blind spot in which a dead peer stays in the routing table. That is the
one every operator gets wrong; it now says so out loud at startup and on reload.

## Zero-config materialisation (first run)

When `tincd -c <file>.yaml` starts and the file is empty, comment-only or absent,
the daemon fills in what is missing for the selected network **before** reading
the config (`core/tincd/src/zeroconf.c`), then writes the file back (mode 0600,
atomic temp+rename). Nothing already present is changed.

| field | default | note |
|---|---|---|
| network name | `-n <net>`, else the first network in the file, else `tincstack` | the CLI resolves it the same way, so `tinc -c file.yaml …` finds the daemon |
| `options.Name` | first label of the hostname, non-`[A-Za-z0-9_]` → `_`; `node_<hex>` if unusable | `$HOST`/`$VAR` forms are honoured if present |
| `options.Mode` | `router` | |
| `options.Port` | `655` if no `ConnectTo` (founding node), else `0` | invitees dial out, so a fresh NAT mapping per start beats a stable port |
| `options.AddressPool` | the first free `10.<x>.<y>.0/24`, from a random start | validated: IPv4, prefix 8–30. "Free" means it overlaps no network this machine is already attached to (`getifaddrs`/`GetAdaptersAddresses`); skipped candidates are logged. A node that is somehow on all of 10/8 warns and uses its first candidate anyway |
| `hosts.<Name>` `Subnet` | first host of the pool, `/32` | |
| `keys.ed25519_priv` + `hosts.<Name>` `Ed25519PublicKey` | generated | public line is re-derived if only the private key exists |
| `keys.rsa_priv` + `hosts.<Name>` RSA public PEM | generated (2048) | unless built with `-Dcrypto=nolegacy` |
| `keys.tls_cert` + `keys.tls_key` + `hosts.<Name>` `TlsFingerprint` | generated (self-signed P-256, `localhost` subject, 10 y) | OpenSSL builds only; skipped if `TlsCert`/`TlsKey` files are set; the fingerprint is the cert's SHA-256 |

An existing file that does not parse is **refused**, never overwritten. No
`hosts/` directory is created next to a YAML config; runtime side-files
(`cache/`, `invitations/`, pid/socket if `/var/run` is unwritable) go under
`<dir of file>/<netname>/`.

## Scripts (`scripts:`)

`networks.<net>.scripts.<name>` holds the text of the script tinc runs as
`<name>` (`tinc-up`, `tinc-down`, `host-up`, `host-down`, `subnet-up`,
`subnet-down`, `invitation-created`, `invitation-accepted`; on Windows the
key carries the `ScriptsExtension`, e.g. `tinc-up.bat`). The daemon
materialises every entry into the runtime dir `<dir of file>/<netname>/`
(`core/tincd/src/zeroconf.c`, `zeroconf_sync_scripts()`), so the unchanged
`execute_script()` path (`script.c`) runs it with tinc's usual environment
(`NETNAME`, `NAME`, `INTERFACE`, `NODE`, `REMOTEADDRESS`, …):

- **when:** on every daemon start and on every reload (`tinc reload`, or any
  CLI edit that asks the daemon to reload), before the `tinc-up` decision
  below, so a script edited in the YAML takes effect without a restart;
- **how:** each file is written atomically — a temp file in the same
  directory, mode 0700 (owner only, executable), fsync, rename — so tinc
  never runs a half-written script and a failed write leaves the previous
  file in place (logged, the daemon keeps running). An entry whose content is
  already on disk is not rewritten. Log: ``Wrote script `host-up' from
  `…/tinc.yaml' into `…/<netname>'``;
- **deleting** a key removes the file the daemon wrote at the next reload
  (``Removed script `…/host-up': no longer in `…/tinc.yaml'``). Only files this
  daemon process wrote are removed; the YAML is the source of truth for what
  it put there;
- **side files:** a script that is on disk but not in the YAML (dropped in by
  hand, or left by an older image) is left alone and still runs; the daemon
  says so once per name (``Script `…/tinc-down' is a side file not described by
  `…/tinc.yaml' (scripts.tinc-down); it runs as is and is left alone``). A side
  file with the same name as a YAML key is overwritten by the YAML;
- a key that is not a plain file name (`/`, `\`, leading `.`) is ignored with
  an error; a text that would not round-trip as a literal block (a line with
  trailing blanks, a tab) is written double-quoted by the emitter and reads
  back byte for byte (property 10 in `core/tincd/test/fuzz/yamlconf_props.c`).

### Editing a script from the CLI

`tinc -c <file>.yaml get|set|del scripts.<name>` edits the stanza the same way
`tinc set` edits `options:` and `hosts.<node>`: under the writers' lock, with a
re-read of the file first (the daemon writes learned keys into it), an atomic
save, and a reload request to the running daemon — so the change is materialised
without a restart and without an explicit `tinc reload`, and without racing the
daemon's own writes (hand-editing a YAML of a *running* node does race them).

    tinc -c tinc.yaml set scripts.tinc-up @./tinc-up   # body from a FILE
    tinc -c tinc.yaml get scripts.tinc-up              # prints the body
    tinc -c tinc.yaml del scripts.tinc-up              # drops the key

- **the body comes from a file**, `@<path>`; an inline value is refused with a
  message naming the `@file` form. A script is multi-line, and `tinc set`
  concatenates its arguments with single spaces into one 4096-byte buffer and
  then splits on `[ \t=]`, which would both mangle and silently truncate a
  script — and a truncated script still runs as root. Stdin is not used either:
  it is already `tinc`'s own command stream in shell/batch mode, so `@-` is
  deliberately not accepted;
- `get` prints the stored text plus a newline; since the emitter writes a
  literal block and the parser chomps, that is a byte-for-byte round trip of a
  file that ends in a single newline;
- `<name>` must be a plain file name (no `/`, no `\`, no leading dot) — the
  same rule the daemon applies when it materialises the stanza. `scripts.` is
  therefore a reserved prefix in the CLI's `<node>.<variable>` namespace: a node
  literally named `scripts` cannot be edited as `scripts.<Variable>`;
- deleting the last entry removes the `scripts:` key itself (an empty map would
  be emitted as `{}` and read back as a scalar);
- YAML mode only: in a confbase tree a script is just a file in the confbase,
  and the CLI says so.

Proof lab: `LAB=wss platforms/linux/docker/yaml-scripts.sh` (step 6 covers the
CLI: `set @file` → `Wrote script`, mode 0700, `get` round trip, inline refused,
the script runs on the next `host-up`, `del` → `Removed script`).

## Built-in interface setup (Linux)

Every YAML-mode node knows its own address, so no hand-written `tinc-up` is
needed. When the daemon brings the device up it looks for `<runtime
dir>/tinc-up` (materialised from `scripts.tinc-up` if present, or dropped in
by hand). If there is none, on Linux it runs the equivalent of

```
ip addr replace <InterfaceAddress> dev $INTERFACE     # or <own Subnet host>/<AddressPool prefix>
ip link set $INTERFACE up
ip route replace <InterfaceRoute> dev $INTERFACE      # one per InterfaceRoute
```

itself (`core/tincd/src/autoif.c`). Windows does the same thing through the
Wintun driver instead of `ip`: the adapter is created on connect and given
`WintunAddress`, or — when that option is absent — the node's own address from
exactly the same pair the built-in tinc-up uses (its `/32` Subnet at the
`AddressPool` prefix, `autoif_own_address()`), so a node that joined by
invitation comes up addressed with nothing written by hand. Android hands the
daemon a pre-configured fd. Neither Windows nor Android runs the `ip`
commands above. **Precedence:** a `scripts.tinc-up` in the YAML always wins — it is
on disk before `device_enable()` looks, so the built-in is *skipped* entirely
(the log then shows `Executing script tinc-up` and no `built-in tinc-up`
line); the same holds for a hand-made side file. With neither, the built-in
runs. `tinc-down` has no built-in counterpart: the kernel drops the address
with the interface.

## Invitation and join in YAML mode

`tinc -c tinc.yaml invite <name>` (the inviter) writes an invitation that
carries, beyond upstream tinc's `Name`/`NetName`/`ConnectTo`:

- every **propagated server option** the inviter has set — the list is
  `PROPAGATED_OPTIONS[]` in `core/tincd/src/invitation.c`, an **exact
  allow-list** (no prefix patterns, security review R): `Mode`, `Broadcast`,
  `AddressPool`, `Transports`, `TlsFingerprint`, `ObfsJunkPacketCount`,
  `ObfsJunkPacketMinSize`, `ObfsJunkPacketMaxSize`, `ObfsInitHeaderJunkSize`,
  `ObfsTransportHeaderJunkSize`, `ObfsInitMagicHeader`,
  `ObfsTransportMagicHeader`, `HttpsSni`. An entry here is written into the
  invitee's `options:` by whoever issued the invitation, without the
  `VAR_SAFE` check every other invitation line goes through, so only options
  both ends must agree on and that cannot make the invitee read, serve or
  execute anything qualify. `HttpsDecoyRoot`, `HttpsDecoyUpstream`,
  `TlsCert`/`TlsKey` and per-node settings (`Port`, `ConnectTo`,
  `PreferredTransports`, `AllowPlainMeta`, …) are deliberately not propagated;
- the invitee's address from the pool: `Subnet = a.b.c.d/32` (its host record)
  and `Ifconfig = a.b.c.d/<pool prefix>` (its interface address);
- the inviter's own host record, with a `Port` line guaranteed (the inviter's
  `Port` normally lives in `options:`, not in its host record).

The address is the **lowest free host address of `AddressPool`**, skipping the
network and broadcast addresses, every `Subnet` in `hosts:` (own record
included), addresses promised by pending invitations in `<runtime
dir>/invitations/`, and — when the daemon is running — every subnet it currently
sees (`tinc dump subnets`); an address held by a live node is never re-issued
even if its host record was edited away. Deleting a pending invitation file
frees its address. The pool is only as consistent as the inviter's view of it:
let one node (or nodes that can see each other) do the inviting.

`tinc -c new.yaml join <invite>` (the invitee; the file may be absent or empty)
writes the joined network into the YAML — `-n` names it, else the invitation's
`NetName`, else `tincstack` — and nothing else: no `tinc.conf`, `hosts/`,
`*_key.priv` or `tinc-up.invitation`. It stores `Name`, the propagated options,
`ConnectTo = <inviter>`, `InterfaceAddress`/`InterfaceRoute` (from
`Ifconfig`/`Route`; `dhcp`/`slaac` forms are not supported and are ignored with a
message; a value must look like an address[/prefix] or a route, since the
daemon later hands it to `ip`, and every applied one is logged), its own
host record (`Subnet`, generated `Ed25519PublicKey` and RSA
public key) and the inviter's host record, then runs the same materialiser as an
empty-file start to generate the keys. **Invitee defaults:** `Port = 0` and
`UDPRebindOnWake = yes` (it always dials out; a fresh NAT mapping per start is
what it wants). The founding node keeps `Port = 655`.

On the inviter, the daemon persists the invitee's learned `Ed25519PublicKey`
**and its assigned `Subnet`** into `hosts.<name>` when the invitation is
redeemed, so the address stays reserved after the invitation file is gone.
An invitation is only consumed once that record is stored: if storing fails,
the inviter puts the invitation back (log: `… was not completed; it can be
used again`), the invitee removes what `tinc join` had written, and the same
invitation string can simply be retried.

## Android interface options (one file on Android too)

Android's VPN interface parameters (interface address, routes, DNS, per-app
split routing) are ordinary `options:` keys of the network's `tinc.yaml`. The
daemon ignores keys it does not use (`tinc get` warns "not a known
configuration variable" but reads them); the app reads them and writes only the
ones it manages. There is **no second file**: the former `network.conf` is gone.
On the device each network is a directory `networks/<net>/` holding `tinc.yaml`
(the daemon's runtime side-files go to `networks/<net>/<net>/`).

```yaml
networks:
  <netname>:
    options:
      InterfaceAddress: 10.210.0.3/24  # the top-level option (one or more); what
                                       # `tinc join` writes from the invitation's
                                       # Ifconfig. Absent → derived from this node's
                                       # own Subnet + AddressPool prefix
      InterfaceRoute:                  # the top-level option; traffic sent through
        - 10.210.0.0/24                # the tunnel. Absent → AddressPool. "prefix
        - 0.0.0.0/0                    # [gateway]" as `tinc join` writes it from the
                                       # invitation's Route; only the prefix is used
                                       # on Android (a tun fd has no next hop)
      DNSServer: [10.210.0.1]          # DNS server(s) for the tunnel
      SearchDomain: mesh.internal
      AllowApplication:                # WHITELIST: only these apps use the VPN
        - org.example.browser
      DisallowApplication: [org.x]     # BLACKLIST: every app except these
      AllowFamily: 2                   # AF_INET (2) / AF_INET6 (10)
      AllowBypass: no                  # let apps bind to the physical network
      Blocking: no
      MTU: 1400
      ReconnectOnNetworkChange: yes
```

Rules:

- `AllowApplication` and `DisallowApplication` are **mutually exclusive**
  (Android forbids mixing them on one `VpnService.Builder`). The app refuses a
  file that has both, and its app-picker writes exactly one key: saving one
  mode removes the other. An empty selection means "all apps" (no key).
- The app writes with a key-level textual splice of the existing document and
  replaces the file atomically (temp + rename), like the daemon's own
  write-back: unrelated options, `keys:`, `hosts:` and comments are preserved
  byte for byte. A change made while that network is connected applies at the
  next connection.
- `InterfaceAddress`/`InterfaceRoute` are the same keys on every platform:
  `tinc join` writes them into `options:` from the invitation's
  `Ifconfig`/`Route` lines (`finalize_join_yaml` in
  `core/tincd/src/invitation.c`), the Linux built-in tinc-up
  (`core/tincd/src/autoif.c`) and the Android app read them. The join writes
  no side-file (`invitation-data` does not exist in YAML mode) and the app
  folds nothing in. With neither key present the interface still comes up on a
  zero-config node: address = own `Subnet` with the `AddressPool` prefix,
  route = `AddressPool` (the same fallback autoif.c applies).
- Private keys are embedded (`keys:`) and unencrypted; the app's former
  passphrase feature (encrypted `*.priv` files + unlock dialog) does not apply
  and was removed.

## Lists: both block styles are read

A list may be written inline (`ConnectTo: [a, b]`) or as a block sequence, and
in a block sequence the dashes may sit at the key's own indentation or deeper:

```yaml
      PreferredTransports:        PreferredTransports:
      - quic                        - quic
      - https                       - https
```

Both parse to the same list. The left-hand form is what PyYAML emits by
default and therefore what the Windows GUI used to write; the daemon refused
it until 2026-09-19, which bricked every config the GUI saved with a list in
it (`Could not parse YAML config` on the next start). The emitter writes the
right-hand form, and so does the GUI now — one house style, both accepted.

A `-` line that follows a key which already has a scalar value is still an
unplaceable line and is still refused: the parser never guesses.

## Routing a subnet another node announces (`InterfaceRoute`)

A node can announce more than its own address: `Subnet = 192.168.1.0/24` in its
host record says "I am the way to that LAN". Every other node then knows, in
tinc's own routing table, that packets for 192.168.1.0/24 go to that peer.

That is only half of it. The operating system still has no reason to hand those
packets to the tunnel adapter in the first place, and `autoif.c` deliberately
installs system routes **only** from explicit `InterfaceRoute` entries, never
from what peers announce — a peer must not be able to change this machine's
routing table by announcing a subnet.

So the second half is one option:

```yaml
options:
  InterfaceRoute:
    - 192.168.1.0/24 10.200.240.7     # "<prefix> [gateway]" -- what `tinc join`
    - 10.99.0.0/24 via 10.200.240.7   # writes; the `ip route` spelling also works
    - 172.16.0.0/12                   # no gateway: on-link through the tunnel
```

Both spellings are accepted on every platform. The gateway is recorded mostly
to say *which node* the route is for: on a tun/Wintun interface the kernel just
hands the packet to the device, and tinc decides where it goes from there.

Where it is installed:

| platform | what installs it |
|---|---|
| Linux | the built-in tinc-up, `ip route replace <prefix> [via <gw>] dev $INTERFACE` (`autoif.c`) — only when there is no `scripts.tinc-up`, which takes over completely |
| Windows | the Wintun backend, `CreateIpForwardEntry2` on the adapter's LUID (`windows/wintun_device.c`) |
| Android | the tun builder takes the prefix; a tun fd has no next hop, so the gateway is ignored |

On both Linux and Windows the route is attached to the tunnel interface, so it
disappears with the interface when tinc stops: a route into a peer's LAN never
outlives the tunnel that was the only way to reach it.

### The Windows GUI writes these for you

In *Peers & Traffic* every peer that announces a routable subnet has a toggle in
the **Route here** column, one per subnet. Ticking it writes the
`InterfaceRoute` entry (with that peer's VPN address as the gateway), saves the
file, and installs the route on the live adapter with `netsh ... store=active`
so it takes effect without restarting the network. Unticking removes both.

Two things it will not do:

- **A peer's own address gets no toggle.** It is a `/32`; it is already
  reachable, and a route to it would be meaningless.
- **`0.0.0.0/0` gets no toggle.** A full tunnel also sends the tunnel's own
  packets through the tunnel unless the peer's endpoint is pinned to the
  physical gateway first, and an endpoint that moves — a NAT rebind, an address
  cache entry, a relayed peer with no direct endpoint at all — then takes the
  machine off the network entirely. That is a feature with its own failure
  modes, not a checkbox.

And one thing it will warn about: if the subnet overlaps a network this machine
is already attached to (`192.168.1.0/24` announced by a peer, on a laptop that
is itself sitting on `192.168.1.0/24` at home) the route takes those addresses
away from the adapter that owns them. The GUI says so and asks before writing.

Proof: `testing/config/interface-route-test.sh` — node2 owns a LAN and
announces it, node1 has the `InterfaceRoute` and no tinc-up script. It asserts
the route is installed on the tinc interface in both spellings, that the LAN is
reachable through it, that tinc knew the subnet all along, and — the control
that makes the rest mean anything — that deleting the route makes the LAN
unreachable again.

## A real certificate for the `https` and `quic` front (`tinc cert`)

The node certificate that the `https` and `quic` carriers present is
self-signed by default (`tls.c`, docs/transports.md §8.1). That is enough for
peers — they pin its fingerprint — but nothing else trusts it, and a
self-signed certificate on a port pretending to be an HTTPS service is exactly
what an observer does not expect. An operator who owns a domain in Cloudflare
can replace it with a publicly trusted one.

All of it is optional: with none of these options set, nothing changes.

```yaml
networks:
  gnet:
    options:
      CertDomain: vpn.example.com          # what the certificate is for
      CloudflareToken: <api token>         # Zone:Read + Zone:DNS:Edit on its zone
      AcmeContact: mailto:you@example.com  # optional, for expiry warnings
      AcmeRenewDays: 30                    # renew inside this many days (default 30)
```

| option | meaning |
|---|---|
| `CertDomain` | the public DNS name to issue for. Plain name, no scheme, no port, no wildcard. |
| `CloudflareToken` | a Cloudflare **API token** (not a Global API Key) that can read the zone and edit its DNS records. |
| `AcmeContact` | `mailto:` address registered with the CA. Optional. |
| `AcmeDirectory` | ACME directory URL. Defaults to Let's Encrypt production; `tinc cert issue --staging` switches to their staging CA for a dry run. |
| `AcmeRenewDays` | `tinc cert renew` reissues when fewer than this many days remain (default 30). The daemon uses the same number for its expiry warning. |
| `AcmePropagation` | seconds to wait after writing the DNS record before asking the CA to look (default 20). |
| `AcmePollTimeout` | seconds to wait for the CA's validation (default 120). |
| `AcmeCaFile` | trust anchor for the CA, **tests only** (testing/acme/). |
| `CloudflareApi` | Cloudflare API base URL, **tests only**. |

None of these is `VAR_SAFE` and none is in `PROPAGATED_OPTIONS`: the token is a
credential and the domain belongs to one node, so an invitation never carries
them. The token is stored in the same file as the private keys, which is mode
0600 — treat it accordingly.

### The command

```
tinc -c tinc.yaml -n gnet cert status     # what this node presents today
tinc -c tinc.yaml -n gnet cert check      # is the token usable for CertDomain?
tinc -c tinc.yaml -n gnet cert issue      # obtain and store a certificate
tinc -c tinc.yaml -n gnet cert renew      # issue only if it is about to expire
```

### Keeping it alive

A certificate from Let's Encrypt is valid for 90 days, and `renew` is a command,
not a daemon. Three things now cover the gap, and none of them is automatic
everywhere:

| where | what happens |
|---|---|
| the daemon (every platform) | once a day, while fewer than `AcmeRenewDays` remain, it logs `The TLS certificate for the https/quic front (…) expires in N days. Run 'tinc cert renew'.` — and keeps saying so, as an error, after it has expired |
| the Linux node image | the entrypoint runs `tinc cert renew` a minute after start and then every `CERT_RENEW_INTERVAL` (12 h by default) once `CertDomain` and `CloudflareToken` are set. `CERT_RENEW=0` turns it off; peers follow a renewal on their own, see "After issuing" below |
| the Windows manager | the toolbar's certificate button turns into `⚠ Certificate: N d left` (and `⚠ Certificate EXPIRED (N d)`), checked at start, on every network switch and every six hours. Renewing is still a click — nothing on Windows runs it unattended |

An expired certificate does not break the VPN: peers pin the fingerprint
(`TlsFingerprint`) and never look at dates. It breaks the *point* of the
certificate — an expired certificate on a public HTTPS port is more remarkable
to an observer than the self-signed one it replaced. Proof that all three work:
`testing/config/cert-lifecycle-test.sh`.

`issue` runs the ACME **DNS-01** challenge: it finds the Cloudflare zone that
contains `CertDomain`, writes `_acme-challenge.<domain>` as a TXT record, waits,
asks the CA to validate, sends a CSR for a fresh P-256 key, stores the
certificate and the key under `keys.tls_cert` / `keys.tls_key`, and removes the
TXT record again — on failure too. The ACME account key is kept under
`keys.acme_account` and reused. A running daemon is asked to reload, so no
restart is needed.

It runs in the **CLI, never in the daemon**: a certificate authority takes
seconds to minutes to answer, and the daemon's main loop may not block (defect
M5-1). The Windows GUI has the same thing behind the *Certificate…* button, on
a worker thread.

### After issuing: the fingerprint moves

Peers pin this certificate by SHA-256 fingerprint (`TlsFingerprint` in this
node's host record, docs/transports.md §8.2). Replacing the certificate
replaces the fingerprint, so `tinc cert issue` rewrites `TlsFingerprint` in the
node's own host record and says so. Peers that hold the old pin follow by
themselves, on every platform: the next session carries on with the new
certificate like a first contact, and its fingerprint replaces the old pin once
SPTPS has authenticated this node (docs/transports.md §8.2, "A moved pin"). No
CA or trust store is involved. For the certificate to be worth anything to an
observer, their host record for this node should have `Address = <CertDomain>`,
because the SNI the dialer sends comes from that address.

### When it does not work

Every failure has its own code, one sentence of what happened and one of what
to do; the code is stable and is what the GUI shows and what a bug report
should quote.

| code | what it means |
|---|---|
| `config` | `CertDomain` or `CloudflareToken` is missing or is not shaped like one. |
| `cloudflare-token` | Cloudflare rejected the token, or the token is not active. A Global API Key lands here. |
| `cloudflare-permission` | the token authenticates but lacks `Zone:Read` / `Zone:DNS:Edit`. |
| `cloudflare-zone` | the token works but reaches no zone containing `CertDomain`. The message lists the zones it *can* see — usually the mistake is a token for a different domain. |
| `cloudflare-api` | Cloudflare answered something else, rate limiting included. |
| `acme-directory` | `AcmeDirectory` is not an ACME directory. |
| `acme-account` | the CA refused to create the account (contact address, terms). |
| `acme-order` | the CA refused to issue for this name (policy, CAA record). |
| `acme-challenge` | the CA could not validate the TXT record — most often the zone is served by nameservers other than Cloudflare's, or propagation needs longer than `AcmePropagation`. |
| `acme-ratelimit` | the CA is rate-limiting this account or domain. Use `--staging` while testing. |
| `acme-finalize` | the CSR was refused or the order never became valid. |
| `network` | DNS, connect, TLS or a malformed HTTP response. |
| `crypto` | a local key, CSR or signature failure. |

Proof: `testing/acme/run.sh` issues a real certificate from a real ACME server
(Pebble) over DNS-01 against a stand-in Cloudflare API, and walks every
Cloudflare code plus `acme-challenge` above.

## Write-back behaviour (must be preserved cross-platform)

- The daemon persists **learned peer keys** (`Ed25519PublicKey`) into
  `hosts.<name>` at runtime via `yamlconf_append_host_line()`. This is how a
  joined node's key reaches the inviter's config.
- **Runtime reconfiguration** goes through the CLI: `tinc -c tinc.yaml set|add|
  del|get [node.]Variable [value]` edits `options:` (server variables; a repeated
  variable such as `ConnectTo` becomes a list) or `hosts.<node>` (host
  variables) with tinc's usual variable table and validation, saves atomically,
  and asks a running daemon to reload. `tinc reload` (and every reload) makes
  the daemon **re-read the YAML from disk** before re-parsing, so edits made by
  the CLI or a GUI take effect without a restart. Nothing ever creates a
  `tinc.conf` next to the YAML.
- A GUI that also writes the file must treat the daemon as a concurrent writer:
  write atomically (temp + rename), never truncate-in-place over the keys, and
  re-read before merging. The tinc-manager adoption fixes this (its current
  truncate-in-place save is a defect).
- **Writers' lock** (security review R): every C writer — the daemon's key
  write-back, `tinc set/add/del`, `tinc join`, the materialiser — serialises
  its whole read-modify-write on `<tinc.yaml>.lock` (a stable file next to the
  config; `flock` on POSIX, exclusive open on Windows). A lock on the config
  file's own inode is useless because saves rename over it. A GUI that writes
  the file should hold the same lock file around its read → merge → write.
- **Strict parser**: a document with a line the parser cannot place (a
  misindented key, a line without a colon inside a mapping) is refused as a
  whole — the daemon logs `Could not parse YAML config` and does not start —
  instead of being truncated at that line and written back without the rest.
  Duplicate keys take the last value, as PyYAML does. Mapping keys are at most
  255 bytes (a node name is also a `hosts/` file name), nesting at most 64
  levels; the C writer refuses to save a document it could not read back.
- The C writer re-emits the whole document (comments are not preserved). Editors
  must not rely on comment round-tripping. Scalars that would not read back
  verbatim (leading `[`, `|`, `#`, `-`, quotes, `: `, outer blanks, control
  characters) are written double-quoted; empty maps/sequences as `{}`/`[]`.
