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
      WintunAddress: 10.210.0.1/24   # Windows: adapter IP, set without netsh
      WintunInterface: gnet          # Windows: adapter name (collision-safe)

      # ── NAT-traversal resilience (Family-A; safe defaults, keep on) ────────
      UDPDiscoveryBurst: 5     # probes per discovery round while unconfirmed
      UDPRebindOnWake: yes     # rebind UDP to a fresh port after sleep/resume.
                               # daemon default is *no*; invitees get *yes* (M2)
      LocalDiscovery: yes

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
                                              # else `localhost'
      HttpsDecoyRoot: /var/www/decoy          # static files served to probers; a
                                              # generic default page ships if unset
      HttpsDecoyUpstream: "example.com:80"    # or transparently proxy probers here
                                              # (host:port; Host header rewritten)

      # QUIC carrier (point 7)
      QuicPort: 443
      # (QUIC keeps SPTPS inside it; cert handling shared with the HTTPS front)

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
    scripts:                   # each entry is written to <runtime dir>/<name>
      tinc-up: |               # (mode 0700) on every daemon start and run as the
        ...                    # script of that name. Rarely needed: see
                               # "Built-in interface setup" below.

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
        TlsFingerprint = 6776...64f2      # pinned; the `https' dial verifies the
                                          # peer cert against it (accept-on-first-
                                          # use then pin if absent)
```

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
| `options.AddressPool` | `10.<random 1–254>.0.0/24` | validated: IPv4, prefix 8–30 |
| `hosts.<Name>` `Subnet` | first host of the pool, `/32` | |
| `keys.ed25519_priv` + `hosts.<Name>` `Ed25519PublicKey` | generated | public line is re-derived if only the private key exists |
| `keys.rsa_priv` + `hosts.<Name>` RSA public PEM | generated (2048) | unless built with `-Dcrypto=nolegacy` |
| `keys.tls_cert` + `keys.tls_key` + `hosts.<Name>` `TlsFingerprint` | generated (self-signed P-256, `localhost` subject, 10 y) | OpenSSL builds only; skipped if `TlsCert`/`TlsKey` files are set; the fingerprint is the cert's SHA-256 |

An existing file that does not parse is **refused**, never overwritten. No
`hosts/` directory is created next to a YAML config; runtime side-files
(`cache/`, `invitations/`, pid/socket if `/var/run` is unwritable) go under
`<dir of file>/<netname>/`.

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

itself (`core/tincd/src/autoif.c`). Windows sets the address through
`WintunAddress`; Android hands the daemon a pre-configured fd; neither uses
this path. A `scripts.tinc-up` in the YAML always wins over the built-in.

## Invitation and join in YAML mode

`tinc -c tinc.yaml invite <name>` (the inviter) writes an invitation that
carries, beyond upstream tinc's `Name`/`NetName`/`ConnectTo`:

- every **propagated server option** the inviter has set — the list is
  `PROPAGATED_OPTIONS[]` in `core/tincd/src/invitation.c`: `Mode`, `Broadcast`,
  `AddressPool`, `Transports`, `TlsFingerprint` and every option starting with
  `Obfs`, `Https` or `Quic`. Per-node settings (`Port`, `ConnectTo`,
  `PreferredTransports`, …) are deliberately not propagated;
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
message), its own host record (`Subnet`, generated `Ed25519PublicKey` and RSA
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
- The C writer re-emits the whole document (comments are not preserved). Editors
  must not rely on comment round-tripping.
