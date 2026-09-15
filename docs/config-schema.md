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

      # obfuscated-UDP tier (point 6, cheap tier; redesigned mechanism)
      ObfsJunkPacketCount: 0        # junk datagrams around the handshake (0 = off)
      ObfsJunkPacketMinSize: 40
      ObfsJunkPacketMaxSize: 200
      ObfsInitHeaderJunkSize: 0
      ObfsInitMagicHeader: 0        # 0 = off, or N, or "MIN-MAX" range
      # (full obfs surface documented in docs/transports.md)

      # HTTPS-mimicking front (point 6; active-probing resistance)
      HttpsFront: no                # enable the TLS front on the listen port
      HttpsFrontPort: 443
      TlsCert: /etc/tincstack/fullchain.pem   # real domain cert; optional
      TlsKey:  /etc/tincstack/privkey.pem     # if absent → self-signed generated
                                              # at first start into keys: below;
                                              # shared by the HTTPS front and QUIC
      HttpsDecoyRoot: /var/www/decoy          # static content for probers; a
                                              # default page ships if unset
      HttpsDecoyUpstream: ""                  # or transparently proxy probers here

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
      node-b: |
        Address = 198.51.100.7
        Port = 443
        Ed25519PublicKey = ...
        Subnet = 10.210.0.2/32
        Transports = quic, https, plain   # peer's advertised carriers
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

## Android-specific interface config

Android's VPN interface parameters (routes, DNS, per-app split routing) do **not**
map to tinc.conf; they live in the platform's `network.conf`, whose keys the
Android app already understands:

```
Address            = 10.210.0.3/24
Route              = 10.210.0.0/24
DNSServer          = 10.210.0.1
AllowApplication   = com.example.foo   # whitelist mode: only these apps use VPN
DisallowApplication= com.example.bar   # blacklist mode: all apps except these
```

`AllowApplication` and `DisallowApplication` are **mutually exclusive** (Android
rejects mixing them); the app-picker UI must enforce a single mode. These keys are
already parsed and applied by the app (`VpnServiceBuilder.kt`); the milestone adds
the picker UI, not the plumbing.

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
