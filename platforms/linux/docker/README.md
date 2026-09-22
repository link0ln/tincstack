# tincstack on Linux — docker compose

One node per compose project. The daemon configures itself on the first start
(ARCHITECTURE.md principle 2, PLAN.md M1): name, keys, address pool, its own
address — everything is materialised into `tinc.yaml` inside a named volume.
Nothing here templates configuration; the entrypoint only carries a handful of
deploy-time choices from the environment into that file.

## Quick start

Two compose files, same node. `compose.release.yml` **pulls** the image the
release workflow built for a tag; `docker-compose.yml` **builds** everything
from this checkout. Running a release:

```sh
cd platforms/linux/docker
export COMPOSE_FILE=compose.release.yml          # invite.sh / join.sh honour it
TINCSTACK_VERSION=v0.1.0 docker compose up -d    # 1. pulls ghcr.io/…/node:v0.1.0
./invite.sh laptop                               # 2. one-line invitation for "laptop"
./join.sh '<the line from step 2>'               # 3. on the other host: joins with it
```

Working on tincstack instead:

```sh
cd platforms/linux/docker
docker compose up -d                 # 1. builds core/ + the node image, starts a node
./invite.sh laptop                   # 2. prints a one-line invitation for "laptop"
./join.sh '<the line from step 2>'   # 3. on the other host: joins with it
```

Set `PUBLIC_ADDRESS` in `.env` (copy `.env.example`) on any node that issues
invitations, so the invitation carries the address peers can actually reach
and `tinc invite` never has to guess or phone home.

Useful afterwards:

```sh
docker compose logs -f node                        # the daemon
docker compose exec node tincstack-cli dump nodes  # any tinc CLI command
docker compose down -v                             # destroy the node incl. keys
```

## Environment (all optional)

| variable | effect | default |
|---|---|---|
| `NETNAME` | network name (`tincd -n`), also the tun interface name | `tincstack` |
| `NODE_NAME` | node name, honoured on the first start only | derived from the hostname by the daemon |
| `PUBLIC_ADDRESS` | `host` or `host:port` written to the node's own host record as `Address`; used verbatim in invitations | unset: the CLI falls back to a local-address guess and warns |
| `PORT` | listen port and the port published on the host; written to `options.Port` with `tinc set Port` | unset: daemon rule (655 founding node, ephemeral invitee) |
| `INVITE` | invitation string, `tinc join` on the first start only (`join.sh` sets it) | unset |
| `LOG_LEVEL` | `tincd -d` | `1` |
| `CERT_RENEW` | `1`: run `tinc cert renew` on a timer when `CertDomain` and `CloudflareToken` are set. Peers follow a renewed certificate on their own (they re-pin it after SPTPS authenticates this node). `0` turns it off | `1` |
| `CERT_RENEW_INTERVAL` | seconds between those checks. The command is a no-op while more than `AcmeRenewDays` remain | `43200` (12 h) |
| `TINCSTACK_TAG` | tag of the `tincstack/core` and `tincstack/node` images | `dev` |

An existing identity in the volume always wins: `NODE_NAME` and `INVITE` are
ignored once `tinc.yaml` exists; `PORT` and `PUBLIC_ADDRESS` are re-applied on
every start.

## What lives where

| path (in the container) | content |
|---|---|
| `/etc/tincstack/tinc.yaml` | the one config file, daemon-owned, keys inside (mode 0600) |
| `/etc/tincstack/<NETNAME>/` | runtime side-files: `cache/`, `invitations/`, and any script from the YAML's `scripts:` stanza (no `tinc-up` by default: the daemon addresses the interface itself) |
| volume `data` | both of the above; project-scoped (`<project>_data`) |

No key material exists outside the volume. The repository ignores `.env` and
every runtime artefact (`.gitignore`), and `git status` stays clean after a
full bring-up.

## Files

- `docker-compose.yml` — the `core` service is build-only (`scale: 0`) and feeds
  the `node` build as the named context `core`, so one `up` on a clean checkout
  builds everything.
- `compose.release.yml` — the same node with no build section at all: it pulls
  `ghcr.io/link0ln/tincstack/node:${TINCSTACK_VERSION:-latest}`
  (`TINCSTACK_IMAGE` overrides the whole reference). This is what a Linux host
  running a release uses.
- `Dockerfile` — the core image plus the entrypoint and `tincstack-cli`,
  nothing else (no interpreter, no helper, no scripts).
- `entrypoint.sh` — join on first start, map env → YAML with the core's
  YAML-aware CLI (`tinc -c tinc.yaml set …`), supervise `tincd`. `Name` goes
  to `options:`, `PUBLIC_ADDRESS` to `hosts.<Name>` as `Address` (before the
  start when the name is known, right after `Ready` otherwise — the CLI is
  its only reader). `PORT` goes to `options:` as `Port`: in this core `Port`
  is a server variable that the daemon and `tinc invite` rank above a `Port`
  line in the host record (`net_setup.c`, `invitation.c`), so the one value
  is what the daemon listens on and what invitations carry.
  The tun interface is addressed by the daemon's built-in tinc-up
  (`core/tincd/src/autoif.c`); a stopgap `tinc-up` left in an old volume is
  removed on start so it cannot shadow the built-in.
- `tincstack-cli` — `tinc -n $NETNAME -c /etc/tincstack/tinc.yaml "$@"`.
- `invite.sh`, `join.sh` — the two onboarding commands.
- `compose.lab.yml` + `two-nodes.sh` (bash only: `sh two-nodes.sh` exits 2
  with a message instead of dying on `set -o pipefail`) — PLAN.md M6 proof (b): two projects on
  one docker network, invite on a, join on b, ping across the tunnel, one
  command, cleans up after itself (`KEEP=1` to inspect).
- `yaml-scripts.sh` — same lab, proof of the `scripts:` stanza: a
  `scripts.host-up` added to b's `tinc.yaml` + `tincstack-cli reload` is
  written to the runtime dir (0700) and runs when a comes back; deleting the
  key + reload removes the file; a hand-made side file is left alone.

## Hook scripts

Put them in the YAML, not in the volume: `networks.<NETNAME>.scripts.<name>`
(`docs/config-schema.md` "Scripts"). The daemon writes each entry to
`/etc/tincstack/<NETNAME>/<name>` on start and on every reload and removes it
when the key is deleted, so `docker compose exec node tincstack-cli reload`
after editing the file is enough. A `scripts.tinc-up` replaces the built-in
interface addressing; anything else (`host-up`, `subnet-up`, …) runs next to
it. The image is Debian slim with `sh`, `bash`, `awk`, `sed` and `ip` — no
`curl`, no `python` — so a hook that needs more should signal a sidecar
(a file in the volume, a socket) rather than do the work itself.

## NAT: a Linux router in front of a node

Measured in the M9 lab (`testing/nat-sim/README.md`, profile `masq`): stock
`MASQUERADE` on **Linux ≥ 6.7** is no longer endpoint-independent. The first
destination a node talks to keeps its source port; every later destination is
mapped through *another* port (one shared port, sometimes several). To the
**first** peer a node contacts — its `ConnectTo`, i.e. the founding node or
relay — the node therefore looks like an ordinary cone NAT; to every other
peer it looks **symmetric**: the port that peer learned through the relay
(`UDP_INFO`) is the relay-facing one and does not match what the NAT presents
to it. The core copes — a peer learns the real port from the first
authenticated datagram (`UDPDiscoveryBurst`) and traffic falls back to the
relay until it does — but direct UDP between two such nodes takes a discovery
round and may stay relayed on a strict remote NAT.

What you can do, in order of effect:

1. **Give the node a stable, reachable port**: set `PORT` (→ `options.Port`)
   and forward that UDP+TCP port on the router to the node, and set
   `PUBLIC_ADDRESS` so its host record carries `Address`/`Port`. Peers then
   dial it directly and no NAT mapping is involved at all. This is the normal
   setup for anything that stays on: a home server, a VPS, an office box.
2. **Keep one public relay** (`Port = 655`, published, `PUBLIC_ADDRESS` set)
   that every node `ConnectTo`s: that relay is each node's *first* peer, so
   the port it sees is the one the NAT keeps stable; laptops and phones
   behind such routers reach everything through it while direct paths are
   discovered.
3. On a router you control, an endpoint-independent NAT is `SNAT
   --to-source <ip>:<fixed port range>` per inside host rather than
   `MASQUERADE`; see `testing/nat-sim/natprofile.sh` (`fullcone`) for the
   netfilter recipe. This is not something the container can do for you.

Nothing in the image needs changing for any of these; they are deployment
choices.

## Requirements

Docker Engine with Compose v2.24+ (`additional_contexts: service:` and
`!reset`), `/dev/net/tun` on the host, `NET_ADMIN` (granted in the compose
file). No host installs.
