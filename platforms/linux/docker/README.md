# tincstack on Linux — docker compose

One node per compose project. The daemon configures itself on the first start
(ARCHITECTURE.md principle 2, PLAN.md M1): name, keys, address pool, its own
address — everything is materialised into `tinc.yaml` inside a named volume.
Nothing here templates configuration; the entrypoint only carries a handful of
deploy-time choices from the environment into that file.

## Quick start

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
| `PORT` | listen port and the port published on the host | unset: daemon rule (655 founding node, ephemeral invitee) |
| `INVITE` | invitation string, `tinc join` on the first start only (`join.sh` sets it) | unset |
| `LOG_LEVEL` | `tincd -d` | `1` |
| `TINCSTACK_TAG` | tag of the `tincstack/core` and `tincstack/node` images | `dev` |

An existing identity in the volume always wins: `NODE_NAME` and `INVITE` are
ignored once `tinc.yaml` exists; `PORT` and `PUBLIC_ADDRESS` are re-applied on
every start.

## What lives where

| path (in the container) | content |
|---|---|
| `/etc/tincstack/tinc.yaml` | the one config file, daemon-owned, keys inside (mode 0600) |
| `/etc/tincstack/<NETNAME>/` | runtime side-files: `cache/`, `invitations/`, `tinc-up` |
| volume `data` | both of the above; project-scoped (`<project>_data`) |

No key material exists outside the volume. The repository ignores `.env` and
every runtime artefact (`.gitignore`), and `git status` stays clean after a
full bring-up.

## Files

- `docker-compose.yml` — the `core` service is build-only (`scale: 0`) and feeds
  the `node` build as the named context `core`, so one `up` on a clean checkout
  builds everything.
- `Dockerfile` — core image + entrypoint + helpers. `python3-minimal` is only
  there for `tincstack-yaml`.
- `entrypoint.sh` — join on first start, map env → YAML, supervise `tincd`.
- `tincstack-yaml` — **temporary bridge.** The tinc CLI's `set`/`add` still
  address the classic `tinc.conf`/`hosts/` tree, so this stdlib-only helper
  edits exactly the requested key of the YAML (structure-preserving, atomic,
  same flock as the daemon). It disappears when `tinc set` becomes YAML-aware
  (PLAN.md M2, stream A).
- `tinc-up` — **temporary, removable.** The core does not yet address the tun
  interface on Linux; this reads own `Subnet` + `AddressPool` from the YAML and
  runs `ip addr`. Installed into the runtime dir on every start.
- `tincstack-cli` — `tinc -n $NETNAME -c /etc/tincstack/tinc.yaml "$@"`.
- `invite.sh`, `join.sh` — the two onboarding commands.
- `compose.lab.yml` + `two-nodes.sh` — PLAN.md M6 proof (b): two projects on
  one docker network, invite on a, join on b, ping across the tunnel, one
  command, cleans up after itself (`KEEP=1` to inspect).

## Requirements

Docker Engine with Compose v2.24+ (`additional_contexts: service:` and
`!reset`), `/dev/net/tun` on the host, `NET_ADMIN` (granted in the compose
file). No host installs.
