# tincstack

A self-hosted mesh VPN distribution built on a hardened tinc 1.1 core, with a
single config file shared across Linux, Windows and Android, one-line peer
onboarding, and opt-in circumvention transports (traffic obfuscation, an
HTTPS-mimicking front with active-probing resistance, and a QUIC carrier) for use
on restrictive networks.

The circumvention features are **optional and layered around tinc's existing
authenticated encryption** — they never replace it. With them off, tincstack is
plain, fast tinc.

## Start here

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — design and the non-negotiable principles.
- [`PLAN.md`](PLAN.md) — the phased implementation plan (M0–M9). This is the
  execution contract.
- [`docs/config-schema.md`](docs/config-schema.md) — the one YAML schema.
- [`docs/source-inventory.md`](docs/source-inventory.md) — what each prior
  experiment contributed and why.

## Repository layout

```
core/tincd/        the daemon + CLI (tinc 1.1 fork; all C feature work lands here)
core/Dockerfile.build   reproducible core build
platforms/linux/docker/ docker compose + zero-config auto-init
platforms/windows/      PySide6 management GUI
platforms/android/      Kotlin VPN client with per-app split routing
testing/                NAT-type lab and obfuscation wire-image checks
docs/                   schema, transports, source inventory
```

## Build the core

```
docker build -f core/Dockerfile.build -t tincstack/core:dev core/
docker run --rm tincstack/core:dev tincd --version
```

## Windows client

`platforms/windows/` is the PySide6 manager (`tincmgr.exe` + `tinc.yaml`). The
core cross-builds for Windows on Linux in Docker:

```
platforms/windows/build-core-win.sh      # core/Dockerfile.build-win → platforms/windows/resources/
```

The GUI (invite/join dialogs, transports editor, atomic YAML save, rotating
daemon log, all `tinc.exe` calls off the Qt thread) is tested headless in Docker
(`QT_QPA_PLATFORM=offscreen`); the onefile `.exe` itself is built on a Windows
host with PyInstaller — see `platforms/windows/build-windows.md`.

## Status

Foundation (M0) complete: core selected, vendored and building. See `PLAN.md` for
the current milestone.
