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

## Build the Android app

The app (`platforms/android/`, Kotlin, adopted from tincapp) runs the same core
as a subprocess: `native/build-core.sh` cross-compiles `core/tincd` with the NDK
for the four ABIs (meson cross files, static LibreSSL libcrypto) and Gradle
packages the result as `libtincd.so` / `libtinc.so`. Nothing is installed on the
host: the toolchain lives in a container and the SDK/NDK is mounted read-only.

```
docker build -t ws-e-android-build -f platforms/android/docker/Dockerfile.build platforms/android/docker
docker run --rm -v "$PWD":/src -v /opt/android-sdk:/opt/android-sdk:ro \
    -v wse-gradle:/root/.gradle -v wse-m2:/root/.m2 -w /src/platforms/android \
    ws-e-android-build ./gradlew assembleDebug        # app/build/outputs/apk/debug/app-debug.apk
docker run --rm ... ws-e-android-build ./gradlew testDebugUnitTest   # JUnit + Robolectric
```

Requires an SDK with platform 34, build-tools 34.0.0 and NDK 26.1.10909125 at
`/opt/android-sdk` (any SDK image works; adjust the mount). Each network on the
device is one `tinc.yaml` (the shared schema; the Android interface keys are
documented in `docs/config-schema.md`); per-app split routing is chosen in the
app and written into that file.

## Status

Foundation (M0) complete: core selected, vendored and building. See `PLAN.md` for
the current milestone.
