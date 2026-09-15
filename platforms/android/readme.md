tincstack for Android
=====================

Android client for the tincstack mesh VPN: the tincstack core (`core/tincd`, a
tinc 1.1 fork) run as a subprocess without root, one `tinc.yaml` per network,
invitation/QR onboarding and per-app split routing. Adopted from
[Tinc Mesh VPN](https://tincapp.euxane.net) (tincapp) by Euxane P. TRAN-GIRARD.

What changed against tincapp
----------------------------

- **Core**: the bundled `libtincd.so` / `libtinc.so` are the tincstack core
  cross-compiled with the NDK by `native/build-core.sh` (meson cross files, one
  per ABI, static LibreSSL libcrypto), not vanilla tinc from an autotools build.
- **One file**: each network is `networks/<net>/tinc.yaml` (the shared schema,
  `docs/config-schema.md`). The Android interface settings that used to live in
  `network.conf` (`DNSServer`, `AllowApplication`, `DisallowApplication`, ...)
  are ordinary `options:` keys of that file; the interface address and routes
  are the daemon's own `InterfaceAddress` / `InterfaceRoute` keys, the same
  spellings the Linux built-in tinc-up reads. Private keys are embedded in it;
  the key-passphrase feature is gone.
- **App picker**: Configure → Tools → "Choose which apps use the VPN" — one
  mode switch (only selected apps / all apps except selected), search,
  multi-select; written straight into `tinc.yaml`.
- **Join**: `tinc join` runs against `tinc.yaml` and the core writes the whole
  joined network into it, `InterfaceAddress` / `InterfaceRoute` included; the
  app folds nothing in and reads no side-file (there is no `invitation-data`).

Build
-----

Everything runs in a container; see the "Build the Android app" section of the
repository `README.md`. In short:

```
docker build -t ws-e-android-build -f docker/Dockerfile.build docker
docker run --rm -v "$REPO":/src -v /opt/android-sdk:/opt/android-sdk:ro \
    -v wse-gradle:/root/.gradle -v wse-m2:/root/.m2 -w /src/platforms/android \
    ws-e-android-build ./gradlew assembleDebug testDebugUnitTest
```

Requirements: Android SDK platform 34, build-tools 34.0.0, NDK 26.1.10909125
(mounted at `/opt/android-sdk`); the container brings JDK 17, meson, ninja,
pkg-config and make. `native/build-core.sh` can also be run on its own to
produce `jniLibs/<abi>/libtincd.so` (`--crypto nolegacy` builds without
LibreSSL: SPTPS/Ed25519 only, no legacy RSA protocol).

License
-------

Copyright (C) 2017-2024 Euxane P. TRAN-GIRARD and contributors (listed in
`contributors.md`); Copyright (C) 2026 tincstack contributors.

Distributed under the terms of the GNU General Public License v3.0, as detailed
in the provided `license.md` file.

Builds of this software embed and make use of the following libraries:

* Kotlin Standard Library, licensed under the Apache v2.0 License
* streamsupport-cfuture, licensed under the GNU General Public License v2.0
* Material Components for Android, licensed under the Apache v2.0 License
* ZXing Android Embedded, licensed under the Apache v2.0 License
* SLF4J, licensed under the MIT License
* logback-android, licensed under the GNU Lesser General Public License v2.1
* SnakeYAML, licensed under the Apache v2.0 License
* Apache Commons IO, licensed under the Apache v2.0 License
* LibreSSL libcrypto, licensed under the OpenSSL License, ISC License, public
  domain
* tinc (tincstack core), licensed under the GNU General Public License v2.0
