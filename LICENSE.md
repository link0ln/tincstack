# Licensing

tincstack is an aggregate of components that arrived with their own licences.
This file records what applies where; it does not relicense anything.

## The core daemon — GPL v2 or later

`core/tincd/` is tinc 1.1 with tincstack's patches (`core/tincd/PATCHES.md`).
tinc is Copyright (C) 1998-2021 Ivo Timmermans, Guus Sliepen and others and is
distributed under the GNU General Public License version 2 or (at your option)
any later version; the full text is in `core/tincd/COPYING` and the linking
exception in `core/tincd/COPYING.README`.

Everything tincstack added inside that tree — the YAML configuration layer, the
zero-config materialisation, the transport/carrier registry and the `sf`,
`obfs`, `https` and `quic` carriers — is a derivative work of tinc and is
therefore covered by the same GPL v2-or-later terms.

## The Android app — GPL v3

`platforms/android/` descends from tincapp, Copyright (C) 2017-2024 Euxane P.
TRAN-GIRARD and contributors (`platforms/android/contributors.md`), under the
GNU General Public License version 3. Full text: `platforms/android/license.md`.
tincstack's changes to it are under the same terms.

## Third-party components shipped in builds

The Android app bundles the libraries listed at the end of
`platforms/android/readme.md` under their own licences (Apache 2.0, MIT, LGPL
2.1, GPL v2, the OpenSSL/ISC terms of LibreSSL). The Windows build links
libgcrypt (LGPL 2.1+) and, at run time, needs `wintun.dll`, which is **not** in
this repository: it is a Microsoft-signed binary distributed by WireGuard LLC
under its own terms from <https://www.wintun.net/>.

## Everything else in this repository

`platforms/windows/`, `platforms/linux/docker/`, `testing/` and the
documentation were written for tincstack and carry no per-file licence header
yet. Until the owner states otherwise, treat them as GPL v2 or later, matching
the core they exist to build, run and verify.
