#!/usr/bin/env bash
#
# tincstack: cross-compile the core daemon (core/tincd, meson) for Android.
#
# Copyright (C) 2026 tincstack contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# The app runs `tincd` / `tinc` as subprocesses, so they are packaged as
# executables named like shared libraries (libtincd.so / libtinc.so) in the
# APK's jniLibs, exactly as upstream tincapp did. tincapp drove an autotools
# build of vanilla tinc from CMake; the tincstack core is meson-only, so this
# script replaces app/CMakeLists.txt: it writes one meson cross file per ABI
# and builds the core with the NDK's clang.
#
# Crypto: -Dcrypto=openssl against a static LibreSSL libcrypto (the same
# library and version tincapp shipped), cross-built here with LibreSSL's own
# autotools configure. Pass --crypto nolegacy to skip LibreSSL entirely
# (SPTPS/Ed25519 only, no legacy RSA protocol; see docs).
#
# Usage:
#   build-core.sh --ndk <NDK dir> --out <dir> [--abis "arm64-v8a armeabi-v7a x86 x86_64"]
#                 [--api 21] [--crypto openssl|nolegacy] [--jobs N] [--core <core/tincd dir>]
#
# Output: <out>/jniLibs/<abi>/libtincd.so and libtinc.so (stripped),
#         <out>/build/<abi>/ (meson build dirs), <out>/deps/<abi>/ (LibreSSL).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

NDK="${ANDROID_NDK_HOME:-}"
OUT=""
ABIS="arm64-v8a armeabi-v7a x86 x86_64"
API=21
CRYPTO=openssl
JOBS="$(nproc 2>/dev/null || echo 4)"
CORE="$(cd "$SCRIPT_DIR/../../../core/tincd" 2>/dev/null && pwd || true)"

LIBRESSL_VERSION=3.7.3
LIBRESSL_SHA256=7948c856a90c825bd7268b6f85674a8dcd254bae42e221781b24e3f8dc335db3
LIBRESSL_URLS=(
  "https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LIBRESSL_VERSION}.tar.gz"
  "https://cdn.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LIBRESSL_VERSION}.tar.gz"
  "https://ftp.fr.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LIBRESSL_VERSION}.tar.gz"
)

usage() { sed -n '/^# Usage:/,/^$/p' "$0"; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --ndk) NDK="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --abis) ABIS="$2"; shift 2 ;;
    --api) API="$2"; shift 2 ;;
    --crypto) CRYPTO="$2"; shift 2 ;;
    --jobs) JOBS="$2"; shift 2 ;;
    --core) CORE="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done

[ -n "$NDK" ] && [ -d "$NDK/toolchains/llvm/prebuilt" ] || { echo "--ndk must point at an Android NDK (r23+)" >&2; exit 1; }
[ -n "$OUT" ] || { echo "--out is required" >&2; exit 1; }
[ -f "$CORE/meson.build" ] || { echo "core source not found at '$CORE' (use --core)" >&2; exit 1; }
case "$CRYPTO" in openssl|nolegacy) ;; *) echo "--crypto must be openssl or nolegacy" >&2; exit 1 ;; esac
for tool in meson ninja pkg-config make; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done

TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/$(ls "$NDK/toolchains/llvm/prebuilt" | head -1)"
BIN="$TOOLCHAIN/bin"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

# ABI -> clang target triple (the NDK's per-API wrapper name), meson cpu_family, meson cpu
abi_triple() {
  case "$1" in
    arm64-v8a)   echo aarch64-linux-android ;;
    armeabi-v7a) echo armv7a-linux-androideabi ;;
    x86)         echo i686-linux-android ;;
    x86_64)      echo x86_64-linux-android ;;
    *) echo "unsupported ABI: $1" >&2; exit 1 ;;
  esac
}
abi_cpu_family() {
  case "$1" in
    arm64-v8a) echo aarch64 ;; armeabi-v7a) echo arm ;; x86) echo x86 ;; x86_64) echo x86_64 ;;
  esac
}
abi_cpu() {
  case "$1" in
    arm64-v8a) echo aarch64 ;; armeabi-v7a) echo armv7a ;; x86) echo i686 ;; x86_64) echo x86_64 ;;
  esac
}

fetch_libressl() {
  local dl="$OUT/dl" tarball="$OUT/dl/libressl-${LIBRESSL_VERSION}.tar.gz"
  mkdir -p "$dl"
  if [ -f "$tarball" ] && echo "$LIBRESSL_SHA256  $tarball" | sha256sum -c --quiet 2>/dev/null; then
    return
  fi
  for url in "${LIBRESSL_URLS[@]}"; do
    echo ">>> fetching $url"
    if curl -fsSL --retry 3 -o "$tarball.part" "$url"; then
      mv "$tarball.part" "$tarball"
      if echo "$LIBRESSL_SHA256  $tarball" | sha256sum -c --quiet; then return; fi
      echo "checksum mismatch for $url" >&2
      rm -f "$tarball"
    fi
  done
  echo "could not fetch LibreSSL ${LIBRESSL_VERSION}" >&2
  exit 1
}

# Build a static LibreSSL libcrypto for one ABI into $OUT/deps/<abi>
build_libressl() {
  local abi="$1" triple prefix src
  triple="$(abi_triple "$abi")"
  prefix="$OUT/deps/$abi"
  if [ -f "$prefix/lib/libcrypto.a" ] && [ -f "$prefix/lib/pkgconfig/openssl.pc" ]; then
    echo ">>> [$abi] LibreSSL already built in $prefix"
    return
  fi
  fetch_libressl
  src="$OUT/src/$abi/libressl-${LIBRESSL_VERSION}"
  rm -rf "$src"; mkdir -p "$(dirname "$src")"
  tar -xzf "$OUT/dl/libressl-${LIBRESSL_VERSION}.tar.gz" -C "$(dirname "$src")"
  echo ">>> [$abi] configuring LibreSSL ${LIBRESSL_VERSION} for $triple$API"
  (
    cd "$src"
    ./configure --host="$triple" --prefix="$prefix" \
        --disable-shared --disable-tests --disable-asm \
        CC="$BIN/${triple}${API}-clang" AR="$BIN/llvm-ar" RANLIB="$BIN/llvm-ranlib" STRIP="$BIN/llvm-strip" \
        CFLAGS="-O2 -ffunction-sections -fdata-sections" > configure.log 2>&1 \
      || { tail -30 configure.log; exit 1; }
    make -j"$JOBS" -C crypto > build.log 2>&1 || { tail -30 build.log; exit 1; }
    make -C crypto install > install.log 2>&1
    make -C include install >> install.log 2>&1
  )
  # tinc's meson build asks pkg-config for `openssl`; libcrypto is all it links.
  mkdir -p "$prefix/lib/pkgconfig"
  cat > "$prefix/lib/pkgconfig/libcrypto.pc" <<EOF
prefix=$prefix
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include

Name: LibreSSL-libcrypto
Description: LibreSSL cryptography library (static, Android $abi)
Version: ${LIBRESSL_VERSION}
Libs: -L\${libdir} -lcrypto
Cflags: -I\${includedir}
EOF
  cat > "$prefix/lib/pkgconfig/openssl.pc" <<EOF
prefix=$prefix
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include

Name: OpenSSL
Description: LibreSSL libcrypto presented as OpenSSL (static, Android $abi)
Version: ${LIBRESSL_VERSION}
Requires: libcrypto
EOF
  rm -rf "$src"
}

write_cross_file() {
  local abi="$1" triple cross
  triple="$(abi_triple "$abi")"
  cross="$OUT/cross/$abi.ini"
  mkdir -p "$OUT/cross"
  cat > "$cross" <<EOF
# generated by build-core.sh for $abi (API $API)
[binaries]
c = '$BIN/${triple}${API}-clang'
ar = '$BIN/llvm-ar'
strip = '$BIN/llvm-strip'
pkgconfig = '$(command -v pkg-config)'

[properties]
pkg_config_libdir = '$OUT/deps/$abi/lib/pkgconfig'
needs_exe_wrapper = true

[built-in options]
c_args = ['-ffunction-sections', '-fdata-sections']
c_link_args = ['-Wl,--gc-sections']

[host_machine]
system = 'android'
cpu_family = '$(abi_cpu_family "$abi")'
cpu = '$(abi_cpu "$abi")'
endian = 'little'
EOF
  echo "$cross"
}

build_core() {
  local abi="$1" cross bdir lib
  cross="$(write_cross_file "$abi")"
  bdir="$OUT/build/$abi"
  lib="$OUT/jniLibs/$abi"
  echo ">>> [$abi] meson setup ($CRYPTO)"
  if [ -f "$bdir/build.ninja" ]; then
    meson setup --reconfigure "$bdir" "$CORE" --cross-file "$cross" "${MESON_OPTS[@]}" > "$bdir.setup.log" 2>&1 \
      || { tail -40 "$bdir.setup.log"; exit 1; }
  else
    mkdir -p "$(dirname "$bdir")"
    meson setup "$bdir" "$CORE" --cross-file "$cross" "${MESON_OPTS[@]}" > "$bdir.setup.log" 2>&1 \
      || { tail -40 "$bdir.setup.log"; exit 1; }
  fi
  echo ">>> [$abi] ninja"
  ninja -C "$bdir" -j"$JOBS" src/tincd src/tinc > "$bdir.build.log" 2>&1 || { tail -60 "$bdir.build.log"; exit 1; }
  mkdir -p "$lib"
  "$BIN/llvm-strip" -o "$lib/libtincd.so" "$bdir/src/tincd"
  "$BIN/llvm-strip" -o "$lib/libtinc.so" "$bdir/src/tinc"
  echo ">>> [$abi] $(ls -l "$lib/libtincd.so" | awk '{print $5}') bytes libtincd.so, $(ls -l "$lib/libtinc.so" | awk '{print $5}') bytes libtinc.so"
}

MESON_OPTS=(
  -Dbuildtype=release
  -Dprefix=/
  -Dcrypto="$CRYPTO"
  -Dcurses=disabled
  -Dreadline=disabled
  -Dsystemd=disabled
  -Ddocs=disabled
  -Dtests=disabled
  -Dminiupnpc=disabled
  -Dlzo=disabled
  -Dlz4=disabled
  -Dzlib=enabled
  -Dvde=disabled
  -Dtunemu=disabled
  -Dvmnet=disabled
  --wrap-mode=nofallback
)

echo "core:   $CORE"
echo "ndk:    $NDK"
echo "api:    $API"
echo "abis:   $ABIS"
echo "crypto: $CRYPTO"
echo "out:    $OUT"

for abi in $ABIS; do
  if [ "$CRYPTO" = openssl ]; then build_libressl "$abi"; fi
  build_core "$abi"
done

echo ">>> done:"
ls -l "$OUT"/jniLibs/*/libtinc*.so
