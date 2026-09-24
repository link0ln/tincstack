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
# Crypto: -Dcrypto=openssl -Dquic=enabled against OpenSSL 3.5 (libssl +
# libcrypto), zstd and ngtcp2, all cross-built here from sha256-pinned
# tarballs and linked statically -- the same versions and OpenSSL options as
# the Linux image and the Windows build, so the https and quic carriers exist
# on Android and its ClientHellos are theirs (docs/transports.md §9.10).
# zstd (and the NDK's zlib) are there for OpenSSL's certificate compression
# only: Debian's OpenSSL offers it, so without them the hello lacks one
# extension. Until 2026-09-24 this was LibreSSL 3.7.3's libcrypto alone, which
# no longer compiled against tls.c (EVP_EC_gen) and could not link libssl:
# the APK had to be built --crypto nolegacy, without either TLS carrier.
# --crypto nolegacy still skips all of it (SPTPS/Ed25519 only, no legacy RSA
# protocol, no https/quic).
#
# Usage:
#   build-core.sh --ndk <NDK dir> --out <dir> [--abis "arm64-v8a armeabi-v7a x86 x86_64"]
#                 [--api 21] [--crypto openssl|nolegacy] [--jobs N] [--core <core/tincd dir>]
#
# Output: <out>/jniLibs/<abi>/libtincd.so and libtinc.so (stripped),
#         <out>/build/<abi>/ (meson build dirs), <out>/deps/<abi>/ (OpenSSL, zstd, ngtcp2).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

NDK="${ANDROID_NDK_HOME:-}"
OUT=""
ABIS="arm64-v8a armeabi-v7a x86 x86_64"
API=21
CRYPTO=openssl
JOBS="$(nproc 2>/dev/null || echo 4)"
CORE="$(cd "$SCRIPT_DIR/../../../core/tincd" 2>/dev/null && pwd || true)"

OPENSSL_VERSION=3.5.7
OPENSSL_SHA256=a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8
OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"
ZSTD_VERSION=1.5.7
ZSTD_SHA256=eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3
ZSTD_URL="https://github.com/facebook/zstd/releases/download/v${ZSTD_VERSION}/zstd-${ZSTD_VERSION}.tar.gz"
NGTCP2_VERSION=1.25.0
NGTCP2_SHA256=2a34d2484ba17847a5d11965704e9dd0fac4c6d8efc75ffe1ec7de66d8c6b6fb
NGTCP2_URL="https://github.com/ngtcp2/ngtcp2/releases/download/v${NGTCP2_VERSION}/ngtcp2-${NGTCP2_VERSION}.tar.xz"

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
for tool in meson ninja pkg-config make perl curl; do
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

# fetch <url> <sha256>: into $OUT/dl once, verified every time
fetch() {
  local url="$1" sum="$2" file="$OUT/dl/${1##*/}"
  mkdir -p "$OUT/dl"
  if [ -f "$file" ] && echo "$sum  $file" | sha256sum -c --quiet 2>/dev/null; then
    echo "$file"; return
  fi
  echo ">>> fetching $url" >&2
  curl -fsSL --retry 3 -o "$file.part" "$url" || { echo "could not fetch $url" >&2; exit 1; }
  mv "$file.part" "$file"
  echo "$sum  $file" | sha256sum -c --quiet || { echo "checksum mismatch for $url" >&2; rm -f "$file"; exit 1; }
  echo "$file"
}

openssl_target() {
  case "$1" in
    arm64-v8a) echo android-arm64 ;; armeabi-v7a) echo android-arm ;;
    x86) echo android-x86 ;; x86_64) echo android-x86_64 ;;
  esac
}

# A static-only prefix: fold each .pc's private libs and requirements into the
# public ones, so a plain `pkg-config --libs` (meson without -Dstatic, which
# on Android would also make the executable static) links everything
# libcrypto.a / libngtcp2_crypto_ossl.a need.
flatten_pc() {
  local pc
  for pc in "$1"/lib/pkgconfig/*.pc; do
    awk '
      /^Libs.private:/     { lp = lp " " substr($0, 15); next }
      /^Requires.private:/ { rp = rp " " substr($0, 18); next }
      { line[++n] = $0 }
      END {
        for (i = 1; i <= n; i++) {
          l = line[i]
          if (l ~ /^Libs:/ && lp != "") l = l lp
          if (l ~ /^Requires:/ && rp != "") { l = l (l ~ /: *$/ ? "" : ",") rp; rp = "" }
          print l
        }
        if (rp != "") print "Requires:" rp
      }' "$pc" > "$pc.tmp" && mv "$pc.tmp" "$pc"
  done
}

# Build static zstd, OpenSSL (libssl + libcrypto) and ngtcp2 for one ABI into
# $OUT/deps/<abi>.
build_deps() {
  local abi="$1" triple prefix src cc tarball
  triple="$(abi_triple "$abi")"
  prefix="$OUT/deps/$abi"
  cc="$BIN/${triple}${API}-clang"
  if [ -f "$prefix/lib/libngtcp2_crypto_ossl.a" ] && [ -f "$prefix/lib/pkgconfig/openssl.pc" ] \
     && grep -q "^Version: ${OPENSSL_VERSION}$" "$prefix/lib/pkgconfig/openssl.pc"; then
    echo ">>> [$abi] OpenSSL ${OPENSSL_VERSION} + ngtcp2 already built in $prefix"
    return
  fi
  rm -rf "$prefix"
  src="$OUT/src/$abi"
  rm -rf "$src"; mkdir -p "$src" "$prefix/lib" "$prefix/include"

  echo ">>> [$abi] zstd ${ZSTD_VERSION}"
  tarball="$(fetch "$ZSTD_URL" "$ZSTD_SHA256")"
  tar -xzf "$tarball" -C "$src"
  make -C "$src/zstd-${ZSTD_VERSION}/lib" -j"$JOBS" libzstd.a CC="$cc" AR="$BIN/llvm-ar" \
      ZSTD_LEGACY_SUPPORT=0 CFLAGS="-O2 -fPIC -ffunction-sections -fdata-sections" > "$src/zstd.log" 2>&1 \
    || { tail -30 "$src/zstd.log"; exit 1; }
  install -m644 "$src/zstd-${ZSTD_VERSION}/lib/libzstd.a" "$prefix/lib/"
  install -m644 "$src/zstd-${ZSTD_VERSION}/lib/"{zstd.h,zstd_errors.h,zdict.h} "$prefix/include/"

  # OpenSSL options as in core/Dockerfile.build-win: no config file read at
  # start, no provider/engine modules loaded at run time, library only.
  # zlib is the NDK's (libz.so is a public NDK library).
  echo ">>> [$abi] OpenSSL ${OPENSSL_VERSION} ($(openssl_target "$abi"), API $API)"
  tarball="$(fetch "$OPENSSL_URL" "$OPENSSL_SHA256")"
  tar -xzf "$tarball" -C "$src"
  (
    cd "$src/openssl-${OPENSSL_VERSION}"
    export ANDROID_NDK_ROOT="$NDK" PATH="$BIN:$PATH"
    ./Configure "$(openssl_target "$abi")" -D__ANDROID_API__="$API" \
        --prefix="$prefix" --libdir=lib --openssldir=/nonexistent/ssl \
        no-shared no-module no-dso no-autoload-config no-tests no-docs no-apps \
        enable-zlib enable-zstd \
        --with-zstd-include="$prefix/include" --with-zstd-lib="$prefix/lib" \
        -ffunction-sections -fdata-sections > configure.log 2>&1 \
      || { tail -30 configure.log; exit 1; }
    make -j"$JOBS" build_libs > build.log 2>&1 || { tail -40 build.log; exit 1; }
    make install_dev > install.log 2>&1 || { tail -20 install.log; exit 1; }
  )
  flatten_pc "$prefix"

  echo ">>> [$abi] ngtcp2 ${NGTCP2_VERSION}"
  tarball="$(fetch "$NGTCP2_URL" "$NGTCP2_SHA256")"
  tar -xJf "$tarball" -C "$src"
  (
    cd "$src/ngtcp2-${NGTCP2_VERSION}"
    export PKG_CONFIG_LIBDIR="$prefix/lib/pkgconfig" PKG_CONFIG_PATH=
    ./configure --host="$triple" --prefix="$prefix" --libdir="$prefix/lib" \
        --enable-lib-only --disable-shared --enable-static --with-openssl --without-gnutls \
        CC="$cc" AR="$BIN/llvm-ar" RANLIB="$BIN/llvm-ranlib" STRIP="$BIN/llvm-strip" \
        CFLAGS="-O2 -fPIC -ffunction-sections -fdata-sections" \
        OPENSSL_LIBS="$(pkg-config --libs openssl)" > configure.log 2>&1 \
      || { tail -30 configure.log; exit 1; }
    make -j"$JOBS" > build.log 2>&1 || { tail -40 build.log; exit 1; }
    make install > install.log 2>&1 || { tail -20 install.log; exit 1; }
  )
  flatten_pc "$prefix"
  rm -rf "$src"
  PKG_CONFIG_LIBDIR="$prefix/lib/pkgconfig" pkg-config --modversion openssl libngtcp2 libngtcp2_crypto_ossl
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
  -Dquic="$([ "$CRYPTO" = openssl ] && echo enabled || echo disabled)"
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
  if [ "$CRYPTO" = openssl ]; then build_deps "$abi"; fi
  build_core "$abi"
done

echo ">>> done:"
ls -l "$OUT"/jniLibs/*/libtinc*.so
