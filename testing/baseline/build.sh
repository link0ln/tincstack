#!/usr/bin/env bash
# Build the upstream tinc 1.1pre18 baseline image (tincstack/baseline:<tag>).
# Usage: build.sh [tag]      env: TINC_TARBALL=/path/to/tinc-1.1pre18.tar.gz
set -euo pipefail
TAG="${1:-ws-f}"
TARBALL="${TINC_TARBALL:-/opt/gitrepo/vpn-experiments/tinc-1.1pre18.tar.gz}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
URL="${TINC_TARBALL_URL:-https://www.tinc-vpn.org/packages/tinc-1.1pre18.tar.gz}"
CTX="$(mktemp -d /tmp/wsf-baseline-ctx.XXXXXX)"
trap 'rm -rf "$CTX"' EXIT
cp "$HERE/Dockerfile" "$CTX/Dockerfile"
if [ -r "$TARBALL" ]; then
    cp "$TARBALL" "$CTX/tinc-1.1pre18.tar.gz"
else
    # no local copy (CI): fetch the release tarball inside a throwaway container
    echo "baseline: $TARBALL not found, downloading $URL" >&2
    docker run --rm -v "$CTX:/ctx" alpine:3.20 wget -q -O /ctx/tinc-1.1pre18.tar.gz "$URL"
fi
docker build -t "tincstack/baseline:$TAG" "$CTX"
docker run --rm "tincstack/baseline:$TAG" tincd --version
