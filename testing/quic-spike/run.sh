#!/bin/sh
# run.sh -- build and run the stream-Q QUIC spike, entirely in Docker.
#
# 1. Builds the ws-q build-stage image from core/Dockerfile.build-quic if it
#    is not present (ngtcp2 1.25 + GnuTLS backend under /usr/local).
# 2. Builds the spike image on top of it (tcpdump, openssl, the two binaries).
# 3. Runs test.sh in one container over loopback: server + client, tcpdump,
#    a wrong-pin session, PASS/FAIL per primitive.
#
# Usage: testing/quic-spike/run.sh          (OUT=/tmp/wsq-spike by default)
# Exit code 0 only when every primitive passed. Logs and the pcap land in $OUT.
set -e

here=$(cd "$(dirname "$0")" && pwd)
root="$here/../.."
BASE=${BASE:-tincstack/core:ws-q-build}
OUT=${OUT:-/tmp/wsq-spike}

if ! docker image inspect "$BASE" >/dev/null 2>&1; then
	echo "building $BASE from core/Dockerfile.build-quic (target build)"
	docker build -f "$root/core/Dockerfile.build-quic" --target build -t "$BASE" "$root/core"
fi

docker build --build-arg "BASE=$BASE" -t tincstack/quic-spike:ws-q "$here"

mkdir -p "$OUT"
exec docker run --rm --name ws-q-spike -v "$OUT":/out tincstack/quic-spike:ws-q /spike/test.sh
