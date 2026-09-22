#!/usr/bin/env bash
# A certificate that nobody renews is a certificate that expires.
#
# `tinc cert issue` was the whole feature and nothing ever ran `tinc cert renew`:
# ~90 days after the first issue the https/quic front starts presenting an
# expired certificate, which is *more* remarkable to an observer than the
# self-signed one it replaced. Two things now cover that, and this proves both
# against a real daemon:
#
#   1. the daemon says so -- tls_expiry_warn() logs once a day while the loaded
#      certificate is within AcmeRenewDays of expiry, and after it has expired;
#   2. the Linux node renews itself -- the entrypoint runs `tinc cert renew` on
#      a timer when CertDomain and CloudflareToken are set (CERT_RENEW=1, the
#      default), the first time a minute after start rather than one interval
#      after it.
#
# Hermetic: AcmeDirectory and CloudflareApi point at a dead local port, so the
# renewal attempt fails immediately and nothing outside this machine is touched.
# The attempt is what is being measured -- that the timer fires at all.
#
# Usage: [CORE_IMAGE=... NODE_IMAGE=...] testing/config/cert-lifecycle-test.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CORE_IMAGE="${CORE_IMAGE:-tincstack/core:${TINCSTACK_TAG:-dev}}"
NODE_IMAGE="${NODE_IMAGE:-tincstack/node:${TINCSTACK_TAG:-dev}}"
RUN="$HERE/run-certlife"
NAME=certlife
NET=certlife
FAILED=0

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
ok()  { log "PASS $1"; }
bad() { log "FAIL $1"; FAILED=1; }

cleanup() {
	docker rm -f "$NAME" >/dev/null 2>&1 || true
	docker run --rm -v "$RUN:/r" "$CORE_IMAGE" sh -c 'rm -rf /r/*' >/dev/null 2>&1 || true
	rm -rf "$RUN" 2>/dev/null || true
}
trap cleanup EXIT
cleanup
mkdir -p "$RUN"

if ! docker image inspect "$NODE_IMAGE" >/dev/null 2>&1; then
	log "building $NODE_IMAGE"
	docker build -q --build-arg CORE_IMAGE="$CORE_IMAGE" -t "$NODE_IMAGE" \
		"$ROOT/platforms/linux/docker" >/dev/null
fi

# start <extra env...> -- a node on the same config volume, detached
start() {
	docker rm -f "$NAME" >/dev/null 2>&1 || true
	docker run -d --name "$NAME" --cap-add NET_ADMIN --device /dev/net/tun \
		-v "$RUN:/etc/tincstack" -e NETNAME="$NET" -e LOG_LEVEL=1 "$@" \
		"$NODE_IMAGE" >/dev/null
}

wait_for() {   # wait_for <pattern> <seconds>
	local deadline=$((SECONDS + $2))

	while ((SECONDS < deadline)); do
		docker logs "$NAME" 2>&1 | grep -q "$1" && return 0
		sleep 1
	done

	return 1
}

cli() { docker exec "$NAME" tinc -n "$NET" -c /etc/tincstack/tinc.yaml "$@"; }

# ---- a node with the certificate it generates for itself --------------------
# Self-signed and valid for ten years: the warning must stay silent, or it is
# noise that teaches people to ignore it.
start -e CERT_RENEW=0
wait_for "Ready" 60 || { log "the node never became ready"; docker logs "$NAME" 2>&1 | tail -20 >&2; exit 1; }
sleep 12        # three periodic handlers

if docker logs "$NAME" 2>&1 | grep -q "expires in .* days"; then
	bad "no expiry warning for a fresh self-signed certificate"
	docker logs "$NAME" 2>&1 | grep "expires in" >&2
else
	ok "a fresh self-signed certificate produces no expiry warning"
fi

# ---- give it a certificate that is about to expire --------------------------
# TlsCert/TlsKey point the daemon at files, which is the shortest way to hand it
# a certificate with a chosen lifetime.
docker exec "$NAME" sh -c '
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3 \
		-subj "/CN=vpn.example.invalid" \
		-keyout /etc/tincstack/short.key -out /etc/tincstack/short.pem 2>/dev/null
' || { log "could not generate the short-lived certificate"; exit 1; }

cli set TlsCert /etc/tincstack/short.pem >/dev/null
cli set TlsKey /etc/tincstack/short.key >/dev/null
cli set CertDomain vpn.example.invalid >/dev/null
cli set CloudflareToken cf-lab-token-000000000000 >/dev/null
cli set CloudflareApi https://127.0.0.1:9/client/v4 >/dev/null
cli set AcmeDirectory https://127.0.0.1:9/directory >/dev/null
cli set AcmeRenewDays 30 >/dev/null

# ---- the daemon notices ------------------------------------------------------
start -e CERT_RENEW=0
wait_for "Ready" 60 || { log "the node never became ready"; exit 1; }

if wait_for "expires in [0-9]* days" 30; then
	ok "the daemon warns that the certificate is about to expire"
	docker logs "$NAME" 2>&1 | grep -o "The TLS certificate.*expires in [0-9]* days.*" | head -1 >&2
else
	bad "the daemon warns that the certificate is about to expire"
	docker logs "$NAME" 2>&1 | tail -15 >&2
fi

# ---- CERT_RENEW=0 really means no renewal ------------------------------------
sleep 8

if docker logs "$NAME" 2>&1 | grep -q "entrypoint: cert renew"; then
	bad "CERT_RENEW=0 runs no renewal"
else
	ok "CERT_RENEW=0 runs no renewal"
fi

# ---- the timer fires ---------------------------------------------------------
# The renewal cannot succeed here (both endpoints are dead ports), and that is
# the point: what is being proven is that something runs it at all -- and with
# CERT_RENEW unset, because on is the default.
start -e CERT_RENEW_INTERVAL=2
wait_for "Ready" 60 || { log "the node never became ready"; exit 1; }

if wait_for "entrypoint: cert renew failed" 40; then
	ok "by default the node runs 'tinc cert renew' on its own timer"
	docker logs "$NAME" 2>&1 | grep -o "entrypoint: cert renew failed:.*" | head -1 | cut -c1-150 >&2
else
	bad "by default the node runs 'tinc cert renew' on its own timer"
	docker logs "$NAME" 2>&1 | tail -15 >&2
fi

# ---- the first check does not wait a whole interval ----------------------------
# With the default 12 h interval a node restarted nightly would never renew if
# the loop slept before its first check. It checks a minute after start.
start -e CERT_RENEW=1 -e CERT_RENEW_INTERVAL=43200
wait_for "Ready" 60 || { log "the node never became ready"; exit 1; }

if wait_for "entrypoint: cert renew failed" 90; then
	ok "with a 12 h interval the first renewal check runs within 90 s of start"
else
	bad "with a 12 h interval the first renewal check runs within 90 s of start"
	docker logs "$NAME" 2>&1 | tail -15 >&2
fi

# ---- and it stays quiet when ACME is not configured --------------------------
# A node without CertDomain/CloudflareToken has nothing to renew; the timer must
# not fill its log with failures.
cli set CertDomain "" >/dev/null 2>&1 || true
docker exec "$NAME" sh -c "sed -i '/CertDomain/d' /etc/tincstack/tinc.yaml"
start -e CERT_RENEW=1 -e CERT_RENEW_INTERVAL=2
wait_for "Ready" 60 || { log "the node never became ready"; exit 1; }
sleep 10

if docker logs "$NAME" 2>&1 | grep -q "entrypoint: cert renew"; then
	bad "a node without CertDomain attempts no renewal"
	docker logs "$NAME" 2>&1 | grep "entrypoint: cert renew" | head -3 >&2
else
	ok "a node without CertDomain attempts no renewal"
fi

if [ "$FAILED" -eq 0 ]; then
	log "certificate lifecycle: all checks passed"
else
	log "certificate lifecycle: FAILURES above"
fi

exit "$FAILED"
