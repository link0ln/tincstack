#!/usr/bin/env bash
# Old and new nodes still talk over the TLS carriers.
#
# A founder on one core image, a leaf on another, `PreferredTransports' set
# to the carrier under test: the leaf must end up connected over it, in both
# directions (old founder / new leaf and the reverse) and new with new.
# Written for the move from GnuTLS 3.7.9 (quic) and OpenSSL 3.0 (https) on
# Debian 12 to OpenSSL 3.5 on Debian 13 (2026-09-23): the authenticator is
# bound to the RFC 5705 exporter, and that only interoperates if both TLS
# stacks compute the same TLS 1.3 exporter value.
#
# Usage: OLD_IMAGE=tincstack/core:<tag> [CORE_IMAGE=...] testing/transports/mixed-version-test.sh
#   OLD_IMAGE: a core image built from an earlier commit (e.g. `git archive
#   <commit> core | tar x -C /tmp/old && docker build -f /tmp/old/core/Dockerfile.build /tmp/old/core').
set -uo pipefail
NEW="${CORE_IMAGE:-tincstack/core:${TINCSTACK_TAG:-dev}}"
OLD="${OLD_IMAGE:?set OLD_IMAGE to a core image from an earlier commit}"
PFX=mvt
NET=${PFX}net
SUBNET=10.47.11
Y=/c/tinc.yaml
FAILED=0

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }

cleanup() {
	docker rm -f "$PFX-f" "$PFX-l" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

t() { local n=$1; shift; docker exec "$PFX-$n" tinc -n lab -c "$Y" "$@"; }

node() { # <name> <ip> <image>
	docker run -d --name "$PFX-$1" --network "$NET" --ip "$2" --cap-add NET_ADMIN --device /dev/net/tun \
		"$3" sh -c 'mkdir -p /c; exec sleep infinity' >/dev/null
}

pair() { # <founder image> <leaf image> <transport>
	local fi=$1 li=$2 tr=$3 inv
	cleanup
	docker network create --internal --subnet "$SUBNET.0/24" "$NET" >/dev/null
	node f "$SUBNET.10" "$fi"
	node l "$SUBNET.11" "$li"
	docker exec "$PFX-f" sh -c "install -m600 /dev/null $Y && tinc -n lab -c $Y set Name founder && tinc -n lab -c $Y set Port 655"
	docker exec -d "$PFX-f" sh -c "tincd -n lab -c $Y -D -d3 >>/tmp/tincd.log 2>&1"
	for _ in $(seq 20); do t f pid >/dev/null 2>&1 && break; sleep 1; done
	t f set founder.Address "$SUBNET.10"
	inv=$(t f invite leaf)
	t l join "$inv" >/dev/null 2>&1
	t l set PreferredTransports "$tr"
	docker exec -d "$PFX-l" sh -c "tincd -n lab -c $Y -D -d3 >>/tmp/tincd.log 2>&1"
	for _ in $(seq 30); do
		if t l dump connections 2>/dev/null | grep -q "^founder .*transport $tr"; then
			log "PASS $tr: founder $fi, leaf $li"
			return
		fi
		sleep 1
	done
	log "FAIL $tr: founder $fi, leaf $li ($(t l dump connections 2>/dev/null | grep -o 'transport [a-z]*' | head -1))"
	docker exec "$PFX-l" grep -iE "quic|https|web server" /tmp/tincd.log | tail -4 >&2 || true
	FAILED=1
}

for tr in quic https; do
	pair "$OLD" "$NEW" "$tr"
	pair "$NEW" "$OLD" "$tr"
	pair "$NEW" "$NEW" "$tr"
done

if [[ $FAILED -eq 0 ]]; then
	log "mixed versions: all pairs connect"
else
	log "mixed versions: FAILURES above"
fi
exit "$FAILED"
