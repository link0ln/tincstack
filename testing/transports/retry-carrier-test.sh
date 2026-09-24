#!/usr/bin/env bash
# `tinc retry' during a TLS or QUIC handshake must not demote the carrier.
#
# retry() (net.c) restarts every outgoing connection still in progress by
# expiring its ping timer. The carrier selector read that as "this carrier
# does not work" and fell back to plain -- for the rest of the session, since
# an activated link is not re-dialled. The Android app runs `tinc retry' on
# every connectivity change, the VPN coming up included, so its https link
# nearly always ended on plain (found 2026-09-24 with
# platforms/android/docker/join-on-emulator.sh TRANSPORT=https).
#
# Here: a founder and a leaf whose link has 400 ms of delay each way, so a
# handshake takes over a second; `tinc retry' is sent while the leaf's dial
# is in flight. The leaf must end up on the carrier it prefers, and its log
# must show the retry restarted that carrier rather than failed it.
#
# Usage: [CORE_IMAGE=...] testing/transports/retry-carrier-test.sh
set -uo pipefail
IMG="${CORE_IMAGE:-tincstack/core:${TINCSTACK_TAG:-dev}}"
PFX=rct
NET=${PFX}net
SUBNET=10.47.15
Y=/c/tinc.yaml
FAILED=0

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }

cleanup() {
	docker rm -f "$PFX-f" "$PFX-l" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
}
[[ -n ${KEEP:-} ]] || trap cleanup EXIT

t() { local n=$1; shift; docker exec "$PFX-$n" tinc -n lab -c "$Y" "$@"; }
node() { # <name> <ip>
	docker run -d --name "$PFX-$1" --network "$NET" --ip "$2" --cap-add NET_ADMIN --device /dev/net/tun \
		"$IMG" sh -c 'mkdir -p /c; exec sleep infinity' >/dev/null
}

run() { # <transport>
	local tr=$1 inv
	cleanup
	docker network create --internal --subnet "$SUBNET.0/24" "$NET" >/dev/null
	node f "$SUBNET.10"
	node l "$SUBNET.11"
	docker exec "$PFX-f" sh -c "install -m600 /dev/null $Y && tinc -n lab -c $Y set Name founder && tinc -n lab -c $Y set Port 655"
	docker exec -d "$PFX-f" sh -c "tincd -n lab -c $Y -D -d3 >>/tmp/tincd.log 2>&1"
	for _ in $(seq 20); do t f pid >/dev/null 2>&1 && break; sleep 1; done
	t f set founder.Address "$SUBNET.10"
	inv=$(t f invite leaf)
	t l join "$inv" >/dev/null 2>&1
	t l set PreferredTransports "$tr"
	# 400 ms each way on the leaf: the dial is in flight for more than a second
	docker exec "$PFX-l" tc qdisc add dev eth0 root netem delay 400ms
	docker exec -d "$PFX-l" sh -c "tincd -n lab -c $Y -D -d3 >>/tmp/tincd.log 2>&1"
	for _ in $(seq 100); do
		docker exec "$PFX-l" grep -q "via $tr" /tmp/tincd.log 2>/dev/null && break
		sleep 0.1
	done
	sleep 0.3
	t l retry >/dev/null 2>&1 || true
	for _ in $(seq 40); do
		t l dump connections 2>/dev/null | grep -q "^founder .*transport " && break
		sleep 1
	done
	local got
	got=$(t l dump connections 2>/dev/null | grep "^founder " | grep -o "transport [a-z]*" | head -1)
	if [[ $got == "transport $tr" ]] && docker exec "$PFX-l" grep -q "restarted by \`tinc retry'" /tmp/tincd.log; then
		log "PASS $tr: \`tinc retry' mid-handshake restarted $tr, the link is on $tr"
	else
		log "FAIL $tr: after \`tinc retry' mid-handshake the link is on '${got:-nothing}'"
		docker exec "$PFX-l" grep -iE "retry|abandoned|Carrier|Timeout" /tmp/tincd.log | tail -5 >&2 || true
		FAILED=1
	fi
}

run https
[[ -n ${KEEP:-} ]] || run quic

if [[ $FAILED -eq 0 ]]; then
	log "retry-carrier: all checks passed"
else
	log "retry-carrier: FAILURES above"
fi
exit "$FAILED"
