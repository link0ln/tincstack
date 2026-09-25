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
# Since 2026-09-24 the quic dialler announces curl's transport parameters, which
# carry no max_datagram_frame_size: an older listener cannot send it datagrams.
# A current dialler sees that (no marker frame after the listener's answer) and
# gives quic up before the link is activated. So with an OLD_IMAGE from before
# then, "old founder, new leaf" over quic must fall back cleanly instead: the
# leaf says why, ends up on another carrier that carries traffic, and does not
# keep re-dialling quic.
#
# Since 2026-09-25 the listener's transport parameters are nginx's, without
# max_datagram_frame_size, and a dialler says in its request that it sends
# datagrams anyway. A dialler from before does not: a current listener answers
# it as a web server, so "new founder, old leaf" over quic must fall back the
# same way (the founder says why). Every pair that stays on its carrier must
# also carry tunnel traffic over it without re-dialling.
#
# Since 2026-09-26 the dialler's authenticator rides a cookie of its request
# HEADERS and the listener decides there, as nginx does; the body still opens
# with it, for older listeners. A dialler from before sends no such cookie: a
# current listener answers its POST at once as a web server (405), and "new
# founder, old leaf" over quic falls back (the leaf says it was answered like
# a web server).
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

pair() { # <founder image> <leaf image> <transport> [fallback]
	local fi=$1 li=$2 tr=$3 expect=${4:-carrier} inv
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
	if [[ $expect == fallback ]]; then
		fallback "$fi" "$li" "$tr" l "too old to send datagrams" "an older listener cannot send datagrams to a current dialler"
		return
	fi
	if [[ $expect == fallback-old-dialler ]]; then
		fallback "$fi" "$li" "$tr" l "answered like a web server" "an older dialler carries no authenticator in its request headers, and a current listener answers it as a web server"
		return
	fi
	for _ in $(seq 30); do
		if t l dump connections 2>/dev/null | grep -q "^founder .*transport $tr"; then
			carries "$fi" "$li" "$tr"
			return
		fi
		sleep 1
	done
	log "FAIL $tr: founder $fi, leaf $li ($(t l dump connections 2>/dev/null | grep -o 'transport [a-z]*' | head -1))"
	docker exec "$PFX-l" grep -iE "quic|https|web server" /tmp/tincd.log | tail -4 >&2 || true
	FAILED=1
}

# Being connected over a carrier is not enough: the tunnel's packets travel
# in it too (quic: as DATAGRAM frames), so ping through it and check that the
# link is still on the same carrier, dialled once.
carries() { # <founder image> <leaf image> <transport>
	local fi=$1 li=$2 tr=$3 fip dials ok=0
	fip=$(docker exec "$PFX-f" ip -4 -br addr show lab 2>/dev/null | awk '{print $3}' | cut -d/ -f1)
	docker exec "$PFX-l" ping -c5 -i0.5 -W2 "$fip" >/dev/null 2>&1 && ok=1
	sleep 3
	dials=$(docker exec "$PFX-l" grep -c "Dialling founder .* via $tr" /tmp/tincd.log || true)
	if [[ $ok -eq 1 ]] && [[ $dials -le 1 ]] &&
	                t l dump connections 2>/dev/null | grep -q "^founder .*transport $tr"; then
		log "PASS $tr: founder $fi, leaf $li (tunnel carries traffic, $tr dialled once)"
	else
		log "FAIL $tr: founder $fi, leaf $li: connected over $tr, but ping=$ok, $dials $tr dial(s), now '$(t l dump connections 2>/dev/null | grep "^founder " | grep -o 'transport [a-z]*' | head -1)'"
		docker exec "$PFX-l" grep -iE "quic|https|carrier|datagram" /tmp/tincd.log | tail -6 >&2 || true
		FAILED=1
	fi
}

fallback() { # <founder image> <leaf image> <transport> <node that says why: f|l> <its log line> <what it means>
	local fi=$1 li=$2 tr=$3 who=$4 why=$5 what=$6 got dials fip
	for _ in $(seq 30); do
		got=$(t l dump connections 2>/dev/null | grep "^founder " | grep -o "transport [a-z]*" | head -1)
		[[ -n $got ]] && break
		sleep 1
	done
	sleep 15
	got=$(t l dump connections 2>/dev/null | grep "^founder " | grep -o "transport [a-z]*" | head -1)
	dials=$(docker exec "$PFX-l" grep -c "Dialling founder .* via $tr" /tmp/tincd.log || true)
	fip=$(docker exec "$PFX-f" ip -4 -br addr show lab 2>/dev/null | awk '{print $3}' | cut -d/ -f1)
	if docker exec "$PFX-$who" grep -q "$why" /tmp/tincd.log &&
	                [[ -n $got && $got != "transport $tr" ]] && [[ $dials -le 1 ]] &&
	                docker exec "$PFX-l" ping -c3 -W2 "$fip" >/dev/null 2>&1; then
		log "PASS $tr: founder $fi, leaf $li: $what; the leaf gave $tr up once and is on '${got#transport }', tunnel carries traffic"
	else
		log "FAIL $tr: founder $fi, leaf $li: expected a clean fallback, got '${got:-nothing}' after $dials $tr dial(s)"
		docker exec "$PFX-l" grep -iE "quic|carrier|datagrams" /tmp/tincd.log | tail -5 >&2 || true
		docker exec "$PFX-$who" grep -iE "datagrams" /tmp/tincd.log | tail -2 >&2 || true
		FAILED=1
	fi
}

# An OLD_IMAGE from before 2026-09-24 knows nothing of datagrams a dialler does not announce.
old_quic=carrier
docker run --rm "$OLD" sh -c 'grep -q "too old to send datagrams" "$(command -v tincd)"' 2>/dev/null || old_quic=fallback
# One from before 2026-09-26 puts its authenticator in the request body only,
# and a current listener decides on the request HEADERS.
old_dialler=carrier
docker run --rm "$OLD" sh -c 'grep -q "by its request headers" "$(command -v tincd)"' 2>/dev/null || old_dialler=fallback-old-dialler

for tr in quic https; do
	if [[ $tr == quic ]]; then
		pair "$OLD" "$NEW" "$tr" "$old_quic"
		pair "$NEW" "$OLD" "$tr" "$old_dialler"
	else
		pair "$OLD" "$NEW" "$tr"
		pair "$NEW" "$OLD" "$tr"
	fi
	pair "$NEW" "$NEW" "$tr"
done

if [[ $FAILED -eq 0 ]]; then
	log "mixed versions: all pairs connect"
else
	log "mixed versions: FAILURES above"
fi
exit "$FAILED"
