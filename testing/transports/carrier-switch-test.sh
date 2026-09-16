#!/bin/sh
# carrier-switch-test.sh -- proof that an operator can change the carrier of a
# RUNNING node without restarting it (PLAN.md "Known Issues", stream AA).
#
# The defect this pins down: `tinc disconnect <peer>' walked connection_list
# while terminate_connection() was appending the replacement dial to that same
# list (control.c REQ_DISCONNECT). The loop reached the replacement, matched
# its name a second time and killed the fresh dial without a word; the carrier
# selector read that silent close as "this carrier failed" and fell back. So
#
#     tinc set PreferredTransports obfs
#     tinc reload
#     tinc disconnect <peer>
#
# always ended on `transport plain', while the identical configuration read at
# startup (a container restart) came up on obfs. Nothing was logged between
# "Dialling ... via obfuscated single-flow UDP" and "Closing connection", even
# at -d5.
#
# WHY EACH CASE RESTARTS FIRST. terminate_connection() only re-dials on the
# spot when the address cache still has an address to give
# (get_recent_address(), address_cache.c); once that cache is walked out the
# re-dial is deferred to retry_outgoing() five seconds later, OUTSIDE the
# `disconnect' loop, and the bug cannot bite. The cache is refilled when a
# node's UDP path is confirmed, so each case restarts the node, waits for
# `udp_confirmed' in `tinc info', and only then switches the carrier. Without
# that precondition this test would pass on a broken build about as often as
# not.
#
# What this asserts, on two nodes (<LAB>-a founding, <LAB>-b invited):
#   1. the link comes up on `plain' and the tunnel carries traffic;
#   2. for every carrier this build has (obfs, sf, https, quic -- the ones
#      missing from the daemon's own "Transports accept=" line are skipped and
#      reported): `set PreferredTransports' + `reload' + `disconnect' on a
#      running node leaves the link ACTIVATED ON THAT CARRIER, with a clean
#      tunnel ping and no "Carrier <c> failed" in the log;
#   3. switching back to `plain' at runtime works too;
#   4. `disconnect' says why it closed a link ("Disconnecting ... on operator
#      request"), so an operator is never left with an unexplained close;
#   5. the restart path still works (it is what every case starts from).
#
# Exit 0 = every step held. Everything it creates is removed on exit.
# Usage: [LAB=prefix] [SUBNET=10.46.9] [WAIT=90] \
#            testing/transports/carrier-switch-test.sh [core image]
#   The image is the first argument, else tincstack/core:$TINCSTACK_TAG (the
#   same selector every other proof here takes). LAB (default wscs) prefixes
#   the containers, the docker network and the /tmp data directories, and a
#   non-default LAB also gets its own /24 (see lab-env.sh), so two runs can
#   share a host.
set -e

IMG=${1:-tincstack/core:${TINCSTACK_TAG:-dev}}
DEFAULT_LAB=wscs; DEFAULT_SUBNET=10.46.9
# shellcheck source=testing/transports/lab-env.sh
. "$(dirname "$0")/lab-env.sh"
NET=${LAB}sw
BASE=/tmp/$LAB-switch
NETNAME=carsw
WAIT=${WAIT:-90}

A_IP=$SUBNET.10
B_IP=$SUBNET.11

fail=0
miss() { echo "  MISS: $*"; fail=1; }
note() { echo "  $*"; }
step() { printf '\n== %s\n' "$*"; }

# shellcheck disable=SC2329  # invoked from the EXIT trap below
cleanup() {
	docker rm -f "$LAB-a" "$LAB-b" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
	rm -rf "$BASE-a" "$BASE-b"
}
trap cleanup EXIT
cleanup
docker network create --subnet "$SUBNET.0/24" "$NET" >/dev/null

mkdir -p "$BASE-a" "$BASE-b"

# a founds the network; b's document is the empty one `tinc join' needs (an
# absent file is refused, an empty one is a valid empty document).
cat > "$BASE-a/tinc.yaml" <<EOF
networks:
  $NETNAME:
    options:
      Name: nodea
      Mode: router
      Port: 655
      AddressPool: 10.183.0.0/24
EOF
: > "$BASE-b/tinc.yaml"
chmod 600 "$BASE-a/tinc.yaml" "$BASE-b/tinc.yaml"

cli() { # letter args...
	l=$1
	shift
	docker exec "$LAB-$l" tinc -c /etc/tincstack/tinc.yaml -n "$NETNAME" "$@"
}
logs() { docker logs "$LAB-$1" 2>&1; }

start() { # letter ip
	docker run -d --name "$LAB-$1" --network "$NET" --ip "$2" --cap-add NET_ADMIN \
		--device /dev/net/tun -v "$BASE-$1":/etc/tincstack "$IMG" \
		tincd -c /etc/tincstack/tinc.yaml -n "$NETNAME" -D -d2 >/dev/null
}

wait_ready() { # letter
	deadline=$(( $(date +%s) + WAIT ))
	until cli "$1" pid >/dev/null 2>&1; do
		if [ "$(date +%s)" -ge "$deadline" ]; then
			echo "    $LAB-$1 did not open its control socket within ${WAIT}s"
			logs "$1" | tail -30
			return 1
		fi
		sleep 1
	done
}

# carrier <letter> <peer>: the `transport' column of `dump connections'.
# Layout: <node> at <host> port <p> options <o> socket <s> status <x> transport <c>
carrier() {
	cli "$1" dump connections 2>/dev/null | awk -v n="$2" '$1 == n { print $13 }' | head -n1
}

# wait_carrier <letter> <peer> <carrier>: that peer's link is up on <carrier>.
wait_carrier() {
	deadline=$(( $(date +%s) + WAIT ))
	while :; do
		got=$(carrier "$1" "$2" || true)
		[ "$got" = "$3" ] && return 0
		if [ "$(date +%s)" -ge "$deadline" ]; then
			echo "    got '${got:-none}' instead of '$3' after ${WAIT}s"
			cli "$1" dump connections || true
			logs "$1" | grep -E 'Carrier|Dialling|Closing connection|abandoned' | tail -n 15 || true
			return 1
		fi
		sleep 1
	done
}

# wait_ping <letter> <ip>: a clean ping run within $WAIT s (a freshly dialled
# link needs a moment for tinc's UDP discovery to confirm each direction).
# NB: never `producer | grep -q' here -- grep leaves on the first match and the
# producer takes SIGPIPE. grep -c reads to EOF.
wait_ping() {
	deadline=$(( $(date +%s) + WAIT ))
	while :; do
		out=$(docker exec "$LAB-$1" ping -c3 -W2 "$2" 2>&1 | tail -2)
		if printf '%s\n' "$out" | grep -c ' 0% packet loss' >/dev/null; then
			return 0
		fi
		if [ "$(date +%s)" -ge "$deadline" ]; then
			printf '%s\n' "$out"
			return 1
		fi
		sleep 2
	done
}

# wait_udp <letter> <peer> <ip>: the peer's UDP path is confirmed, which is
# what refills the address cache and so makes the re-dial that follows a
# `disconnect' happen inside the disconnect itself. See the header.
wait_udp() {
	deadline=$(( $(date +%s) + WAIT ))
	while :; do
		docker exec "$LAB-$1" ping -c2 -W2 "$3" >/dev/null 2>&1 || true

		if cli "$1" info "$2" 2>/dev/null | grep -c '^Status:.*udp_confirmed' >/dev/null; then
			return 0
		fi

		if [ "$(date +%s)" -ge "$deadline" ]; then
			cli "$1" info "$2" || true
			return 1
		fi
		sleep 2
	done
}

# prefer <letter> <carrier>: the operator's dial order, `plain' last as the
# universal fallback (writing it twice would be a duplicate line).
prefer() {
	cli "$1" set PreferredTransports "$2" >/dev/null
	[ "$2" = plain ] || cli "$1" add PreferredTransports plain >/dev/null
}

step "1. a founds the network, b joins it"
start a "$A_IP"
wait_ready a || exit 1
cli a set nodea.Address "$A_IP" >/dev/null
inv=$(cli a invite nodeb | tr -d '\r')
note "invitation: $inv"
docker run --rm --network "$NET" --ip "$B_IP" -v "$BASE-b":/etc/tincstack "$IMG" \
	tinc -c /etc/tincstack/tinc.yaml -n "$NETNAME" join "$inv" >/dev/null
# A fixed listening port for b. An invitee defaults to an ephemeral one, which
# changes on every restart -- and every case below restarts b, so a's cached
# UDP address for b would be stale each time and the UDP path would take a
# discovery round (sometimes longer than this test's patience) to reconfirm.
docker run --rm --network "$NET" --ip "$B_IP" -v "$BASE-b":/etc/tincstack "$IMG" \
	tinc -c /etc/tincstack/tinc.yaml -n "$NETNAME" set Port 656 >/dev/null
start b "$B_IP"
wait_ready b || exit 1

a_vpn=$(cli b get nodea.Subnet | head -n1 | tr -d '\r'); a_vpn=${a_vpn%%/*}
note "a's tunnel address: $a_vpn"
wait_carrier b nodea plain || miss "b did not come up on the default carrier (plain)"
wait_ping b "$a_vpn" || miss "the tunnel does not carry traffic on plain"
note "baseline: b -> nodea on $(carrier b nodea), tunnel clean"

# Which carriers does this build actually have? The daemon prints its own
# accept list, so a core built without quic (QUIC=disabled) reports it and the
# quic case is skipped instead of failing.
accept=$(logs b | sed -n 's/.*Transports accept=\([^ ]*\).*/\1/p' | tail -n1)
note "b's build accepts: ${accept:-unknown}"

have() { # carrier -> 0 when this build accepts it
	case ",$accept," in
	*",$1,"*) return 0 ;;
	*) return 1 ;;
	esac
}

# switch_case <from> <to>: bring b up on <from> by restarting it (so the
# configuration is the one read at startup, the path that always worked), then
# change the carrier to <to> on the RUNNING daemon and require that it lands
# there with a working tunnel.
switch_case() {
	from=$1
	to=$2
	printf '\n-- %s -> %s\n' "$from" "$to"

	prefer b "$from"
	cli b reload >/dev/null
	docker restart "$LAB-b" >/dev/null
	wait_ready b || {
		miss "$from -> $to: b did not restart"
		return 0
	}

	wait_carrier b nodea "$from" || {
		miss "$from -> $to: b did not come up on $from after a restart"
		return 0
	}
	wait_udp b nodea "$a_vpn" || {
		miss "$from -> $to: nodea's UDP path was not confirmed, so this case could not test the runtime switch"
		return 0
	}
	note "restarted on $from, udp confirmed"

	before=$(logs b | grep -c "Carrier $to failed" || true)
	prefer b "$to"
	cli b reload >/dev/null
	cli b disconnect nodea >/dev/null

	if wait_carrier b nodea "$to"; then
		if wait_ping b "$a_vpn"; then
			note "$to: activated by set + reload + disconnect, tunnel clean"
		else
			miss "$from -> $to: activated but the tunnel does not carry traffic"
		fi
	else
		miss "$from -> $to: a runtime set + reload + disconnect did not put the link on $to"
	fi

	after=$(logs b | grep -c "Carrier $to failed" || true)
	[ "$after" = "$before" ] \
		|| miss "$from -> $to: the dial was abandoned ($(( after - before ))x 'Carrier $to failed')"
}

step "2. change the carrier of the running node, once per carrier"
for want in obfs sf https quic; do
	if have "$want"; then
		switch_case plain "$want"
	else
		note "$want: not in this build's accept list, skipped"
	fi
done

step "3. back to plain at runtime"
back_from=plain
for want in obfs sf https quic; do
	have "$want" && { back_from=$want; break; }
done
if [ "$back_from" = plain ]; then
	note "this build has no carrier other than plain, nothing to switch back from"
else
	switch_case "$back_from" plain
fi

step "4. every close says why"
# The silent close is the other half of the defect: an operator saw "Carrier
# obfs failed" with nothing between the dial and the close, even at -d5.
logs b | grep -c 'Disconnecting nodea .* on operator request' >/dev/null \
	|| miss "\`disconnect' closed a link without saying so"
note "disconnect logged its reason $(logs b | grep -c 'on operator request' || true) time(s)"

echo
if [ "$fail" -ne 0 ]; then
	echo "FAIL: see MISS lines above"
	exit 1
fi
echo "PASS: the carrier of a running node can be changed with set + reload + disconnect"
