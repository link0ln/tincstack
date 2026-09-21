#!/usr/bin/env bash
# The address pool a node invents for itself must not be one the machine is
# already on.
#
# A zero-config node that lands on 10.7.0.0/24 while its office LAN is
# 10.7.0.0/24 puts the tunnel route in front of the LAN -- reliably, on every
# start, for exactly the user whose network that is. zeroconf.c therefore walks
# the 10.x.y.0/24 space from a random point and takes the first candidate that
# overlaps nothing local.
#
# Four cases, each a fresh container with its own fake "LAN" interfaces:
#   1. no local 10/8 network       -> some pool is chosen, and it is a valid /24
#   2. the chosen pool is then occupied, config wiped, node restarted
#                                  -> it moves off it
#   3. a machine that claims all of 10/8 (a dummy with 10.0.0.1/8)
#                                  -> it warns and still starts (no refusal)
#   4. the pool it picks never overlaps the interfaces it can see (30 runs)
#
# Usage: [CORE_IMAGE=tincstack/core:tag] testing/config/zeroconf-pool-test.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_IMAGE="${CORE_IMAGE:-tincstack/core:${TINCSTACK_TAG:-dev}}"
RUN="$HERE/run-pool"
NET=pooltest
FAILED=0

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
ok()  { log "PASS $1"; }
bad() { log "FAIL $1"; FAILED=1; }

cleanup() {
	docker run --rm -v "$RUN:/r" "$CORE_IMAGE" sh -c 'rm -rf /r/*' >/dev/null 2>&1 || true
	rm -rf "$RUN" 2>/dev/null || true
}
trap cleanup EXIT
cleanup
mkdir -p "$RUN"

# start_node <dir> <cidr...>
#   Fresh container: give it one dummy interface per CIDR, start the daemon
#   against an empty tinc.yaml, and let it materialise its configuration. The
#   daemon is killed as soon as the pool is in the file -- this is about the
#   one decision it makes at first start, not about running a network.
start_node() {
	local dir="$1"
	shift
	mkdir -p "$RUN/$dir"
	: >"$RUN/$dir/tinc.yaml"
	docker run --rm --cap-add NET_ADMIN --device /dev/net/tun \
		-v "$RUN/$dir:/c" -e CIDRS="$*" "$CORE_IMAGE" sh -c '
			i=0
			for cidr in $CIDRS; do
				i=$((i + 1))
				ip link add "lan$i" type dummy
				ip addr add "$cidr" dev "lan$i"
				ip link set "lan$i" up
			done
			tincd -n '"$NET"' -c /c/tinc.yaml -D -d1 >/c/log 2>&1 &
			pid=$!
			n=0
			while [ $n -lt 100 ]; do
				grep -q "AddressPool" /c/tinc.yaml 2>/dev/null && break
				kill -0 $pid 2>/dev/null || break
				n=$((n + 1))
				sleep 0.1
			done
			sleep 0.3
			kill -TERM $pid 2>/dev/null || true
			wait $pid 2>/dev/null || true
			chmod -R a+rX /c 2>/dev/null || true
		' >/dev/null 2>&1 || true
}

pool_of() {   # pool_of <dir> -> the AddressPool it wrote, or ""
	sed -n 's/^ *AddressPool: *//p' "$RUN/$1/tinc.yaml" 2>/dev/null | tr -d '"' | head -n1
}

# overlaps <cidr-a> <cidr-b> -- true when the two IPv4 prefixes intersect
overlaps() {
	python3 - "$1" "$2" <<-'PY'
		import ipaddress, sys
		a = ipaddress.ip_network(sys.argv[1], strict=False)
		b = ipaddress.ip_network(sys.argv[2], strict=False)
		sys.exit(0 if a.overlaps(b) else 1)
	PY
}

# ---- 1. a machine with no 10/8 network of its own ---------------------------
start_node plain 192.168.77.1/24
POOL="$(pool_of plain)"

if [ -n "$POOL" ] && overlaps "$POOL" 10.0.0.0/8 && [ "${POOL##*/}" = 24 ]; then
	ok "a fresh node invents a pool ($POOL)"
else
	bad "a fresh node invents a usable /24 in 10/8 (got '${POOL:-nothing}')"
fi

if overlaps "$POOL" 192.168.77.0/24; then
	bad "the pool avoids the machine's own LAN"
else
	ok "the pool does not overlap the machine's own LAN (192.168.77.0/24)"
fi

# ---- 2. that very pool is now in use here -----------------------------------
# The interesting case, and the one that used to be broken: the node must move,
# and it must say why rather than silently shadowing the LAN.
start_node taken "${POOL%.0/24}.1/24"   # an interface inside the pool it just chose
MOVED="$(pool_of taken)"

if [ -n "$MOVED" ] && [ "$MOVED" != "$POOL" ]; then
	ok "a node whose first choice is occupied moves to $MOVED"
else
	bad "a node whose first choice ($POOL) is occupied moves elsewhere (got '${MOVED:-nothing}')"
fi

if overlaps "$MOVED" "$POOL"; then
	bad "the replacement pool avoids the occupied one"
else
	ok "the replacement pool avoids the occupied one"
fi

# ---- 3. a machine that is on all of 10/8 ------------------------------------
# Every candidate collides. Starting anyway with a warning beats refusing to
# start: the operator can see the line and set AddressPool.
start_node everything 10.0.0.1/8
ALL="$(pool_of everything)"

if [ -n "$ALL" ]; then
	ok "a node on all of 10/8 still starts (pool $ALL)"
else
	bad "a node on all of 10/8 still starts"
fi

if grep -q "Every 10.x.y.0/24 overlaps a network this machine is on" "$RUN/everything/log"; then
	ok "it warns that the pool it had to use is in conflict"
else
	bad "it warns that the pool it had to use is in conflict"
fi

# The per-candidate line is only reachable when a candidate is actually
# occupied, and the walk starts at a random point -- so this is the case where
# it is guaranteed: here every candidate is.
if grep -q "Not using address pool .*: this machine is already on an overlapping network" "$RUN/everything/log"; then
	ok "it names the pools it skipped and why"
else
	bad "it names the pools it skipped and why"
	sed -n '1,12p' "$RUN/everything/log" >&2 || true
fi

# ---- 4. the invariant, over repetitions -------------------------------------
# One run proves the mechanism; the choice is random, so the property is what
# has to hold every time.
LANS="10.11.0.1/24 10.12.0.1/24 10.13.0.1/24 10.14.0.1/24"
BAD=0
TRIES=30

for i in $(seq 1 "$TRIES"); do
	# shellcheck disable=SC2086  # LANS is a list of arguments on purpose
	start_node "rep$i" $LANS
	P="$(pool_of "rep$i")"

	if [ -z "$P" ]; then
		BAD=$((BAD + 1))
		continue
	fi

	for lan in $LANS; do
		if overlaps "$P" "${lan%/*}/24"; then
			BAD=$((BAD + 1))
			log "  run $i chose $P, which overlaps $lan"
			break
		fi
	done

	rm -rf "$RUN/rep$i"
done

if [ "$BAD" -eq 0 ]; then
	ok "$TRIES runs, none picked a pool overlapping the four local LANs"
else
	bad "$BAD of $TRIES runs picked a pool overlapping a local LAN"
fi

if [ "$FAILED" -eq 0 ]; then
	log "zeroconf pool: all checks passed"
else
	log "zeroconf pool: FAILURES above"
fi

exit "$FAILED"
