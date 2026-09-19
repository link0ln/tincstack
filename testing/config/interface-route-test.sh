#!/usr/bin/env bash
# InterfaceRoute: a subnet another node announces becomes a route this machine
# uses. This is the contract behind the Windows GUI's per-peer route toggle --
# the button writes exactly this option, and the daemon installs it.
#
# Two nodes. node2 owns a LAN (192.168.5.0/24, a dummy interface) and announces
# it. node1 has `InterfaceRoute: 192.168.5.0/24 via 10.79.0.2` and no tinc-up
# script, so the built-in interface setup (autoif.c) is what installs the route.
#
# The negative control is the point: with the route deleted, node1 cannot reach
# the LAN even though tinc knows the subnet and the tunnel is up. tinc knowing
# how to forward a subnet and the operating system knowing to send it to the
# tunnel are two different things, and this option is the second one.
#
# Usage: [CORE_IMAGE=tincstack/core:tag] testing/config/interface-route-test.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export CORE_IMAGE="${CORE_IMAGE:-tincstack/core:${TINCSTACK_TAG:-${WSF_TAG:-dev}}}"
export IR_PROJECT="${IR_PROJECT:-tincstack-ifroute}"
export IR_SUBNET="${IR_SUBNET:-172.28.81}"
NET=ifroute
LAN=192.168.5.0/24
LAN_IP=192.168.5.1
ALT=192.168.6.0/24          # second route, written the way `tinc join' writes it
RUN="$HERE/run-ifroute"
FAILED=0

compose() { docker compose -f "$HERE/interface-route-compose.yml" "$@"; }
log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
ok()  { log "PASS $1"; }
bad() { log "FAIL $1"; FAILED=1; }

cleanup() {
	compose down -v --remove-orphans >/dev/null 2>&1 || true
	docker run --rm -v "$RUN:/r" "$CORE_IMAGE" sh -c 'rm -rf /r/*' >/dev/null 2>&1 || true
	rm -rf "$RUN" 2>/dev/null || true
}
trap cleanup EXIT
cleanup
mkdir -p "$RUN"

# gen NAME VPN_IP  -- keys + host record, in the container (tinc writes 0600 root)
gen() {
	local name="$1"
	mkdir -p "$RUN/keys-$name/hosts"
	printf 'Name = %s\n' "$name" > "$RUN/keys-$name/tinc.conf"
	docker run --rm -v "$RUN/keys-$name:/k" "$CORE_IMAGE" \
		sh -c "tinc -c /k generate-keys >/dev/null 2>&1 && chmod -R a+rX /k"
}
gen node1
gen node2

host_record() {   # host_record NAME LAN_IP VPN_IP [extra Subnet]
	printf 'Address = %s\nPort = 655\nSubnet = %s/32\n' "$2" "$3"
	[ -n "${4:-}" ] && printf 'Subnet = %s\n' "$4"
	cat "$RUN/keys-$1/hosts/$1"
}
host_record node1 "$IR_SUBNET.11" 10.79.0.1        > "$RUN/host-node1"
host_record node2 "$IR_SUBNET.12" 10.79.0.2 "$LAN" > "$RUN/host-node2"

# node1: no scripts stanza on purpose -- the built-in tinc-up (autoif.c) is the
# code under test, and InterfaceRoute is what it has to install.
mkdir -p "$RUN/node1" "$RUN/node2"
{
	echo "networks:"
	echo "  $NET:"
	echo "    options:"
	echo "      Name: node1"
	echo "      Mode: router"
	echo "      Port: 655"
	echo "      AddressFamily: ipv4"
	echo "      InterfaceAddress: 10.79.0.1/24"
	# Both spellings the daemon accepts, in one config: the `ip route' one an
	# operator types, and the "<prefix> <gateway>" one `tinc join' writes from
	# an invitation (and the Windows GUI writes from its route toggles).
	echo "      InterfaceRoute:"
	echo "        - $LAN via 10.79.0.2"
	echo "        - $ALT 10.79.0.2"
	echo "    keys:"
	echo "      ed25519_priv: |"; sed 's/^/        /' "$RUN/keys-node1/ed25519_key.priv"
	echo "      rsa_priv: |"; sed 's/^/        /' "$RUN/keys-node1/rsa_key.priv"
	echo "    hosts:"
	for m in node1 node2; do echo "      $m: |"; sed 's/^/        /' "$RUN/host-$m"; done
} > "$RUN/node1/tinc.yaml"

{
	echo "networks:"
	echo "  $NET:"
	echo "    options:"
	echo "      Name: node2"
	echo "      Mode: router"
	echo "      Port: 655"
	echo "      AddressFamily: ipv4"
	echo "      ConnectTo: [node1]"
	echo "    keys:"
	echo "      ed25519_priv: |"; sed 's/^/        /' "$RUN/keys-node2/ed25519_key.priv"
	echo "      rsa_priv: |"; sed 's/^/        /' "$RUN/keys-node2/rsa_key.priv"
	echo "    scripts:"
	echo "      tinc-up: |"
	echo "        #!/bin/sh"
	# shellcheck disable=SC2016  # $INTERFACE is expanded by tincd, not here
	echo '        ip link set "$INTERFACE" up'
	echo "        ip addr add 10.79.0.2/24 dev \"\$INTERFACE\""
	echo "        ip link add lan type dummy"
	echo "        ip addr add $LAN_IP/24 dev lan"
	echo "        ip link set lan up"
	echo "    hosts:"
	for m in node1 node2; do echo "      $m: |"; sed 's/^/        /' "$RUN/host-$m"; done
} > "$RUN/node2/tinc.yaml"
rm -f "$RUN"/host-* ; rm -rf "$RUN"/keys-*

log "starting the two nodes"
compose up -d >/dev/null

up=0
for _ in $(seq 40); do
	if compose exec -T node1 ping -c 1 -W 1 10.79.0.2 >/dev/null 2>&1; then up=1; break; fi
	sleep 1
done
[ "$up" = 1 ] || { log "FAIL the tunnel never came up"; compose logs; exit 1; }
ok "the tunnel is up"

# 1. the built-in tinc-up installed the route on the tinc interface
if compose exec -T node1 ip route show "$LAN" 2>/dev/null | grep -c "dev $NET" >/dev/null; then
	ok "InterfaceRoute is in node1's routing table, on the tinc interface"
else
	bad "InterfaceRoute did not reach node1's routing table"
	compose exec -T node1 ip route || true
fi

# 1b. the same option written as "<prefix> <gateway>" (no `via') works too
if compose exec -T node1 ip route show "$ALT" 2>/dev/null | grep -c "dev $NET" >/dev/null; then
	ok "the \"<prefix> <gateway>\" spelling is installed as well"
else
	bad "the \"<prefix> <gateway>\" spelling did not reach the routing table"
fi

# 2. and the LAN behind node2 is reachable through it
if compose exec -T node1 ping -c 3 -W 2 "$LAN_IP" >/dev/null 2>&1; then
	ok "node1 reaches $LAN_IP in the LAN node2 announces"
else
	bad "node1 cannot reach $LAN_IP"
	compose logs --no-log-prefix node1 | tail -30 || true
fi

# 3. the negative control: tinc still knows the subnet, but without the system
#    route nothing sends the packets to the tunnel.
compose exec -T node1 ip route del "$LAN" >/dev/null 2>&1 || true
if compose exec -T node1 ping -c 2 -W 2 "$LAN_IP" >/dev/null 2>&1; then
	bad "without the route node1 still reached the LAN -- this test proves nothing"
else
	ok "without the route the LAN is unreachable (the route is what makes it work)"
fi

# 4. tinc knew the subnet all along: this is a routing-table gap, not a tinc one
if compose exec -T node1 tinc -c /etc/tincstack/tinc.yaml -n "$NET" dump subnets 2>/dev/null \
		| grep -c "$LAN owner node2" >/dev/null; then
	ok "tinc knew $LAN belongs to node2 the whole time"
else
	bad "node1 never learned that node2 owns $LAN"
fi

if [ "$FAILED" = 0 ]; then
	log "interface-route-test: PASS"
else
	log "interface-route-test: FAIL"
fi
exit "$FAILED"
