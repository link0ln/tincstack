#!/usr/bin/env bash
# announced-routes-on-emulator.sh -- proof that the app routes what the other
# nodes announce, with no setting (owner, 2026-09-28; docs/config-schema.md
# "Android takes every announced route"), on a real Android runtime:
#
#   1. join-on-emulator.sh (KEEP=1): inviter node_a, emulator, joined network,
#      tunnel up;
#   2. node_a holds 198.51.100.7 (TEST-NET-2, routed nowhere) on its loopback.
#      Before any announcement the phone gets no answer from it: the address
#      is not in the VPN, and the emulator's own uplink has no route to it;
#   3. node_a announces 0.0.0.0/0 (`tinc add` + `reload`, as a running exit
#      would): the app rebuilds its interface on its own, the VPN network has
#      the default route and the full-tunnel resolvers, 198.51.100.7 answers
#      (only the tunnel can have carried that) and node_a's pool address still
#      answers (tincd relaunched on the new fd);
#   4. disconnect + connect: the remembered route is on the interface from the
#      start, no rebuild;
#   5. node_a withdraws 0.0.0.0/0: the route goes, 198.51.100.7 stops
#      answering, the tunnel keeps working.
#
# Tunables: those of join-on-emulator.sh (LAB, SUBNET, APK, TINCSTACK_TAG,
# WAIT), KEEP=1 to leave the lab up.
set -euo pipefail
cd "$(dirname "$0")"
export LAB=${LAB:-wsr}
export SUBNET=${SUBNET:-10.44.79.0/24}
export INVITER_IP=${INVITER_IP:-10.44.79.10}
export NAME=${NAME:-$LAB-emulator}
PKG=net.tincstack.android
INVITER=$LAB-a-node-1
EXIT_ADDR=198.51.100.7
WAIT=${WAIT:-120}
step() { printf '\n== [%(%H:%M:%S)T] %s\n' -1 "$*"; }
fail() {
    echo "FAIL: $*" >&2
    echo "--- app log (tail) ---" >&2
    adb shell "su 0 tail -n 60 /data/data/$PKG/cache/logs/tincapp.log" 2>/dev/null | tr -d '\r' >&2 || true
    exit 1
}
adb() { docker exec -i "$NAME" adb "$@"; }
cleanup() {
    [[ ${KEEP:-0} == 1 ]] && { echo "KEEP=1: lab left up"; return; }
    step "cleanup"
    docker rm -f "$INVITER" "$NAME" >/dev/null 2>&1 || true
    docker volume rm "$LAB-a-data" >/dev/null 2>&1 || true
    docker network rm "$LAB-lab" >/dev/null 2>&1 || true
}
trap cleanup EXIT
wait_for() { local limit=$1; shift; local t0=$SECONDS; until "$@"; do (( SECONDS - t0 < limit )) || return 1; sleep 2; done; }
not() { ! "$@"; }
reach() { adb shell "ping -c1 -W2 $1" >/dev/null 2>&1; }
# a rebuilt interface may get the next name (tun1, ...)
has_tun() { adb shell 'su 0 ip -br link' 2>/dev/null | tr -d '\r' | grep -qE '^tun[0-9]+'; }
# the VPN network's LinkProperties line (routes, DNS) as ConnectivityService has it
vpn_lp() { adb shell 'dumpsys connectivity' | tr -d '\r' | grep -oE '\{InterfaceName: tun[0-9]+[^}]*\}' | head -1; }
default_routed() { vpn_lp | grep -qE 'Routes: \[.*[ ,]0\.0\.0\.0/0 -> '; }
rebuilds() { adb shell "su 0 cat /data/data/$PKG/cache/logs/tincapp.log" | tr -d '\r' | grep -c 'Interface rebuilt' || true; }
cli() { docker exec "$INVITER" tincstack-cli "$@"; }

step "lab: join + connect (join-on-emulator.sh, KEEP=1)"
KEEP=1 ./join-on-emulator.sh
# shellcheck source=ui-lib.sh
. ./ui-lib.sh
NETNAME=$(app_network) || fail "no single joined network"
pool_a=$(cli get node_a.Subnet | head -n1 | tr -d '\r'); pool_a=${pool_a%%/*}
echo "network: $NETNAME, inviter tunnel address: $pool_a"

step "node_a holds $EXIT_ADDR; nothing announces it yet"
docker exec "$INVITER" ip addr add "$EXIT_ADDR/32" dev lo
vpn_lp
default_routed && fail "the VPN has a default route before anyone announced one"
reach "$EXIT_ADDR" && fail "$EXIT_ADDR answered before it was routed into the tunnel"
reach "$pool_a" || fail "the tunnel does not carry traffic to $pool_a"
echo "OK: $EXIT_ADDR unreachable, tunnel up"

step "node_a announces 0.0.0.0/0"
before=$(rebuilds)
cli add node_a.Subnet 0.0.0.0/0
cli reload
cli dump subnets | tr -d '\r' | grep '0.0.0.0/0' || fail "node_a does not list its 0.0.0.0/0"
t0=$SECONDS
wait_for "$WAIT" default_routed || fail "the app did not route 0.0.0.0/0 within ${WAIT}s"
echo "default route on the VPN after $(( SECONDS - t0 ))s"
vpn_lp
vpn_lp | grep -q 'DnsAddresses: \[ */1\.1\.1\.1,/8\.8\.8\.8 *\]' || fail "no full-tunnel resolvers on the VPN network"
wait_for 60 reach "$EXIT_ADDR" || fail "$EXIT_ADDR does not answer through the tunnel"
reach "$pool_a" || fail "the tunnel lost $pool_a after the rebuild"
[ "$(rebuilds)" -gt "$before" ] || fail "no 'Interface rebuilt' in the app log"
adb shell "su 0 grep -E 'Announced routes changed|Interface rebuilt' /data/data/$PKG/cache/logs/tincapp.log" | tr -d '\r' | tail -2
echo "OK: 0.0.0.0/0 taken, DNS 1.1.1.1/8.8.8.8, $EXIT_ADDR answers, tunnel up"

step "reconnect: the remembered route is there from the start"
adb shell am start -a "$PKG.intent.action.DISCONNECT" >/dev/null
wait_for 30 not has_tun || fail "tun0 did not go away on disconnect"
before=$(rebuilds)
adb shell am start -a "$PKG.intent.action.CONNECT" -d "tinc:$NETNAME" >/dev/null
wait_for 60 has_tun || fail "no tun0 after reconnect"
wait_for 10 default_routed || fail "the remembered default route is not on the new interface"
wait_for 60 reach "$EXIT_ADDR" || fail "$EXIT_ADDR does not answer after the reconnect"
sleep 15   # several polls: the unchanged set must not rebuild anything
[ "$(rebuilds)" -eq "$before" ] || fail "an unchanged route set rebuilt the interface"
echo "OK: routed from the first moment, no rebuild"

step "node_a withdraws 0.0.0.0/0"
cli del node_a.Subnet 0.0.0.0/0
cli reload
wait_for "$WAIT" not default_routed || fail "the app kept 0.0.0.0/0 after it was withdrawn"
vpn_lp
wait_for 30 not reach "$EXIT_ADDR" || fail "$EXIT_ADDR still answers after the withdrawal"
wait_for 60 reach "$pool_a" || fail "the tunnel lost $pool_a after the withdrawal"
echo "OK: route gone, $EXIT_ADDR unreachable again, tunnel up"

echo
echo "PASS: announced routes followed on their own (added, remembered across a reconnect, withdrawn)"
