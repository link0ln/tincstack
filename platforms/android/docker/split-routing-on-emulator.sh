#!/usr/bin/env bash
# split-routing-on-emulator.sh -- PLAN.md M8 proof for per-app split routing
# (AllowApplication whitelist / DisallowApplication blacklist), end to end.
#
#   1. join-on-emulator.sh (KEEP=1): inviter, emulator, joined network, tunnel;
#   2. two throwaway apps of their own packages (probe-apps.sh):
#      net.tincstack.probe.a and net.tincstack.probe.b. `run-as <pkg> ping`
#      runs as that app's UID, and per-app VPN routing is per UID;
#   3. whitelist through the app's settings screen (ui-pick-apps.sh: tick
#      probe.a, "Only the selected apps use the VPN", Save), the yaml it
#      wrote, reconnect: probe.a reaches the inviter's tunnel address, probe.b
#      does not; the VPN network's UID ranges and `ip rule` for both UIDs;
#   4. blacklist through the same screen (mode switched, selection kept):
#      DisallowApplication probe.a -> probe.a does not reach it, probe.b does.
#
# The tunnel address (the inviter's pool address) exists only inside the
# mesh: an answer can only have come through tincd, and silence from the
# other UID means its traffic was not given to the tunnel.
set -euo pipefail
cd "$(dirname "$0")"

export LAB=${LAB:-ww-d2}
export SUBNET=${SUBNET:-10.44.78.0/24}
export INVITER_IP=${INVITER_IP:-10.44.78.10}
export NETNAME=${NETNAME:-phonenet}
export NAME=${NAME:-$LAB-emulator}
PKG=net.tincstack.android
PA=net.tincstack.probe.a
PB=net.tincstack.probe.b
INVITER=$LAB-a-node-1
PROBES=${PROBES:-$(mktemp -d)}

step() { printf '\n== [%(%H:%M:%S)T] %s\n' -1 "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
adb() { docker exec -i "$NAME" adb "$@"; }

cleanup() {
    [[ ${KEEP:-0} == 1 ]] && { echo "KEEP=1: lab left up"; return; }
    step "cleanup"
    docker rm -f "$INVITER" "$NAME" >/dev/null 2>&1 || true
    docker volume rm "$LAB-a-data" >/dev/null 2>&1 || true
    docker network rm "$LAB-lab" >/dev/null 2>&1 || true
}
trap cleanup EXIT

has_tun() { adb shell 'su 0 ip -br link show tun0' >/dev/null 2>&1; }
wait_for() { local limit=$1; shift; local t0=$SECONDS; until "$@"; do (( SECONDS - t0 < limit )) || return 1; sleep 2; done; }
no_tun() { ! has_tun; }
reach() { adb shell "run-as $1 ping -c2 -W2 $pool_a" >/dev/null 2>&1; }
yaml() { adb shell "su 0 cat /data/data/$PKG/files/networks/$NETNAME/tinc.yaml" | tr -d '\r'; }
options() { yaml | sed -n '/^    options:/,/^    [a-z]*:$/p' | grep -vE 'PrivateKey|^    [a-z]+:$' ; }

reconnect() {
    adb shell am start -a "$PKG.intent.action.DISCONNECT" >/dev/null
    wait_for 30 no_tun || fail "tun0 did not go away on disconnect"
    "$@"
    adb shell am start -a "$PKG.intent.action.CONNECT" -d "tinc:$NETNAME" >/dev/null
    wait_for 60 has_tun || fail "no tun0 after reconnect"
    # the shell (uid 2000) is in the VPN in both modes below only if listed: use the
    # routed probe as the liveness check instead of a fixed sleep
}

routing_evidence() {
    echo "--- UIDs: $(adb shell "pm list packages -U $PA; pm list packages -U $PB" | tr -d '\r' | tr '\n' ' ')"
    echo "--- VPN network (dumpsys connectivity):"
    adb shell 'dumpsys connectivity' | tr -d '\r' | grep -E 'NetworkAgentInfo.*VPN|Uids: ' | grep -A1 'VPN' | head -4 || true
    echo "--- ip rule (uid ranges into the VPN table):"
    adb shell 'su 0 ip rule' | tr -d '\r' | grep -E 'uidrange' | head -12 || true
}

step "lab: join + connect (join-on-emulator.sh, KEEP=1)"
KEEP=1 ./join-on-emulator.sh
pool_a=$(docker exec "$INVITER" tincstack-cli get node_a.Subnet | head -n1 | tr -d '\r'); pool_a=${pool_a%%/*}
echo "inviter tunnel address: $pool_a"

step "probe apps"
[ -f "$PROBES/probe-a.apk" ] || ./probe-apps.sh "$PROBES"
for a in probe-a probe-b; do docker cp "$PROBES/$a.apk" "$NAME:/tmp/$a.apk"; adb install -r -t "/tmp/$a.apk"; done

step "no split routing: both probes reach $pool_a"
reach "$PA" || fail "probe.a cannot reach $pool_a with every app in the VPN"
reach "$PB" || fail "probe.b cannot reach $pool_a with every app in the VPN"
echo "OK: a=reach b=reach"

step "WHITELIST via the settings screen: only $PA"
reconnect ./ui-pick-apps.sh "$NAME" whitelist no "$PA"
options
grep -qE "^ +AllowApplication: $PA$" <<<"$(yaml)" || fail "the picker did not write AllowApplication: $PA"
grep -q DisallowApplication <<<"$(yaml)" && fail "DisallowApplication left in the file with a whitelist"
wait_for 60 reach "$PA" || fail "whitelisted $PA does not reach $pool_a"
reach "$PB" && fail "$PB (not whitelisted) reached $pool_a"
echo "OK: whitelist: a=reach b=NO"
routing_evidence

step "BLACKLIST via the settings screen: all but $PA"
reconnect ./ui-pick-apps.sh "$NAME" blacklist no
options
grep -qE "^ +DisallowApplication: $PA$" <<<"$(yaml)" || fail "the picker did not write DisallowApplication: $PA"
grep -qE "^ +AllowApplication:" <<<"$(yaml)" && fail "AllowApplication left in the file with a blacklist"
wait_for 60 reach "$PB" || fail "$PB (not blacklisted) does not reach $pool_a"
reach "$PA" && fail "blacklisted $PA reached $pool_a"
echo "OK: blacklist: a=NO b=reach"
routing_evidence

echo
echo "PASS: split routing per app: whitelist and blacklist written by the settings screen, enforced per UID${TRANSPORT:+ (transport $TRANSPORT)}"
