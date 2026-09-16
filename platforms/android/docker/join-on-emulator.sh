#!/usr/bin/env bash
# join-on-emulator.sh -- PLAN.md M8 proof: join an invitation from the app
# running on a real Android runtime, and check what the core wrote.
#
# One command, everything in containers, nothing installed on the host:
#
#   1. a Linux inviter node (the same image the compose lab builds) on its own
#      docker network, with a fixed address so the invitation is dialable;
#   2. the headless emulator (docker/emulator.sh) attached to that network --
#      the guest reaches the inviter through the emulator's user-mode NAT;
#   3. the debug APK installed, the VpnService consent granted with appops
#      (the dialog cannot be tapped from a script);
#   4. the join driven through the UI: Configure -> Tools -> Join a network,
#      the invitation typed into the very field the QR scanner fills
#      (JoinNetworkToolDialogFragment.onActivityResult -> invitation_url);
#   5. assertions on the file the core wrote: the shared YAML schema
#      (docs/config-schema.md), a pool address, the inviter as a host record;
#   6. connect (the exported CONNECT intent) and ping the inviter through the
#      tunnel.
#
# Tunables: LAB (prefix, default wsy), SUBNET, APK, NETNAME, TINCSTACK_TAG,
# KEEP=1 (leave the lab up), WAIT (seconds for each deadline).
set -euo pipefail
cd "$(dirname "$0")"

LAB=${LAB:-wsy}
SUBNET=${SUBNET:-10.44.77.0/24}
INVITER_IP=${INVITER_IP:-10.44.77.10}
TAG=${TINCSTACK_TAG:-wsy}
NETNAME=${NETNAME:-phonenet}
PKG=net.tincstack.android
APK=${APK:-../app/build/outputs/apk/debug/app-debug.apk}
WAIT=${WAIT:-120}
REPO=$(cd ../../.. && pwd)

NET=$LAB-lab
INVITER=$LAB-a-node-1
export NAME=${NAME:-$LAB-emulator}

step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
adb() { docker exec -i "$NAME" adb "$@"; }

cleanup() {
    [[ ${KEEP:-0} == 1 ]] && { echo "KEEP=1: $INVITER, $NAME and $NET left up"; return; }
    step "cleanup"
    docker rm -f "$INVITER" >/dev/null 2>&1 || true
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker volume rm "$LAB-a-data" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

[ -f "$APK" ] || fail "no APK at $APK -- build it first (see readme.md 'Build')"

step "images"
docker image inspect "tincstack/node:$TAG" >/dev/null 2>&1 || {
    docker build -f "$REPO/core/Dockerfile.build" -t "tincstack/core:$TAG" "$REPO/core"
    docker build --build-arg "CORE_IMAGE=tincstack/core:$TAG" -t "tincstack/node:$TAG" \
        "$REPO/platforms/linux/docker"
}

step "inviter: a Linux node at $INVITER_IP (PUBLIC_ADDRESS so the invitation is dialable)"
docker network inspect "$NET" >/dev/null 2>&1 || docker network create --subnet "$SUBNET" "$NET" >/dev/null
docker rm -f "$INVITER" >/dev/null 2>&1 || true
docker volume rm "$LAB-a-data" >/dev/null 2>&1 || true
docker run -d --name "$INVITER" --network "$NET" --ip "$INVITER_IP" \
    --cap-add NET_ADMIN --device /dev/net/tun \
    -e NODE_NAME=node_a -e PUBLIC_ADDRESS="$INVITER_IP" -e PORT=655 -e LOG_LEVEL=2 \
    -v "$LAB-a-data:/etc/tincstack" "tincstack/node:$TAG" >/dev/null

deadline=$(( SECONDS + WAIT ))
until docker logs "$INVITER" 2>&1 | grep -c ' Ready$' >/dev/null; do
    (( SECONDS < deadline )) || { docker logs "$INVITER" >&2; fail "inviter not ready in ${WAIT}s"; }
    sleep 2
done
docker logs "$INVITER" 2>&1 | grep -E 'AddressPool|Listening on 0' || true

step "emulator on $NET"
NET=$NET ./emulator.sh up

step "install the debug APK (clean: the app's data must start empty)"
adb uninstall "$PKG" >/dev/null 2>&1 || true
docker cp "$APK" "$NAME:/tmp/app.apk"
adb install -r -t /tmp/app.apk

step "grant the VpnService consent non-interactively"
adb shell appops set "$PKG" ACTIVATE_VPN allow || fail "could not grant ACTIVATE_VPN"

step "invitation for the phone"
invitation=$(docker exec "$INVITER" tincstack-cli invite phone | tr -d '\r')
echo "invitation: $invitation"
case $invitation in "$INVITER_IP:655/"*) ;; *) fail "invitation does not carry $INVITER_IP:655" ;; esac

step "join through the UI (the field the QR scanner fills)"
./ui-join.sh "$NAME" "$NETNAME" "$invitation" || fail "the join dialog did not complete"

step "the file the core wrote"
yaml=$(adb shell "su 0 cat /data/data/$PKG/files/networks/$NETNAME/tinc.yaml" | tr -d '\r')
[ -n "$yaml" ] || fail "no tinc.yaml under networks/$NETNAME"
# printed with every PEM body dropped: this file holds the node's private keys
sed -E '/-----BEGIN/,/-----END/{/-----BEGIN/!d}; s/^( *)-----BEGIN.*/\1<key redacted>/' <<<"$yaml"

grep -q "^networks:"            <<<"$yaml" || fail "no networks: mapping (not the shared schema)"
grep -qE "^  $NETNAME:"         <<<"$yaml" || fail "no networks.$NETNAME stanza"
grep -qE "^    options:"        <<<"$yaml" || fail "no options: under the network"
grep -qE "^    hosts:"          <<<"$yaml" || fail "no hosts: under the network"
grep -qE "^    keys:"           <<<"$yaml" || fail "no keys: under the network"
grep -qE "^      node_a:"       <<<"$yaml" || fail "the inviter is not a host record"
grep -qE "InterfaceAddress: 10\." <<<"$yaml" || fail "no pool address (InterfaceAddress)"
echo "OK: schema-conformant, pool address present"

step "connect and ping the inviter through the tunnel"
# the app's own intent API (intent/Actions.kt): CONNECT with a tinc:<net> URI
adb shell am start -a "$PKG.intent.action.CONNECT" -d "tinc:$NETNAME" >/dev/null
deadline=$(( SECONDS + WAIT ))
until adb shell 'su 0 ip -br addr show tun0' 2>/dev/null | grep -c 'UNKNOWN\|UP' >/dev/null; do
    (( SECONDS < deadline )) || {
        adb shell "su 0 cat /data/data/$PKG/cache/logs/tincapp.log" >&2 || true
        fail "VpnService.establish() produced no tun interface within ${WAIT}s"
    }
    sleep 3
done
adb shell 'su 0 ip -br addr show tun0'
pool_a=$(docker exec "$INVITER" tincstack-cli get node_a.Subnet | head -n1 | tr -d '\r')
pool_a=${pool_a%%/*}
deadline=$(( SECONDS + WAIT ))
until adb shell "ping -c1 -W2 $pool_a" >/dev/null 2>&1; do
    (( SECONDS < deadline )) || {
        echo "--- app log ---" >&2
        adb shell "su 0 cat /data/data/$PKG/cache/logs/tinc.$NETNAME.log" >&2 || true
        fail "no traffic to $pool_a through the tunnel within ${WAIT}s"
    }
    sleep 3
done
adb shell "ping -c3 -W2 $pool_a"

step "and back: the inviter reaches the phone's pool address"
phone_ip=$(grep -oE 'InterfaceAddress: [0-9.]+' <<<"$yaml" | head -1 | awk '{print $2}')
docker exec "$INVITER" ping -c3 -W2 "$phone_ip"

echo
echo "PASS: joined on Android, schema-conformant config, tunnel carries traffic"
