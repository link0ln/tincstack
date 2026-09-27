#!/usr/bin/env bash
# ui-flows-on-emulator.sh -- the app's join and connect flows, end to end,
# through the UI only: what a user does, system dialogs included.
#
#   1. lab: a Linux founder node (the core of this tree) on its own docker
#      network, the headless emulator attached to it, the debug APK freshly
#      installed with nothing granted;
#   2. first launch shows the join form, its button disabled until the text
#      holds an invitation; text that is not one is said to be so;
#   3. failed joins leave nothing behind and say why, in words:
#        - an address nobody answers on         -> "No answer from ..."
#        - the founder, with a made-up token    -> "... doesn't match it"
#        - the founder, invitation already used -> "... turned this invitation down"
#      after each: no network directory, no staging leftovers, still the
#      join form;
#   4. the owner's case (2026-09-27): the invitation typed with blanks in
#      front and a line break after it -> "Join and connect" -> the
#      notification permission and the VPN consent answered by tapping them
#      -> "Connected" on screen, one network, named by the app;
#   5. ping the founder's tunnel address from the phone; the founder sees
#      the phone reachable;
#   6. Disconnect on the big button -> "Disconnected", no tun0.
#
# Run it under the lab lock (it creates containers and a network):
#   flock /tmp/tincstack-lab.lock ./ui-flows-on-emulator.sh
#
# Tunables: LAB (prefix, default wsu-ui), SUBNET, FOUNDER_IP, DEAD_IP (an
# address on SUBNET nobody uses), TINCSTACK_TAG (core/node image tag), IMAGE
# (emulator image), APK, WAIT (seconds per deadline), SHOTS (directory:
# save a screenshot at each step), KEEP=1 (leave the lab up).
set -euo pipefail
cd "$(dirname "$0")"

LAB=${LAB:-wsu-ui}
SUBNET=${SUBNET:-10.44.81.0/24}
FOUNDER_IP=${FOUNDER_IP:-10.44.81.10}
DEAD_IP=${DEAD_IP:-10.44.81.99}
TAG=${TINCSTACK_TAG:-dev}
PKG=net.tincstack.android
APK=${APK:-../app/build/outputs/apk/debug/app-debug.apk}
WAIT=${WAIT:-120}
REPO=$(cd ../../.. && pwd)
NET=$LAB-lab
FOUNDER=$LAB-founder
export NAME=${NAME:-$LAB-emulator}
export UI_TIMEOUT=${UI_TIMEOUT:-60}
# shellcheck source=ui-lib.sh
. ./ui-lib.sh

step() { printf '\n== [%(%H:%M:%S)T] %s\n' -1 "$*"; }
ok() { echo "OK: $*"; }
fail() {
    echo "FAIL: $*" >&2
    echo "--- screen:" >&2; ui_texts >&2 || true
    echo "--- app log:" >&2; adb shell "run-as $PKG tail -n 40 cache/logs/tincapp.log" 2>/dev/null | tr -d '\r' >&2 || true
    exit 1
}
shot() {
    [ -n "${SHOTS:-}" ] || return 0
    mkdir -p "$SHOTS"
    docker exec "$NAME" sh -c "adb exec-out screencap -p > /tmp/shot.png" && docker cp -q "$NAME:/tmp/shot.png" "$SHOTS/$1.png"
}

cleanup() {
    [[ ${KEEP:-0} == 1 ]] && { echo "KEEP=1: $FOUNDER, $NAME and $NET left up"; return; }
    step "cleanup"
    docker rm -f "$FOUNDER" "$NAME" >/dev/null 2>&1 || true
    docker volume rm "$LAB-founder-data" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

[ -f "$APK" ] || fail "no APK at $APK -- build it first (see readme.md 'Build')"
rid() { echo "resource-id=\"$PKG:id/$1\""; }
state_title() { ui_attr "$(rid state_title)" text; }
has_tun() { adb shell 'su 0 ip -br link show tun0' >/dev/null 2>&1; }
leftovers() { adb shell "run-as $PKG ls files/joining" 2>/dev/null | tr -d '\r'; }

# ---------------------------------------------------------------------------
step "lab: founder node_a at $FOUNDER_IP (core tincstack/core:$TAG)"
docker image inspect "tincstack/core:$TAG" >/dev/null 2>&1 ||
    docker build -f "$REPO/core/Dockerfile.build" -t "tincstack/core:$TAG" "$REPO/core"
docker build -q --build-arg "CORE_IMAGE=tincstack/core:$TAG" -t "tincstack/node:$TAG" \
    "$REPO/platforms/linux/docker" >/dev/null
docker network inspect "$NET" >/dev/null 2>&1 || docker network create --subnet "$SUBNET" "$NET" >/dev/null
docker rm -f "$FOUNDER" >/dev/null 2>&1 || true
docker volume rm "$LAB-founder-data" >/dev/null 2>&1 || true
docker run -d --name "$FOUNDER" --network "$NET" --ip "$FOUNDER_IP" \
    --cap-add NET_ADMIN --device /dev/net/tun \
    -e NODE_NAME=node_a -e PUBLIC_ADDRESS="$FOUNDER_IP" -e PORT=655 -e LOG_LEVEL=2 \
    -v "$LAB-founder-data:/etc/tincstack" "tincstack/node:$TAG" >/dev/null
deadline=$(( SECONDS + WAIT ))
until docker logs "$FOUNDER" 2>&1 | grep -c ' Ready$' >/dev/null; do
    (( SECONDS < deadline )) || { docker logs "$FOUNDER" >&2; fail "founder not ready in ${WAIT}s"; }
    sleep 2
done
tunnel_ip=$(docker exec "$FOUNDER" tincstack-cli get node_a.Subnet | head -n1 | tr -d '\r')
tunnel_ip=${tunnel_ip%%/*}
echo "founder tunnel address: $tunnel_ip"

step "emulator on $NET, the APK installed fresh, nothing granted"
NET=$NET ./emulator.sh up
adb uninstall "$PKG" >/dev/null 2>&1 || true
docker cp "$APK" "$NAME:/tmp/app.apk"
adb install -r -t /tmp/app.apk >/dev/null
adb shell 'settings put system screen_off_timeout 1800000'
adb shell input keyevent KEYCODE_WAKEUP
adb shell wm dismiss-keyguard || true

# ---------------------------------------------------------------------------
step "first launch: the join form, its button disabled"
app_open
ui_wait "$(rid invitation_input)" >/dev/null || fail "no join form on first launch"
[[ $(ui_attr "$(rid join_button)" enabled) == false ]] || fail "Join enabled with an empty field"
shot 01-first-launch
ok "join form, button disabled"

step "text that is no invitation"
ui_type "$(rid invitation_input)" 'hello%sworld'
ui_wait 'text="This isn' >/dev/null || fail "no 'This isn't an invitation' message"
[[ $(ui_attr "$(rid join_button)" enabled) == false ]] || fail "Join enabled for 'hello world'"
shot 02-not-an-invitation
ok "rejected before dialling, with a message"

# failed_join <label> <invitation> <expected message fragment> <max seconds>
failed_join() {
    local label=$1 inv=$2 expect=$3 limit=$4 t0 msg
    step "failed join: $label"
    ui_type "$(rid invitation_input)" "$inv"
    [[ $(ui_attr "$(rid join_button)" enabled) == true ]] || fail "Join disabled for a well-formed invitation"
    t0=$SECONDS
    ui_tap "$(rid join_button)"
    until ui_find "$(rid join_error_message)" >/dev/null; do
        (( SECONDS - t0 < limit )) || fail "$label: no error message within ${limit}s"
        sleep 2
    done
    msg=$(ui_attr "$(rid join_error_message)" text)
    echo "after $(( SECONDS - t0 ))s the app says: $msg"
    grep -qF -- "$expect" <<<"$msg" || fail "$label: expected '$expect' in the message"
    shot "$label"
    [ -z "$(app_networks)" ] || fail "$label left a network behind: $(app_networks)"
    [ -z "$(leftovers)" ] || fail "$label left staging directories: $(leftovers)"
    ui_find "$(rid invitation_input)" >/dev/null || fail "$label: the join form is gone"
    ok "$label: message shown, nothing saved"
}

token() { head -c 36 /dev/urandom | base64 | tr '+/' '-_' | head -c 48; }

failed_join 03-unreachable "$DEAD_IP:655/$(token)" "No answer from $DEAD_IP:655" 45
failed_join 04-bad-token "$FOUNDER_IP:655/$(token)" "doesn't match it" 45

used=$(docker exec "$FOUNDER" tincstack-cli invite used1 | tr -d '\r')
echo "spending $used from another node"
docker run --rm --network "$NET" --entrypoint sh "tincstack/node:$TAG" \
    -c "touch /tmp/t.yaml; tinc -c /tmp/t.yaml join $used" 2>&1 | tail -n1
failed_join 05-used-invitation "$used" "turned this invitation down" 60

# ---------------------------------------------------------------------------
step "the owner's case: blanks in front, a line break after"
invitation=$(docker exec "$FOUNDER" tincstack-cli invite phone | tr -d '\r')
echo "invitation: $invitation"
ui_tap "$(rid invitation_input)"
ui_wait_ime 5 || true
ui_clear_field
adb shell "input text '%s%s$invitation'" >/dev/null
adb shell input keyevent KEYCODE_ENTER >/dev/null
ui_hide_ime
field=$(ui_attr "$(rid invitation_input)" text)
[[ $field == "  $invitation"* ]] || fail "the field does not hold the padded invitation: '$field'"
[[ $(ui_attr "$(rid join_button)" enabled) == true ]] || fail "Join disabled for a padded invitation"
shot 06-padded-invitation
ok "padded invitation accepted: '${field//$'\n'/\\n}'"

step "Join and connect; answer the system dialogs by tapping them"
t0=$SECONDS
ui_hide_ime
ui_tap "$(rid join_button)"
connected=0
while (( SECONDS - t0 < WAIT )); do
    screen=$(ui_dump)
    if grep -q 'permission_allow_button' <<<"$screen"; then
        shot 07-notification-permission
        echo "notification permission: Allow"
        UI_TIMEOUT=5 ui_tap 'resource-id="com.android.permissioncontroller:id/permission_allow_button"' || true
    elif grep -q 'com.android.vpndialogs' <<<"$screen"; then
        shot 08-vpn-consent
        echo "VPN consent: OK"
        UI_TIMEOUT=5 ui_tap 'resource-id="android:id/button1"' || true
    elif grep -q "$(rid join_error_message)" <<<"$screen"; then
        fail "the join failed: $(ui_attr "$(rid join_error_message)" text)"
    elif [[ $(state_title) == Connected ]]; then
        connected=1
        break
    fi
    sleep 2
done
(( connected )) || fail "not Connected within ${WAIT}s"
echo "Connected after $(( SECONDS - t0 ))s: $(ui_attr "$(rid state_detail)" text)"
shot 09-connected
net=$(app_network) || fail "not exactly one network after the join"
ok "one network, named by the app: $net"

step "ping the founder's tunnel address ($tunnel_ip) from the phone"
deadline=$(( SECONDS + 60 ))
until adb shell "ping -c1 -W2 $tunnel_ip" >/dev/null 2>&1; do
    (( SECONDS < deadline )) || fail "no answer from $tunnel_ip through the tunnel"
    sleep 2
done
adb shell "ping -c3 -W2 $tunnel_ip" | tr -d '\r' | tail -n2
docker exec "$FOUNDER" tincstack-cli dump reachable nodes | grep -q '^phone ' || fail "the founder does not see the phone"
ok "tunnel carries traffic, the founder sees the phone"

step "Disconnect on the big button"
ui_tap "$(rid connect_button)"
deadline=$(( SECONDS + 30 ))
until [[ $(state_title) == Disconnected ]] && ! has_tun; do
    (( SECONDS < deadline )) || fail "not Disconnected (or tun0 still up) 30s after Disconnect"
    sleep 2
done
shot 10-disconnected
ok "Disconnected, tun0 gone"

echo
echo "PASS: first launch, 3 failed joins leaving nothing, padded invitation joined and connected through the UI, ping $tunnel_ip, disconnect"
