#!/usr/bin/env bash
# ui-join.sh <emulator-container> <netname> <invitation> -- drive the app's
# "Join network" dialog on a running emulator, through the UI.
#
# This is deliberately the user's path, not a shell call to the bundled `tinc`
# binary: Configure -> "Join network via invitation URL or QR code" -> the
# invitation goes into the `invitation_url` field, which is exactly what the QR
# scanner writes into (JoinNetworkToolDialogFragment.onActivityResult does
# `joinDialog?.invitationUrl?.setText(contents)`), then the dialog's positive
# button, which calls Tinc.join(netName, url). Scanning a code with the
# emulated camera would only fill the same field.
#
# Every wait has a deadline; an emulator is too slow and too jittery for fixed
# sleeps. Screens are dumped with uiautomator and elements are located by text
# or resource id, never by hardcoded coordinates.
set -euo pipefail

NAME=${1:?usage: ui-join.sh <emulator-container> <netname> <invitation>}
NETNAME=${2:?}
INVITATION=${3:?}
PKG=${PKG:-net.tincstack.android}
UI_TIMEOUT=${UI_TIMEOUT:-90}

adb() { docker exec -i "$NAME" adb "$@"; }

dump() {
    adb shell 'uiautomator dump /sdcard/wsy-ui.xml >/dev/null 2>&1; cat /sdcard/wsy-ui.xml' \
        | tr -d '\r' | grep -o '<node[^>]*>' || true
}

# bounds_of <needle>: centre coordinates of the first node whose XML matches
find_node() {
    local needle=$1 line b x1 y1 x2 y2
    line=$(dump | grep -F -- "$needle" | head -1) || true
    [ -n "$line" ] || return 1
    b=$(grep -o 'bounds="\[[0-9]*,[0-9]*\]\[[0-9]*,[0-9]*\]"' <<<"$line" | head -1)
    [ -n "$b" ] || return 1
    read -r x1 y1 x2 y2 < <(grep -o '[0-9]\+' <<<"$b" | tr '\n' ' ')
    echo "$(( (x1 + x2) / 2 )) $(( (y1 + y2) / 2 ))"
}

wait_node() {
    local needle=$1 deadline=$(( SECONDS + UI_TIMEOUT )) pos
    until pos=$(find_node "$needle"); do
        (( SECONDS < deadline )) || { echo "ui-join: no element matching '$needle' within ${UI_TIMEOUT}s" >&2; return 1; }
        sleep 2
    done
    echo "$pos"
}

tap() { adb shell input tap "$1" "$2" >/dev/null; }

tap_node() {
    local pos
    pos=$(wait_node "$1") || return 1
    # shellcheck disable=SC2086
    tap $pos
}

# the launcher activity, then the toolbar's Configure button: ConfigureActivity
# is not exported, so `am start -n .../ConfigureActivity` is a SecurityException
# for anyone but root -- and tapping it is the user's path anyway.
echo ">>> open the app"
adb shell am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER \
    -n "$PKG/org.pacien.tincapp.activities.start.StartActivity" >/dev/null
wait_node 'content-desc="Configure"' >/dev/null

echo ">>> open Configure"
tap_node 'content-desc="Configure"'
wait_node 'Join network via invitation' >/dev/null

echo ">>> open the Join network dialog"
tap_node 'Join network via invitation'
wait_node 'Invitation URL' >/dev/null

echo ">>> network name: $NETNAME"
tap_node 'tinc network name'
adb shell "input text '$NETNAME'" >/dev/null

echo ">>> invitation into the field the QR scanner fills"
tap_node 'Invitation URL'
adb shell "input text '$INVITATION'" >/dev/null
adb shell input keyevent 111 >/dev/null   # dismiss the IME so nothing is covered

# read the fields back: what the dialog will hand to Tinc.join
if ! dump | grep -F -q "text=\"$INVITATION\""; then
    echo "ui-join: the invitation did not land in the field; screen was:" >&2
    dump | grep -o 'text="[^"]*"' >&2
    exit 1
fi

echo ">>> Join"
tap_node 'resource-id="android:id/button1"'

# the dialog closes and a progress modal shows while `tinc join` runs
deadline=$(( SECONDS + UI_TIMEOUT ))
until adb shell "su 0 test -f /data/data/$PKG/files/networks/$NETNAME/tinc.yaml" >/dev/null 2>&1; do
    (( SECONDS < deadline )) || {
        echo "ui-join: no networks/$NETNAME/tinc.yaml within ${UI_TIMEOUT}s; screen text:" >&2
        dump | grep -o 'text="[^"]*"' >&2
        echo "--- app log ---" >&2
        adb shell "su 0 cat /data/data/$PKG/cache/logs/tincapp.log" 2>/dev/null | tail -40 >&2 || true
        exit 1
    }
    sleep 3
done
echo ">>> joined: networks/$NETNAME/tinc.yaml exists"
