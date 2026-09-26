#!/usr/bin/env bash
# ui-join.sh <emulator-container> <invitation> -- join a network through the
# app's UI on a running emulator; prints the new network's name (its
# directory under files/networks/) as the last line.
#
# The user's path: open the app; with no network yet the main screen *is* the
# join form, otherwise the toolbar's "Add network" opens it. The invitation
# goes into the field that paste and the QR scanner fill, "Join and connect"
# is tapped. The network is named by the app (from the invitation), not typed.
# On success the app connects right away: grant the VpnService consent
# (appops ACTIVATE_VPN) and POST_NOTIFICATIONS beforehand, or answer the two
# system dialogs yourself.
#
# Fails, with the message the app showed, if the join fails.
set -euo pipefail
NAME=${1:?usage: ui-join.sh <emulator-container> <invitation>}
INVITATION=${2:?}
PKG=${PKG:-net.tincstack.android}
# shellcheck source=ui-lib.sh
. "$(dirname "$0")/ui-lib.sh"
UI_TIMEOUT=${UI_TIMEOUT:-90}

before=$(app_networks)

echo ">>> open the app" >&2
app_open
if ! ui_find "resource-id=\"$PKG:id/join_button\"" >/dev/null; then
    echo ">>> Add network" >&2
    ui_tap "resource-id=\"$PKG:id/menu_add_network\""
fi
ui_wait "resource-id=\"$PKG:id/invitation_input\"" >/dev/null

echo ">>> invitation into the field (the one paste and the QR scanner fill)" >&2
ui_type "resource-id=\"$PKG:id/invitation_input\"" "$INVITATION"
[[ $(ui_attr "resource-id=\"$PKG:id/join_button\"" enabled) == true ]] || {
    echo "ui-join: the app did not accept the invitation; screen:" >&2
    ui_texts >&2
    exit 1
}

echo ">>> Join and connect" >&2
ui_tap "resource-id=\"$PKG:id/join_button\""

deadline=$(( SECONDS + UI_TIMEOUT ))
while :; do
    now=$(app_networks)
    new=$(comm -13 <(sort <<<"$before") <(sort <<<"$now") | head -1)
    [ -n "$new" ] && break
    if ui_find "resource-id=\"$PKG:id/join_error_message\"" >/dev/null; then
        echo "ui-join: the join failed: $(ui_attr "resource-id=\"$PKG:id/join_error_message\"" text)" >&2
        exit 1
    fi
    (( SECONDS < deadline )) || {
        echo "ui-join: no new network within ${UI_TIMEOUT}s; screen:" >&2
        ui_texts >&2
        adb shell "run-as $PKG tail -n 30 cache/logs/tincapp.log" 2>/dev/null | tr -d '\r' >&2 || true
        exit 1
    }
    sleep 2
done
echo ">>> joined: networks/$new" >&2
echo "$new"
