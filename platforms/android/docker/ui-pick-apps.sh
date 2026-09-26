#!/usr/bin/env bash
# ui-pick-apps.sh <emulator-container> <whitelist|blacklist> <lock-pause yes|no> [package...]
#
# Drive the app's per-network settings screen (Configure -> "Choose which apps
# use the VPN", activities/apps/AppPickerActivity) through the UI: pick the
# split-routing mode, tick each package (found through the search field), set
# the "Pause the VPN while the screen is locked" switch, Save. The caller reads
# back the tinc.yaml it wrote. Packages are *toggled*: start from a network
# with no selection. The app must have exactly one network (the picker then
# opens it directly).
set -euo pipefail
NAME=${1:?usage: ui-pick-apps.sh <container> <whitelist|blacklist> <yes|no> [package...]}
MODE=${2:?}
LOCK=${3:?}
shift 3
PKG=${PKG:-net.tincstack.android}
# shellcheck source=ui-lib.sh
. "$(dirname "$0")/ui-lib.sh"

echo ">>> open the app, Configure"
# a fresh task: whatever screen the app was left on (status, a dialog) must not
# stand in front of the network list
adb shell am start --activity-clear-task -a android.intent.action.MAIN -c android.intent.category.LAUNCHER \
    -n "$PKG/org.pacien.tincapp.activities.start.StartActivity" >/dev/null
ui_tap 'content-desc="Configure"'

echo ">>> open the picker"
ui_tap 'Choose which apps use the VPN'
ui_wait "resource-id=\"$PKG:id/apps_search\"" >/dev/null
# the list loads asynchronously; the radio group is set from the file once it has
ui_wait "resource-id=\"$PKG:id/app_package\"" >/dev/null

case $MODE in
    whitelist) ui_tap 'Only the selected apps use the VPN' ;;
    blacklist) ui_tap 'All apps except the selected ones use the VPN' ;;
    *) echo "ui-pick-apps: mode is whitelist or blacklist" >&2; exit 64 ;;
esac

for p in "$@"; do
    echo ">>> tick $p"
    ui_tap "resource-id=\"$PKG:id/apps_search\""
    adb shell input keyevent $(printf '67 %.0s' $(seq 60)) >/dev/null   # clear the field
    adb shell "input text '$p'" >/dev/null
    # the row's package line, not the search field that now holds the same text
    ui_tap "text=\"$p\" resource-id=\"$PKG:id/app_package\""
done
ui_tap "resource-id=\"$PKG:id/apps_search\""
adb shell input keyevent $(printf '67 %.0s' $(seq 60)) >/dev/null
adb shell input keyevent 111 >/dev/null   # hide the IME

want=false; [[ $LOCK == yes ]] && want=true
have=$(ui_attr "resource-id=\"$PKG:id/apps_disconnect_on_screen_off\"" checked)
echo ">>> lock-pause switch: $have -> $want"
[[ $have == "$want" ]] || ui_tap "resource-id=\"$PKG:id/apps_disconnect_on_screen_off\""
have=$(ui_attr "resource-id=\"$PKG:id/apps_disconnect_on_screen_off\"" checked)
[[ $have == "$want" ]] || { echo "ui-pick-apps: the switch did not move" >&2; exit 1; }

echo ">>> Save"
ui_tap "resource-id=\"$PKG:id/apps_picker_save\""
# the picker finishes after writing
deadline=$(( SECONDS + UI_TIMEOUT ))
while ui_find "resource-id=\"$PKG:id/apps_search\"" >/dev/null; do
    (( SECONDS < deadline )) || { echo "ui-pick-apps: the picker did not close after Save" >&2; exit 1; }
    sleep 2
done
echo ">>> saved"
