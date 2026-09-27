#!/usr/bin/env bash
# ui-pick-apps.sh <emulator-container> <all|whitelist|blacklist> <lock-pause yes|no> [package...]
#
# Drive the app's per-network settings through the UI, on the main screen of
# the (only) network: "Apps using the VPN" opens the picker
# (activities/apps/AppPickerActivity) -- pick the split-routing mode, tick
# each package (found through the search field), Save; then set the "Pause
# while the screen is locked" switch on the main screen. The caller reads back
# the tinc.yaml they wrote. Packages are *toggled*: start from a network with
# no selection. whitelist/blacklist without packages means all apps.
set -euo pipefail
NAME=${1:?usage: ui-pick-apps.sh <container> <all|whitelist|blacklist> <yes|no> [package...]}
MODE=${2:?}
LOCK=${3:?}
shift 3
PKG=${PKG:-net.tincstack.android}
# shellcheck source=ui-lib.sh
. "$(dirname "$0")/ui-lib.sh"

case $MODE in
    all) mode_id=apps_mode_all ;;
    whitelist) mode_id=apps_mode_whitelist ;;
    blacklist) mode_id=apps_mode_blacklist ;;
    *) echo "ui-pick-apps: mode is all, whitelist or blacklist" >&2; exit 64 ;;
esac

echo ">>> open the app, Apps using the VPN"
app_open
ui_tap "resource-id=\"$PKG:id/apps_row\""
# the list loads asynchronously; the mode is set from the file once it has
ui_wait "resource-id=\"$PKG:id/apps_mode_all\"" >/dev/null
deadline=$(( SECONDS + UI_TIMEOUT ))
while ui_find "resource-id=\"$PKG:id/apps_progress\"" >/dev/null; do
    (( SECONDS < deadline )) || { echo "ui-pick-apps: the app list did not load" >&2; exit 1; }
    sleep 2
done

ui_tap "resource-id=\"$PKG:id/$mode_id\""
[[ $(ui_attr "resource-id=\"$PKG:id/$mode_id\"" checked) == true ]] || { echo "ui-pick-apps: mode $MODE not selected" >&2; exit 1; }

for p in "$@"; do
    echo ">>> tick $p"
    ui_type "resource-id=\"$PKG:id/apps_search\"" "$p"
    # the row's package line, not the search field that now holds the same text
    ui_tap "text=\"$p\" resource-id=\"$PKG:id/app_package\""
done
echo ">>> Save"
ui_tap "resource-id=\"$PKG:id/apps_picker_save\""
# the picker finishes after writing, back on the main screen
ui_wait "resource-id=\"$PKG:id/apps_row\"" >/dev/null
echo ">>> saved"

want=false; [[ $LOCK == yes ]] && want=true
switch="resource-id=\"$PKG:id/row_switch\""
ui_scroll_to "resource-id=\"$PKG:id/screen_off_row\""
# the only visible switch on the main screen is the screen-off row's
have=$(ui_attr "$switch" checked)
echo ">>> lock-pause switch: $have -> $want"
if [[ $have != "$want" ]]; then
    ui_tap "resource-id=\"$PKG:id/screen_off_row\""
    deadline=$(( SECONDS + 20 ))
    until [[ $(ui_attr "$switch" checked) == "$want" ]]; do
        (( SECONDS < deadline )) || { echo "ui-pick-apps: the switch did not move" >&2; exit 1; }
        sleep 1
    done
fi
echo ">>> done"
