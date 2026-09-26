# ui-lib.sh -- uiautomator helpers shared by the emulator UI scripts.
# Source it with NAME (emulator container) set. Every wait has a deadline;
# elements are located by text / resource id / content-desc, never by fixed
# coordinates.

UI_TIMEOUT=${UI_TIMEOUT:-90}

adb() { docker exec -i "$NAME" adb "$@"; }

ui_dump() {
    adb shell 'uiautomator dump /sdcard/ww-ui.xml >/dev/null 2>&1; cat /sdcard/ww-ui.xml' \
        | tr -d '\r' | grep -o '<node[^>]*>' || true
}

# ui_find <needle>: centre of the first node whose XML contains needle
ui_find() {
    local needle=$1 line b x1 y1 x2 y2
    line=$(ui_dump | grep -F -- "$needle" | head -1) || true
    [ -n "$line" ] || return 1
    b=$(grep -o 'bounds="\[[0-9]*,[0-9]*\]\[[0-9]*,[0-9]*\]"' <<<"$line" | head -1)
    [ -n "$b" ] || return 1
    read -r x1 y1 x2 y2 < <(grep -o '[0-9]\+' <<<"$b" | tr '\n' ' ')
    echo "$(( (x1 + x2) / 2 )) $(( (y1 + y2) / 2 ))"
}

ui_wait() {
    local needle=$1 deadline=$(( SECONDS + UI_TIMEOUT )) pos
    until pos=$(ui_find "$needle"); do
        (( SECONDS < deadline )) || {
            echo "ui: no element matching '$needle' within ${UI_TIMEOUT}s; screen:" >&2
            ui_dump | grep -oE '(text|content-desc|resource-id)="[^"]+"' | sort -u | head -40 >&2
            return 1
        }
        sleep 2
    done
    echo "$pos"
}

ui_tap() {
    local pos
    pos=$(ui_wait "$1") || return 1
    # shellcheck disable=SC2086
    adb shell input tap $pos >/dev/null
}

# ui_attr <needle> <attr>: attribute value of the first matching node
ui_attr() {
    ui_dump | grep -F -- "$1" | head -1 | grep -o " $2=\"[^\"]*\"" | sed -E 's/.*="(.*)"/\1/'
}

# ui_texts: the visible texts and descriptions, one per line (for failure output)
ui_texts() {
    ui_dump | grep -oE '(text|content-desc)="[^"]+"' | sort -u
}

# ui_type <needle> <text>: focus the field, clear it, type the text. In <text>
# a space is %s (adb `input text`); a trailing newline is typed separately.
ui_type() {
    ui_tap "$1"
    ui_clear_field
    adb shell "input text '$2'" >/dev/null
    ui_hide_ime
}

# delete up to 150 characters on both sides of the cursor (wherever the tap
# put it: MOVE_END only reaches the end of a wrapped line)
ui_clear_field() {
    adb shell input keyevent $(printf '112 %.0s' $(seq 150)) $(printf '67 %.0s' $(seq 150)) >/dev/null
}

# the soft keyboard covers the lower half of a small screen; BACK hides it
# (and only it) while it is shown -- ESC would finish the activity otherwise
ui_hide_ime() {
    if adb shell dumpsys input_method | tr -d '\r' | grep -q 'mInputShown=true'; then
        adb shell input keyevent KEYCODE_BACK >/dev/null
        sleep 1
    fi
}

# the app's networks: directories under files/networks/ with a non-empty tinc.yaml
app_networks() {
    adb shell "run-as ${PKG:-net.tincstack.android} find files/networks -mindepth 2 -maxdepth 2 -name tinc.yaml -size +0" 2>/dev/null \
        | tr -d '\r' | sed -n 's|^files/networks/\([^/]*\)/tinc.yaml$|\1|p' | sort
}

# the one network (fails unless there is exactly one)
app_network() {
    local n
    n=$(app_networks)
    [[ -n $n && $(wc -l <<<"$n") -eq 1 ]] || { echo "ui-lib: expected one network, have: [${n//$'\n'/ }]" >&2; return 1; }
    echo "$n"
}

# the main screen, fresh (whatever screen or dialog was up is gone)
app_open() {
    adb shell am start --activity-clear-task -a android.intent.action.MAIN -c android.intent.category.LAUNCHER \
        -n "${PKG:-net.tincstack.android}/org.pacien.tincapp.activities.main.MainActivity" >/dev/null
    ui_wait 'resource-id="'"${PKG:-net.tincstack.android}"':id/toolbar"' >/dev/null
}

# ui_scroll_to <needle>: swipe the main screen up until the element shows
ui_scroll_to() {
    local i
    for i in 1 2 3 4; do
        ui_find "$1" >/dev/null && return 0
        adb shell input swipe 300 1000 300 400 300 >/dev/null
        sleep 1
    done
    ui_find "$1" >/dev/null
}
