# ui-lib.sh -- uiautomator helpers shared by the emulator UI scripts.
# Source it with NAME (emulator container) set. Every wait has a deadline;
# elements are located by text / resource id / content-desc, never by fixed
# coordinates. (ui-join.sh predates this file and keeps its own copy.)

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
        (( SECONDS < deadline )) || { echo "ui: no element matching '$needle' within ${UI_TIMEOUT}s" >&2; return 1; }
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
