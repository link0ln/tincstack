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
    local want=${2//%s/ } have try
    for try in 1 2; do
        ui_tap "$1" || return 1
        # the keyboard comes up a moment after the tap (seconds, the first
        # time for a new window): wait for it, or it appears after
        # ui_hide_ime looked and covers the buttons below the field
        ui_wait_ime 5 || true
        ui_clear_field
        adb shell "input text '$2'" >/dev/null
        ui_hide_ime
        have=$(ui_attr "$1" text)
        [[ $have == "$want" ]] && return 0
        echo "ui_type: the field holds '$have', not '$want' (try $try)" >&2
    done
    return 1
}

# delete up to 150 characters on both sides of the cursor (wherever the tap
# put it: MOVE_END only reaches the end of a wrapped line)
ui_clear_field() {
    adb shell input keyevent $(printf '112 %.0s' $(seq 150)) $(printf '67 %.0s' $(seq 150)) >/dev/null
}

# the soft keyboard covers the lower half of a small screen; BACK hides it
# (and only it) while it is shown -- ESC would finish the activity otherwise
ui_ime_shown() { adb shell dumpsys input_method | tr -d '\r' | grep -q 'mInputShown=true'; }
ui_wait_ime() {
    local deadline=$(( SECONDS + ${1:-5} ))
    until ui_ime_shown; do (( SECONDS < deadline )) || return 1; sleep 0.5; done
}
ui_hide_ime() {
    local try deadline
    for try in 1 2 3; do
        ui_ime_shown || break
        adb shell input keyevent KEYCODE_BACK >/dev/null
        deadline=$(( SECONDS + 5 ))
        while ui_ime_shown && (( SECONDS < deadline )); do sleep 0.5; done
    done
    # the screen re-lays out as the keyboard slides away: bounds read during
    # that animation send the next tap into the keyboard (whose clipboard
    # chip then pastes into the field)
    ui_settle
}

# ui_settle: wait (up to 5 s) until two dumps in a row agree, i.e. nothing
# on the screen is still moving (keyboard animation, a card that appears
# once the window has focus)
ui_settle() {
    local a b deadline=$(( SECONDS + 5 ))
    a=$(ui_dump)
    while (( SECONDS < deadline )); do
        sleep 0.5
        b=$(ui_dump)
        [[ $a == "$b" ]] && return 0
        a=$b
    done
}

# the app's networks: directories under files/networks/ with a non-empty tinc.yaml
# (none, and no failure, before the app has ever run: there is no files/ yet).
# run-as needs a debuggable build; a release APK is read through the
# emulator's root shell instead, so the proofs can run on what ships.
app_networks() {
    local pkg=${PKG:-net.tincstack.android}
    local find="find files/networks -mindepth 2 -maxdepth 2 -name tinc.yaml -size +0"
    { adb shell "run-as $pkg $find" 2>/dev/null \
        || adb shell "su 0 sh -c 'cd /data/data/$pkg && $find'" 2>/dev/null || true; } \
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
    # the join form offers a copied invitation once the window has focus,
    # which moves the field down: let that happen before anyone reads bounds
    ui_settle
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
