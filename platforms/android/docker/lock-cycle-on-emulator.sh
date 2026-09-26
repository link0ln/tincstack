#!/usr/bin/env bash
# lock-cycle-on-emulator.sh -- PLAN.md M8 proof for DisconnectOnScreenOff:
# the VPN session survives a locked screen with tincd stopped, and tincd comes
# back on unlock and carries traffic again.
#
#   1. join-on-emulator.sh (KEEP=1) brings up the inviter, the emulator, the
#      joined network, the tunnel (TRANSPORT=https|quic as there);
#   2. the option is switched on through the app's own settings screen
#      (ui-pick-apps.sh), then the network is reconnected (the option is read
#      at connect);
#   3. CYCLES times: lock (KEYCODE_SLEEP) -> within STOP_WAIT s tincd is gone
#      while tun0 and the VPN stay (a ping into the tunnel is dropped, not
#      answered) -> stay locked LOCKED_WAIT s (>= 90: the old app's service
#      was stopped by then) with the app process (same pid) and the foreground
#      service alive -> unlock (KEYCODE_WAKEUP + wm dismiss-keyguard) -> tincd
#      back and the inviter answers a ping through the tunnel within
#      RESUME_WAIT s;
#   4. SECURE=1 (default): the same with a PIN keyguard -- SCREEN_ON alone
#      (bouncer still up) must not resume, the PIN unlock must;
#   5. negative: an explicit disconnect, then a lock/unlock cycle -> stays
#      disconnected (no tincd, no tun0).
#
# Tunables: everything join-on-emulator.sh takes (LAB, SUBNET, INVITER_IP,
# TRANSPORT, APK, WAIT...), CYCLES (3), LOCKED_WAIT (95), STOP_WAIT (20),
# RESUME_WAIT (30), SECURE (1), PIN (1234), KEEP (0).
#
# What the emulator cannot show: real Doze/app-standby buckets under a long
# unplugged idle (`dumpsys deviceidle force-idle` is not the same thing), OEM
# task killers (MIUI, EMUI, ...), a real radio and its wake-ups.
set -euo pipefail
cd "$(dirname "$0")"

export LAB=${LAB:-ww-d2}
export SUBNET=${SUBNET:-10.44.78.0/24}
export INVITER_IP=${INVITER_IP:-10.44.78.10}
export NETNAME=${NETNAME:-phonenet}
export NAME=${NAME:-$LAB-emulator}
PKG=net.tincstack.android
SVC=$PKG/org.pacien.tincapp.service.TincVpnService
CYCLES=${CYCLES:-3}
LOCKED_WAIT=${LOCKED_WAIT:-95}
STOP_WAIT=${STOP_WAIT:-20}
RESUME_WAIT=${RESUME_WAIT:-30}
SECURE=${SECURE:-1}
PIN=${PIN:-1234}
INVITER=$LAB-a-node-1

step() { printf '\n== [%(%H:%M:%S)T] %s\n' -1 "$*"; }
note() { printf '   [%(%H:%M:%S)T] %s\n' -1 "$*"; }
fail() { echo "FAIL: $*" >&2; diagnostics >&2; exit 1; }
adb() { docker exec -i "$NAME" adb "$@"; }

tincd_pid() { adb shell 'pidof libtincd.so' 2>/dev/null | tr -d '\r' || true; }
app_pid() { adb shell "pidof $PKG" 2>/dev/null | tr -d '\r' || true; }
has_tun() { adb shell 'su 0 ip -br link show tun0' >/dev/null 2>&1; }
fgs_line() { adb shell "dumpsys activity services $SVC" | tr -d '\r' | grep -oE 'isForeground=[a-z]+ foregroundId=[0-9]+ types=[^ ]+|isForeground=[a-z]+[^ ]*' | head -1 || true; }
service_up() { adb shell "dumpsys activity services $SVC" | tr -d '\r' | grep -q 'ServiceRecord'; }
screen() { adb shell 'dumpsys power' | tr -d '\r' | grep -oE 'mWakefulness=[A-Za-z]+' | head -1; }
keyguard() { adb shell 'dumpsys window' | tr -d '\r' | grep -oE 'mKeyguardShowing=[a-z]+|isKeyguardShowing=[a-z]+|KeyguardShowing=[a-z]+' | head -1 || true; }
ping_pool() { adb shell "ping -c1 -W2 $pool_a" >/dev/null 2>&1; }

diagnostics() {
    echo "--- diagnostics"
    echo "tincd: $(tincd_pid)  app: $(app_pid)  $(screen) $(keyguard)"
    adb shell "dumpsys activity services $SVC" | tr -d '\r' | head -20 || true
    adb shell "su 0 tail -n 60 /data/data/$PKG/cache/logs/tincapp.log" 2>/dev/null | tr -d '\r' || true
    adb shell 'logcat -d -t 400' 2>/dev/null | tr -d '\r' | grep -E 'tincapp|TincVpnService|ActivityManager.*tincstack|Vpn' | tail -40 || true
}

cleanup() {
    [[ ${KEEP:-0} == 1 ]] && { echo "KEEP=1: lab left up"; return; }
    step "cleanup"
    docker rm -f "$INVITER" "$NAME" >/dev/null 2>&1 || true
    docker volume rm "$LAB-a-data" >/dev/null 2>&1 || true
    docker network rm "$LAB-lab" >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_until() { # wait_until <seconds> <description> <command...>: seconds taken, or fail
    local limit=$1 what=$2 t0=$SECONDS; shift 2
    until "$@"; do
        (( SECONDS - t0 < limit )) || fail "$what not within ${limit}s"
        sleep 1
    done
    echo $(( SECONDS - t0 ))
}
no_tincd() { [ -z "$(tincd_pid)" ]; }
has_tincd() { [ -n "$(tincd_pid)" ]; }
no_tun() { ! has_tun; }

connect() { adb shell am start -a "$PKG.intent.action.CONNECT" -d "tinc:$NETNAME" >/dev/null; }
disconnect() { adb shell am start -a "$PKG.intent.action.DISCONNECT" >/dev/null; }

lock() { adb shell input keyevent KEYCODE_SLEEP; }
unlock() {
    adb shell input keyevent KEYCODE_WAKEUP
    adb shell wm dismiss-keyguard
    if [[ ${pin_set:-0} == 1 ]]; then
        sleep 1
        adb shell input text "$PIN"
        adb shell input keyevent KEYCODE_ENTER
    fi
}

# ---------------------------------------------------------------------------
step "lab: join + connect (join-on-emulator.sh, KEEP=1)"
KEEP=1 ./join-on-emulator.sh

pool_a=$(docker exec "$INVITER" tincstack-cli get node_a.Subnet | head -n1 | tr -d '\r')
pool_a=${pool_a%%/*}
note "inviter pool address: $pool_a"

adb shell "pm grant $PKG android.permission.POST_NOTIFICATIONS" || true
adb shell 'settings put system screen_off_timeout 1800000' # no spontaneous screen-off mid-test
adb shell 'svc power stayon false' || true

step "switch DisconnectOnScreenOff on through the settings screen, reconnect"
disconnect
wait_until 30 "disconnect (tun0 gone)" no_tun >/dev/null
./ui-pick-apps.sh "$NAME" blacklist yes
yaml=$(adb shell "su 0 cat /data/data/$PKG/files/networks/$NETNAME/tinc.yaml" | tr -d '\r')
grep -E '^ +DisconnectOnScreenOff: yes$' <<<"$yaml" || fail "the settings screen did not write DisconnectOnScreenOff: yes"
connect
wait_until "$RESUME_WAIT" "tun0 after connect" has_tun >/dev/null
t=$(wait_until 60 "first ping through the tunnel" ping_pool)
note "connected, ping answered after ${t}s; service: $(fgs_line)"
fgs_line | grep -q 'isForeground=true' || fail "the VPN service is not in the foreground"
adb shell input keyevent KEYCODE_HOME

cycle() { # cycle <n> <label>
    local n=$1 label=$2 app0 app1 t
    step "cycle $n ($label): lock"
    app0=$(app_pid)
    note "before: tincd=$(tincd_pid) app=$app0 $(screen)"
    lock
    t=$(wait_until "$STOP_WAIT" "tincd stopped after lock" no_tincd)
    note "tincd gone ${t}s after lock; $(screen) $(keyguard)"
    has_tun || fail "tun0 went away while locked (the VPN must stay established)"
    ping_pool && fail "a ping through the tunnel was answered while tincd is stopped"
    note "tun0 kept, traffic into it dropped (ping unanswered)"

    local end=$(( SECONDS + LOCKED_WAIT ))
    while (( SECONDS < end )); do
        sleep 15
        [ -n "$(app_pid)" ] || fail "the app process died while locked"
        has_tincd && fail "tincd came back while locked"
        note "locked $(( LOCKED_WAIT - (end - SECONDS) ))s: app=$(app_pid) tun0=$(has_tun && echo up || echo DOWN) $(fgs_line)"
    done
    app1=$(app_pid)
    [[ $app1 == "$app0" ]] || fail "the app process was restarted while locked ($app0 -> $app1)"
    service_up || fail "the VPN service was stopped while locked"
    fgs_line | grep -q 'isForeground=true' || fail "the service left the foreground while locked"
    has_tun || fail "tun0 went away while locked"

    if [[ ${pin_set:-0} == 1 ]]; then
        step "cycle $n: screen on, PIN bouncer still up -> must stay suspended"
        adb shell input keyevent KEYCODE_WAKEUP
        sleep 4   # the lock screen turns itself off again after ~10 s
        note "$(screen) $(keyguard) tincd=[$(tincd_pid)]"
        has_tincd && fail "tincd resumed on SCREEN_ON with the secure keyguard still locked"
        step "cycle $n: PIN unlock"
        unlock
    else
        step "cycle $n: unlock"
        unlock
    fi
    t=$(wait_until "$RESUME_WAIT" "tincd back after unlock" has_tincd)
    note "tincd back ${t}s after unlock (pid $(tincd_pid))"
    t=$(wait_until "$RESUME_WAIT" "ping through the tunnel after unlock" ping_pool)
    note "inviter answers through the tunnel ${t}s after tincd came back"
    [[ $(app_pid) == "$app0" ]] || fail "the app process changed across the cycle"
    # the fd the daemon runs on: a dup of the service's kept tun fd
    note "tun fds: app $(adb shell "su 0 ls -l /proc/$app0/fd" | tr -d '\r' | grep -c /dev/tun), tincd $(adb shell "su 0 ls -l /proc/$(tincd_pid)/fd" | tr -d '\r' | grep -c /dev/tun)"
}

for i in $(seq 1 "$CYCLES"); do cycle "$i" "swipe keyguard"; done

# Disconnect from the notification's action while the screen is locked, then
# unlock: the session must stay down. Meaningful with a showing keyguard (the
# PIN run); without one, SCREEN_ON already resumes the session before the tap.
notification_disconnect() {
    step "negative 2: disconnect from the notification while locked -> stays disconnected after unlock"
    has_tun || { connect; wait_until "$RESUME_WAIT" "tun0 after connect" has_tun >/dev/null; }
    wait_until 60 "ping before the lock" ping_pool >/dev/null
    adb shell input keyevent KEYCODE_HOME
    lock
    wait_until "$STOP_WAIT" "tincd stopped after lock" no_tincd >/dev/null
    adb shell input keyevent KEYCODE_WAKEUP
    sleep 3
    note "screen on: $(screen) $(keyguard) tincd=[$(tincd_pid)]"
    adb shell cmd statusbar expand-notifications >/dev/null 2>&1 || true
    # shellcheck source=ui-lib.sh
    . ./ui-lib.sh
    if UI_TIMEOUT=20 ui_tap 'text="Disconnect"' || { adb shell input swipe 540 900 540 1600 >/dev/null; UI_TIMEOUT=20 ui_tap 'text="Disconnect"'; }; then
        local t0=$SECONDS
        while has_tun && (( SECONDS - t0 < 20 )); do sleep 1; done
        if no_tun; then
            note "notification Disconnect tapped: tun0 gone $(( SECONDS - t0 ))s later, before any unlock; $(keyguard)"
        else
            note "notification Disconnect tapped: the lock screen held the action back (tun0 still up); unlocking lets it run"
        fi
        unlock
        wait_until 30 "tun0 gone after the notification's Disconnect" no_tun >/dev/null
        sleep 30
        has_tincd && fail "tincd came back after a disconnect made while locked"
        has_tun && fail "tun0 came back after a disconnect made while locked"
        note "stays disconnected after unlock"
    else
        note "the notification's Disconnect action was not reachable: step not proven here (unit test: userDisconnectWhileLockedIsFinal)"
        adb shell cmd statusbar collapse >/dev/null 2>&1 || true
        unlock
        disconnect
        wait_until 30 "tun0 gone after disconnect" no_tun >/dev/null
    fi
}

step "transport after the cycles"
docker exec "$INVITER" tincstack-cli dump connections | tr -d '\r' | grep '^phone ' || true

step "negative: explicit disconnect, then lock/unlock -> stays disconnected"
disconnect
wait_until 30 "tun0 gone after disconnect" no_tun >/dev/null
wait_until 30 "tincd gone after disconnect" no_tincd >/dev/null
lock
sleep 20
unlock
sleep 30
has_tincd && fail "tincd came back after an explicit disconnect"
has_tun && fail "tun0 came back after an explicit disconnect"
note "stays disconnected: no tincd, no tun0; service: $(service_up && echo running || echo stopped)"

if [[ $SECURE == 1 ]]; then
    step "secure keyguard: PIN $PIN"
    if adb shell "locksettings set-pin $PIN" | tr -d '\r'; then
        pin_set=1
        connect
        wait_until "$RESUME_WAIT" "tun0 after connect" has_tun >/dev/null
        wait_until 60 "ping after connect" ping_pool >/dev/null
        adb shell input keyevent KEYCODE_HOME
        cycle "$(( CYCLES + 1 ))" "PIN keyguard"
        notification_disconnect
        adb shell "locksettings clear --old $PIN" | tr -d '\r' || true
        pin_set=0
    else
        note "locksettings set-pin refused on this image: secure-keyguard run skipped"
    fi
else
    notification_disconnect
fi

step "service log excerpt"
adb shell "su 0 cat /data/data/$PKG/cache/logs/tincapp.log" | tr -d '\r' \
    | grep -E 'Session|suspended|resumed|foreground|Ending|revoked|Intent received' | tail -40 || true

echo
echo "PASS: DisconnectOnScreenOff: $CYCLES lock/unlock cycles${pin_set:+}${TRANSPORT:+ over $TRANSPORT}, locked ${LOCKED_WAIT}s each, tincd stopped while locked and back on unlock; explicit disconnect is final"
