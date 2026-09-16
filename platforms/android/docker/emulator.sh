#!/usr/bin/env bash
# emulator.sh -- one command for a headless Android emulator in Docker.
#
# Nothing is installed on the host: the SDK, the system image, the AVD, adb and
# the emulator all live inside the container built from Dockerfile.emulator.
# The only host requirement is /dev/kvm (hardware virtualisation).
#
#   ./emulator.sh up            build the image if needed, boot the AVD, wait
#                               until the framework is up (deadline, not sleep)
#   ./emulator.sh adb <args>    run adb inside the container (adb shell, install…)
#   ./emulator.sh install <apk> copy an APK in and install it
#   ./emulator.sh logs          emulator console output
#   ./emulator.sh status        booted? which AVD?
#   ./emulator.sh down          remove the container
#
# Environment: NAME (container, default wsy-emulator), IMAGE, NET (docker
# network to attach, so the guest can reach lab containers through the
# emulator's user-mode NAT), BOOT_TIMEOUT (seconds, default 600).
set -euo pipefail
cd "$(dirname "$0")"

IMAGE=${IMAGE:-wsy-android-emulator}
NAME=${NAME:-wsy-emulator}
NET=${NET:-}
BOOT_TIMEOUT=${BOOT_TIMEOUT:-600}

die() { echo "emulator.sh: $*" >&2; exit 1; }

build() {
    docker image inspect "$IMAGE" >/dev/null 2>&1 && return 0
    echo ">>> building $IMAGE (Android SDK + system image, one time)"
    docker build -t "$IMAGE" -f Dockerfile.emulator .
}

up() {
    [ -e /dev/kvm ] || die "/dev/kvm is missing: this host cannot run the emulator with hardware acceleration"
    build
    if docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then
        docker start "$NAME" >/dev/null
    else
        docker run -d --name "$NAME" --device /dev/kvm \
            ${NET:+--network "$NET"} "$IMAGE" >/dev/null
    fi
    wait_booted
}

# Poll with a deadline; an emulator boot is minutes, and how many is not fixed.
wait_booted() {
    local deadline=$(( SECONDS + BOOT_TIMEOUT )) prop=""
    echo ">>> waiting for the framework to come up (timeout ${BOOT_TIMEOUT}s)"
    until [ "$prop" = 1 ]; do
        if (( SECONDS >= deadline )); then
            echo "FAIL: emulator did not boot within ${BOOT_TIMEOUT}s; last console output:" >&2
            docker logs --tail 40 "$NAME" >&2 || true
            return 1
        fi
        docker ps --format '{{.Names}}' | grep -qx "$NAME" || {
            echo "FAIL: container $NAME exited; console output:" >&2
            docker logs --tail 40 "$NAME" >&2
            return 1
        }
        prop=$(docker exec "$NAME" adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r\n' || true)
        [ "$prop" = 1 ] || sleep 5
    done
    # the property is set before the package manager is usable
    until docker exec "$NAME" adb shell pm list packages >/dev/null 2>&1; do
        (( SECONDS < deadline )) || { echo "FAIL: package manager never answered" >&2; return 1; }
        sleep 5
    done
    echo ">>> booted: $(docker exec "$NAME" adb shell getprop ro.build.version.release | tr -d '\r') (API $(docker exec "$NAME" adb shell getprop ro.build.version.sdk | tr -d '\r'))"
}

case "${1:-}" in
    build) build ;;
    up) up ;;
    wait) wait_booted ;;
    adb) shift; exec docker exec -i "$NAME" adb "$@" ;;
    install)
        shift; [ $# -eq 1 ] || die "usage: emulator.sh install <apk>"
        docker cp "$1" "$NAME:/tmp/app.apk"
        docker exec "$NAME" adb install -r -t /tmp/app.apk ;;
    logs) docker logs "${2:---tail=50}" "$NAME" ;;
    status)
        docker ps --filter "name=^${NAME}$" --format '{{.Names}}\t{{.Status}}'
        docker exec "$NAME" adb devices 2>/dev/null || true ;;
    down) docker rm -f "$NAME" >/dev/null 2>&1 || true; echo "removed $NAME" ;;
    *) sed -n '2,25p' "$0"; exit 64 ;;
esac
