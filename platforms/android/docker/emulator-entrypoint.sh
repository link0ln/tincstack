#!/bin/bash
# Boot the baked-in AVD headless and keep it in the foreground.
#
# -no-window + swiftshader_indirect: no X server, software GL.
# -no-snapshot: a cold boot every time, so a run never inherits state.
# KVM is required (/dev/kvm must be passed to the container); without it the
# emulator would fall back to a TCG software CPU, which is too slow to be
# useful, so this fails loudly instead.
set -euo pipefail

AVD=${AVD_NAME:-wsy}

if [ ! -w /dev/kvm ]; then
    echo "emulator-entrypoint: /dev/kvm is not available in this container." >&2
    echo "  run with --device /dev/kvm on a host with virtualisation enabled." >&2
    exit 1
fi

adb start-server

exec emulator -avd "$AVD" \
    -no-window -gpu swiftshader_indirect -no-audio -no-boot-anim \
    -no-snapshot -accel on -netdelay none -netspeed full \
    -camera-back none -camera-front none \
    "$@"
