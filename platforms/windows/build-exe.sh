#!/bin/sh
# Build platforms/windows/dist/tincmgr.exe from Linux, entirely in Docker
# (a Windows CPython + PyInstaller running under Wine). Nothing on the host.
#
#   platforms/windows/build-exe.sh              # build + smoke-test under Wine
#   SMOKE=0 platforms/windows/build-exe.sh      # build only
#   TAG=mytag platforms/windows/build-exe.sh    # custom image tag
#
# Needs platforms/windows/resources/{tincd.exe,tinc.exe,wintun.dll} first:
#   platforms/windows/build-core-win.sh         # tincd.exe + tinc.exe
#   wintun.dll: https://www.wintun.net/ -> bin/amd64/wintun.dll
#
# The artefact and its SHA256SUMS land in platforms/windows/dist/ — gitignored,
# like resources/. See build-windows.md §2b for what this route does and does
# not prove.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
TAG=${TAG:-tincstack/win-exe:dev}
SMOKE=${SMOKE:-1}

docker build -f "$HERE/Dockerfile.build-exe" -t "$TAG" "$HERE"
docker run --rm -e SMOKE="$SMOKE" -e SMOKE_MS="${SMOKE_MS:-2000}" \
    -v "$HERE:/work" "$TAG"
