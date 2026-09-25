#!/bin/sh
# Build platforms/windows/dist/tincmgr.exe from Linux, entirely in Docker
# (a Windows CPython + PyInstaller running under Wine). Nothing on the host.
#
#   platforms/windows/build-exe.sh              # build + smoke-test under Wine
#   SMOKE=0 platforms/windows/build-exe.sh      # build only
#   TAG=mytag platforms/windows/build-exe.sh    # custom image tag
#   TINCMGR_VERSION=v0.4.2 platforms/windows/build-exe.sh   # version in the
#                                               # install manifest (default dev)
#
# Two artefacts (tincmgr.spec): dist/tincmgr.exe, the onefile users run, and
# dist/tincmgr-app/, the onedir tree that onefile installs under Program Files
# for the logon task -- a onefile unpacks into the user's %TEMP%, so it must
# never be what runs elevated without a prompt. The smoke test installs the
# tree and runs the installed copy (pyinstaller-in-wine.sh).
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
    -e TINCMGR_VERSION="${TINCMGR_VERSION:-}" \
    -v "$HERE:/work" "$TAG"
