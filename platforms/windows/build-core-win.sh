#!/bin/sh
# Cross-build the tincstack core for Windows and drop tincd.exe / tinc.exe into
# platforms/windows/resources/ (gitignored) for the GUI / PyInstaller to bundle.
# Runs entirely in Docker (nothing installed on the host).
#
#   platforms/windows/build-core-win.sh            # build + copy
#   TAG=mytag platforms/windows/build-core-win.sh  # custom image tag
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
TAG=${TAG:-tincstack/core-win:dev}
OUT="$HERE/resources"
mkdir -p "$OUT"
docker build -f "$ROOT/core/Dockerfile.build-win" -t "$TAG" "$ROOT/core"
docker run --rm -v "$OUT:/out" "$TAG"
echo
echo "core binaries in $OUT:"
ls -l "$OUT"
echo
echo "wintun.dll is NOT built here: download the signed driver bundle from"
echo "https://www.wintun.net/ and copy bin/amd64/wintun.dll into $OUT"
