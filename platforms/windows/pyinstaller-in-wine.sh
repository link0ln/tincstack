#!/bin/sh
# Entrypoint of tincstack/win-exe (Dockerfile.build-exe). Runs PyInstaller as a
# Windows process under Wine over /work (= platforms/windows) and reports the
# artefact. Never run this on the host — it expects the image's Wine prefix.
#
#   SMOKE=1   after the build, start the exe under Wine + Xvfb and print the
#             TINCMGR_SELFTEST_MS report (proves the onefile unpacks, Qt comes
#             up and the bundled tincd.exe is found).
#   SMOKE_MS  how long the smoke window stays up before it quits (default 2000).
set -eu

cd /work

for f in tincd.exe tinc.exe wintun.dll; do
    if [ ! -f "resources/$f" ]; then
        echo "missing resources/$f" >&2
        echo "  tincd.exe/tinc.exe: platforms/windows/build-core-win.sh" >&2
        echo "  wintun.dll:         https://www.wintun.net/ -> bin/amd64/wintun.dll" >&2
        exit 2
    fi
done

rm -rf build dist
xvfb-run -a wine "$WINPY" -m PyInstaller tincmgr.spec --noconfirm \
    --distpath dist --workpath build
wineserver -w

echo
echo "== artefact =="
ls -l dist/tincmgr.exe
file dist/tincmgr.exe
( cd dist && sha256sum tincmgr.exe | tee SHA256SUMS )
objdump -p dist/tincmgr.exe | grep 'DLL Name'

if [ "${SMOKE:-0}" = "1" ]; then
    echo
    echo "== wine smoke test =="
    rm -rf /tmp/smoke
    mkdir -p /tmp/smoke
    cp dist/tincmgr.exe /tmp/smoke/
    cd /tmp/smoke
    TINCMGR_SELFTEST_MS="${SMOKE_MS:-2000}" \
    TINCMGR_SELFTEST_LOG="C:\\selftest.log" \
        xvfb-run -a wine /tmp/smoke/tincmgr.exe
    wineserver -w
    echo "-- selftest log --"
    cat "$WINEPREFIX/drive_c/selftest.log"
fi
