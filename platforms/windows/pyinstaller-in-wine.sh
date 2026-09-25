#!/bin/sh
# Entrypoint of tincstack/win-exe (Dockerfile.build-exe). Runs PyInstaller as a
# Windows process under Wine over /work (= platforms/windows) and reports the
# artefacts. Never run this on the host — it expects the image's Wine prefix.
#
#   dist/tincmgr.exe     the onefile users download (tincmgr.spec)
#   dist/tincmgr-app/    the onedir tree the onefile installs under Program
#                        Files for the logon task (listed for the record)
#
#   SMOKE=1   after the build, under Wine + Xvfb (TINCMGR_SELFTEST_MS):
#             1. run the onefile, which installs its onedir tree into
#                C:\Program Files\tincmgr\app (TINCMGR_SELFTEST_INSTALL=1, the
#                run-at-startup code path) and writes the config there;
#             2. run the INSTALLED tincmgr.exe and check that it runs from
#                Program Files, loads its Python from app\_internal and
#                creates nothing named _MEI* in %TEMP% (nothing unpacked);
#             3. read the config's DACL (tools/file_sddl.py): no Everyone ACE.
#   SMOKE_MS  how long each smoke window stays up before it quits (default 2000).
#   TINCMGR_VERSION  recorded in the install manifest (default "dev").
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
echo "== artefacts =="
ls -l dist/tincmgr.exe
file dist/tincmgr.exe
( cd dist && sha256sum tincmgr.exe | tee SHA256SUMS )
objdump -p dist/tincmgr.exe | grep 'DLL Name'
echo "onedir tree: $(find dist/tincmgr-app -type f | wc -l) files, $(du -sh dist/tincmgr-app | cut -f1)"
ls -l dist/tincmgr-app/tincmgr.exe

if [ "${SMOKE:-0}" = "1" ]; then
    fail=0
    check() { # <description> <command...>
        d=$1; shift
        if "$@"; then printf "PASS %s\n" "$d"; else printf "FAIL %s\n" "$d"; fail=1; fi
    }
    pf="$WINEPREFIX/drive_c/Program Files/tincmgr"
    temps() { find "$WINEPREFIX/drive_c/users" -maxdepth 6 -name '_MEI*' 2>/dev/null | sort; }

    echo
    echo "== wine smoke 1: the onefile, installing its onedir tree =="
    rm -rf /tmp/smoke "$pf"
    mkdir -p /tmp/smoke
    cp dist/tincmgr.exe /tmp/smoke/
    ( cd /tmp/smoke && TINCMGR_SELFTEST_MS="${SMOKE_MS:-2000}" TINCMGR_SELFTEST_INSTALL=1 \
        TINCMGR_SELFTEST_LOG="C:\\selftest.log" xvfb-run -a wine /tmp/smoke/tincmgr.exe )
    wineserver -w
    echo "-- selftest log --"
    tr -d '\r' < "$WINEPREFIX/drive_c/selftest.log" | tee /tmp/smoke/one.log
    check "the onefile ran from its unpack dir" grep -q "^meipass=.*_MEI" /tmp/smoke/one.log
    check "the onefile installed C:\\Program Files\\tincmgr\\app\\tincmgr.exe" \
        grep -qx 'installed=C:\\Program Files\\tincmgr\\app\\tincmgr.exe' /tmp/smoke/one.log
    check "the install recorded version ${TINCMGR_VERSION:-dev}" \
        grep -qx "installed_version=${TINCMGR_VERSION:-dev}" /tmp/smoke/one.log
    check "the installed tree holds the Python DLL" test -f "$pf/app/_internal/python312.dll"
    check "the installed tree holds tincd.exe" test -f "$pf/app/_internal/tincd.exe"
    check "no staging or old tree left behind" test ! -e "$pf/app.new" -a ! -e "$pf/app.old"

    echo
    echo "== wine smoke 2: the installed onedir copy =="
    temps > /tmp/smoke/mei-before
    rm -f "$WINEPREFIX/drive_c/selftest.log"
    ( cd /tmp && TINCMGR_SELFTEST_MS="${SMOKE_MS:-2000}" TINCMGR_SELFTEST_LOG="C:\\selftest.log" \
        xvfb-run -a wine "C:\\Program Files\\tincmgr\\app\\tincmgr.exe" )
    wineserver -w
    temps > /tmp/smoke/mei-after
    echo "-- selftest log --"
    tr -d '\r' < "$WINEPREFIX/drive_c/selftest.log" | tee /tmp/smoke/dir.log
    check "the installed copy runs from Program Files" \
        grep -qx 'exe=C:\\Program Files\\tincmgr\\app\\tincmgr.exe' /tmp/smoke/dir.log
    check "it loads its Python from app\\_internal, not %TEMP%" \
        grep -qx 'meipass=C:\\Program Files\\tincmgr\\app\\_internal' /tmp/smoke/dir.log
    check "it saw no _MEI* dir in %TEMP% while running" grep -qx 'temp_mei=\[\]' /tmp/smoke/dir.log
    check "no _MEI* dir appeared in %TEMP% across its run" cmp -s /tmp/smoke/mei-before /tmp/smoke/mei-after
    check "it cannot install anything itself (no manifest in the onedir)" \
        grep -qx 'bundle_version=None' /tmp/smoke/dir.log
    check "it uses the Program Files config" \
        grep -qx 'config=C:\\Program Files\\tincmgr\\tinc.yaml' /tmp/smoke/dir.log
    check "it finds the core in its own tree" grep -qx 'tincd_exists=True' /tmp/smoke/dir.log

    echo
    echo "== wine smoke 3: the config's DACL =="
    wine "$WINPY" /work/tools/file_sddl.py "C:\\Program Files\\tincmgr\\tinc.yaml" \
        | tr -d '\r' | tee /tmp/smoke/sddl.txt
    wineserver -w
    check "the config has no Everyone (WD) or Users (BU) ACE" \
        sh -c '! grep -qE ";;;(WD|BU|AU)\)" /tmp/smoke/sddl.txt && grep -q "D:" /tmp/smoke/sddl.txt'
    if [ "$fail" -ne 0 ]; then
        echo "wine smoke: FAILURES above" >&2
        exit 1
    fi
    echo "wine smoke: all checks passed"
fi
