# PyInstaller spec -- tincmgr, two artefacts from one analysis
# Build (on Windows, see build-windows.md; or build-exe.sh under Wine):
#   pyinstaller tincmgr.spec --noconfirm
#
#   dist\tincmgr-app\     the ONEDIR tree: tincmgr.exe + _internal\ (Python,
#                         Qt, tincd.exe, tinc.exe, wintun.dll). This is what
#                         runs elevated from %ProgramFiles%\tincmgr\app at
#                         every logon: it loads everything from where it lies
#                         and unpacks nothing.
#   dist\tincmgr.exe      the ONEFILE the user downloads and runs (uac_admin).
#                         It unpacks into %TEMP%\_MEIxxxx like any onefile, so
#                         it is never what the logon task starts: turning
#                         run-at-startup on installs the onedir tree, copied
#                         out of the unpack dir and checked file by file
#                         against a SHA-256 manifest compiled into this exe's
#                         archive (module `tincmgr_bundle`, see
#                         backend/paths.py bundle(), management.install_self()).
#
# The onefile carries the onedir's own tincmgr.exe (a few MB: bootloader +
# archive) under _app\; every _internal\ file of the onedir is a file the
# onefile unpacks anyway, so the tree costs no second copy of Qt. The build
# fails if that stops being true (a file of the tree the onefile does not
# carry, or carries with different bytes).
#
# TINCMGR_VERSION (environment, e.g. v0.4.2 from the release tag) is recorded
# in the manifest; an automatic refresh never replaces a newer install with
# an older build. Unset, the build is "dev", which a release replaces and
# which never replaces a release on its own.

import hashlib
import os

ROOT = os.path.abspath(SPECPATH)
RES = os.path.join(ROOT, "resources")
VERSION = os.environ.get("TINCMGR_VERSION", "").strip() or "dev"
APP = "tincmgr-app"

for _name in ("tincd.exe", "tinc.exe", "wintun.dll"):
    if not os.path.isfile(os.path.join(RES, _name)):
        raise SystemExit(f"missing {RES}\\{_name}: run build-core-win.sh (tincd/tinc) "
                         f"and copy wintun.dll from https://www.wintun.net/")

a = Analysis(
    [os.path.join(ROOT, "main.py")],
    pathex=[ROOT, os.path.join(ROOT, "backend")],
    binaries=[
        (os.path.join(RES, "tincd.exe"), "."),
        (os.path.join(RES, "tinc.exe"), "."),
        (os.path.join(RES, "wintun.dll"), "."),
    ],
    datas=[],
    hiddenimports=[
        "paths", "yaml_config", "runtime", "tinc_control", "transports",
        "management", "netmtu", "routes",
        "gui", "gui.workers", "gui.dialogs", "gui.transports_panel", "gui.cert_dialog",
        "pyqtgraph", "yaml",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        # trim the big Qt modules we never touch (keeps the bundle smaller)
        "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets",
        "PySide6.QtWebEngineQuick", "PySide6.QtQml", "PySide6.QtQuick",
        "PySide6.QtQuick3D", "PySide6.Qt3DCore", "PySide6.Qt3DRender",
        "PySide6.QtMultimedia", "PySide6.QtMultimediaWidgets",
        "PySide6.QtCharts", "PySide6.QtDataVisualization", "PySide6.QtPdf",
        "PySide6.QtPositioning", "PySide6.QtBluetooth", "PySide6.QtSql",
        "PySide6.QtTest", "PySide6.QtDesigner", "tkinter",
        # pyqtgraph optionally imports cupy/scipy/matplotlib; never used here.
        # cupyx is a SEPARATE top-level package — must be excluded too.
        "cupy", "cupyx", "cupy_backends", "nvidia", "fastrlock",
        "scipy", "matplotlib",
        # generated below for the onefile only; the onedir must not install
        "tincmgr_bundle",
    ],
    noarchive=False,
)

_EXE_OPTS = dict(
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,        # GUI app, no console window
    uac_admin=True,       # request elevation (needed to create Wintun adapters)
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

# ---- 1. the onedir tree (what Program Files runs) ----------------------------
pyz = PYZ(a.pure)
exe_dir = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="tincmgr",
    contents_directory="_internal",
    **_EXE_OPTS,
)
coll = COLLECT(exe_dir, a.binaries, a.datas, strip=False, upx=False, name=APP)

# ---- 2. the manifest of that tree ----------------------------------------------
app_dir = os.path.join(DISTPATH, APP)


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


# What the onefile unpacks into _MEIPASS, by destination name.
_carried = {os.path.normcase(dest): src for dest, src, _typ in a.binaries + a.datas}
files = {}
for dirpath, _dirs, names in os.walk(app_dir):
    for n in names:
        full = os.path.join(dirpath, n)
        rel = os.path.relpath(full, app_dir).replace(os.sep, "/")
        sha = _sha256(full)
        if rel == "tincmgr.exe":
            src_rel = "_app/tincmgr.exe"
        elif rel.startswith("_internal/"):
            src_rel = rel[len("_internal/"):]
            carried = _carried.get(os.path.normcase(src_rel.replace("/", os.sep)))
            if carried is None:
                raise SystemExit(f"onedir file {rel} is not carried by the onefile")
            if _sha256(carried) != sha:
                raise SystemExit(f"onedir file {rel} differs from the onefile's {carried}")
        else:
            raise SystemExit(f"unexpected file in the onedir tree: {rel}")
        files[rel] = (sha, src_rel)

gen = os.path.join(workpath, "gen")
os.makedirs(gen, exist_ok=True)
bundle_py = os.path.join(gen, "tincmgr_bundle.py")
with open(bundle_py, "w", encoding="utf-8") as f:
    f.write("# Generated by tincmgr.spec: the onedir tree this onefile installs.\n")
    f.write(f"VERSION = {VERSION!r}\n")
    f.write("FILES = {\n")
    for rel in sorted(files):
        f.write(f"    {rel!r}: {files[rel]!r},\n")
    f.write("}\n")
print(f"tincmgr.spec: manifest of {len(files)} files, version {VERSION}, {bundle_py}")

# ---- 3. the onefile (what the user downloads) ---------------------------------
pyz_one = PYZ(a.pure + [("tincmgr_bundle", bundle_py, "PYMODULE")])
exe_one = EXE(
    pyz_one,
    a.scripts,
    a.binaries,
    a.datas + [(os.path.join("_app", "tincmgr.exe"), os.path.join(app_dir, "tincmgr.exe"), "DATA")],
    [],
    name="tincmgr",
    runtime_tmpdir=None,
    **_EXE_OPTS,
)
