# PyInstaller spec — single-file tincmgr.exe
# Build (on Windows, see build-windows.md):
#   pyinstaller tincmgr.spec --noconfirm
#
# Produces dist\tincmgr.exe : the GUI + bundled tincd.exe / tinc.exe (from the
# core cross-build, core/Dockerfile.build-win) + wintun.dll, in one
# always-elevated (uac_admin) onefile. Drop it next to a tinc.yaml and run.

import os

ROOT = os.path.abspath(SPECPATH)
RES = os.path.join(ROOT, "resources")

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
        "management", "netmtu",
        "gui", "gui.workers", "gui.dialogs", "gui.transports_panel",
        "pyqtgraph", "yaml",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        # trim the big Qt modules we never touch (keeps the onefile smaller)
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
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="tincmgr",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=False,        # GUI app, no console window
    uac_admin=True,       # request elevation (needed to create Wintun adapters)
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
