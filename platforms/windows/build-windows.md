# Building the Windows deliverable

The Windows delivery is **two files**: `tincmgr.exe` (GUI + bundled core) and
`tinc.yaml` (the one config; may be empty — the daemon materialises it).

Two halves, built in two places:

| what | where it builds | status in the Linux build lab |
|---|---|---|
| core: `tincd.exe`, `tinc.exe` | Linux, Docker (mingw-w64 cross-build) | **runnable** — `core/Dockerfile.build-win` |
| GUI: `tincmgr.exe` (PyInstaller onefile) | **Windows host** with Python 3.12 | not runnable here (PyInstaller cannot cross-build a Windows exe from Linux) |

## 1. Core binaries (Linux, Docker only)

```sh
platforms/windows/build-core-win.sh
# = docker build -f core/Dockerfile.build-win -t tincstack/core-win:dev core/
#   docker run --rm -v "$PWD/platforms/windows/resources:/out" tincstack/core-win:dev
```

Output: `platforms/windows/resources/{tincd.exe,tinc.exe,SHA256SUMS}` (the
directory is gitignored; binaries never enter git).

Build options (mirrors `core/tincd/PATCHES.md`): `-Dcrypto=gcrypt` (Debian has
`libgcrypt-mingw-w64-dev`; there is no mingw OpenSSL package),
`-Dminiupnpc=disabled`, static link, no zlib/lzo/lz4 (no mingw packages; the
meson wraps would download at build time — kept offline/deterministic; tinc's
`Compression` defaults to 0 anyway), no curses/readline (`tinc top` is not used
by the GUI).

Verified 2026-09-16: `file` → `PE32+ executable (console) x86-64, for MS
Windows`; imports `ADVAPI32 IPHLPAPI KERNEL32 msvcrt USER32 WS2_32` only (no
external DLLs besides `wintun.dll`, which `tincd` loads at runtime); under
`wine64` in a throwaway container `tincd.exe --version` → `tinc version
1.1pre18 (… protocol 17.7) Features: libgcrypt legacy_protocol`.

`wintun.dll` is a signed Microsoft-signed driver bundle, not built here:
download from <https://www.wintun.net/>, copy `bin/amd64/wintun.dll` into
`platforms/windows/resources/`.

## 2. `tincmgr.exe` (Windows host)

Prerequisites on the Windows build box: Python 3.12 (x64), the three files in
`platforms\windows\resources\` from step 1.

```bat
cd platforms\windows
py -3.12 -m venv v
v\Scripts\pip install PySide6-Essentials==6.7.3 pyqtgraph pyyaml pyinstaller pytest
v\Scripts\python -m pytest -q tests            # backend + offscreen GUI tests
v\Scripts\pyinstaller tincmgr.spec --noconfirm
:: -> dist\tincmgr.exe  (onefile, windowed, uac_admin)
```

Then copy `dist\tincmgr.exe` next to a `tinc.yaml` (or an empty file, or
nothing — the GUI creates `networks: {}` and the daemon fills the rest on the
first Start) and run it.

Manual end-to-end check on the Windows box (needs admin, creates a Wintun
adapter): `v\Scripts\python tests\selftest_runtime.py`.

## 3. Running from source on Windows (dev)

```bat
v\Scripts\python main.py
```

The GUI relaunches itself elevated via UAC (needed for Wintun). Binaries are
taken from `resources\`; set `TINCSTACK_BIN_DIR` to point elsewhere.

## Not done in this milestone (no Windows host in the build lab)

- the actual `pyinstaller tincmgr.spec` run and the resulting `tincmgr.exe`;
- `tests\selftest_runtime.py` against the cross-built core (Wintun adapter
  creation, MTU clamp, graceful stop);
- an interactive GUI session on Windows.

Everything else (backend, dialogs, transports editor, atomic save, log
rotation, threading) is covered by `tests/` and was run headless in Docker
(`QT_QPA_PLATFORM=offscreen`).
