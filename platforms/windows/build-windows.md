# Building the Windows deliverable

The Windows delivery is **two files**: `tincmgr.exe` (GUI + bundled core) and
`tinc.yaml` (the one config; may be empty — the daemon materialises it).

Two halves, built in two places:

| what | where it builds | status in the Linux build lab |
|---|---|---|
| core: `tincd.exe`, `tinc.exe` | Linux, Docker (mingw-w64 cross-build) | **runnable** — `core/Dockerfile.build-win` |
| GUI: `tincmgr.exe` (PyInstaller onefile) | a Windows host (§2), **or** Linux + Docker + Wine (§2b) | **runnable** — `platforms/windows/build-exe.sh` |

PyInstaller genuinely cannot cross-build: it copies a bootloader and the host
interpreter's own DLLs into the bundle. §2b does not cross-build either — it
runs a real Windows CPython and a real PyInstaller, as Windows processes, on
Wine. That produces a correct PE32+ onefile from a Linux CI box; what it cannot
do is exercise the parts of the app that need a real Windows kernel (§2b limits).

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
`platforms/windows/resources/`. Verify what you got before bundling it —
`strings -el wintun.dll | grep -A1 -E 'CompanyName|ProductVersion'` must say
`WireGuard LLC` / the version you meant (0.14.1 amd64 is 427 552 bytes,
SHA-256 `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`).

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

## 2b. `tincmgr.exe` from Linux, in Docker, under Wine

Same PyInstaller, same spec, no Windows box: the image runs the official
python.org Windows CPython under WineHQ, so PyInstaller executes as a Windows
process and takes its `win_amd64` bootloader out of its own wheel.

```sh
platforms/windows/build-core-win.sh          # §1 first: tincd.exe + tinc.exe
# + drop wintun.dll (§1) into platforms/windows/resources/
platforms/windows/build-exe.sh               # build + smoke-test under Wine
# = docker build -f platforms/windows/Dockerfile.build-exe \
#       -t tincstack/win-exe:dev platforms/windows/
#   docker run --rm -e SMOKE=1 -v "$PWD/platforms/windows:/work" tincstack/win-exe:dev
```

Output: `platforms/windows/dist/{tincmgr.exe,SHA256SUMS}` — gitignored, like
`resources/`; the exe never enters git. Nothing is installed on the host.

Everything is pinned in `Dockerfile.build-exe`: `winehq-stable=11.0.0.0~bookworm-1`,
CPython 3.12.7 (installer SHA-256 checked), and every wheel including the
transitive ones (`PySide6-Essentials`/`shiboken6` 6.7.3, `pyqtgraph` 0.13.7,
`numpy` 1.26.4, `PyYAML` 6.0.2, `pyinstaller` 6.11.1, `pyinstaller-hooks-contrib`
2026.7, `pefile` 2023.2.7, `pywin32-ctypes` 0.2.3, `altgraph` 0.17.5,
`packaging` 26.3, `setuptools` 84.0.0). The i386 Wine runtime is required: the
`python-3.12.7-amd64.exe` bootstrapper is itself a PE32 binary.

`SMOKE=1` starts the finished exe under `xvfb-run wine` with
`TINCMGR_SELFTEST_MS` set: the onefile unpacks, Qt builds the main window,
`tinc.yaml` is created and the bundled `tincd.exe` is located, then the app
quits. The exe is built `console=False` (`uac_admin`), so it has no `--help`
to print — `TINCMGR_SELFTEST_MS` + `TINCMGR_SELFTEST_LOG` is the headless probe
on Wine and on real Windows alike.

You can also run the test suite with the *Windows* interpreter this way:

```sh
docker run --rm --entrypoint /bin/bash -v "$PWD/platforms/windows:/work" \
  tincstack/win-exe:dev -c 'wine "$WINPY" -m pip install -q pytest==8.3.3; cd /work;
    QT_QPA_PLATFORM=offscreen xvfb-run -a wine "$WINPY" -m pytest -q tests'
```

### What §2b does **not** prove

Wine is not Windows. The container route is a build and link check plus a
shallow start check; every one of these still needs §2's Windows box:

- **Wintun** — no driver, no adapter, no MTU clamp. `tests/selftest_runtime.py`
  remains the manual on-Windows check.
- **UAC / `uac_admin`** — Wine reports the process as elevated unconditionally,
  so the manifest and the `relaunch_self_elevated()` path are untested.
- **Scheduled Task autostart** (`schtasks`), tray icon / shell integration,
  `CREATE_NO_WINDOW` behaviour, and Windows service control.
- **Antivirus / SmartScreen** reaction to an unsigned PyInstaller onefile, and
  **code signing** (the artefact is unsigned).
- Real-Windows Qt rendering; Wine's Qt platform plugin is not the Windows one.

## 3. Running from source on Windows (dev)

```bat
v\Scripts\python main.py
```

The GUI relaunches itself elevated via UAC (needed for Wintun). Binaries are
taken from `resources\`; set `TINCSTACK_BIN_DIR` to point elsewhere.

## Still not done (no Windows host in the build lab)

The exe itself is now built and started in the lab (§2b, 2026-09-16:
57 665 248 B, SHA-256 `4c3725d9…a53e6`; the size is stable run to run, the
digest is not — PyInstaller stamps timestamps into the PE and the archive).
What is left needs real Windows:

- `tests\selftest_runtime.py` against the bundled core — Wintun adapter
  creation, MTU clamp, graceful stop;
- an interactive GUI session, the UAC prompt, and the Scheduled-Task autostart;
- a real double-click of `tincmgr.exe` next to a `tinc.yaml` past SmartScreen.

Everything else (backend, dialogs, transports editor, atomic save, log
rotation, threading) is covered by `tests/` and was run headless in Docker
(`QT_QPA_PLATFORM=offscreen`) with both the Linux and the Windows interpreter.
