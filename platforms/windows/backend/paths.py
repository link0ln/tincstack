"""
paths.py — locate the tincstack core binaries and resolve config / work dirs.

The whole point of this app is "drop two files (the .exe and a .yaml) anywhere,
run, and the VPNs come up". So binary resolution works in these modes:

  * override — $TINCSTACK_BIN_DIR names a directory holding tincd/tinc
               (used by tests and by the Linux CLI against a core build).
  * frozen   — PyInstaller --onefile: tincd.exe / tinc.exe / wintun.dll are
               unpacked into sys._MEIPASS; the .exe lives at sys.executable.
  * source   — running main.py from a checkout: binaries live in
               platforms/windows/resources/, populated by
               `platforms/windows/build-core-win.sh` from the core cross-build
               (core/Dockerfile.build-win). That directory is gitignored.
  * PATH     — on non-Windows hosts, fall back to `tincd`/`tinc` on $PATH
               (the Linux path of cli.py used to be broken because only the
               Windows binaries were looked for).

Nothing here writes anything; callers create the runtime dirs (see runtime.py).
"""

from __future__ import annotations

import os
import shutil
import sys

APP_NAME = "tincmgr"
CONFIG_BASENAMES = ("tinc.yaml", "tinc.yml", "tincmgr.yaml")
BIN_DIR_ENV = "TINCSTACK_BIN_DIR"

_EXE = ".exe" if sys.platform == "win32" else ""


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def resource_dir() -> str:
    """Directory that holds tincd / tinc / wintun.dll (see module docstring)."""
    override = os.environ.get(BIN_DIR_ENV)
    if override:
        return override
    if is_frozen():
        # onefile: extracted to _MEIPASS; onedir: next to the exe
        return getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "resources")


def app_dir() -> str:
    """Directory the executable (or main.py) lives in — where we look for the
    YAML and, by default, place the runtime data folder."""
    if is_frozen():
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _binary(name: str) -> str:
    """Resolve one core binary: resource dir first, then (non-Windows) $PATH.
    Always returns a path; `os.path.isfile()` tells the caller if it exists."""
    cand = os.path.join(resource_dir(), name + _EXE)
    if os.path.isfile(cand):
        return cand
    if sys.platform != "win32":
        found = shutil.which(name)
        if found:
            return found
    return cand


def tincd_exe() -> str:
    return _binary("tincd")


def tinc_exe() -> str:
    return _binary("tinc")


def wintun_dll() -> str:
    return os.path.join(resource_dir(), "wintun.dll")


def binaries_present() -> tuple[bool, str]:
    """(ok, human message) — whether both core binaries resolve."""
    missing = [p for p in (tincd_exe(), tinc_exe()) if not os.path.isfile(p)]
    if not missing:
        return True, f"core binaries: {os.path.dirname(tincd_exe())}"
    return False, ("core binaries missing: " + ", ".join(missing)
                   + f" — run platforms/windows/build-core-win.sh or set ${BIN_DIR_ENV}")


def _writable(d: str) -> bool:
    try:
        os.makedirs(d, exist_ok=True)
        probe = os.path.join(d, ".w")
        with open(probe, "w") as f:
            f.write("")
        os.remove(probe)
        return True
    except OSError:
        return False


def local_appdata_dir() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, APP_NAME)


def find_config(explicit: str | None = None) -> str | None:
    """Locate the YAML config. Order: explicit arg → next to the exe → cwd →
    %LOCALAPPDATA%\\tincmgr. Returns a path that exists, else None."""
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    for base in (app_dir(), os.getcwd(), local_appdata_dir()):
        for name in CONFIG_BASENAMES:
            p = os.path.join(base, name)
            if os.path.isfile(p):
                return p
    return None


def default_config_path() -> str:
    """Where to create a config if none exists (next to the exe if writable,
    else %LOCALAPPDATA%)."""
    if _writable(app_dir()):
        return os.path.join(app_dir(), CONFIG_BASENAMES[0])
    return os.path.join(local_appdata_dir(), CONFIG_BASENAMES[0])
