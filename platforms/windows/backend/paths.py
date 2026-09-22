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

Trust (review 2026-09-22, local privilege escalation): the app runs elevated,
and everything it used to read from -- next to the exe, the working directory,
%LOCALAPPDATA% -- an unelevated process of the same user can rewrite. So an
elevated app on Windows keeps what it executes and what it obeys under
protected_dir() (%ProgramFiles%\\tincmgr), which only Administrators and SYSTEM
may write: the staged core binaries (bin\\), the autostart copy of the exe, and
the config. A config found in the old places is imported once (adopt_config).

Apart from stage_file() and adopt_config(), nothing here writes anything;
callers create the runtime dirs (see runtime.py).
"""

from __future__ import annotations

import hashlib
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


# -- the admin-only folder (Windows, elevated) ---------------------------------

_CSIDL_PROGRAM_FILES = 0x0026


def _program_files() -> str:
    """%ProgramFiles% from the shell, not from the environment: an elevated
    process inherits its environment from whoever launched it, so the variable
    is exactly as trustworthy as the folders this is meant to avoid."""
    import ctypes
    buf = ctypes.create_unicode_buffer(260)
    rc = ctypes.windll.shell32.SHGetFolderPathW(None, _CSIDL_PROGRAM_FILES, None, 0, buf)  # type: ignore[attr-defined]
    if rc != 0 or not buf.value:
        raise OSError(f"SHGetFolderPathW(CSIDL_PROGRAM_FILES) failed: {rc:#x}")
    return buf.value


def protected_dir() -> str | None:
    """Windows: %ProgramFiles%\\tincmgr. Program Files lets only Administrators
    and SYSTEM create or change anything, so an unelevated process cannot plant
    a file there before or after us -- which %ProgramData% (users may create
    files there) and %LOCALAPPDATA% cannot promise. None elsewhere, or if the
    folder cannot be resolved."""
    if sys.platform != "win32":
        return None
    try:
        return os.path.join(_program_files(), APP_NAME)
    except (OSError, AttributeError):
        return None


def bin_stage_dir(elevated: bool) -> str:
    """Where the core binaries are staged and run from: the protected folder
    when elevated (an elevated tincd must not be replaceable by the user), else
    %LOCALAPPDATA%\\tincmgr\\bin as before (nothing elevated runs it)."""
    prot = protected_dir() if elevated else None
    return os.path.join(prot or local_appdata_dir(), "bin")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def stage_file(src: str, dst: str) -> bool:
    """Make dst a copy of src; True if it had to be written. Compared by
    SHA-256, not size: PE files are section-aligned, and two different builds
    of tincd.exe measured 1816078 bytes each, so a size check staged nothing on
    an upgrade and kept running the old daemon. src is read once and the bytes
    that were hashed are the bytes written, so swapping src between the check
    and the copy changes nothing. Written to dst.new and renamed into place:
    a failed copy never leaves a truncated binary behind."""
    with open(src, "rb") as f:
        data = f.read()
    if os.path.isfile(dst) and sha256_file(dst) == hashlib.sha256(data).hexdigest():
        return False
    os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
    tmp = dst + ".new"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, dst)
    return True


def adopt_config(protected: str, legacy: str | None) -> tuple[str, str]:
    """The elevated app's config is `protected`. The first time, a config found
    in the old places (`legacy`) is copied in -- once: that is the user choosing
    the file they run with; re-reading it on every start is what let any
    unelevated process decide what the elevated one executes (ScriptsInterpreter,
    scripts in the runtime folder). Returns (path, note for the status bar)."""
    if os.path.isfile(protected):
        if legacy and os.path.normcase(os.path.abspath(legacy)) != os.path.normcase(os.path.abspath(protected)):
            return protected, (f"config: {protected} -- {legacy} is not read: the elevated app "
                               "only uses a config in a folder only administrators can change")
        return protected, ""
    os.makedirs(os.path.dirname(protected), exist_ok=True)
    tmp = protected + ".new"
    if legacy:
        shutil.copyfile(legacy, tmp)
    else:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write("networks: {}\n")
    os.replace(tmp, protected)
    if legacy:
        return protected, f"config: imported {legacy} into {protected}; that copy is the one used from now on"
    return protected, f"config: created {protected}"
