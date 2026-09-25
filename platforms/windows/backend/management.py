"""
management.py — Windows host integration: elevation, run-at-startup
(Scheduled Task) and the firewall rule for the daemon.

Everything that touched the classic `C:\\Program Files\\tinc` tree or the
`tinc.<net>` Windows services was removed in the tincstack adoption: networks
are child processes of the GUI and the config is the single YAML.

Privilege model:
  - Creating Wintun adapters, the Scheduled Task and the firewall rule need
    Administrator. is_admin() reports the current token; run_elevated()
    relaunches a command via UAC (ShellExecute runas).
"""

from __future__ import annotations

import ctypes
import os
import re
import shutil
import subprocess
import sys

import paths

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def is_admin() -> bool:
    if sys.platform != "win32":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def run_elevated(exe: str, params: str, wait: bool = True) -> bool:
    """Launch exe with params elevated via UAC. Returns True if launched."""
    if sys.platform != "win32":
        return False
    try:
        # SW_HIDE = 0 ; returns >32 on success
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 0)  # type: ignore[attr-defined]
        return int(rc) > 32
    except Exception:
        return False


def relaunch_self_elevated() -> bool:
    """Relaunch the current GUI elevated (so all management ops are available)."""
    if getattr(sys, "frozen", False):
        return run_elevated(sys.executable, "")
    exe = sys.executable  # pythonw.exe in the venv
    script = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "main.py"))
    return run_elevated(exe, f'"{script}"')


# ---- run-at-Windows-startup (elevated, via Scheduled Task) --------------------

STARTUP_TASK = "tincmgr-autostart"


def startup_task_enabled() -> bool:
    if sys.platform != "win32":
        return False
    try:
        p = subprocess.run(["schtasks", "/query", "/tn", STARTUP_TASK],
                           capture_output=True, text=True, creationflags=_NO_WINDOW)
        return p.returncode == 0
    except OSError:
        return False


def _clear_task_battery_limits(name: str) -> None:
    """schtasks bakes in laptop-hostile defaults: DisallowStartIfOnBatteries and
    StopIfGoingOnBatteries are TRUE, plus a 72h ExecutionTimeLimit. On a laptop
    that boots on battery the logon task is refused with 0x800710E0. Strip those
    so the task starts on battery and the long-running GUI is never killed."""
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        f"$s=Get-ScheduledTask -TaskName '{name}';"
        "if($s){$s.Settings.DisallowStartIfOnBatteries=$false;"
        "$s.Settings.StopIfGoingOnBatteries=$false;"
        "$s.Settings.ExecutionTimeLimit='PT0S';"
        f"Set-ScheduledTask -TaskName '{name}' -Settings $s.Settings | Out-Null}}"
    )
    try:
        subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                       capture_output=True, text=True, creationflags=_NO_WINDOW, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        pass


INSTALL_SUBDIR = "app"
INSTALL_RECORD = "tincmgr-install.txt"


class DowngradeRefused(OSError):
    """The installed copy is newer than (or not provably older than) this one."""


def install_dir() -> str | None:
    """The onedir tree the logon task runs (admin-only)."""
    prot = paths.protected_dir()
    return os.path.join(prot, INSTALL_SUBDIR) if prot else None


def installed_exe() -> str | None:
    """The program the autostart task runs: the onedir tincmgr.exe under
    %ProgramFiles%\\tincmgr\\app. Not a onefile: a onefile unpacks its Python
    and Qt DLLs into %TEMP%\\_MEIxxxx, writable by the user's unelevated
    processes, before loading them elevated."""
    d = install_dir()
    return os.path.join(d, "tincmgr.exe") if d else None


def _legacy_installed_exe() -> str | None:
    """Where tincmgr <= this change put the autostart copy: the onefile itself."""
    prot = paths.protected_dir()
    return os.path.join(prot, "tincmgr.exe") if prot else None


def installed_version() -> str | None:
    """The version recorded by the install, None if there is none (nothing
    installed, or the pre-onedir layout, which recorded no version)."""
    d = install_dir()
    try:
        with open(os.path.join(d or "", INSTALL_RECORD), encoding="utf-8") as f:
            first = f.readline().split()
    except OSError:
        return None
    return first[1] if len(first) == 2 and first[0] == "version" else None


def _same_path(a: str, b: str) -> bool:
    return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def check_downgrade(ours: str, installed: str | None) -> None:
    """Raise DowngradeRefused unless installing `ours` over `installed` is
    provably not a downgrade. Last run must not win: running an older
    tincmgr.exe elevated would otherwise put that older copy -- and its old
    bugs -- behind the logon task."""
    if installed is None:
        return                                  # nothing, or the unversioned old layout
    o, i = paths.version_key(ours), paths.version_key(installed)
    if i is None:
        if ours == installed:
            return
        # a dev build is installed: only a release, or the same dev build, replaces it
        if o is not None:
            return
        raise DowngradeRefused(f"installed {installed} and this {ours} cannot be ordered")
    if o is None or o < i:
        raise DowngradeRefused(f"installed {installed} is newer than this {ours}")


def install_self(exe_path: str, allow_downgrade: bool = False) -> str:
    """Install this build's onedir tree into install_dir() and return the exe
    the logon task should run. The task runs its target elevated with no
    prompt, so the target must be a file only administrators can replace and
    must load nothing from anywhere else.

    Every file is copied out of this onefile's unpack dir -- which an
    unelevated process may have rewritten by now -- with
    paths.stage_verified() against the manifest compiled into the exe, into a
    fresh `app.new`, and only a complete, verified tree is swapped in. A copy
    of the installed tree that is running (DLLs mapped) makes the swap fail;
    the old tree then stays as it was."""
    target = installed_exe()
    d = install_dir()
    if not target or not d:
        raise OSError("Program Files could not be resolved")
    if _same_path(exe_path, target):
        return target                           # this is the installed copy
    b = paths.bundle()
    if b is None:
        raise OSError("only the single-file tincmgr.exe can install itself")
    record = os.path.join(d, INSTALL_RECORD)
    try:
        with open(record, encoding="utf-8") as f:
            if f.read() == b.manifest_text():
                return target                   # already this build
    except OSError:
        pass
    if not allow_downgrade:
        check_downgrade(b.version, installed_version())

    staging, old = d + ".new", d + ".old"
    shutil.rmtree(staging, ignore_errors=True)
    try:
        for rel, (sha, src_rel) in b.files.items():
            paths.stage_verified(os.path.join(b.root, *src_rel.split("/")),
                                 os.path.join(staging, *rel.split("/")), sha)
        with open(os.path.join(staging, INSTALL_RECORD), "w", encoding="utf-8") as f:
            f.write(b.manifest_text())
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    shutil.rmtree(old, ignore_errors=True)
    if os.path.isdir(d):
        try:
            os.rename(d, old)
        except OSError as e:
            shutil.rmtree(staging, ignore_errors=True)
            raise OSError(f"cannot replace {d} (is the installed tincmgr running?): {e}") from e
    os.rename(staging, d)
    shutil.rmtree(old, ignore_errors=True)
    legacy = _legacy_installed_exe()
    if legacy and os.path.isfile(legacy):
        try:
            os.remove(legacy)                   # the old onefile copy; nothing runs it now
        except OSError:
            pass
    return target


def startup_task_command() -> str | None:
    """The program the logon task runs, or None if there is no task (or it
    cannot be read)."""
    if sys.platform != "win32":
        return None
    try:
        p = subprocess.run(["schtasks", "/query", "/tn", STARTUP_TASK, "/xml"],
                           capture_output=True, text=True, creationflags=_NO_WINDOW)
    except OSError:
        return None
    m = re.search(r"<Command>(.*?)</Command>", p.stdout or "", re.S)
    return m.group(1).strip().strip('"') if p.returncode == 0 and m else None


def set_startup_task(enabled: bool, exe_path: str) -> tuple[bool, str]:
    """Create/remove a logon Scheduled Task that runs tincmgr with highest
    privileges (starts elevated at login). Needs admin to create. The task runs
    the admin-only onedir copy from install_self(), never `exe_path` itself.
    Turning it on is the user choosing this copy, so an older one may replace
    a newer install here (refresh_startup_task() refuses that)."""
    if sys.platform != "win32":
        return False, "run-at-startup is Windows-only"
    try:
        if enabled:
            target = install_self(exe_path, allow_downgrade=True)
            return _point_task_at(target)
        p = subprocess.run(["schtasks", "/delete", "/tn", STARTUP_TASK, "/f"],
                           capture_output=True, text=True, creationflags=_NO_WINDOW)
        return p.returncode == 0, (p.stdout + p.stderr).strip()
    except OSError as e:
        return False, str(e)


def _point_task_at(target: str) -> tuple[bool, str]:
    """(Re)create the logon task with `target` as its program."""
    try:
        p = subprocess.run(
            ["schtasks", "/create", "/tn", STARTUP_TASK, "/tr", f'"{target}"',
             "/sc", "onlogon", "/rl", "highest", "/f"],
            capture_output=True, text=True, creationflags=_NO_WINDOW)
        if p.returncode == 0:
            _clear_task_battery_limits(STARTUP_TASK)
        return p.returncode == 0, (p.stdout + p.stderr).strip()
    except OSError as e:
        return False, str(e)


def refresh_startup_task(exe_path: str) -> str:
    """At every elevated start: if run-at-startup is on, bring the installed
    copy up to this build (an upgrade must not leave the task on the old
    version) -- but never down to it: an older build leaves a newer install
    alone. A task created by an older tincmgr (pointing at a user-writable
    path, or at the Program Files onefile) is moved onto the onedir copy.
    Returns a status note. Runs schtasks and copies the app tree: call it off
    the Qt thread."""
    cmd = startup_task_command()
    if cmd is None:
        return ""
    target = installed_exe()
    if not target:
        return "run-at-startup: Program Files could not be resolved; task left as it is"
    note = ""
    try:
        if _same_path(exe_path, target) or paths.bundle() is not None:
            install_self(exe_path)
        elif not os.path.isfile(target):
            return ("run-at-startup: this copy cannot install itself (use the single-file "
                    f"tincmgr.exe); the task still runs {cmd}")
    except DowngradeRefused as e:
        note = (f"run-at-startup: left the installed copy as it is ({e}); "
                "turn run-at-startup off and on to install this one")
    except OSError as e:
        return f"run-at-startup: could not update {target}: {e}"
    if _same_path(cmd, target) or not os.path.isfile(target):
        return note
    ok, msg = _point_task_at(target)
    moved = (f"run-at-startup now runs {target}" if ok
             else f"run-at-startup: could not move the task off {cmd}: {msg[:80]}")
    return "; ".join(n for n in (note, moved) if n)


# ---- firewall (pre-allow tincd so Windows doesn't prompt every launch) --------

FIREWALL_RULE = "tincmgr-tincd"


def set_firewall_allow(program: str) -> tuple[bool, str]:
    """Allow `program` (the daemon) through Windows Firewall in+out, so Windows
    stops prompting on each launch. Idempotent (delete-then-add by a fixed name).
    The daemon must run from a STABLE path for this to persist. Needs admin."""
    if sys.platform != "win32":
        return False, "firewall rule is Windows-only"
    try:
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={FIREWALL_RULE}"],
                       capture_output=True, text=True, creationflags=_NO_WINDOW)
        rcs = []
        for direction in ("in", "out"):
            p = subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={FIREWALL_RULE}", f"dir={direction}", "action=allow",
                 f"program={program}", "enable=yes", "profile=any"],
                capture_output=True, text=True, creationflags=_NO_WINDOW)
            rcs.append(p.returncode)
        return all(r == 0 for r in rcs), f"rc={rcs}"
    except OSError as e:
        return False, str(e)


if __name__ == "__main__":
    print("is_admin:", is_admin())
    print("python:", sys.executable)
