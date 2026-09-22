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


def installed_exe() -> str | None:
    """Where the autostart task's copy of tincmgr.exe lives (admin-only)."""
    prot = paths.protected_dir()
    return os.path.join(prot, "tincmgr.exe") if prot else None


def install_self(exe_path: str) -> str:
    """Copy the running exe to installed_exe() (by content, paths.stage_file)
    and return that path. The logon task runs its target elevated with no
    prompt, so the target must be a file only administrators can replace --
    not wherever the user happened to drop the download."""
    dst = installed_exe()
    if not dst:
        raise OSError("Program Files could not be resolved")
    paths.stage_file(exe_path, dst)
    return dst


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
    the admin-only copy from install_self(), never `exe_path` itself."""
    if sys.platform != "win32":
        return False, "run-at-startup is Windows-only"
    try:
        if enabled:
            target = install_self(exe_path)
            p = subprocess.run(
                ["schtasks", "/create", "/tn", STARTUP_TASK, "/tr", f'"{target}"',
                 "/sc", "onlogon", "/rl", "highest", "/f"],
                capture_output=True, text=True, creationflags=_NO_WINDOW)
            if p.returncode == 0:
                _clear_task_battery_limits(STARTUP_TASK)
        else:
            p = subprocess.run(["schtasks", "/delete", "/tn", STARTUP_TASK, "/f"],
                               capture_output=True, text=True, creationflags=_NO_WINDOW)
        return p.returncode == 0, (p.stdout + p.stderr).strip()
    except OSError as e:
        return False, str(e)


def refresh_startup_task(exe_path: str) -> str:
    """At every elevated start: if run-at-startup is on, bring the installed
    copy up to this exe (an upgrade must not leave the task on the old
    version) and move a task created by an older tincmgr -- which points at a
    user-writable path -- onto the installed copy. Returns a status note."""
    cmd = startup_task_command()
    if cmd is None:
        return ""
    target = installed_exe()
    if not target:
        return "run-at-startup: Program Files could not be resolved; task left as it is"
    try:
        if os.path.normcase(cmd) != os.path.normcase(target):
            ok, msg = set_startup_task(True, exe_path)
            return (f"run-at-startup now runs {target}" if ok
                    else f"run-at-startup: could not move the task off {cmd}: {msg[:80]}")
        if os.path.normcase(os.path.abspath(exe_path)) != os.path.normcase(target):
            paths.stage_file(exe_path, target)
        return ""
    except OSError as e:
        return f"run-at-startup: could not update {target}: {e}"


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
