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
import subprocess
import sys

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


def set_startup_task(enabled: bool, exe_path: str) -> tuple[bool, str]:
    """Create/remove a logon Scheduled Task that runs `exe_path` with highest
    privileges (starts elevated at login). Needs admin to create."""
    if sys.platform != "win32":
        return False, "run-at-startup is Windows-only"
    try:
        if enabled:
            p = subprocess.run(
                ["schtasks", "/create", "/tn", STARTUP_TASK, "/tr", f'"{exe_path}"',
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
