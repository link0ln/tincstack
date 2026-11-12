"""
runtime.py — drive tincd directly against the single YAML config (YAML-native).

No materialise, no sync: the tincstack core reads AND writes the YAML itself
(config_fopen / yamlconf.c; zero-config materialisation on first start).
tincmgr just spawns `tincd -n <net> -c <tinc.yaml> -D` as a child process and
stops it gracefully via `tinc stop`. Runtime files (pid/socket/cache) land in
<yaml_dir>/<net>/ (chosen by tinc's names.c in YAML mode).

The daemon's stdout/stderr go through a pipe into LogSink, which rotates the
per-network log by size *while the daemon runs* (rotation only at start let
the log grow to 13 MB in the original tinc-manager).

Every method here blocks on subprocesses; the GUI must call them from a
worker thread (gui/workers.py), never from the Qt thread.
"""

from __future__ import annotations

import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
from typing import Callable, IO

import fulltunnel
import paths
import routes
import yaml_config
from tinc_control import TincControl
from yaml_config import AppConfig

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

LOG_MAX_BYTES = 2 * 1024 * 1024   # rotate the daemon log at 2 MB
LOG_BACKUPS = 2                   # keep <net>-tincd.log.1 and .2


# -- host-file public-key helpers ---------------------------------------------
_RSA_PUB_RE = re.compile(r"-----BEGIN RSA PUBLIC KEY-----.*?-----END RSA PUBLIC KEY-----", re.DOTALL)
_ED_PUB_RE = re.compile(r"^[ \t]*Ed25519PublicKey[ \t]*=.*$", re.MULTILINE)
_TINC_NOTE_RE = re.compile(r"^[ \t]*#.*automatically added by tinc.*$\n?", re.MULTILINE)


def _strip_pubkeys(text: str) -> str:
    """Drop Ed25519/RSA PUBLIC KEY lines (+ tinc's auto-added comment) from a
    host-file body, leaving Subnet/Address/Port/etc. intact."""
    text = _RSA_PUB_RE.sub("", text)
    text = _ED_PUB_RE.sub("", text)
    text = _TINC_NOTE_RE.sub("", text)
    return text


def merge_pubkeys(existing: str, fresh: str) -> str:
    """Splice the PUBLIC keys from `fresh` (a just-generated host file, pubkeys
    only) into `existing`, PRESERVING the existing Subnet/Address/Port lines.
    generate-keys emits pubkeys without Subnet, so a blind overwrite would drop
    this node's Subnet — hence this merge."""
    rsa = _RSA_PUB_RE.findall(fresh)
    ed = [e.strip() for e in _ED_PUB_RE.findall(fresh)]
    pub = "\n".join(rsa + ed).strip()
    rest = _strip_pubkeys(existing).strip()
    if not pub:
        return existing.strip()
    return (pub + "\n" + rest).strip() if rest else pub


# -- size-rotating log sink ----------------------------------------------------

class LogSink(threading.Thread):
    """Pump a child's stdout pipe into `path`, rotating by size while the child
    runs: path -> path.1 -> path.2 (…backups). Owns the file handle, so the
    rotation works on Windows too (the daemon never holds the log open)."""

    def __init__(self, path: str, pipe: IO[bytes], max_bytes: int = LOG_MAX_BYTES,
                 backups: int = LOG_BACKUPS) -> None:
        super().__init__(name=f"log-{os.path.basename(path)}", daemon=True)
        self.path = path
        self.pipe = pipe
        self.max_bytes = max_bytes
        self.backups = backups
        self.rotations = 0
        self._f: IO[bytes] | None = None
        self._size = 0

    def _open(self) -> None:
        self._f = paths.open_private_append(self.path, binary=True)
        try:
            self._size = os.path.getsize(self.path)
        except OSError:
            self._size = 0

    def rotate(self) -> None:
        if self._f:
            self._f.close()
            self._f = None
        for i in range(self.backups, 0, -1):
            src = self.path if i == 1 else f"{self.path}.{i - 1}"
            dst = f"{self.path}.{i}"
            try:
                if os.path.exists(src):
                    os.replace(src, dst)
            except OSError:
                pass
        if self.backups == 0:
            try:
                os.remove(self.path)
            except OSError:
                pass
        self.rotations += 1
        self._open()

    def write(self, chunk: bytes) -> None:
        if self._f is None:
            self._open()
        if self._size + len(chunk) > self.max_bytes and self._size > 0:
            self.rotate()
        assert self._f is not None
        self._f.write(chunk)
        self._size += len(chunk)

    def run(self) -> None:
        try:
            self._open()
            for line in iter(self.pipe.readline, b""):
                self.write(line)
        except (OSError, ValueError):
            pass
        finally:
            try:
                if self._f:
                    self._f.close()
            except OSError:
                pass
            try:
                self.pipe.close()
            except OSError:
                pass


# -- the runtime ---------------------------------------------------------------

class Runtime:
    def __init__(self, app: AppConfig, log_max_bytes: int = LOG_MAX_BYTES,
                 log_backups: int = LOG_BACKUPS, ft_system: "fulltunnel.System | None" = None,
                 ft_interval: float = fulltunnel.INTERVAL,
                 load_error: str = "",
                 diag_port_fn: Callable[[], int] | None = None) -> None:
        self.app = app
        self.yaml = os.path.abspath(app.path)
        self.base = os.path.dirname(self.yaml)
        self.load_error = load_error
        self.diag_port_fn = diag_port_fn
        self.log_max_bytes = log_max_bytes
        self.log_backups = log_backups
        self._procs: dict[str, subprocess.Popen] = {}
        self._sinks: dict[str, LogSink] = {}
        self._op_lock = threading.RLock()
        self._fw_done = False
        # full tunnel (fulltunnel.py): one maintainer thread per network whose
        # `full_tunnel` names an exit node, while that network runs. The system
        # layer is injectable for tests; None = the real one on Windows.
        self._ft: dict[str, fulltunnel.Maintainer] = {}
        self._ft_lock = threading.RLock()
        self._ft_system = ft_system
        self._ft_interval = ft_interval
        self._all_stopped = False
        if self.base and (paths.is_elevated() or paths._under_protected_dir(self.base)):
            try:
                paths.mkdir_private(os.path.join(self.base, "logs"))
            except OSError:
                pass
            if os.path.isfile(self.yaml):
                paths.lock_down_acl(self.yaml)
            if os.path.isfile(self.yaml + ".lock"):
                paths.lock_down_acl(self.yaml + ".lock")
        self._ensure_bins()

    @staticmethod
    def _read_pidfile_pid(pid_file: str) -> int | None:
        try:
            with open(pid_file, "r", encoding="utf-8", errors="replace") as f:
                tok = (f.read().split() or [""])[0]
            pid = int(tok)
            return pid if pid > 0 else None
        except (OSError, ValueError):
            return None

    @staticmethod
    def _is_tincd_pid(pid: int) -> bool:
        if pid <= 0 or pid == os.getpid():
            return False
        if sys.platform == "win32":
            try:
                import ctypes
                from ctypes import wintypes
                k32 = ctypes.WinDLL("kernel32", use_last_error=True)
                k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
                k32.OpenProcess.restype = wintypes.HANDLE
                k32.QueryFullProcessImageNameW.argtypes = [
                    wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
                ]
                k32.QueryFullProcessImageNameW.restype = wintypes.BOOL
                k32.CloseHandle.argtypes = [wintypes.HANDLE]
                h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
                if h:
                    try:
                        sz = wintypes.DWORD(1024)
                        buf = ctypes.create_unicode_buffer(1024)
                        if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(sz)):
                            return os.path.basename(buf.value).lower() == "tincd.exe"
                    finally:
                        k32.CloseHandle(h)
            except Exception:
                pass
            try:
                p = subprocess.run(
                    ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                    capture_output=True, text=True, timeout=3.0,
                    stdin=subprocess.DEVNULL, creationflags=_NO_WINDOW,
                )
                return "tincd.exe" in (p.stdout or "").lower()
            except Exception:
                return False
        try:
            with open(f"/proc/{pid}/comm", "r", encoding="utf-8", errors="replace") as f:
                return f.read().strip() == "tincd"
        except OSError:
            return False

    @classmethod
    def _terminate_tincd_pid(cls, pid: int) -> bool:
        if not cls._is_tincd_pid(pid):
            return False
        if sys.platform == "win32":
            try:
                p = subprocess.run(
                    ["taskkill", "/F", "/PID", str(pid)],
                    capture_output=True, text=True, timeout=5.0,
                    stdin=subprocess.DEVNULL, creationflags=_NO_WINDOW,
                )
                return p.returncode == 0
            except Exception:
                return False
        try:
            import signal
            os.kill(pid, signal.SIGTERM)
            return True
        except OSError:
            return False

    @staticmethod
    def _pid_cmdline(pid: int) -> list[str] | None:
        """Return argv tokens for `pid` when queryable, or None if unavailable."""
        if pid <= 0:
            return None
        if sys.platform == "win32":
            try:
                p = subprocess.run(
                    [
                        "powershell", "-NoProfile", "-NonInteractive", "-Command",
                        f"(Get-CimInstance Win32_Process -Filter 'ProcessId={int(pid)}').CommandLine",
                    ],
                    capture_output=True, text=True, timeout=3.0,
                    stdin=subprocess.DEVNULL, creationflags=_NO_WINDOW,
                )
                if p.returncode != 0:
                    return None
                raw = (p.stdout or "").strip()
                if not raw:
                    return None
                import shlex
                return shlex.split(raw, posix=False)
            except Exception:
                return None
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                data = f.read()
            if not data:
                return None
            parts = [x.decode("utf-8", errors="replace") for x in data.rstrip(b"\x00").split(b"\x00")]
            return parts if parts and parts[0] else None
        except OSError:
            return None

    @classmethod
    def _pid_matches_net(cls, pid: int, net_name: str) -> bool:
        """Verify `pid` is a `tincd` instance running `-n <net_name>` when its
        command line can be inspected. Returns True when cmdline is unqueryable
        so `_is_tincd_pid` remains the fallback."""
        argv = cls._pid_cmdline(pid)
        if not argv:
            return True
        exe_base = os.path.basename(argv[0].strip('"')).lower()
        if exe_base not in ("tincd", "tincd.exe"):
            return False
        cleaned = [tok.strip('"') for tok in argv[1:]]
        for i, tok in enumerate(cleaned):
            if tok in ("-n", "--net") and i + 1 < len(cleaned):
                return cleaned[i + 1] == net_name
            if tok.startswith("-n") and len(tok) > 2:
                return tok[2:] == net_name
            if tok.startswith("--net="):
                return tok.split("=", 1)[1] == net_name
        return False

    def _kill_orphan_daemons(self, net_name: str | None = None) -> None:
        """Terminate only stale `tincd` PIDs recorded in `<runtime_dir(net)>/pid`
        for networks confirmed NOT responding on their control socket and matching
        `-n <net>` in their command line. Never uses a global image kill and never
        kills anything when `load_error` is set."""
        if self.load_error or getattr(self.app, "load_error", ""):
            return
        if net_name:
            nets = [net_name]
        else:
            with yaml_config._MEM_LOCK:
                cfg_nets = list(self.app.networks)
            nets = list(dict.fromkeys(list(self._procs) + cfg_nets))
            if os.path.isdir(self.base):
                try:
                    for entry in os.listdir(self.base):
                        if entry not in nets and os.path.isfile(os.path.join(self.base, entry, "pid")):
                            nets.append(entry)
                except OSError:
                    pass
        for n in nets:
            pid_file = os.path.join(self.runtime_dir(n), "pid")
            if not os.path.isfile(pid_file):
                continue
            if self.has_live_process(n) or self.is_running(n):
                continue
            pid = self._read_pidfile_pid(pid_file)
            matched = pid is not None and self._pid_matches_net(pid, n)
            if pid is not None and matched:
                self._terminate_tincd_pid(pid)
            if pid is None or not matched or not self._is_tincd_pid(pid):
                try:
                    os.remove(pid_file)
                except OSError:
                    pass

    def stage_binaries(self, bindir: str | None = None) -> str:
        """Stage `tincd.exe`, `tinc.exe`, and `wintun.dll` into `bindir`, skipping
        any binary whose SHA-256 already matches on disk so running daemons do
        not trigger `PermissionError`."""
        import management
        target_dir = bindir or paths.bin_stage_dir(management.is_admin())
        names = ["tincd.exe", "tinc.exe", "wintun.dll"]
        b = paths.bundle()
        self._stage_all(names, target_dir, b)
        return target_dir

    def _stage_all(self, names: list[str], bindir: str, b) -> None:
        paths.reject_reparse_point(bindir)
        for n in names:
            src = os.path.join(paths.resource_dir(), n)
            if os.path.isfile(src):
                want = b.files.get("_internal/" + n) if b else None
                if want:
                    paths.stage_verified(src, os.path.join(bindir, n), want[0])
                else:
                    paths.stage_file(src, os.path.join(bindir, n))
        if not os.path.isfile(os.path.join(bindir, "tincd.exe")):
            raise OSError("tincd not staged")

    def _ensure_bins(self) -> None:
        """Windows: copy the bundled tincd/tinc (+ wintun.dll) to a STABLE bin
        dir and run from there. When elevated or frozen, NEVER fall back to
        executing binaries from `%TEMP%\\_MEI*`!"""
        self.tincd = paths.tincd_exe()
        self.tinc = paths.tinc_exe()
        self.bindir = os.path.dirname(self.tincd)
        self.stage_note = ""
        if sys.platform != "win32":
            return
        import management
        elevated = management.is_admin()
        must_not_fallback = elevated or paths.is_frozen()
        names = ["tincd.exe", "tinc.exe", "wintun.dll"]
        bindir = paths.bin_stage_dir(elevated)
        if must_not_fallback:
            self.tincd = os.path.join(bindir, "tincd.exe")
            self.tinc = os.path.join(bindir, "tinc.exe")
            self.bindir = bindir
        b = paths.bundle()
        try:
            try:
                self._stage_all(names, bindir, b)
            except OSError:
                self._kill_orphan_daemons()
                time.sleep(0.3)
                self._stage_all(names, bindir, b)
            self.tincd = os.path.join(bindir, "tincd.exe")
            self.tinc = os.path.join(bindir, "tinc.exe")
            self.bindir = bindir
        except paths.IntegrityError as e:
            self.tincd = os.path.join(bindir, "tincd.exe")
            self.tinc = os.path.join(bindir, "tinc.exe")
            self.bindir = bindir
            self.stage_note = f"refused to stage the bundled core: {e}"
        except OSError as e:
            if must_not_fallback:
                self.tincd = os.path.join(bindir, "tincd.exe")
                self.tinc = os.path.join(bindir, "tinc.exe")
                self.bindir = bindir
                self.stage_note = f"could not update {bindir} ({e}); using existing staged binaries"
            else:
                self.stage_note = f"could not update {bindir} ({e}); running the bundled core"

    # -- paths --
    def runtime_dir(self, net: str) -> str:
        return os.path.join(self.base, net)

    def log_path(self, net: str) -> str:
        return os.path.join(self.base, net + "-tincd.log")

    # -- control --
    def _tinc(self, net: str, *args: str, timeout: float = 8.0) -> tuple[int, str]:
        try:
            p = subprocess.run([self.tinc, "-n", net, "-c", self.yaml, *args],
                               capture_output=True, text=True, timeout=timeout,
                               stdin=subprocess.DEVNULL, creationflags=_NO_WINDOW)
            return p.returncode, (p.stdout + p.stderr)
        except (OSError, subprocess.TimeoutExpired) as e:
            return 1, str(e)

    def has_live_process(self, net: str) -> bool:
        """True when a tincd child process spawned by this Runtime is still alive."""
        proc = self._procs.get(net)
        return proc is not None and proc.poll() is None

    def is_running(self, net: str) -> bool:
        rc, _ = self._tinc(net, "dump", "nodes", timeout=5.0)
        return rc == 0

    # -- lifecycle --
    def start(self, net_name: str, detached: bool = False) -> tuple[bool, str]:
        with self._op_lock:
            return self._start_locked(net_name, detached=detached)

    def _rotate_log_once(self, log_file: str) -> None:
        try:
            if not os.path.isfile(log_file) or os.path.getsize(log_file) <= self.log_max_bytes:
                return
        except OSError:
            return
        for i in range(self.log_backups, 0, -1):
            src = log_file if i == 1 else f"{log_file}.{i - 1}"
            dst = f"{log_file}.{i}"
            try:
                if os.path.exists(src):
                    os.replace(src, dst)
            except OSError:
                pass

    def _start_locked(self, net_name: str, detached: bool = False) -> tuple[bool, str]:
        with yaml_config._MEM_LOCK:
            nc = self.app.net(net_name)
        if nc is None:
            return False, f"network '{net_name}' not in config"
        if not os.path.isfile(self.tincd):
            return False, f"tincd not found: {self.tincd}"
        self._all_stopped = False
        if self.is_running(net_name):
            if not detached:
                self.full_tunnel_sync(net_name)
            self._sync_diag_port(net_name, sync=detached)
            return True, "already running"
        if self.has_live_process(net_name):
            if self.is_running(net_name):
                if not detached:
                    self.full_tunnel_sync(net_name)
                self._sync_diag_port(net_name, sync=detached)
                return True, "already running"
            self.stop(net_name)
        else:
            self._kill_orphan_daemons(net_name)
        if sys.platform == "win32" and not self._fw_done:
            try:
                import management
                management.set_firewall_allow(self.tincd)
            except Exception:
                pass
            self._fw_done = True
        paths.mkdir_private(self.runtime_dir(net_name))
        if detached:
            log_file = self.log_path(net_name)
            self._rotate_log_once(log_file)
            log_fh = None
            try:
                log_fh = paths.open_private_append(log_file, binary=True)
                popen_kw: dict = {
                    "stdout": log_fh,
                    "stderr": subprocess.STDOUT,
                    "stdin": subprocess.DEVNULL,
                    "cwd": os.path.dirname(self.tincd),
                }
                if sys.platform == "win32":
                    popen_kw["creationflags"] = (
                        _NO_WINDOW
                        | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                        | getattr(subprocess, "DETACHED_PROCESS", 0)
                    )
                else:
                    popen_kw["start_new_session"] = True
                proc = subprocess.Popen(
                    [self.tincd, "-n", net_name, "-c", self.yaml, "-D"],
                    **popen_kw,
                )
            except OSError as e:
                return False, f"spawn failed: {e}"
            finally:
                if log_fh is not None:
                    try:
                        log_fh.close()
                    except OSError:
                        pass
            started_ok = False
            for _ in range(20):
                time.sleep(0.25)
                if proc.poll() is not None:
                    return False, f"tincd exited rc={proc.returncode} (see {log_file})"
                if self.is_running(net_name):
                    started_ok = True
                    break
            if sys.platform == "win32" and nc.device_type in ("", "wintun"):
                self._apply_wintun_mtu(net_name)
            if started_ok:
                self._sync_diag_port(net_name, sync=True)
                if nc.full_tunnel:
                    self._full_tunnel_oneshot(net_name)
                return True, "started"
            return True, "started (control not yet responding)"

        try:
            proc = subprocess.Popen(
                [self.tincd, "-n", net_name, "-c", self.yaml, "-D"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                creationflags=_NO_WINDOW, cwd=os.path.dirname(self.tincd))
        except OSError as e:
            return False, f"spawn failed: {e}"
        assert proc.stdout is not None
        sink = LogSink(self.log_path(net_name), proc.stdout, self.log_max_bytes, self.log_backups)
        sink.start()
        self._procs[net_name] = proc
        self._sinks[net_name] = sink
        if sys.platform == "win32" and nc.device_type in ("", "wintun"):
            threading.Thread(target=self._apply_wintun_mtu, args=(net_name,),
                             name=f"mtu-{net_name}", daemon=True).start()
        self.full_tunnel_sync(net_name)
        for _ in range(20):
            time.sleep(0.25)
            if proc.poll() is not None:
                self._full_tunnel_off(net_name)
                return False, f"tincd exited rc={proc.returncode} (see {self.log_path(net_name)})"
            if self.is_running(net_name):
                self._sync_diag_port(net_name)
                return True, "started"
        return True, "started (control not yet responding)"

    def _full_tunnel_oneshot(self, net_name: str) -> None:
        """Apply one synchronous FullTunnel pass for detached CLI start without
        spawning a background daemon thread that exits with the CLI process."""
        system = self._ft_sys()
        if system is None:
            return
        with yaml_config._MEM_LOCK:
            nc = self.app.net(net_name)
            if not nc or not nc.full_tunnel:
                return
            want = nc.full_tunnel
            opts = dict(nc.options)
            hosts = dict(nc.hosts)
            own = nc.node_name
        aliases = routes.adapter_aliases(opts, net_name)
        jpath = self.full_tunnel_journal_path(net_name)
        paths.mkdir_private(self.runtime_dir(net_name))
        ft = fulltunnel.FullTunnel(
            net=net_name, exit_node=want, aliases=aliases,
            system=system, journal_path=jpath,
        )
        tc = TincControl(tinc_exe=self.tinc, yaml_path=self.yaml)
        snap = tc.snapshot(net_name)
        if not getattr(snap, "error", ""):
            for line in ft.step(snap, opts, hosts, own, refresh_dns=True):
                self._log_line(net_name, f"[tincmgr] {line}")

    def _live_diag_port(self) -> int:
        if self.diag_port_fn is not None:
            try:
                return max(0, int(self.diag_port_fn() or 0))
            except Exception:
                return 0
        try:
            import diagnostics
            return diagnostics.live_diag_port(self.base)
        except Exception:
            return 0

    def _sync_diag_port(self, net_name: str, sync: bool = False) -> None:
        port = self._live_diag_port()

        def _bg() -> None:
            try:
                TincControl(tinc_exe=self.tinc, yaml_path=self.yaml).diag_port(
                    net_name, port, timeout=3.0
                )
            except Exception:
                pass

        if sync:
            _bg()
        else:
            threading.Thread(target=_bg, name=f"diag-port-{net_name}", daemon=True).start()

    def _log_line(self, net_name: str, text: str) -> None:
        # own file (separate from the daemon's log), protected by private DACL
        try:
            with paths.open_private_append(os.path.join(self.base, net_name + "-tincmgr.log")) as f:
                f.write(text + "\n")
        except Exception:
            pass

    def _apply_wintun_mtu(self, net_name: str) -> None:
        """Clamp the Wintun adapter's IPv4 MTU once tincd has created it. Wintun
        defaults to MTU 65535 → Windows advertises a huge TCP MSS and fragments
        large packets over the tunnel; force the configured value (default 1400)
        via the Win32 IP Helper API (no netsh)."""
        nc = self.app.net(net_name)
        if not nc or nc.device_type not in ("", "wintun"):
            return
        mtu = nc.wintun_mtu or 1400
        try:
            import netmtu
        except Exception as e:
            self._log_line(net_name, f"[tincmgr] wintun MTU: import failed: {e}")
            return
        aliases = routes.adapter_aliases(nc.options, net_name)
        try:
            ok, msg = netmtu.set_interface_mtu(aliases, mtu)
        except Exception as e:
            ok, msg = False, f"exception: {e}"
        if ok:
            self._log_line(net_name, f"[tincmgr] wintun MTU: {msg}")
        else:
            # not the same line as a success: the adapter keeps Wintun's MTU
            # 65535, Windows advertises a huge MSS and large packets fragment
            self._log_line(net_name, f"[tincmgr] wintun MTU clamp to {mtu} FAILED: {msg}")

    def stop(self, net_name: str, timeout: float = 10.0) -> tuple[bool, str]:
        with self._op_lock:
            return self._stop_locked(net_name, timeout=timeout)

    def _stop_locked(self, net_name: str, timeout: float = 10.0) -> tuple[bool, str]:
        # the split routes and pins go first, while the adapter still exists
        self._full_tunnel_off(net_name)
        # graceful: tincd removes its Wintun adapter on a clean stop
        self._tinc(net_name, "stop", timeout=timeout)
        proc = self._procs.get(net_name)
        pid_file = os.path.join(self.runtime_dir(net_name), "pid")
        deadline = time.time() + timeout
        while time.time() < deadline:
            if proc is not None:
                if proc.poll() is not None:
                    break
            else:
                if not os.path.exists(pid_file) and not self.is_running(net_name):
                    break
            time.sleep(0.25)
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    proc.kill()
                except OSError:
                    pass
        self._procs.pop(net_name, None)
        sink = self._sinks.pop(net_name, None)
        if sink:
            sink.join(timeout=2)
        self._kill_orphan_daemons(net_name)
        return (not self.is_running(net_name)), "stopped"

    def restart(self, net_name: str, detached: bool = False) -> tuple[bool, str]:
        with self._op_lock:
            self._stop_locked(net_name)
            return self._start_locked(net_name, detached=detached)

    # -- full tunnel: all IPv4 traffic through the exit node (fulltunnel.py) --
    def _ft_sys(self) -> "fulltunnel.System | None":
        return self._ft_system if self._ft_system is not None else fulltunnel.system()

    def full_tunnel_journal_path(self, net_name: str) -> str:
        return os.path.join(self.runtime_dir(net_name), "fulltunnel.json")

    def _daemon_alive(self, net_name: str) -> bool:
        return self.has_live_process(net_name) or self.is_running(net_name)

    def _full_tunnel_off(self, net_name: str) -> None:
        with self._ft_lock:
            m = self._ft.pop(net_name, None)
            if m is not None:
                m.stop()
        jpath = self.full_tunnel_journal_path(net_name)
        if os.path.isfile(jpath):
            with yaml_config._MEM_LOCK:
                nc = self.app.net(net_name)
                opts = dict(nc.options) if nc else {}
            aliases = routes.adapter_aliases(opts, net_name)
            for line in fulltunnel.cleanup_journal(jpath, self._ft_sys(), aliases):
                self._log_line(net_name, f"[tincmgr] {line}")

    def active_full_tunnel_net(self, exclude: str = "") -> str:
        """Return another network name that currently has an active FullTunnel
        Maintainer (or '' if none)."""
        with self._ft_lock:
            for other in self._ft:
                if other != exclude:
                    return other
        return ""

    def full_tunnel_exit(self, net_name: str) -> str:
        """Exit node currently maintained for `net_name`, or '' when off."""
        with self._ft_lock:
            m = self._ft.get(net_name)
        return m.exit_node if m else ""

    def full_tunnel_sync(self, net_name: str) -> str:
        """Make the maintainer match the config: running while `full_tunnel`
        names an exit node and the daemon runs, stopped (split routes and pins
        removed) otherwise. Serialized under `_op_lock` + `_ft_lock`, and
        refuses activating simultaneous full-tunnel maintainers on two networks."""
        with self._op_lock:
            with self._ft_lock:
                with yaml_config._MEM_LOCK:
                    nc = self.app.net(net_name)
                    want = nc.full_tunnel if nc else ""
                    opts_snap = dict(nc.options) if nc else {}
                jpath = self.full_tunnel_journal_path(net_name)
                aliases = routes.adapter_aliases(opts_snap, net_name)
                cur = self._ft.get(net_name)
                if cur is not None and cur.exit_node != want:
                    self._full_tunnel_off(net_name)
                    cur = None
                if not want:
                    if os.path.isfile(jpath):
                        for line in fulltunnel.cleanup_journal(jpath, self._ft_sys(), aliases):
                            self._log_line(net_name, f"[tincmgr] {line}")
                    return "full tunnel off"
                if cur is not None:
                    return f"full tunnel via {want}: {cur.ft.state}"
                other_ft = self.active_full_tunnel_net(exclude=net_name)
                if other_ft:
                    return f"full tunnel via {want} refused: full tunnel is already active on '{other_ft}'"
                system = self._ft_sys()
                if system is None:
                    return f"full tunnel via {want} saved; routes are only applied on Windows"
                if not self._daemon_alive(net_name):
                    return f"full tunnel via {want} saved; applied when '{net_name}' starts"
                self._all_stopped = False
                if os.path.isfile(jpath):
                    for line in fulltunnel.cleanup_journal(jpath, system, aliases):
                        self._log_line(net_name, f"[tincmgr] {line}")
                paths.mkdir_private(self.runtime_dir(net_name))
                ft = fulltunnel.FullTunnel(net=net_name, exit_node=want,
                                           aliases=aliases,
                                           system=system,
                                           journal_path=jpath)
                tc = TincControl(tinc_exe=self.tinc, yaml_path=self.yaml)

                def config() -> tuple[dict, dict, str]:
                    with yaml_config._MEM_LOCK:
                        cfg = self.app.net(net_name)
                        if cfg is None:
                            return {}, {}, ""
                        return dict(cfg.options), dict(cfg.hosts), cfg.node_name

                m = fulltunnel.Maintainer(ft, lambda: tc.snapshot(net_name), config,
                                          lambda line: self._log_line(net_name, f"[tincmgr] {line}"),
                                          interval=self._ft_interval)
                self._ft[net_name] = m
                m.start()
                return f"full tunnel via {want}: starting"

    def full_tunnel_state(self, net_name: str) -> str:
        """What the maintainer is doing right now, '' when it is not running."""
        with self._ft_lock:
            m = self._ft.get(net_name)
        return m.ft.state if m else ""

    def start_autostart(self) -> list[tuple[str, bool, str]]:
        results = []
        with yaml_config._MEM_LOCK:
            nets = [(name, nc.autostart) for name, nc in self.app.networks.items()]
        for name, autostart in nets:
            if autostart:
                ok, msg = self.start(name)
                results.append((name, ok, msg))
        return results

    def stop_all(self) -> None:
        with self._op_lock:
            if self._all_stopped and not self._procs and not self._ft:
                return
            with yaml_config._MEM_LOCK:
                net_names = list(self.app.networks)
            for name in net_names:
                if self.is_running(name) or name in self._procs:
                    self._stop_locked(name, timeout=5.0)
                else:
                    self._full_tunnel_off(name)
            for name in list(self._ft):
                self._full_tunnel_off(name)
            self._all_stopped = True

    def status(self, net: str) -> str:
        return "running" if self.is_running(net) else "stopped"

    # -- key generation: generate in a throwaway dir, fold PEM + self host into the YAML --
    def generate_keys(self, net_name: str, bits: int = 0) -> tuple[bool, str]:
        with yaml_config._MEM_LOCK:
            nc = self.app.net(net_name)
            if not nc:
                return False, f"network '{net_name}' not in config"
            node_name = nc.node_name
        if not node_name:
            return False, "set the network's Name option before generating keys"
        os.makedirs(self.base or ".", exist_ok=True)
        tmp = paths.mkdir_private(
            os.path.join(self.base or ".", f".tincmgr_keys_{os.getpid()}_{secrets.token_hex(6)}")
        )
        try:
            os.makedirs(os.path.join(tmp, "hosts"), exist_ok=True)
            paths.write_private(
                os.path.join(tmp, "tinc.conf"),
                f"Name = {node_name}\n".encode("utf-8"),
            )
            args = [self.tinc, "-n", net_name, "-c", tmp, "generate-keys"]
            if bits:
                args.append(str(bits))
            p = subprocess.run(args, capture_output=True, text=True, input="\n\n\n\n",
                               timeout=60, creationflags=_NO_WINDOW)
            if p.returncode != 0:
                return False, (p.stdout + p.stderr).strip()[:200]
            new_keys: dict[str, str] = {}
            for ykey, fname in (("ed25519_priv", "ed25519_key.priv"), ("rsa_priv", "rsa_key.priv")):
                fp = os.path.join(tmp, fname)
                if os.path.isfile(fp):
                    with open(fp, "r", encoding="utf-8", errors="replace") as f:
                        new_keys[ykey] = f.read().rstrip("\n")
            # fold the freshly generated PUBLIC keys into our self host file but
            # KEEP its existing Subnet/Address/Port (generate emits pubkeys only)
            fresh_host: str | None = None
            sh = os.path.join(tmp, "hosts", node_name)
            if os.path.isfile(sh):
                with open(sh, "r", encoding="utf-8", errors="replace") as f:
                    fresh_host = f.read()
            with yaml_config._MEM_LOCK:
                nc = self.app.net(net_name)
                if not nc:
                    return False, f"network '{net_name}' not in config"
                nc.keys.update(new_keys)
                if fresh_host is not None:
                    nc.hosts[node_name] = merge_pubkeys(nc.hosts.get(node_name, ""), fresh_host)
            return True, "keys generated"
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    import yaml_config
    app = yaml_config.load(sys.argv[1])
    rt = Runtime(app)
    print("yaml:", rt.yaml, "| tincd:", rt.tincd, "exists:", os.path.isfile(rt.tincd))
    for name in app.networks:
        print(f"  {name}: running={rt.is_running(name)}")
