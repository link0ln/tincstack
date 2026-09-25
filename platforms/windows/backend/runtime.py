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
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from typing import IO

import paths
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
        self._f = open(self.path, "ab", buffering=0)
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
                 log_backups: int = LOG_BACKUPS) -> None:
        self.app = app
        self.yaml = os.path.abspath(app.path)
        self.base = os.path.dirname(self.yaml)
        self.log_max_bytes = log_max_bytes
        self.log_backups = log_backups
        self._procs: dict[str, subprocess.Popen] = {}
        self._sinks: dict[str, LogSink] = {}
        self._fw_done = False
        self._ensure_bins()

    def _ensure_bins(self) -> None:
        """Windows: copy the bundled tincd/tinc (+ wintun.dll) to a STABLE bin
        dir and run from there. A onefile exe unpacks to a random %TEMP% path
        each launch; Windows Firewall keys rules by program path, so a stable
        path stops the repeated 'allow tincd' prompts (and lets us pre-add a
        firewall rule that persists). Elevated, that dir is under Program
        Files (paths.bin_stage_dir): a daemon run as administrator from a
        user-writable folder is a privilege escalation. Files are compared by
        SHA-256 (paths.stage_file), so an upgrade replaces them even when the
        size did not change. Elsewhere: use the resolved paths as they are
        (resources/, $TINCSTACK_BIN_DIR or $PATH)."""
        self.tincd = paths.tincd_exe()
        self.tinc = paths.tinc_exe()
        self.bindir = os.path.dirname(self.tincd)
        self.stage_note = ""
        if sys.platform != "win32":
            return
        import management
        names = ["tincd.exe", "tinc.exe", "wintun.dll"]
        bindir = paths.bin_stage_dir(management.is_admin())
        # The onefile carries a manifest of its own files (paths.bundle()):
        # its unpack dir is writable by the user's unelevated processes, and
        # tincd.exe there is not even open, so it is checked, not trusted.
        b = paths.bundle()
        try:
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
            self.tincd = os.path.join(bindir, "tincd.exe")
            self.tinc = os.path.join(bindir, "tinc.exe")
            self.bindir = bindir
        except paths.IntegrityError as e:
            # Never fall back to the file that failed the check: keep what is
            # staged (it passed the check when it was staged), or nothing.
            self.tincd = os.path.join(bindir, "tincd.exe")
            self.tinc = os.path.join(bindir, "tinc.exe")
            self.bindir = bindir
            self.stage_note = f"refused to stage the bundled core: {e}"
        except OSError as e:
            # Most likely a daemon from the previous version still runs from
            # bindir and holds the file. Run the bundled copy instead of the
            # stale staged one, and say so.
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

    def is_running(self, net: str) -> bool:
        rc, _ = self._tinc(net, "dump", "nodes", timeout=5.0)
        return rc == 0

    # -- lifecycle --
    def start(self, net_name: str) -> tuple[bool, str]:
        nc = self.app.net(net_name)
        if nc is None:
            return False, f"network '{net_name}' not in config"
        if not os.path.isfile(self.tincd):
            return False, f"tincd not found: {self.tincd}"
        if self.is_running(net_name):
            return True, "already running"
        # No key check here: the core materialises Name/keys/pool on first start
        # (M1 zero-config) — an empty network stanza is a valid starting point.
        # pre-allow tincd (stable path) through the firewall so Windows doesn't
        # prompt on launch
        if sys.platform == "win32" and not self._fw_done:
            try:
                import management
                management.set_firewall_allow(self.tincd)
            except Exception:
                pass
            self._fw_done = True
        os.makedirs(self.runtime_dir(net_name), exist_ok=True)
        try:
            # default debug level (notices/warnings/errors only) — -d2 floods the
            # log with per-connection lines
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
        if sys.platform == "win32" and nc.device_type == "wintun":
            threading.Thread(target=self._apply_wintun_mtu, args=(net_name,),
                             name=f"mtu-{net_name}", daemon=True).start()
        for _ in range(20):
            time.sleep(0.25)
            if proc.poll() is not None:
                return False, f"tincd exited rc={proc.returncode} (see {self.log_path(net_name)})"
            if self.is_running(net_name):
                return True, "started"
        return True, "started (control not yet responding)"

    def _log_line(self, net_name: str, text: str) -> None:
        # own file (separate from the daemon's log)
        try:
            with open(os.path.join(self.base, net_name + "-tincmgr.log"), "a",
                      encoding="utf-8") as f:
                f.write(text + "\n")
        except Exception:
            pass

    def _apply_wintun_mtu(self, net_name: str) -> None:
        """Clamp the Wintun adapter's IPv4 MTU once tincd has created it. Wintun
        defaults to MTU 65535 → Windows advertises a huge TCP MSS and fragments
        large packets over the tunnel; force the configured value (default 1400)
        via the Win32 IP Helper API (no netsh)."""
        nc = self.app.net(net_name)
        if not nc or nc.device_type != "wintun":
            return
        mtu = nc.wintun_mtu or 1400
        try:
            import netmtu
        except Exception as e:
            self._log_line(net_name, f"[tincmgr] wintun MTU: import failed: {e}")
            return
        aliases = [net_name]
        for k in ("WintunInterface", "Interface"):
            v = nc.options.get(k)
            if v and str(v) not in aliases:
                aliases.append(str(v))
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

    def stop(self, net_name: str, timeout: float = 8.0) -> tuple[bool, str]:
        # graceful: tincd removes its Wintun adapter on a clean stop
        self._tinc(net_name, "stop", timeout=timeout)
        proc = self._procs.get(net_name)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not self.is_running(net_name) and (proc is None or proc.poll() is not None):
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
        return (not self.is_running(net_name)), "stopped"

    def restart(self, net_name: str) -> tuple[bool, str]:
        self.stop(net_name)
        return self.start(net_name)

    def start_autostart(self) -> list[tuple[str, bool, str]]:
        results = []
        for name, nc in self.app.networks.items():
            if nc.autostart:
                ok, msg = self.start(name)
                results.append((name, ok, msg))
        return results

    def stop_all(self) -> None:
        for name in list(self.app.networks):
            if self.is_running(name) or name in self._procs:
                self.stop(name, timeout=5.0)

    def status(self, net: str) -> str:
        return "running" if self.is_running(net) else "stopped"

    # -- key generation: generate in a throwaway dir, fold PEM + self host into the YAML --
    def generate_keys(self, net_name: str, bits: int = 0) -> tuple[bool, str]:
        nc = self.app.net(net_name)
        if not nc:
            return False, f"network '{net_name}' not in config"
        if not nc.node_name:
            return False, "set the network's Name option before generating keys"
        tmp = tempfile.mkdtemp(prefix="tincmgr_keys_")
        try:
            os.makedirs(os.path.join(tmp, "hosts"), exist_ok=True)
            with open(os.path.join(tmp, "tinc.conf"), "w", encoding="utf-8") as f:
                f.write(f"Name = {nc.node_name}\n")
            args = [self.tinc, "-n", net_name, "-c", tmp, "generate-keys"]
            if bits:
                args.append(str(bits))
            p = subprocess.run(args, capture_output=True, text=True, input="\n\n\n\n",
                               timeout=60, creationflags=_NO_WINDOW)
            if p.returncode != 0:
                return False, (p.stdout + p.stderr).strip()[:200]
            for ykey, fname in (("ed25519_priv", "ed25519_key.priv"), ("rsa_priv", "rsa_key.priv")):
                fp = os.path.join(tmp, fname)
                if os.path.isfile(fp):
                    with open(fp, "r", encoding="utf-8", errors="replace") as f:
                        nc.keys[ykey] = f.read().rstrip("\n")
            # fold the freshly generated PUBLIC keys into our self host file but
            # KEEP its existing Subnet/Address/Port (generate emits pubkeys only)
            sh = os.path.join(tmp, "hosts", nc.node_name)
            if os.path.isfile(sh):
                with open(sh, "r", encoding="utf-8", errors="replace") as f:
                    fresh = f.read()
                nc.hosts[nc.node_name] = merge_pubkeys(nc.hosts.get(nc.node_name, ""), fresh)
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
