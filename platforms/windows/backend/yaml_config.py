"""
yaml_config.py — the single, self-contained YAML config (docs/config-schema.md).

One file describes every network: the tinc.conf options, the host files, the
private keys and whether to auto-start:

    workdir: tincmgr-data        # optional; where runtime side-files go
    networks:
      gnet2:
        autostart: true
        options:                 # -> tinc.conf  (scalar => one line, list => many)
          Name: gnet2book
          Mode: router
          Port: 0
          PreferredTransports: [quic, plain]
        keys:
          ed25519_priv: |
            -----BEGIN ED25519 PRIVATE KEY-----
            ...
        hosts:
          gnet2book: |
            Ed25519PublicKey = ...
            Subnet = 10.210.0.1/32

This module only models / (de)serialises the config. runtime.py drives tincd
against it; the daemon reads AND writes the same file (learned peer keys,
zero-config materialisation), so this module treats the daemon as a concurrent
writer:

  * `load()` raises ConfigError (never a bare YAML exception) on a malformed
    file, and remembers the document it loaded as the *baseline*.
  * `save()` re-reads the file, applies only the keys that changed relative to
    the baseline, and writes atomically (temp file + fsync + rename). It never
    truncates the file in place and never clobbers keys the daemon added in
    the meantime.
"""

from __future__ import annotations

import copy
import os
import re
import secrets
import stat
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Any

import yaml


class ConfigError(Exception):
    """The YAML file is unreadable or does not have the expected shape."""


# ---- model -------------------------------------------------------------------

@dataclass
class NetworkCfg:
    name: str                                   # the network key (tinc -n <name>)
    autostart: bool = False
    options: dict = field(default_factory=dict)  # tinc.conf options (scalar or list)
    hosts: dict = field(default_factory=dict)    # host name -> raw host-file text
    keys: dict = field(default_factory=dict)     # 'ed25519_priv' / 'rsa_priv' / 'tls_*' -> PEM
    scripts: dict = field(default_factory=dict)  # 'tinc-up'/... -> script text
    wintun_mtu: int = 0                           # forced IPv4 MTU on the Wintun adapter (0 = 1400)
    full_tunnel: str = ""                         # exit node for all IPv4 traffic ('' = off), fulltunnel.py
    extra: dict = field(default_factory=dict)    # unknown per-network keys, carried verbatim

    @property
    def node_name(self) -> str:
        return _scalar(self.options.get("Name", ""))

    @property
    def device_type(self) -> str:
        return _scalar(self.options.get("DeviceType", "")).lower()

    @property
    def wintun_address(self) -> str:
        return _scalar(self.options.get("WintunAddress", ""))


@dataclass
class AppConfig:
    path: str = ""
    workdir: str = ""
    networks: dict = field(default_factory=dict)  # net name -> NetworkCfg
    extra: dict = field(default_factory=dict)     # unknown top-level keys, carried verbatim
    # the document as last read from / written to disk; `save()` diffs against it
    baseline: dict = field(default_factory=dict, repr=False, compare=False)

    def net(self, name: str) -> NetworkCfg | None:
        return self.networks.get(name)


# ---- helpers -----------------------------------------------------------------

_NET_KEYS = ("autostart", "options", "hosts", "keys", "scripts", "wintun_mtu", "full_tunnel")


def _scalar(v: Any) -> str:
    if isinstance(v, list):
        return str(v[0]) if v else ""
    return "" if v is None else str(v)


def _yaml_bool(v: Any) -> str:
    return "yes" if v else "no"


def options_to_conf(options: dict) -> str:
    """Render an options dict into tinc.conf text.

    scalar  -> 'Key = value'      (bool -> yes/no)
    list    -> one 'Key = item' line per element (e.g. ConnectTo, Subnet)
    """
    lines: list[str] = []
    for key, val in options.items():
        if isinstance(val, (list, tuple)):
            for item in val:
                lines.append(f"{key} = {_fmt(item)}")
        else:
            lines.append(f"{key} = {_fmt(val)}")
    return "\n".join(lines) + ("\n" if lines else "")


def _fmt(v: Any) -> str:
    if isinstance(v, bool):
        return _yaml_bool(v)
    return str(v)


_STR_OPTIONS = frozenset(k.lower() for k in (
    "Name", "Interface", "WintunInterface", "WintunAddress", "InterfaceAddress",
    "InterfaceRoute", "AddressPool", "ConnectTo", "NoDirectNodes", "BlockedNodes",
    "HttpsSni", "QuicSni", "QuicAlpn", "CertDomain", "CloudflareToken",
    "CloudflareApi", "AcmeContact", "AcmeDirectory", "AcmeCaFile",
    "Device", "DeviceType", "Mode", "AddressFamily", "Broadcast", "Forwarding",
    "SingleFlow", "MultipathMode", "MultipathInterface", "ScriptsInterpreter",
    "ScriptsExtension", "HttpsDecoyRoot", "HttpsDecoyUpstream", "TlsCert", "TlsKey",
    "ObfsInitMagicHeader", "ObfsTransportMagicHeader", "Proxy",
    "Ed25519PrivateKey", "Ed25519PrivateKeyFile", "PrivateKey", "PrivateKeyFile",
))
_INT_RE = re.compile(r"(?:0|-?[1-9]\d*)")


def _coerce(v: str, key: str = "") -> Any:
    """'yes'/'no' -> bool, canonical integers -> int, else the trimmed string.
    String-typed options stay str even when their value looks like bool/int."""
    s = v.strip()
    if key and key.strip().lower() in _STR_OPTIONS:
        return s
    low = s.lower()
    if low in ("yes", "true"):
        return True
    if low in ("no", "false"):
        return False
    if _INT_RE.fullmatch(s):
        try:
            return int(s)
        except ValueError:
            pass
    return s


def conf_to_options(text: str) -> dict:
    """Inverse of options_to_conf: parse tinc.conf text into an options dict.
    A key seen once becomes a scalar; repeated keys become a list."""
    multi: dict[str, list] = {}
    order: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, val = line.split("=", 1)
        k = k.strip()
        if k not in multi:
            order.append(k)
        multi.setdefault(k, []).append(val.strip())
    opts: dict = {}
    for k in order:
        vals = multi[k]
        opts[k] = _coerce(vals[0], k) if len(vals) == 1 else [_coerce(x, k) for x in vals]
    return opts


# ---- raw document I/O --------------------------------------------------------

def parse_text(text: str, path: str = "<string>") -> dict:
    """Parse YAML text into the raw document dict; ConfigError on any problem."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ConfigError(f"{path}: malformed YAML: {e}") from e
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be a mapping, got {type(data).__name__}")
    nets = data.get("networks")
    if nets is not None and not isinstance(nets, dict):
        raise ConfigError(f"{path}: 'networks' must be a mapping, got {type(nets).__name__}")
    for name, nd in (nets or {}).items():
        if nd is not None and not isinstance(nd, dict):
            raise ConfigError(f"{path}: network '{name}' must be a mapping")
        for sect in ("options", "hosts", "keys", "scripts"):
            v = (nd or {}).get(sect)
            if v is not None and not isinstance(v, dict):
                raise ConfigError(f"{path}: networks.{name}.{sect} must be a mapping")
    return data


def read_document(path: str) -> dict:
    """Read the raw document from disk. Missing file -> {}. Malformed -> ConfigError."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError:
        return {}
    except OSError as e:
        raise ConfigError(f"{path}: {e}") from e
    return parse_text(text, path)


def atomic_write_text(path: str, text: str, mode: int = 0o600) -> None:
    """Write `text` to `path` atomically: temp file in the same directory,
    fsync, then rename over the target. The target is never truncated in
    place, so a crash mid-write leaves either the old or the new file — never
    a half-written one over the only copy of the private keys.

    On Windows the temporary is created with paths.private_sddl()'s protected
    DACL -- the one the core writes the config with -- and the rename keeps it,
    so the keys never sit under an inherited ACL (Program Files: Users may
    read). mkstemp's mode bits mean nothing to Windows."""
    path = os.path.abspath(path)
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)   # keep the existing mode
    except OSError:
        pass
    if sys.platform == "win32":
        import paths
        tmp = os.path.join(d, f".tinc.yaml.{os.getpid()}.{secrets.token_hex(6)}.tmp")
        fd = paths.open_private_new(tmp)
    else:
        fd, tmp = tempfile.mkstemp(prefix=".tinc.yaml.", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(tmp, mode)
        except OSError:
            pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    if hasattr(os, "O_DIRECTORY"):   # POSIX: persist the rename itself
        try:
            dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass


# literal block style for multi-line strings (keys, host files) -> readable YAML
class _Dumper(yaml.SafeDumper):
    # PyYAML writes block sequences "indentless": the dashes sit at the
    # indentation of their own key. That is valid YAML and the daemon reads
    # it, but the daemon's emitter indents them, so without this every save
    # from here reshuffled the file. Match the C emitter and keep one style.
    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)


def _str_representer(dumper: yaml.SafeDumper, data: str):
    style = "|" if "\n" in data else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


_Dumper.add_representer(str, _str_representer)


def dump_text(doc: dict) -> str:
    return yaml.dump(doc, Dumper=_Dumper, sort_keys=False,
                     default_flow_style=False, allow_unicode=True, width=10000)


# ---- model <-> document ------------------------------------------------------

def from_document(doc: dict, path: str = "") -> AppConfig:
    app = AppConfig(path=path, workdir=str(doc.get("workdir", "") or ""))
    app.extra = {k: copy.deepcopy(v) for k, v in doc.items() if k not in ("workdir", "networks")}
    for name, nd in (doc.get("networks") or {}).items():
        nd = nd or {}
        app.networks[name] = NetworkCfg(
            name=name,
            autostart=bool(nd.get("autostart", False)),
            options=copy.deepcopy(dict(nd.get("options") or {})),
            hosts=copy.deepcopy(dict(nd.get("hosts") or {})),
            keys=copy.deepcopy(dict(nd.get("keys") or {})),
            scripts=copy.deepcopy(dict(nd.get("scripts") or {})),
            wintun_mtu=int(nd.get("wintun_mtu") or 0),
            full_tunnel=str(nd.get("full_tunnel") or "").strip(),
            extra={k: copy.deepcopy(v) for k, v in nd.items() if k not in _NET_KEYS},
        )
    app.baseline = copy.deepcopy(doc)
    return app


def to_dict(app: AppConfig) -> dict:
    out: dict = {}
    if app.workdir:
        out["workdir"] = app.workdir
    nets: dict = {}
    for name, nc in app.networks.items():
        entry: dict = {"autostart": nc.autostart, "options": nc.options}
        if nc.wintun_mtu:
            entry["wintun_mtu"] = nc.wintun_mtu
        if nc.full_tunnel:
            entry["full_tunnel"] = nc.full_tunnel
        if nc.keys:
            entry["keys"] = nc.keys
        if nc.scripts:
            entry["scripts"] = nc.scripts
        if nc.hosts:
            entry["hosts"] = nc.hosts
        entry.update(nc.extra)
        nets[name] = entry
    out["networks"] = nets
    out.update(app.extra)
    return out


def load(path: str) -> AppConfig:
    """Load the config; ConfigError if the file is malformed."""
    return from_document(read_document(path), path)


# ---- diff / patch (the concurrent-writer contract) ---------------------------

class _Delete:
    def __repr__(self) -> str:
        return "DELETE"


DELETE = _Delete()

# sections whose children are merged key-by-key; everything else is a leaf
_MERGE_DEPTHS = {
    (): True, ("networks",): True, ("networks", "*"): True,
    ("networks", "*", "options"): True, ("networks", "*", "hosts"): True,
    ("networks", "*", "keys"): True, ("networks", "*", "scripts"): True,
}


def _mergeable(path: tuple) -> bool:
    """True for mapping levels that are merged key-by-key (network names are
    wildcarded), False for leaves (host texts, option values, lists)."""
    key = tuple("*" if i == 1 else p for i, p in enumerate(path))
    return _MERGE_DEPTHS.get(key, False)


def diff_documents(old: dict, new: dict, path: tuple = ()) -> dict[tuple, Any]:
    """Minimal patch turning `old` into `new`: {path_tuple: value | DELETE}.
    Mappings at known levels are compared key by key; leaves by equality."""
    patch: dict[tuple, Any] = {}
    keys = list(old.keys()) + [k for k in new.keys() if k not in old]
    for k in keys:
        p = path + (k,)
        if k not in new:
            patch[p] = DELETE
        elif k not in old:
            patch[p] = copy.deepcopy(new[k])
        else:
            ov, nv = old[k], new[k]
            if isinstance(ov, dict) and isinstance(nv, dict) and _mergeable(p):
                patch.update(diff_documents(ov, nv, p))
            elif ov != nv or type(ov) is not type(nv):
                patch[p] = copy.deepcopy(nv)
    return patch


_HOST_LEARNED_KV_SPECS = (
    ("Ed25519PublicKey", re.compile(r"^[ \t]*Ed25519PublicKey[ \t]*=[ \t]*(.+?)[ \t]*$", re.IGNORECASE | re.MULTILINE)),
    ("TlsFingerprint", re.compile(r"^[ \t]*TlsFingerprint[ \t]*=[ \t]*(.+?)[ \t]*$", re.IGNORECASE | re.MULTILINE)),
)
_HOST_RSA_PEM_RE = re.compile(
    r"-----BEGIN RSA PUBLIC KEY-----.*?-----END RSA PUBLIC KEY-----",
    re.DOTALL,
)


def merge_learned_host_keys(base_text: str, disk_text: str, wanted_text: str) -> str:
    """Preserve daemon-learned host identity lines (Ed25519PublicKey,
    TlsFingerprint, RSA PUBLIC KEY) added or updated on disk since `base_text`
    when the user did not explicitly change that key in `wanted_text`."""
    if not disk_text or disk_text == base_text:
        return wanted_text
    trailing_nl = wanted_text.endswith("\n")
    out = wanted_text.rstrip("\n")
    for canon, rx in _HOST_LEARNED_KV_SPECS:
        b_m = rx.search(base_text or "")
        d_m = rx.search(disk_text)
        w_m = rx.search(out)
        b_val = b_m.group(1) if b_m else None
        d_val = d_m.group(1) if d_m else None
        w_val = w_m.group(1) if w_m else None
        if d_val and d_val != b_val and w_val == b_val:
            line = f"{canon} = {d_val}"
            if w_m:
                out = rx.sub(lambda _m, ln=line: ln, out, count=1)
            else:
                out = f"{out}\n{line}" if out else line
    b_rsa = _HOST_RSA_PEM_RE.search(base_text or "")
    d_rsa = _HOST_RSA_PEM_RE.search(disk_text)
    w_rsa = _HOST_RSA_PEM_RE.search(out)
    b_pem = b_rsa.group(0).strip() if b_rsa else None
    d_pem = d_rsa.group(0).strip() if d_rsa else None
    w_pem = w_rsa.group(0).strip() if w_rsa else None
    if d_pem and d_pem != b_pem and w_pem == b_pem:
        if w_rsa:
            out = _HOST_RSA_PEM_RE.sub(lambda _m, pem=d_pem: pem, out, count=1)
        else:
            out = f"{out}\n{d_pem}" if out else d_pem
    return (out + "\n") if trailing_nl and out else out


def apply_patch(doc: dict, patch: dict[tuple, Any], baseline: dict | None = None) -> dict:
    doc = copy.deepcopy(doc)
    for p, v in patch.items():
        node = doc
        for k in p[:-1]:
            child = node.get(k)
            if not isinstance(child, dict):
                child = {}
                node[k] = child
            node = child
        if v is DELETE:
            node.pop(p[-1], None)
        else:
            val = copy.deepcopy(v)
            if (len(p) == 4 and p[0] == "networks" and p[2] == "hosts"
                    and isinstance(val, str)):
                disk_host = node.get(p[-1])
                base_host = ""
                if isinstance(baseline, dict):
                    base_host = ((((baseline.get("networks") or {}).get(p[1]) or {})
                                  .get("hosts") or {}).get(p[3]) or "")
                if isinstance(disk_host, str):
                    val = merge_learned_host_keys(str(base_host), disk_host, val)
            node[p[-1]] = val
    return doc


from contextlib import contextmanager
import threading
import time

_MEM_LOCK = threading.RLock()


@contextmanager
def _file_lock(path: str):
    """Acquire `<path>.lock` using the same protocol as C `yamlconf_lock()` so
    concurrent daemon/CLI/GUI read-modify-writes serialize cleanly."""
    lockpath = os.path.abspath(path) + ".lock"
    d = os.path.dirname(lockpath)
    if d:
        os.makedirs(d, exist_ok=True)
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        k32.CreateFileW.restype = wintypes.HANDLE
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.CloseHandle.restype = wintypes.BOOL
        invalid = wintypes.HANDLE(-1).value
        handle = None
        for _ in range(200):
            h = k32.CreateFileW(lockpath, 0xC0000000, 0, None, 4, 0x80, None)
            if h not in (None, 0, -1, invalid):
                handle = h
                break
            time.sleep(0.05)
        if handle is None:
            raise ConfigError(f"{path}: timed out waiting for lock {lockpath}")
        try:
            yield
        finally:
            k32.CloseHandle(handle)
    else:
        import fcntl
        fd = os.open(lockpath, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)


def save(app: AppConfig, path: str | None = None) -> str:
    """Persist `app`.

    Saving to the config's own path is a *merge*: the file is re-read, only the
    keys that changed since the baseline are applied on top of it, and the
    result is written atomically. A file that no longer parses is refused
    (ConfigError) rather than overwritten. Saving to another path is a plain
    full export.
    """
    with _MEM_LOCK:
        target = path or app.path
        if not target:
            raise ConfigError("no path to save to")
        wanted = to_dict(app)
        if path and os.path.abspath(path) != os.path.abspath(app.path or ""):
            with _file_lock(target):
                atomic_write_text(target, dump_text(wanted))
            return target
        patch = diff_documents(app.baseline, wanted)
        with _file_lock(target):
            current = read_document(target)          # the daemon may have written meanwhile
            merged = apply_patch(current, patch, app.baseline) if patch else current
            if patch or not os.path.exists(target):
                atomic_write_text(target, dump_text(merged))
        # absorb what the daemon wrote so the model (and the next diff) start from
        # the file as it is now, not from the GUI's stale view of it
        refresh_in_place(app, merged)
        return target


def refresh_in_place(app: AppConfig, doc: dict) -> None:
    """Update `app` from a raw document without replacing the NetworkCfg
    objects the GUI may still hold references to."""
    with _MEM_LOCK:
        fresh = from_document(doc, app.path)
        app.workdir = fresh.workdir
        app.extra = fresh.extra
        for name in list(app.networks):
            if name not in fresh.networks:
                del app.networks[name]
        for name, fnc in fresh.networks.items():
            nc = app.networks.get(name)
            if nc is None:
                app.networks[name] = fnc
                continue
            nc.autostart = fnc.autostart
            nc.wintun_mtu = fnc.wintun_mtu
            nc.full_tunnel = fnc.full_tunnel
            for attr in ("options", "hosts", "keys", "scripts", "extra"):
                d = getattr(nc, attr)
                src = getattr(fnc, attr)
                for k in list(d):
                    if k not in src:
                        d.pop(k, None)
                d.update(src)
        app.baseline = copy.deepcopy(doc)


def save_text(path: str, text: str) -> None:
    """Raw-editor save: validate the text as a config document, then write it
    atomically. Raises ConfigError instead of writing a broken file."""
    parse_text(text, path)
    with _file_lock(path):
        atomic_write_text(path, text if text.endswith("\n") else text + "\n")


if __name__ == "__main__":
    app = load(sys.argv[1])
    print("workdir:", app.workdir or "(default)")
    for name, nc in app.networks.items():
        print(f"\n=== {name} (autostart={nc.autostart}) ===")
        print("  node name:", nc.node_name, "| device:", nc.device_type or "tap",
              "| addr:", nc.wintun_address or "-")
        print("  hosts:", ", ".join(nc.hosts) or "-")
        print("  keys:", ", ".join(nc.keys) or "-")
        print("  --- tinc.conf ---")
        for ln in options_to_conf(nc.options).splitlines():
            print("   ", ln)
