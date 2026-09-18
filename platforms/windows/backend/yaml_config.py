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
import stat
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

_NET_KEYS = ("autostart", "options", "hosts", "keys", "scripts", "wintun_mtu")


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


def _coerce(v: str) -> Any:
    """'yes'/'no' -> bool, integers -> int, else the trimmed string."""
    s = v.strip()
    low = s.lower()
    if low in ("yes", "true"):
        return True
    if low in ("no", "false"):
        return False
    if s.lstrip("-").isdigit():
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
        opts[k] = _coerce(vals[0]) if len(vals) == 1 else [_coerce(x) for x in vals]
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
    a half-written one over the only copy of the private keys."""
    path = os.path.abspath(path)
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)   # keep the existing mode
    except OSError:
        pass
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


def apply_patch(doc: dict, patch: dict[tuple, Any]) -> dict:
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
            node[p[-1]] = copy.deepcopy(v)
    return doc


def save(app: AppConfig, path: str | None = None) -> str:
    """Persist `app`.

    Saving to the config's own path is a *merge*: the file is re-read, only the
    keys that changed since the baseline are applied on top of it, and the
    result is written atomically. A file that no longer parses is refused
    (ConfigError) rather than overwritten. Saving to another path is a plain
    full export.
    """
    target = path or app.path
    if not target:
        raise ConfigError("no path to save to")
    wanted = to_dict(app)
    if path and os.path.abspath(path) != os.path.abspath(app.path or ""):
        atomic_write_text(target, dump_text(wanted))
        return target
    patch = diff_documents(app.baseline, wanted)
    current = read_document(target)          # the daemon may have written meanwhile
    merged = apply_patch(current, patch) if patch else current
    if patch or not os.path.exists(target):
        atomic_write_text(target, dump_text(merged))
    # absorb what the daemon wrote so the model (and the next diff) start from
    # the file as it is now, not from the GUI's stale view of it
    refresh_in_place(app, merged)
    return target


def refresh_in_place(app: AppConfig, doc: dict) -> None:
    """Update `app` from a raw document without replacing the NetworkCfg
    objects the GUI may still hold references to."""
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
        for attr in ("options", "hosts", "keys", "scripts", "extra"):
            d = getattr(nc, attr)
            d.clear()
            d.update(getattr(fnc, attr))
    app.baseline = copy.deepcopy(doc)


def save_text(path: str, text: str) -> None:
    """Raw-editor save: validate the text as a config document, then write it
    atomically. Raises ConfigError instead of writing a broken file."""
    parse_text(text, path)
    atomic_write_text(path, text if text.endswith("\n") else text + "\n")


if __name__ == "__main__":
    import sys
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
