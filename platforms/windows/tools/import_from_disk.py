"""
import_from_disk.py — migrate an existing on-disk tinc layout into one tinc.yaml.

Reads <conf_base>/<net>/{tinc.conf, hosts/*, ed25519_key.priv, rsa_key.priv}
for each network and emits a single self-contained YAML (the new format).

Reading the private keys needs read access to the key files (run elevated if
they live under C:\\Program Files\\tinc). Unreadable keys are skipped with a
warning so a non-elevated dry run still produces a (keyless) config.

Usage:
  python tools/import_from_disk.py [--conf-base DIR] [--out FILE]
                                   [--nets gnet gnet2] [--autostart-running]
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "backend"))

import yaml_config as yc  # noqa: E402

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _coerce(v: str):
    low = v.strip().lower()
    if low in ("yes", "true"):
        return True
    if low in ("no", "false"):
        return False
    s = v.strip()
    if s.lstrip("-").isdigit():
        try:
            return int(s)
        except ValueError:
            pass
    return v


def parse_conf(path: str) -> dict:
    multi: dict[str, list] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, val = line.split("=", 1)
                multi.setdefault(k.strip(), []).append(val.strip())
    except OSError:
        return {}
    opts: dict = {}
    for k, vals in multi.items():
        opts[k] = _coerce(vals[0]) if len(vals) == 1 else [_coerce(x) for x in vals]
    return opts


def read_text(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read().rstrip("\n")
    except OSError:
        return None


def service_running(net: str) -> bool:
    try:
        p = subprocess.run(["sc", "query", f"tinc.{net}"], capture_output=True,
                           text=True, timeout=6, creationflags=_NO_WINDOW)
        return "RUNNING" in p.stdout.upper()
    except (OSError, subprocess.TimeoutExpired):
        return False


def import_net(conf_base: str, net: str, autostart_running: bool) -> yc.NetworkCfg:
    d = os.path.join(conf_base, net)
    nc = yc.NetworkCfg(name=net)
    nc.options = parse_conf(os.path.join(d, "tinc.conf"))
    # private keys
    for ykey, fname in (("ed25519_priv", "ed25519_key.priv"), ("rsa_priv", "rsa_key.priv")):
        body = read_text(os.path.join(d, fname))
        if body:
            nc.keys[ykey] = body
        elif os.path.isfile(os.path.join(d, fname)):
            print(f"  WARN: {net}/{fname} exists but is unreadable (run elevated)", file=sys.stderr)
    # scripts (tinc-up/down etc.) — carried so YAML-native tincd writes them out
    for sname in ("tinc-up", "tinc-down", "host-up", "host-down", "subnet-up", "subnet-down"):
        body = read_text(os.path.join(d, sname))
        if body is not None:
            nc.scripts[sname] = body
    # hosts
    hosts_dir = os.path.join(d, "hosts")
    try:
        for hn in sorted(os.listdir(hosts_dir)):
            fp = os.path.join(hosts_dir, hn)
            if os.path.isfile(fp):
                body = read_text(fp)
                if body is not None:
                    nc.hosts[hn] = body
    except OSError:
        pass
    nc.autostart = service_running(net) if autostart_running else True
    return nc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--conf-base", default=r"C:\Program Files\tinc")
    ap.add_argument("--out", default=os.path.join(HERE, "..", "tinc.yaml"))
    ap.add_argument("--nets", nargs="*", default=None)
    ap.add_argument("--autostart-running", action="store_true")
    args = ap.parse_args()

    nets = args.nets
    if not nets:
        nets = []
        for name in sorted(os.listdir(args.conf_base)):
            if os.path.isfile(os.path.join(args.conf_base, name, "tinc.conf")):
                nets.append(name)
    print("importing networks:", ", ".join(nets))

    app = yc.AppConfig(workdir="tincmgr-data")
    for net in nets:
        nc = import_net(args.conf_base, net, args.autostart_running)
        app.networks[net] = nc
        print(f"  {net}: node={nc.node_name or '?'} hosts={len(nc.hosts)} "
              f"keys={list(nc.keys)} autostart={nc.autostart}")
    out = os.path.abspath(args.out)
    yc.save(app, out)
    print("wrote", out)


if __name__ == "__main__":
    main()
