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


def _coerce(v: str, key: str = ""):
    return yc._coerce(v, key)


def parse_conf(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return yc.conf_to_options(f.read())
    except OSError:
        return {}


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


def _resolve_conf_file(net_dir: str, raw_path: str) -> str:
    if os.path.isabs(raw_path):
        return raw_path
    return os.path.join(net_dir, raw_path)


def import_net(conf_base: str, net: str, autostart_running: bool) -> yc.NetworkCfg:
    d = os.path.join(conf_base, net)
    nc = yc.NetworkCfg(name=net)
    nc.options = parse_conf(os.path.join(d, "tinc.conf"))

    # Private keys & TLS / ACME material (both default filenames and explicit tinc.conf file options)
    key_specs: list[tuple[str, list[str], str | None]] = [
        ("ed25519_priv", ["ed25519_key.priv"], "Ed25519PrivateKeyFile"),
        ("rsa_priv", ["rsa_key.priv"], "PrivateKeyFile"),
        ("tls_cert", ["tls_cert.pem", "tls.crt", "cert.pem"], "TlsCert"),
        ("tls_key", ["tls_key.pem", "tls.key", "privkey.pem"], "TlsKey"),
        ("acme_account", ["acme_account.key", "acme_account.pem"], None),
    ]
    opts_ci = {k.lower(): k for k in nc.options}
    for ykey, default_names, opt_key in key_specs:
        candidates: list[tuple[str, bool]] = []
        if opt_key and opt_key.lower() in opts_ci:
            actual_opt = opts_ci[opt_key.lower()]
            opt_val = nc.options.get(actual_opt)
            if isinstance(opt_val, str) and opt_val.strip():
                candidates.append((_resolve_conf_file(d, opt_val.strip()), True))
        for fn in default_names:
            candidates.append((os.path.join(d, fn), False))
        for cand_path, from_opt in candidates:
            body = read_text(cand_path)
            if body:
                nc.keys[ykey] = body
                if from_opt and opt_key and opt_key.lower() in opts_ci:
                    nc.options.pop(opts_ci[opt_key.lower()], None)
                break
            if os.path.isfile(cand_path):
                print(
                    f"  WARN: {net}/{os.path.basename(cand_path)} exists but is unreadable (run elevated)",
                    file=sys.stderr,
                )

    # Hook scripts (extensionless on POSIX, plus .bat/.cmd/ScriptsExtension on Windows)
    script_exts = ["", ".bat", ".cmd"]
    if "scriptsextension" in opts_ci:
        raw_ext = str(nc.options.get(opts_ci["scriptsextension"]) or "").strip()
        if raw_ext and raw_ext not in script_exts:
            script_exts.append(raw_ext if raw_ext.startswith(".") else f".{raw_ext}")
    hook_bases = (
        "tinc-up", "tinc-down", "host-up", "host-down",
        "subnet-up", "subnet-down", "invitation-created", "invitation-accepted",
    )
    for sbase in hook_bases:
        for ext in script_exts:
            sname = sbase + ext
            body = read_text(os.path.join(d, sname))
            if body is not None:
                nc.scripts[sname] = body
                break
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
