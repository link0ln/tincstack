#!/usr/bin/env python3
"""
tincmgr CLI — headless (no-GUI) manager for the single-YAML tincstack core.

Same backend as the Windows GUI: drives the YAML-native tincd/tinc against one
tinc.yaml. Works on Linux (binaries from $TINCSTACK_BIN_DIR or $PATH) and on
Windows (bundled resources/).

  tincmgr [-c tinc.yaml] <command>
    list | status            networks and whether they're running
    up [NET | --all]         start NET (or all autostart nets if omitted)
    down [NET | --all]       stop
    restart NET
    peers NET                peer table (direct/relay, via, RTT, subnets)
    invite NET NAME          print the one-line invitation for a new peer
    join [-n NET] STRING     join a network from an invitation string
    genkeys NET              generate keys into the YAML (the daemon does this
                             itself on first start; kept for re-keying)

Run as root on Linux (tincd needs CAP_NET_ADMIN for the tun device).
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend"))

import paths  # noqa: E402
import yaml_config  # noqa: E402
from runtime import Runtime  # noqa: E402
from tinc_control import TincControl  # noqa: E402

LINK_LABEL = {"direct-udp": "direct-udp", "direct-tcp": "direct-tcp",
              "relay": "relay", "down": "down", "self": "self"}


def human(n: int) -> str:
    f = float(n)
    for u in ("B", "K", "M", "G", "T"):
        if f < 1024 or u == "T":
            return f"{f:.0f}{u}"
        f /= 1024
    return f"{f:.0f}T"


def main() -> int:
    ap = argparse.ArgumentParser(prog="tincmgr", description="single-YAML tinc manager (CLI)")
    ap.add_argument("-c", "--config", help="path to tinc.yaml (default: auto-detect)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    sub.add_parser("status")
    for c in ("up", "down"):
        p = sub.add_parser(c)
        p.add_argument("net", nargs="?")
        p.add_argument("--all", action="store_true")
    for c in ("restart", "peers", "genkeys"):
        p = sub.add_parser(c)
        p.add_argument("net")
    p = sub.add_parser("invite")
    p.add_argument("net")
    p.add_argument("name")
    p = sub.add_parser("join")
    p.add_argument("-n", "--net", help="network name to create (default: from the invitation / first)")
    p.add_argument("invitation")
    args = ap.parse_args()

    cfg = paths.find_config(args.config)
    if not cfg:
        if args.config and args.cmd in ("join", "up"):
            cfg = args.config          # a fresh file is fine: the core materialises it
        else:
            print("error: no tinc.yaml found (pass -c PATH)", file=sys.stderr)
            return 2
    try:
        app = yaml_config.load(cfg)
    except yaml_config.ConfigError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    ok, msg = paths.binaries_present()
    if not ok:
        print(f"error: {msg}", file=sys.stderr)
        return 2
    rt = Runtime(app)
    tc = TincControl(tinc_exe=rt.tinc, yaml_path=app.path)

    def listing() -> None:
        print(f"config: {app.path}")
        for name, nc in app.networks.items():
            st = "running" if rt.is_running(name) else "stopped"
            print(f"  {name:16} {st:8}{'  autostart' if nc.autostart else ''}")

    if args.cmd in ("list", "status"):
        listing()

    elif args.cmd == "up":
        if args.all:
            nets = list(app.networks)
        elif args.net:
            nets = [args.net]
            if args.net not in app.networks:
                # a new, empty network: the daemon materialises defaults + keys
                app.networks[args.net] = yaml_config.NetworkCfg(name=args.net)
                yaml_config.save(app)
        else:
            nets = [n for n, nc in app.networks.items() if nc.autostart]
        rc = 0
        for n in nets:
            ok, msg = rt.start(n)
            rc |= 0 if ok else 1
            print(f"up {n}: {'ok' if ok else 'FAILED'} — {msg}")
        return rc

    elif args.cmd == "down":
        nets = list(app.networks) if args.all else ([args.net] if args.net else [])
        if not nets:
            print("specify a network or --all", file=sys.stderr)
            return 2
        for n in nets:
            ok, msg = rt.stop(n)
            print(f"down {n}: {msg}")

    elif args.cmd == "restart":
        ok, msg = rt.restart(args.net)
        print(f"restart {args.net}: {'ok' if ok else 'FAILED'} — {msg}")
        return 0 if ok else 1

    elif args.cmd == "peers":
        snap = tc.snapshot(args.net)
        if snap.error:
            print(f"{args.net}: {snap.error}")
            return 1
        print(f"{'PEER':16} {'LINK':11} {'VIA':14} {'RTT':>6}  {'RX':>7} {'TX':>7}  SUBNETS")
        for n in sorted(snap.nodes.values(), key=lambda n: (not n.is_self, n.name)):
            via = "" if n.is_self or n.link.startswith("direct") else n.nexthop
            rtt = f"{n.rtt:.0f}" if n.rtt > 0 else ""
            print(f"{n.name:16} {LINK_LABEL.get(n.link, n.link):11} {via:14} {rtt:>6}  "
                  f"{human(n.rx_bytes):>7} {human(n.tx_bytes):>7}  {','.join(n.subnets)}")

    elif args.cmd == "invite":
        res = tc.invite(args.net, args.name)
        if res.stderr:
            print(res.stderr, file=sys.stderr)
        if not res.ok:
            print(f"invite failed (rc={res.rc})", file=sys.stderr)
            return 1
        print(res.stdout)

    elif args.cmd == "join":
        res = tc.join(args.net, args.invitation)
        if res.stdout:
            print(res.stdout)
        if res.stderr:
            print(res.stderr, file=sys.stderr)
        if not res.ok:
            print(f"join failed (rc={res.rc})", file=sys.stderr)
            return 1
        print(f"joined; networks now: {', '.join(yaml_config.load(app.path).networks)}")

    elif args.cmd == "genkeys":
        ok, msg = rt.generate_keys(args.net)
        if ok:
            yaml_config.save(app)
            print(f"genkeys {args.net}: {msg} (saved to {app.path})")
        else:
            print(f"genkeys {args.net}: FAILED — {msg}")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
