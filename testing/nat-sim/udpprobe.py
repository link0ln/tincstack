#!/usr/bin/env python3
"""UDP NAT-behaviour probe (stdlib only) used to validate the lab's NAT emulation
before any tinc result is trusted.

Server (on the "public" side; needs two IPs on the same interface):
    udpprobe server --ip1 100.64.0.20 --ip2 100.64.0.21 [--port 9001] [--port2 9002]

    Sockets: S1 = ip1:port, S1b = ip1:port2, S2 = ip2:port, S2b = ip2:port2.
    Requests (ASCII datagrams):
      PROBE  -> reply "OBS <ip> <port>" from the receiving socket (observed mapping)
      XPORT  -> S1b sends "XPORT-HIT" to the observed address (same IP, other port)
      XHOST  -> S2  sends "XHOST-HIT" to the observed address (other IP)

Client (inside a NATed LAN):
    udpprobe client --sport 4000 --server 100.64.0.20 --server2 100.64.0.21
                    [--port 9001] [--port2 9002] [--expect TYPE] [--expect-ext-port N]

    Sequence: PROBE S1 -> XPORT -> XHOST -> PROBE S1b -> PROBE S2 -> PROBE S2b,
    then classify (RFC 4787 vocabulary):
      mapping   EIM  if all four observed ports are equal,
                EIM-after-first if S1 differs but S1b == S2 == S2b (what Linux
                MASQUERADE does on kernels >= 6.7), else APDM
      filtering EIF  if XPORT-HIT and XHOST-HIT arrived
                ADF  if only XPORT-HIT arrived
                APDF if neither arrived
      type      fullcone = EIM+EIF, restricted = EIM+ADF,
                portrestricted = EIM+APDF, symmetric = APDM+APDF,
                masq = (EIM|EIM-after-first)+APDF with the first mapping
                port-preserving, masqfw = EIM+APDF port-preserving (the
                XPORT/XHOST datagrams are unsolicited: behind an open INPUT
                chain they are what pushes later flows onto another port),
                udpblock = no reply to any PROBE
    Prints one JSON line; exit 0 if --expect matches (or no --expect), 1 otherwise.
"""
import argparse
import json
import select
import socket
import sys
import time


def server(args):
    s1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s1.bind((args.ip1, args.port))
    s1b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s1b.bind((args.ip1, args.port2))
    s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s2.bind((args.ip2, args.port))
    s2b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s2b.bind((args.ip2, args.port2))
    socks = [s1, s1b, s2, s2b]
    print(f"udpprobe server on {args.ip1}:{args.port},{args.port2} and {args.ip2}:{args.port},{args.port2}", flush=True)
    while True:
        ready, _, _ = select.select(socks, [], [])
        for s in ready:
            data, addr = s.recvfrom(1500)
            req = data.decode(errors="replace").strip()
            print(f"{time.strftime('%H:%M:%S')} {s.getsockname()} <- {addr} {req}", flush=True)
            if req.startswith("PROBE"):
                s.sendto(f"OBS {addr[0]} {addr[1]}".encode(), addr)
            elif req.startswith("XPORT"):
                s1b.sendto(b"XPORT-HIT", addr)
            elif req.startswith("XHOST"):
                s2.sendto(b"XHOST-HIT", addr)


def rx(sock, want, timeout):
    """Wait up to timeout s for a datagram starting with `want`; return payload or None."""
    end = time.monotonic() + timeout
    while True:
        left = end - time.monotonic()
        if left <= 0:
            return None
        r, _, _ = select.select([sock], [], [], left)
        if not r:
            return None
        data, _ = sock.recvfrom(1500)
        text = data.decode(errors="replace")
        if text.startswith(want):
            return text


def probe(sock, dst, tries=3, timeout=1.0):
    for _ in range(tries):
        sock.sendto(b"PROBE", dst)
        ans = rx(sock, "OBS", timeout)
        if ans:
            _, ip, port = ans.split()
            return ip, int(port)
    return None


def client(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", args.sport))
    s1 = (args.server, args.port)
    s1b = (args.server, args.port2)
    s2 = (args.server2, args.port)
    s2b = (args.server2, args.port2)
    result = {"sport": args.sport, "obs": {}, "xport": False, "xhost": False}

    obs1 = probe(sock, s1)
    if obs1 is None:
        result.update({"type": "udpblock", "mapping": None, "filtering": None})
        return finish(result, args)
    result["obs"]["s1"] = obs1

    # Filtering tests before the client has ever sent to S1b / S2.
    for _ in range(2):
        sock.sendto(b"XPORT", s1)
        if rx(sock, "XPORT-HIT", 1.0):
            result["xport"] = True
            break
    for _ in range(2):
        sock.sendto(b"XHOST", s1)
        if rx(sock, "XHOST-HIT", 1.0):
            result["xhost"] = True
            break

    obs2 = probe(sock, s1b)
    obs3 = probe(sock, s2)
    obs4 = probe(sock, s2b)
    result["obs"]["s1b"] = obs2
    result["obs"]["s2"] = obs3
    result["obs"]["s2b"] = obs4
    rest = {o[1] for o in (obs2, obs3, obs4) if o}
    if obs2 and obs3 and obs4 and len(rest) == 1:
        result["mapping"] = "EIM" if obs1[1] in rest else "EIM-after-first"
    else:
        result["mapping"] = "APDM"
    if result["xport"] and result["xhost"]:
        result["filtering"] = "EIF"
    elif result["xport"]:
        result["filtering"] = "ADF"
    else:
        result["filtering"] = "APDF"
    result["type"] = {
        ("EIM", "EIF"): "fullcone",
        ("EIM", "ADF"): "restricted",
        ("EIM", "APDF"): "portrestricted",
        ("APDM", "APDF"): "symmetric",
        ("EIM-after-first", "APDF"): "masq",
    }.get((result["mapping"], result["filtering"]), "unclassified")
    result["port_preserving"] = obs1[1] == args.sport
    return finish(result, args)


def finish(result, args):
    ok = True
    if args.expect == "masq":
        ok = result.get("type") in ("masq", "portrestricted") and bool(result.get("port_preserving"))
    elif args.expect == "masqfw":
        ok = result.get("type") == "portrestricted" and bool(result.get("port_preserving"))
    elif args.expect:
        ok = result["type"] == args.expect
    if args.expect_ext_port and result["obs"].get("s1"):
        ok = ok and result["obs"]["s1"][1] == args.expect_ext_port
    result["expect"] = args.expect
    result["ok"] = ok
    print(json.dumps(result), flush=True)
    return 0 if ok else 1


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="mode", required=True)
    s = sub.add_parser("server")
    s.add_argument("--ip1", required=True)
    s.add_argument("--ip2", required=True)
    s.add_argument("--port", type=int, default=9001)
    s.add_argument("--port2", type=int, default=9002)
    c = sub.add_parser("client")
    c.add_argument("--sport", type=int, required=True)
    c.add_argument("--server", required=True)
    c.add_argument("--server2", required=True)
    c.add_argument("--port", type=int, default=9001)
    c.add_argument("--port2", type=int, default=9002)
    c.add_argument("--expect", default="")
    c.add_argument("--expect-ext-port", type=int, default=0)
    args = p.parse_args()
    if args.mode == "server":
        server(args)
        return 0
    return client(args)


if __name__ == "__main__":
    sys.exit(main())
