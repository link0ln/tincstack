#!/usr/bin/env python3
"""NAT-traversal experiments (stdlib only) for the tincstack NAT lab.

udpprobe.py classifies a NAT; this tool measures what a hole puncher could do
with it, independently of tincd, so a technique can be proven (or refuted) in
the lab before anyone changes the daemon.

Reflector / rendezvous server (public side, any number of ip:port sockets):
    nattrav server --bind 100.64.0.20:3478 --bind 100.64.0.20:3479 ...

    PROBE           -> "OBS <ip> <port>" from the receiving socket
    REG <name> <ip> <port>
                    -> store the address <name> advertises; reply "OK"
    GET <name>      -> "ADDR <ip> <port>" once <name> registered, else "NONE"
    READY <name> <peer>
                    -> once both <name> and <peer> sent READY naming each
                       other, "GO" to both, back to back (a relay-timed
                       simultaneous open)
    POKE <ip> <port> -> our socket <ip>:<port> sends "POKED" to the caller

Port-allocation map (from inside a NAT):
    nattrav portmap --sport 655 --dst IP:PORT --dst IP:PORT ... [--gap S]

    One socket, PROBE each destination in order (--gap seconds apart, default
    0.2) and record the external port each one observed. Prints one JSON line.

Hole punch between two NATed hosts (run one per side, concurrently):
    nattrav punch --name a --peer b --sport 655 --rdv IP:PORT
                  --strategy first|second|burn|burn-keep [--second IP:PORT]
                  [--burn IP:PORT] [--duration S] [--spray N] [--sync]

    strategy (how this side learns the address it advertises to the peer):
      first      PROBE the rendezvous first and advertise what it saw. This is
                 what tinc does today: the relay is a node's first UDP
                 destination and UDP_INFO / ANS_KEY carry the relay-facing
                 mapping.
      second     PROBE the rendezvous first, then PROBE a second reflector
                 (--second, typically the same host on another port) and
                 advertise what THAT one saw -- the mapping a Linux >= 6.7
                 MASQUERADE gives to every destination after the first.
      burn       send one datagram to --burn (a throwaway destination) before
                 anything else, then PROBE the rendezvous and advertise that
                 observation: the relay is no longer the first destination.
      burn-keep  as burn, and keep refreshing the burn destination while
                 punching (so the burned mapping cannot expire).
    --spray N    additionally send to N ports around the peer's advertised
                 port (+-N/2), i.e. naive port prediction.
    --sync       send nothing to the peer until the rendezvous says GO to
                 both sides at once (READY/GO). Without it each side starts
                 as soon as it has the peer's address, up to 0.5 s apart.

    Then both sides send PUNCH datagrams to the peer's advertised address
    every 100 ms for --duration seconds; the first datagram that arrives from
    the peer is answered and its source recorded. Prints one JSON line with
    ok, the advertised/learned addresses and the time to first contact.
"""
import argparse
import json
import select
import socket
import sys
import time


def hostport(s):
    h, p = s.rsplit(":", 1)
    return h, int(p)


def server(args):
    socks = []
    for b in args.bind:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(hostport(b))
        socks.append(s)
    reg = {}
    pending = {}
    print("nattrav server on " + " ".join(args.bind), flush=True)
    while True:
        ready, _, _ = select.select(socks, [], [])
        for s in ready:
            data, addr = s.recvfrom(1500)
            req = data.decode(errors="replace").split()
            if not req:
                continue
            print(f"{time.strftime('%H:%M:%S')} {s.getsockname()} <- {addr} {' '.join(req)}", flush=True)
            if req[0] == "PROBE":
                s.sendto(f"OBS {addr[0]} {addr[1]}".encode(), addr)
            elif req[0] == "REG" and len(req) == 4:
                reg[req[1]] = (req[2], req[3])
                s.sendto(b"OK", addr)
            elif req[0] == "POKE" and len(req) == 3:
                # unsolicited datagram to the caller's mapping from another of
                # our sockets (the caller never sent to that one)
                for o in socks:
                    if o.getsockname() == (req[1], int(req[2])):
                        o.sendto(b"POKED", addr)
            elif req[0] == "READY" and len(req) == 3:
                name, peer = req[1], req[2]
                if pending.get(name, (None, None, False))[2]:
                    continue  # this pair already got its GO
                pending[name] = (addr, peer, False)
                if peer in pending and pending[peer][1] == name:
                    s.sendto(b"GO", pending[peer][0])
                    s.sendto(b"GO", addr)
                    pending[name] = (addr, peer, True)
                    pending[peer] = (pending[peer][0], name, True)
                    print(f"{time.strftime('%H:%M:%S')} GO {name} {peer}", flush=True)
            elif req[0] == "GET" and len(req) == 2:
                if req[1] in reg:
                    ip, port = reg[req[1]]
                    s.sendto(f"ADDR {ip} {port}".encode(), addr)
                else:
                    s.sendto(b"NONE", addr)


def rx(sock, want, timeout):
    end = time.monotonic() + timeout
    while True:
        left = end - time.monotonic()
        if left <= 0:
            return None, None
        r, _, _ = select.select([sock], [], [], left)
        if not r:
            return None, None
        data, addr = sock.recvfrom(1500)
        text = data.decode(errors="replace")
        if text.startswith(want):
            return text, addr


def probe(sock, dst, tries=3, timeout=1.0):
    for _ in range(tries):
        sock.sendto(b"PROBE", dst)
        ans, _ = rx(sock, "OBS", timeout)
        if ans:
            _, ip, port = ans.split()
            return ip, int(port)
    return None


def portmap(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", args.sport))
    obs = []
    alive = []
    for d in args.dst:
        if d.startswith("burn="):
            # one datagram nobody answers: claims a mapping, then expires
            sock.sendto(b"BURN", hostport(d[5:]))
            obs.append({"dst": d, "port": None})
        elif d.startswith("poke="):
            # poke=SRV_IP:PORT>FROM_IP:PORT: ask the server socket we already
            # talk to to have FROM send us an unsolicited datagram
            srv, frm = d[5:].split(">")
            fh, fp = hostport(frm)
            sock.sendto(f"POKE {fh} {fp}".encode(), hostport(srv))
            got, _ = rx(sock, "POKED", 1.0)
            obs.append({"dst": d, "port": None, "poke_arrived": got is not None})
            continue
        elif d.startswith("sleep="):
            # keep every answered flow alive (as tinc's keepalives do) while
            # unanswered ones are left to expire
            end = time.monotonic() + float(d[6:])
            while time.monotonic() < end:
                for a in alive:
                    sock.sendto(b"PROBE", a)
                time.sleep(1.0)
                while select.select([sock], [], [], 0)[0]:
                    sock.recvfrom(1500)
            continue
        else:
            o = probe(sock, hostport(d))
            obs.append({"dst": d, "port": o[1] if o else None})
            if o:
                alive.append(hostport(d))
        time.sleep(args.gap)
    ports = [o["port"] for o in obs if not o["dst"].startswith(("burn=", "poke="))]
    rest = [p for p in ports[1:] if p is not None]
    out = {"sport": args.sport, "obs": obs,
           "first_preserved": ports[0] == args.sport,
           "rest_shared": len(set(rest)) == 1 if rest else None,
           "distinct_ports": len({p for p in ports if p is not None})}
    print(json.dumps(out), flush=True)
    return 0


def punch(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", args.sport))
    rdv = hostport(args.rdv)
    res = {"name": args.name, "strategy": args.strategy, "sport": args.sport, "ok": False}
    burn = hostport(args.burn) if args.burn else None
    if args.strategy.startswith("burn"):
        sock.sendto(b"BURN", burn)
        time.sleep(0.2)
    first = probe(sock, rdv)
    res["rdv_obs"] = first
    if first is None:
        res["error"] = "no reply from the rendezvous"
        print(json.dumps(res), flush=True)
        return 1
    adv = first
    if args.strategy == "second":
        sec = probe(sock, hostport(args.second))
        res["second_obs"] = sec
        if sec:
            adv = sec
    res["advertised"] = adv
    for _ in range(3):
        sock.sendto(f"REG {args.name} {adv[0]} {adv[1]}".encode(), rdv)
        if rx(sock, "OK", 1.0)[0]:
            break
    peer = None
    end = time.monotonic() + 20
    while time.monotonic() < end and not peer:
        sock.sendto(f"GET {args.peer}".encode(), rdv)
        ans, _ = rx(sock, "ADDR", 0.5)
        if ans:
            _, ip, port = ans.split()
            peer = (ip, int(port))
    if not peer:
        res["error"] = "peer never registered"
        print(json.dumps(res), flush=True)
        return 1
    res["peer_advertised"] = peer
    targets = [peer]
    if args.spray:
        half = args.spray // 2
        targets += [(peer[0], p) for p in range(max(1, peer[1] - half), min(65535, peer[1] + half) + 1) if p != peer[1]]
    res["targets"] = len(targets)
    if args.sync:
        go = None
        end = time.monotonic() + 20
        while time.monotonic() < end and not go:
            sock.sendto(f"READY {args.name} {args.peer}".encode(), rdv)
            go, _ = rx(sock, "GO", 0.2)
        if not go:
            res["error"] = "no GO from the rendezvous"
            print(json.dumps(res), flush=True)
            return 1
    t0 = time.monotonic()
    next_send = 0.0
    next_burn = 0.0
    got = None
    acked = False
    while time.monotonic() - t0 < args.duration:
        now = time.monotonic()
        if now >= next_send:
            for t in targets:
                sock.sendto(f"PUNCH {args.name}".encode(), t)
            next_send = now + 0.1
        if args.strategy == "burn-keep" and now >= next_burn:
            sock.sendto(b"BURN", burn)
            next_burn = now + 5
        r, _, _ = select.select([sock], [], [], 0.05)
        if not r:
            continue
        data, addr = sock.recvfrom(1500)
        text = data.decode(errors="replace")
        if text.startswith("PUNCH") or text.startswith("ACK"):
            if got is None:
                got = {"from": list(addr), "t": round(time.monotonic() - t0, 3), "what": text.split()[0]}
            sock.sendto(f"ACK {args.name}".encode(), addr)
            targets = [addr]
            if text.startswith("ACK"):
                acked = True
        if got and acked:
            break
    res["first_contact"] = got
    res["acked"] = acked
    res["ok"] = got is not None
    print(json.dumps(res), flush=True)
    return 0 if res["ok"] else 1


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="mode", required=True)
    s = sub.add_parser("server")
    s.add_argument("--bind", action="append", required=True)
    m = sub.add_parser("portmap")
    m.add_argument("--sport", type=int, required=True)
    m.add_argument("--dst", action="append", required=True)
    m.add_argument("--gap", type=float, default=0.2)
    c = sub.add_parser("punch")
    c.add_argument("--name", required=True)
    c.add_argument("--peer", required=True)
    c.add_argument("--sport", type=int, required=True)
    c.add_argument("--rdv", required=True)
    c.add_argument("--strategy", choices=["first", "second", "burn", "burn-keep"], default="first")
    c.add_argument("--second", default="")
    c.add_argument("--burn", default="")
    c.add_argument("--duration", type=float, default=8.0)
    c.add_argument("--spray", type=int, default=0)
    c.add_argument("--sync", action="store_true")
    args = p.parse_args()
    if args.mode == "server":
        server(args)
        return 0
    if args.mode == "portmap":
        return portmap(args)
    return punch(args)


if __name__ == "__main__":
    sys.exit(main())
