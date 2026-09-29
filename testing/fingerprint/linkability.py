#!/usr/bin/env python3
"""Cross-session linkability of a carrier: can an observer tell that two
sessions, seen from different addresses, come from the same node?

Input: linkability-audit.sh's session table and one tshark field dump per
session (time, src, dst, udp length, TLS content types, TLS record lengths;
multi-valued fields comma-joined). A session is one dial of one node over one
carrier, or one reference client connection to nginx.

Three matchers, each run over every carrier and over the reference:

  SameSizes   the first K units a session sends in each direction (TLS
              records other than the cleartext handshake and CCS; for UDP
              carriers every datagram), one sequence per direction: the
              sender decides that order, so it does not depend on how units
              cross in flight. A position where every session of one node has
              one value and another node has a different one is a per-node
              constant: it links that node's sessions and tells nodes apart. A
              position where every session of every node agrees is a protocol
              constant (a tell for the protocol, not the node). A position
              where each node has one value in at least 2/3 of its sessions
              and the nodes' values differ is a weaker per-node tell ("mostly
              constant"): coalesced frames or a retransmission blur it, an
              observer with many sessions does not care.
  SameGaps    the idle phase: how many units, at what intervals. A timer that
              fires at the same period in every session is a protocol tell; a
              period that differs by node would link.
  LengthTracksPayload
              pings of known sizes: outer unit size minus inner IP length. One
              value for every size and session means the observer reads every
              inner packet length exactly (what the TLS-in-TLS model feeds on);
              a spread means it does not.

Standard library only. Usage: linkability.py [--k 24] [--json OUT] SESSIONS.tsv DIR
  SESSIONS.tsv: name, kind (carrier or ref-*), node, node IP, server IP,
  port, t_start, t_idle, t_stop, then ping marks "size@epoch" (tab-separated);
  DIR/<name>.tsv: the session's tshark dump.
"""
import argparse
import collections
import json
import statistics


def load_units(path, node_ip, server_ip, port):
    """[(t, dir, size, ctype)] of one session: dir 0 = node -> server."""
    out = []
    for line in open(path):
        f = line.rstrip("\n").split("\t")
        f += [""] * (8 - len(f))
        t, src, dst, ulen, ctypes, rlens, tports, uports = f[:8]
        if {src, dst} != {node_ip, server_ip}:
            continue
        ports = {int(x) for x in (tports + "," + uports).split(",") if x}
        if port not in ports:
            continue
        d = 0 if src == node_ip else 1
        if ulen:
            out.append((float(t), d, int(ulen) - 8, None))
            continue
        cts = [int(x) for x in ctypes.split(",") if x]
        for i, rl in enumerate(x for x in rlens.split(",") if x):
            out.append((float(t), d, int(rl), cts[i] if i < len(cts) else None))
    return out


def signature(units, k):
    """Per direction, the first k units that are not cleartext TLS handshake (22) or CCS (20)."""
    kept = [(d, s) for _, d, s, ct in units if ct not in (20, 22)]
    return [[s for d, s in kept if d == want][:k] for want in (0, 1)]


def same_sizes(sessions, k):
    """Position by position, per direction: protocol constant, per-node constant or varying."""
    by_node = collections.defaultdict(list)
    for s in sessions:
        by_node[s["node"]].append(s["sig"])
    nodes = sorted(by_node)
    res = dict(protocol_constant=[], per_node_constant=[], per_node_mostly=[], varying=[], compared=[0, 0])
    for d in (0, 1):
        n = min((len(sig[d]) for sigs in by_node.values() for sig in sigs), default=0)
        res["compared"][d] = min(k, n)
        for p in range(min(k, n)):
            vals = {nd: {sig[d][p] for sig in by_node[nd]} for nd in nodes}
            if all(len(v) == 1 for v in vals.values()):
                flat = {next(iter(v)) for v in vals.values()}
                if len(flat) == 1:
                    res["protocol_constant"].append((d, p))
                else:
                    res["per_node_constant"].append((d, p, {nd: next(iter(v)) for nd, v in vals.items()}))
            else:
                res["varying"].append((d, p))
                modes = {}
                for nd in nodes:
                    v, c = collections.Counter(sig[d][p] for sig in by_node[nd]).most_common(1)[0]
                    if 3 * c < 2 * len(by_node[nd]):
                        break
                    modes[nd] = v
                else:
                    if len(set(modes.values())) > 1:
                        res["per_node_mostly"].append((d, p, modes))
    res["linkable"] = bool(res["per_node_constant"])
    return res


def same_gaps(sessions):
    rows = []
    for s in sessions:
        ts = [t for t, _, _, _ in s["units"] if s["t_idle"] <= t <= s["t_stop"]]
        gaps = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0.5]
        rows.append(dict(node=s["node"], units=len(ts), gaps=[round(g, 1) for g in gaps],
                         median_gap=round(statistics.median(gaps), 2) if gaps else None))
    periods = collections.defaultdict(list)
    for r in rows:
        if r["median_gap"] is not None:
            periods[r["node"]].append(r["median_gap"])
    return dict(sessions=rows, median_gap_by_node={k: sorted(v) for k, v in periods.items()})


def length_tracks(sessions):
    over = collections.defaultdict(set)
    for s in sessions:
        units = s["units"]
        for size, mt in s["pings"]:
            inner = size + 28
            for d in (0, 1):
                cand = [u for u in units if u[1] == d and mt <= u[0] <= mt + 0.3 and u[2] >= inner]
                if cand:
                    over[d].add(cand[0][2] - inner)
    res = {}
    for d, name in ((0, "node->server"), (1, "server->node")):
        v = sorted(over[d])
        res[name] = dict(values=v[:12], distinct=len(v),
                         verdict=("exact: every inner length readable (overhead %d B)" % v[0]) if len(v) == 1 else
                         ("spread %d..%d B" % (v[0], v[-1]) if v else "no ping matched"))
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--k", type=int, default=24)
    ap.add_argument("--json")
    ap.add_argument("sessions")
    ap.add_argument("dir")
    a = ap.parse_args()
    groups = collections.defaultdict(list)
    for line in open(a.sessions):
        f = line.rstrip("\n").split("\t")
        if len(f) < 9 or f[0] == "name":
            continue
        name, kind, node, node_ip, server_ip, port, t0, ti, t1 = f[:9]
        pings = [(int(x.split("@")[0]), float(x.split("@")[1])) for x in f[9:] if "@" in x]
        units = load_units("%s/%s.tsv" % (a.dir, name), node_ip, server_ip, int(port))
        groups[kind].append(dict(name=name, node=node, units=units, sig=signature(units, a.k),
                                 t_idle=float(ti), t_stop=float(t1), pings=pings))
    report = {}
    for kind in sorted(groups, key=lambda k: (k.startswith("ref"), k)):
        ss = groups[kind]
        r = report[kind] = dict(sessions=len(ss), nodes=sorted({s["node"] for s in ss}),
                                same_sizes=same_sizes(ss, a.k), same_gaps=same_gaps(ss),
                                length_tracks=length_tracks(ss))
        sz = r["same_sizes"]
        print("[%s] %d sessions, nodes %s" % (kind, len(ss), ", ".join(r["nodes"])))
        print("  SameSizes  first %d units node->server, %d server->node: %d protocol-constant, %d per-node constant, "
              "%d varying -> %s" % (
                  sz["compared"][0], sz["compared"][1], len(sz["protocol_constant"]), len(sz["per_node_constant"]),
                  len(sz["varying"]),
                  "LINKABLE: a node's sessions share sizes no other node has" if sz["linkable"] else "no per-node constant"))
        for d, p, vals in sz["per_node_constant"][:10]:
            print("             %s unit %2d: %s" % ("node->server" if d == 0 else "server->node", p,
                                                   ", ".join("%s %d B" % (nd, v) for nd, v in sorted(vals.items()))))
        if sz["per_node_mostly"]:
            print("             mostly constant per node (>= 2/3 of its sessions), %d position(s):" % len(sz["per_node_mostly"]))
            for d, p, vals in sz["per_node_mostly"][:10]:
                print("             %s unit %2d: %s" % ("node->server" if d == 0 else "server->node", p,
                                                       ", ".join("%s %d B" % (nd, v) for nd, v in sorted(vals.items()))))
        g = r["same_gaps"]
        print("  SameGaps   idle: median gap by node %s; units per session %s" % (
            g["median_gap_by_node"], [x["units"] for x in g["sessions"]]))
        lt = r["length_tracks"]
        print("  LengthTracksPayload  node->server: %s; server->node: %s" % (
            lt["node->server"]["verdict"], lt["server->node"]["verdict"]))
    if a.json:
        with open(a.json, "w") as fh:
            json.dump(report, fh, indent=1, default=list)


if __name__ == "__main__":
    main()
