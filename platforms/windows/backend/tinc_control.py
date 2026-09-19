"""
tinc_control.py — GUI-agnostic wrapper around the tinc 1.1 control interface.

Drives `tinc -n <net> -c <tinc.yaml> <cmd>` and parses the output of dump
commands into plain dataclasses; also carries the invite/join commands
(PLAN.md M2 CLI contract: `tinc -c tinc.yaml invite <name>` prints one line on
stdout; `tinc -c tinc.yaml join <string>` writes the joined network into the
YAML). No Qt, no GUI deps — testable headless: pass a `runner` to replace the
subprocess call.

Every call blocks; the GUI runs them on worker threads (gui/workers.py).

Status decoding follows node_status_t (union bitfield) in tinc src/node.h:
  bit0 unused_active, bit1 validkey, bit2 waitingforkey, bit3 visited,
  bit4 reachable, bit5 indirect, bit6 sptps, bit7 udp_confirmed,
  bit8 send_locally, bit9 udppacket, bit10 validkey_in, bit11 has_address,
  bit12 ping_sent.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass, field
from typing import Callable

Runner = Callable[[list[str], float], tuple[int, str, str]]

# ---- status bitfield (src/node.h node_status_t) -------------------------------

STATUS_BITS = [
    "unused_active", "validkey", "waitingforkey", "visited", "reachable",
    "indirect", "sptps", "udp_confirmed", "send_locally", "udppacket",
    "validkey_in", "has_address", "ping_sent",
]


def decode_status(hexval: str) -> dict:
    """Decode the hex status word from `dump nodes` into a {flag: bool} dict."""
    try:
        val = int(hexval, 16)
    except (ValueError, TypeError):
        return {}
    return {name: bool(val & (1 << i)) for i, name in enumerate(STATUS_BITS)}


# ---- data model ---------------------------------------------------------------

@dataclass
class Node:
    name: str
    node_id: str = ""
    address: str = ""          # external/real address as known to us
    port: str = ""
    options: str = ""
    status_hex: str = ""
    status: dict = field(default_factory=dict)
    nexthop: str = ""
    via: str = ""
    distance: int = -1
    pmtu: int = 0
    pmtu_min: int = 0
    pmtu_max: int = 0
    rx_packets: int = 0
    rx_bytes: int = 0
    tx_packets: int = 0
    tx_bytes: int = 0
    rtt: float = 0.0
    subnets: list = field(default_factory=list)

    @property
    def reachable(self) -> bool:
        return bool(self.status.get("reachable"))

    @property
    def vpn_address(self) -> str:
        """This node's own address inside the VPN: its host-route Subnet. tinc
        prints a /32 without the prefix, so a bare address is what we look for.
        '' when the node announces only networks and no address of its own."""
        for s in self.subnets:
            try:
                net = ipaddress.ip_network(str(s).strip(), strict=False)
            except ValueError:
                continue
            if net.prefixlen == net.max_prefixlen:
                return str(net.network_address)
        return ""

    @property
    def is_self(self) -> bool:
        return self.address == "MYSELF" or self.distance == 0

    @property
    def link(self) -> str:
        """Human-readable connectivity: direct-udp / direct-tcp / relay / down / self.

        IMPORTANT: distance/nexthop describe the META tree (TCP control / SPTPS
        key exchange), NOT the data path. In tinc 1.1 data packets flow
        peer-to-peer over UDP as soon as `udp_confirmed` is set, even when the
        meta connection is relayed (distance > 1, nexthop = some relay). So a
        node can be "directly with UDP" (what `tinc info` reports) while its
        meta nexthop is a relay. udp_confirmed therefore wins for the label.
        """
        if self.is_self:
            return "self"
        if not self.reachable:
            return "down"
        if self.status.get("udp_confirmed"):
            return "direct-udp"
        if self.distance == 1 and (self.nexthop == self.name or self.nexthop == ""):
            return "direct-tcp"
        return "relay"


@dataclass
class Edge:
    frm: str
    to: str
    address: str = ""
    port: str = ""
    local_address: str = ""
    local_port: str = ""
    options: str = ""
    weight: int = 0


@dataclass
class Subnet:
    subnet: str
    owner: str


@dataclass
class NetworkSnapshot:
    net: str
    nodes: dict = field(default_factory=dict)     # name -> Node
    edges: list = field(default_factory=list)     # list[Edge]
    subnets: list = field(default_factory=list)   # list[Subnet]
    error: str = ""

    def attach_subnets(self) -> None:
        for s in self.subnets:
            n = self.nodes.get(s.owner)
            if n and s.subnet not in n.subnets:
                n.subnets.append(s.subnet)


@dataclass
class CommandResult:
    rc: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.rc == 0


# `tinc cert` prints "tinc cert: FAILED (<code>)" followed by one sentence of
# detail and one of hint. The code is the stable name from acme.h, so the UI can
# key on it; the two sentences are what the user is told.
_CERT_FAIL = re.compile(r"^tinc cert: FAILED \((?P<code>[a-z0-9-]+)\)\s*$", re.M)


def parse_cert_failure(text: str) -> tuple[str, str, str]:
    """(code, detail, hint) from `tinc cert` output; ("", "", "") if it did not
    report a failure. Unknown codes come back verbatim -- a code this build has
    never heard of is still shown, never swallowed."""
    m = _CERT_FAIL.search(text or "")
    if not m:
        return "", "", ""
    rest = [ln.strip() for ln in text[m.end():].splitlines() if ln.strip()]
    detail = rest[0] if rest else ""
    hint = rest[1] if len(rest) > 1 else ""
    return m.group("code"), detail, hint


# ---- the controller -----------------------------------------------------------

def subprocess_runner(cmd: list[str], timeout: float) -> tuple[int, str, str]:
    """Default runner: run `cmd` without a console window, stdin closed (the
    CLI must never wait for a TTY answer under the GUI)."""
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            stdin=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 1, "", f"timeout after {timeout:.0f}s"
    except OSError as e:
        return 1, "", str(e)


class TincControl:
    """Thin wrapper that shells out to tinc for a control connection."""

    def __init__(self, tinc_exe: str, yaml_path: str, runner: Runner | None = None) -> None:
        self.tinc_exe = tinc_exe
        # YAML-native mode: drive control with -c <tinc.yaml> (same as tincd),
        # so tinc resolves the per-net runtime dir / control socket identically.
        self.yaml_path = yaml_path
        self.runner: Runner = runner or subprocess_runner

    # -- raw command --

    def argv(self, net: str | None, *args: str) -> list[str]:
        cmd = [self.tinc_exe]
        if net:
            cmd += ["-n", net]
        cmd += ["-c", self.yaml_path, *args]
        return cmd

    def _run(self, net: str | None, *args: str, timeout: float = 8.0) -> tuple[int, str, str]:
        return self.runner(self.argv(net, *args), timeout)

    # -- parsers --

    def parse_nodes(self, text: str) -> dict:
        """Parse `tinc -n NET dump nodes`."""
        nodes: dict = {}
        for line in text.splitlines():
            t = line.split()
            if len(t) < 4 or t[1] != "id":
                continue
            n = Node(name=t[0])
            try:
                n.node_id = t[2]
                # walk tokens by keyword for robustness against version drift
                i = 3
                while i < len(t):
                    kw = t[i]
                    if kw == "at":
                        n.address = t[i + 1]; i += 2
                    elif kw == "port":
                        n.port = t[i + 1]; i += 2
                    elif kw == "options":
                        n.options = t[i + 1]; i += 2
                    elif kw == "status":
                        n.status_hex = t[i + 1]
                        n.status = decode_status(t[i + 1]); i += 2
                    elif kw == "nexthop":
                        n.nexthop = t[i + 1]; i += 2
                    elif kw == "via":
                        n.via = t[i + 1]; i += 2
                    elif kw == "distance":
                        n.distance = int(t[i + 1]); i += 2
                    elif kw == "pmtu":
                        n.pmtu = int(float(t[i + 1])); i += 2
                    elif kw == "(min":
                        n.pmtu_min = int(float(t[i + 1])); i += 2
                    elif kw == "max":
                        n.pmtu_max = int(float(t[i + 1].rstrip(")"))); i += 2
                    elif kw == "rx":
                        n.rx_packets = int(t[i + 1]); n.rx_bytes = int(t[i + 2]); i += 3
                    elif kw == "tx":
                        n.tx_packets = int(t[i + 1]); n.tx_bytes = int(t[i + 2]); i += 3
                    elif kw == "rtt":
                        n.rtt = float(t[i + 1]); i += 2
                    else:
                        i += 1
            except (IndexError, ValueError):
                pass
            nodes[n.name] = n
        return nodes

    def parse_edges(self, text: str) -> list:
        edges = []
        for line in text.splitlines():
            t = line.split()
            if len(t) < 3 or t[1] != "to":
                continue
            e = Edge(frm=t[0], to=t[2])
            try:
                i = 3
                while i < len(t):
                    kw = t[i]
                    if kw == "at":
                        e.address = t[i + 1]; i += 2
                    elif kw == "port":
                        if not e.port:
                            e.port = t[i + 1]
                        else:
                            e.local_port = t[i + 1]
                        i += 2
                    elif kw == "local":
                        e.local_address = t[i + 1]; i += 2
                    elif kw == "options":
                        e.options = t[i + 1]; i += 2
                    elif kw == "weight":
                        e.weight = int(t[i + 1]); i += 2
                    else:
                        i += 1
            except (IndexError, ValueError):
                pass
            edges.append(e)
        return edges

    def parse_subnets(self, text: str) -> list:
        subnets = []
        for line in text.splitlines():
            t = line.split()
            if len(t) >= 3 and t[1] == "owner":
                subnets.append(Subnet(subnet=t[0], owner=t[2]))
        return subnets

    # -- high level --

    def is_running(self, net: str) -> bool:
        rc, _, _ = self._run(net, "dump", "nodes", timeout=5.0)
        return rc == 0

    def snapshot(self, net: str) -> NetworkSnapshot:
        """One full topology snapshot of a running network."""
        snap = NetworkSnapshot(net=net)
        rc, out, err = self._run(net, "dump", "nodes")
        if rc != 0:
            snap.error = err.strip() or "tinc dump nodes failed (network running?)"
            return snap
        snap.nodes = self.parse_nodes(out)
        _, eout, _ = self._run(net, "dump", "edges")
        snap.edges = self.parse_edges(eout)
        _, sout, _ = self._run(net, "dump", "subnets")
        snap.subnets = self.parse_subnets(sout)
        snap.attach_subnets()
        return snap

    # -- invitations (M2 CLI contract) --

    def invite(self, net: str, name: str, timeout: float = 90.0) -> CommandResult:
        """`tinc -n NET -c tinc.yaml invite NAME` → the one-line invitation on
        stdout. The daemon must be running (it hands out the pool address).
        stderr carries the address-discovery warnings; surface it."""
        rc, out, err = self._run(net, "invite", name, timeout=timeout)
        return CommandResult(rc, out.strip(), err.strip())

    # -- TLS certificate (tinc cert; ACME + Cloudflare) --

    def cert(self, net: str, *args: str, timeout: float = 300.0) -> CommandResult:
        """`tinc -n NET -c tinc.yaml cert ...`. Issuing talks to a CA and to
        Cloudflare and can take minutes, hence the long default timeout; the
        GUI runs it on a worker thread. Both streams carry text the user needs:
        stdout the outcome, stderr the progress and the failure taxonomy."""
        rc, out, err = self._run(net, "cert", *args, timeout=timeout)
        return CommandResult(rc, out.strip(), err.strip())

    def cert_status(self, net: str) -> CommandResult:
        return self.cert(net, "status", timeout=15.0)

    def cert_check(self, net: str) -> CommandResult:
        return self.cert(net, "check", timeout=60.0)

    def cert_issue(self, net: str, force: bool = False, staging: bool = False,
                   renew: bool = False) -> CommandResult:
        args = ["renew" if renew else "issue"]
        if force:
            args.append("--force")
        if staging:
            args.append("--staging")
        return self.cert(net, *args)

    def join(self, net: str | None, invitation: str, timeout: float = 120.0) -> CommandResult:
        """`tinc [-n NET] -c tinc.yaml join STRING` → the joined network is
        written into the YAML by the CLI (identity + inherited options +
        inviter host record). Reload the config afterwards."""
        rc, out, err = self._run(net, "join", invitation.strip(), timeout=timeout)
        return CommandResult(rc, out.strip(), err.strip())


if __name__ == "__main__":
    import sys
    tc = TincControl(tinc_exe=sys.argv[1], yaml_path=sys.argv[2])
    for net in sys.argv[3:]:
        snap = tc.snapshot(net)
        print(f"\n=== {net} ===")
        if snap.error:
            print("  (not running / error:", snap.error, ")")
            continue
        for name, n in sorted(snap.nodes.items()):
            print(f"  {name:14} {n.link:11} dist={n.distance:>2} "
                  f"rtt={n.rtt:7.1f} pmtu={n.pmtu:>4} "
                  f"rx={n.rx_bytes:>10} tx={n.tx_bytes:>10} "
                  f"subnets={','.join(n.subnets)}")
