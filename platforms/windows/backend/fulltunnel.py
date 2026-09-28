"""
fulltunnel.py — send all of this machine's IPv4 traffic through one peer, the
exit node that announces 0.0.0.0/0, without routing the tunnel into itself.

A peer's LAN is one route on the tunnel adapter (routes.py, InterfaceRoute).
The default route is not: every packet tincd sends to its peers would follow it
into the adapter, reach tincd again and go round until the link died. What
makes it safe is the order of three things, kept true for as long as the
network runs:

1. a /32 "pin" through the PHYSICAL default gateway for every public address
   tincd talks to -- the peers it dials (ConnectTo), and every address the
   snapshot knows for a node or an edge -- so those packets keep leaving
   through the real network;
2. only then 0.0.0.0/1 + 128.0.0.0/1 on the tunnel adapter. Two halves instead
   of 0.0.0.0/0: they beat the physical default route by prefix length and
   leave it in place, which is what step 1 needs to find it again later;
3. the split routes come off while the exit node is unreachable or no longer
   announces 0.0.0.0/0 (fail-open: a dead exit leaves the machine on its own
   network instead of cutting it off), and go back when it returns.

This is maintained, not set once: endpoints move (NAT rebind, a new direct
peer), the physical gateway changes (Wi-Fi to LTE), and Windows removes the
adapter's routes whenever tincd restarts. `FullTunnel.step()` is one
reconciliation pass over a `tinc dump` snapshot; `Maintainer` runs it every few
seconds from Runtime while the network is up, and `FullTunnel.stop()` undoes
everything it added.

IPv4 only. IPv6 traffic and the DNS servers Windows uses are not touched.

Routes are written with `netsh ... store=active` (routes.route_args), so none
of this survives a reboot; the setting itself is the network-level
`full_tunnel: <node>` key in tinc.yaml (yaml_config.NetworkCfg.full_tunnel),
owned by tincmgr and never passed to the daemon.

Everything above the Win32 line is pure and testable on any platform.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable

import routes

SPLIT = ("0.0.0.0/1", "128.0.0.0/1")
DEFAULT_V4 = "0.0.0.0/0"
INTERVAL = 3.0          # seconds between reconciliation passes
RESOLVE_TTL = 300.0     # seconds a resolved ConnectTo hostname is reused


@dataclass(frozen=True)
class Route:
    """One IPv4 route as the routing table reports it."""
    prefix: str          # "0.0.0.0/0"
    nexthop: str         # "192.168.1.1"; "0.0.0.0" = on-link
    ifindex: int
    metric: int = 0


@dataclass(frozen=True)
class Gateway:
    """The physical default route the pins go through."""
    ifindex: int
    nexthop: str         # "0.0.0.0" = on-link (PPP, some LTE modems)

    @property
    def via(self) -> str:
        return "" if self.nexthop in ("", "0.0.0.0") else self.nexthop


# ---- pure logic ----------------------------------------------------------------

def _ipv4(text: str):
    try:
        return ipaddress.IPv4Address(str(text).strip())
    except (ValueError, TypeError):
        return None


def _nets(items: Iterable) -> list:
    out = []
    for s in items:
        n = routes.parse_subnet(s) if isinstance(s, str) else s
        if n is not None and n.version == 4:
            out.append(n)
    return out


def pinnable(addr: str, local_nets: Iterable = (), vpn_nets: Iterable = ()) -> bool:
    """True if `addr` is a peer endpoint that must keep leaving through the
    physical gateway: a unicast IPv4 address that is neither on a network this
    machine is attached to (the on-link route is already more specific than
    the split routes) nor inside the VPN (that traffic belongs in the tunnel)."""
    ip = _ipv4(addr)
    if ip is None or ip.is_loopback or ip.is_unspecified or ip.is_multicast \
            or ip.is_link_local or ip == ipaddress.IPv4Address("255.255.255.255"):
        return False
    if any(ip in n for n in _nets(local_nets)):
        return False
    if any(ip in n for n in _nets(vpn_nets)):
        return False
    return True


def vpn_networks(snap, options: dict) -> list:
    """Everything that is reached THROUGH the tunnel, apart from the default
    route itself: every subnet a node announces except 0.0.0.0/0, and the
    adapter's own network (InterfaceAddress / WintunAddress, e.g. 10.8.179.3/24)."""
    out = []
    for s in getattr(snap, "subnets", []) or []:
        n = routes.parse_subnet(s.subnet)
        if n is not None and n.version == 4 and n.prefixlen > 0:
            out.append(n)
    for key in ("InterfaceAddress", "WintunAddress"):
        v = options.get(key)
        for item in (v if isinstance(v, (list, tuple)) else [v]):
            if not item:
                continue
            try:
                out.append(ipaddress.ip_interface(str(item).split()[0]).network)
            except ValueError:
                continue
    return out


def neighbour_addresses(snap, own: str) -> set[str]:
    """The addresses of this node's own meta connections: the edges that start
    at this node. A pin missing for one of these is exactly the loop, so the
    split routes are not installed until they are all pinned."""
    out = set()
    for e in getattr(snap, "edges", []) or []:
        if e.frm == own and _ipv4(e.address):
            out.add(e.address)
    return out


def snapshot_addresses(snap, own: str) -> set[str]:
    """Every IPv4 address the daemon knows for another node or edge: where it
    sends UDP to that node, and where each meta connection in the mesh runs."""
    out = set()
    for n in (getattr(snap, "nodes", {}) or {}).values():
        if n.name != own and not n.is_self and _ipv4(n.address):
            out.add(n.address)
    for e in getattr(snap, "edges", []) or []:
        # an edge towards this node carries this node's own public address
        if e.to != own and _ipv4(e.address):
            out.add(e.address)
    return out


def host_addresses(host_text: str) -> list[str]:
    """The `Address = host [port]` values of one host record, host part only."""
    out = []
    for line in str(host_text or "").splitlines():
        key, sep, val = line.partition("=")
        if sep and key.strip().lower() == "address" and val.split():
            out.append(val.split()[0])
    return out


def connect_to_hosts(options: dict, hosts: dict) -> list[str]:
    """Hostnames/addresses of the peers this node dials (ConnectTo), from their
    host records. These have to be pinned before the first connection exists,
    and again after a reconnect to a new address."""
    names = options.get("ConnectTo")
    if names is None:
        return []
    if not isinstance(names, (list, tuple)):
        names = [names]
    out = []
    for name in names:
        for a in host_addresses(hosts.get(str(name).strip(), "")):
            if a not in out:
                out.append(a)
    return out


def choose_gateway(table: Iterable[Route], tunnel_ifindex: int | None) -> Gateway | None:
    """The physical default route: the 0.0.0.0/0 entry with the lowest metric
    that is not on the tunnel adapter. None when this machine has no default
    route of its own (offline), and then there is nothing to pin through."""
    best = None
    for r in table:
        if r.prefix != DEFAULT_V4 or r.ifindex == tunnel_ifindex:
            continue
        if best is None or r.metric < best.metric:
            best = r
    return Gateway(best.ifindex, best.nexthop) if best else None


def has_route(table: Iterable[Route], prefix: str, ifindex: int) -> bool:
    return any(r.prefix == prefix and r.ifindex == ifindex for r in table)


def exit_ready(snap, exit_node: str) -> tuple[bool, str]:
    """(usable, reason): the exit node is reachable and still announces the
    default route. The reason is what the state line shows when it is not."""
    n = (getattr(snap, "nodes", {}) or {}).get(exit_node)
    if n is None:
        return False, f"{exit_node} is not in the network"
    if not n.reachable:
        return False, f"{exit_node} is unreachable"
    owners = {s.owner for s in (getattr(snap, "subnets", []) or [])
              if str(routes.parse_subnet(s.subnet)) == DEFAULT_V4}
    if exit_node not in owners:
        return False, f"{exit_node} does not announce 0.0.0.0/0"
    return True, ""


# ---- the reconciler ------------------------------------------------------------

class System:
    """What FullTunnel needs from the operating system. `Win32` is the real
    one; tests pass a fake with the same methods."""

    def route_table(self) -> list[Route]:
        raise NotImplementedError

    def ifindex(self, aliases: list[str]) -> int | None:
        raise NotImplementedError

    def local_nets(self) -> list[str]:
        raise NotImplementedError

    def resolve(self, host: str) -> list[str]:
        raise NotImplementedError

    def add_route(self, prefix: str, ifindex: int, via: str = "") -> tuple[bool, str]:
        raise NotImplementedError

    def delete_route(self, prefix: str, ifindex: int, via: str = "") -> tuple[bool, str]:
        raise NotImplementedError


@dataclass
class FullTunnel:
    net: str
    exit_node: str
    aliases: list[str]
    system: System
    clock: Callable[[], float] = time.monotonic
    pins: dict = field(default_factory=dict)        # ip -> Gateway it is pinned through
    split_if: int | None = None                     # adapter the split routes are on
    state: str = "starting"
    _resolved: dict = field(default_factory=dict)   # host -> (expiry, [ip])

    def _connect_to_ips(self, options: dict, hosts: dict) -> set[str]:
        out = set()
        now = self.clock()
        for host in connect_to_hosts(options, hosts):
            if _ipv4(host):
                out.add(host)
                continue
            exp, ips = self._resolved.get(host, (0.0, []))
            if now >= exp:
                try:
                    ips = [a for a in self.system.resolve(host) if _ipv4(a)]
                except OSError:
                    ips = ips or []   # keep the last answer while DNS is down
                self._resolved[host] = (now + RESOLVE_TTL, ips)
            out.update(ips)
        return out

    def _set_state(self, text: str, log: list[str]) -> None:
        if text != self.state:
            log.append(f"full tunnel: {text}")
        self.state = text

    def _remove_split(self, log: list[str]) -> None:
        if self.split_if is None:
            return
        for p in SPLIT:
            ok, msg = self.system.delete_route(p, self.split_if)
            log.append(f"full tunnel: removed {p}" if ok else f"full tunnel: removing {p}: {msg}")
        self.split_if = None

    def step(self, snap, options: dict, hosts: dict, own: str) -> list[str]:
        """One reconciliation pass. Returns log lines for what changed."""
        log: list[str] = []
        sysm = self.system
        tunnel_if = sysm.ifindex(self.aliases)
        if tunnel_if is None:
            # tincd not up yet, or restarting: Windows took the adapter's
            # routes with it, so there is nothing of ours on it any more
            self.split_if = None
            self._set_state("waiting for the tunnel adapter", log)
            return log
        if self.split_if is not None and self.split_if != tunnel_if:
            self.split_if = None     # a new adapter instance after a restart
        table = sysm.route_table()
        gw = choose_gateway(table, tunnel_if)
        if gw is None:
            self._remove_split(log)
            self._set_state("no physical default route (offline?)", log)
            return log

        local = sysm.local_nets()
        vpn = vpn_networks(snap, options)
        must = {a for a in neighbour_addresses(snap, own) | self._connect_to_ips(options, hosts)
                if pinnable(a, local, vpn)}
        want = must | {a for a in snapshot_addresses(snap, own) if pinnable(a, local, vpn)}

        # 1. pins first, through the current physical gateway
        failed = {}
        for ip in sorted(want):
            have = self.pins.get(ip)
            if have == gw:
                continue
            if have is not None:
                sysm.delete_route(f"{ip}/32", have.ifindex, have.via)
            ok, msg = sysm.add_route(f"{ip}/32", gw.ifindex, gw.via)
            if ok:
                self.pins[ip] = gw
                log.append(f"full tunnel: pinned {ip} via {gw.via or 'on-link'} (if {gw.ifindex})")
            else:
                self.pins.pop(ip, None)
                failed[ip] = msg

        # 2. then the split routes, and only when the exit can take them
        usable, why = exit_ready(snap, self.exit_node)
        missing = sorted(ip for ip in must if ip in failed)
        if missing:
            self._remove_split(log)
            self._set_state(f"not applied: could not pin {missing[0]} ({failed[missing[0]]})", log)
            return log
        if not usable:
            self._remove_split(log)
            self._set_state(f"paused: {why}", log)
            return log
        for p in SPLIT:
            if not has_route(table, p, tunnel_if):
                ok, msg = sysm.add_route(p, tunnel_if)
                if not ok:
                    self._set_state(f"not applied: adding {p}: {msg}", log)
                    return log
                log.append(f"full tunnel: added {p} on the tunnel adapter (if {tunnel_if})")
        self.split_if = tunnel_if
        self._set_state(f"active via {self.exit_node}", log)
        return log

    def stop(self) -> list[str]:
        """Remove the split routes, then every pin. Split first, so no packet
        is routed into a tunnel whose endpoints are no longer pinned."""
        log: list[str] = []
        if self.split_if is None:
            # the adapter may still carry them if a pass installed them and the
            # index was lost; look before giving up
            idx = self.system.ifindex(self.aliases)
            if idx is not None and any(has_route(self.system.route_table(), p, idx) for p in SPLIT):
                self.split_if = idx
        self._remove_split(log)
        for ip, gw in sorted(self.pins.items()):
            ok, msg = self.system.delete_route(f"{ip}/32", gw.ifindex, gw.via)
            if not ok:
                log.append(f"full tunnel: unpinning {ip}: {msg}")
        if self.pins:
            log.append(f"full tunnel: removed {len(self.pins)} pin(s)")
        self.pins.clear()
        self.state = "off"
        return log


class Maintainer(threading.Thread):
    """Runs FullTunnel.step() every INTERVAL seconds until stopped, then
    FullTunnel.stop(). `snapshot` returns a tinc_control.NetworkSnapshot (its
    `error` set while the daemon does not answer yet); `config` returns the
    network's (options, hosts, own name) as they are now."""

    def __init__(self, ft: FullTunnel, snapshot: Callable[[], object],
                 config: Callable[[], tuple[dict, dict, str]],
                 log: Callable[[str], None], interval: float = INTERVAL) -> None:
        super().__init__(name=f"fulltunnel-{ft.net}", daemon=True)
        self.ft = ft
        self._snapshot = snapshot
        self._config = config
        self._log = log
        self.interval = interval
        self._halt = threading.Event()

    @property
    def exit_node(self) -> str:
        return self.ft.exit_node

    def run(self) -> None:
        self._log(f"full tunnel: on, exit node {self.ft.exit_node}")
        while not self._halt.is_set():
            try:
                snap = self._snapshot()
                if getattr(snap, "error", ""):
                    self.ft.state = "waiting for the daemon"
                else:
                    options, hosts, own = self._config()
                    for line in self.ft.step(snap, options, hosts, own):
                        self._log(line)
            except Exception as e:     # never let one bad pass end the loop
                self._log(f"full tunnel: pass failed: {type(e).__name__}: {e}")
            self._halt.wait(self.interval)
        try:
            for line in self.ft.stop():
                self._log(line)
        except Exception as e:
            self._log(f"full tunnel: cleanup failed, routes may remain until reboot: "
                      f"{type(e).__name__}: {e}")
        self._log("full tunnel: off")

    def stop(self, timeout: float = 15.0) -> None:
        self._halt.set()
        self.join(timeout)


# ---- Win32 -------------------------------------------------------------------

class Win32(System):
    """The routing table through iphlpapi (GetIpForwardTable), the adapter's
    index from its alias (ConvertInterfaceAliasToLuid/LuidToIndex), and route
    changes through netsh (routes.route_args, `store=active`) -- the same tool
    the per-subnet toggles use, addressed by interface index."""

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        class _ROW(ctypes.Structure):
            _fields_ = [(n, ctypes.c_uint32) for n in (
                "dest", "mask", "policy", "nexthop", "ifindex", "type", "proto",
                "age", "nexthop_as", "metric1", "metric2", "metric3", "metric4", "metric5")]

        self._ct = ctypes
        self._ROW = _ROW
        self._lib = ctypes.WinDLL("iphlpapi.dll")
        self._lib.ConvertInterfaceAliasToLuid.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_uint64)]
        self._lib.ConvertInterfaceAliasToLuid.restype = ctypes.c_ulong
        self._lib.ConvertInterfaceLuidToIndex.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_ulong)]
        self._lib.ConvertInterfaceLuidToIndex.restype = ctypes.c_ulong

    @staticmethod
    def _addr(v: int) -> ipaddress.IPv4Address:
        return ipaddress.IPv4Address(int(v).to_bytes(4, "little"))

    def route_table(self) -> list[Route]:
        ct = self._ct
        size = ct.c_ulong(0)
        self._lib.GetIpForwardTable(None, ct.byref(size), False)
        buf = ct.create_string_buffer(max(size.value, 4))
        if self._lib.GetIpForwardTable(buf, ct.byref(size), False) != 0:
            return []
        count = ct.cast(buf, ct.POINTER(ct.c_uint32))[0]
        rows = ct.cast(ct.byref(buf, 4), ct.POINTER(self._ROW))
        out = []
        for i in range(count):
            r = rows[i]
            try:
                net = ipaddress.IPv4Network(f"{self._addr(r.dest)}/{self._addr(r.mask)}", strict=False)
            except ValueError:
                continue
            out.append(Route(str(net), str(self._addr(r.nexthop)), int(r.ifindex), int(r.metric1)))
        return out

    def ifindex(self, aliases: list[str]) -> int | None:
        ct = self._ct
        for alias in aliases:
            luid = ct.c_uint64(0)
            if self._lib.ConvertInterfaceAliasToLuid(alias, ct.byref(luid)) != 0 or not luid.value:
                continue
            idx = ct.c_ulong(0)
            if self._lib.ConvertInterfaceLuidToIndex(ct.byref(luid), ct.byref(idx)) == 0 and idx.value:
                return int(idx.value)
        return None

    def local_nets(self) -> list[str]:
        return routes.local_ipv4_subnets()

    def resolve(self, host: str) -> list[str]:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        return sorted({i[4][0] for i in infos})

    def add_route(self, prefix: str, ifindex: int, via: str = "") -> tuple[bool, str]:
        try:
            return routes._netsh(routes.route_args("add", str(ifindex), prefix, via))
        except ValueError as e:
            return False, str(e)

    def delete_route(self, prefix: str, ifindex: int, via: str = "") -> tuple[bool, str]:
        try:
            return routes._netsh(routes.route_args("delete", str(ifindex), prefix, via))
        except ValueError as e:
            return False, str(e)


def system() -> System | None:
    """The real System on Windows, None elsewhere (nothing to apply)."""
    if os.name != "nt":
        return None
    try:
        return Win32()
    except (OSError, AttributeError):
        return None
