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
import json
import os
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable

import paths
import routes
import transports

SPLIT = ("0.0.0.0/1", "128.0.0.0/1")
SPLIT_V6 = ("::/1", "8000::/1")
DEFAULT_V4 = "0.0.0.0/0"
DEFAULT_V6 = "::/0"
DEFAULT_TUNNEL_DNS = ("1.1.1.1", "8.8.8.8")
INTERVAL = 3.0          # seconds between reconciliation passes
RESOLVE_TTL = 300.0     # seconds a resolved ConnectTo hostname is reused
RESOLVE_TIMEOUT = 3.0   # max seconds to wait on a DNS lookup


@dataclass(frozen=True)
class Route:
    """One IPv4 or IPv6 route as the routing table reports it."""
    prefix: str          # "0.0.0.0/0" or "::/0"
    nexthop: str         # "192.168.1.1" / "fe80::1"; "0.0.0.0" or "::" = on-link
    ifindex: int
    metric: int = 0


@dataclass(frozen=True)
class Gateway:
    """The physical default route the pins go through."""
    ifindex: int
    nexthop: str         # "0.0.0.0" / "::" = on-link (PPP, some LTE modems)

    @property
    def via(self) -> str:
        return "" if self.nexthop in ("", "0.0.0.0", "::") else self.nexthop


# ---- pure logic ----------------------------------------------------------------

def _ipv4(text: str):
    try:
        ip = ipaddress.ip_address(str(text).strip())
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        return ip if isinstance(ip, ipaddress.IPv4Address) else None
    except (ValueError, TypeError):
        return None


def _ipv6(text: str):
    try:
        raw = str(text).strip()
        if raw.startswith("[") and raw.endswith("]"):
            raw = raw[1:-1]
        if "%" in raw:
            raw = raw.split("%", 1)[0]
        ip = ipaddress.ip_address(raw)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is None:
            return ip
        return None
    except (ValueError, TypeError):
        return None


def _nets(items: Iterable) -> list:
    out = []
    for s in items:
        n = routes.parse_subnet(s) if isinstance(s, str) else s
        if n is not None and n.version == 4:
            out.append(n)
    return out


def _nets_v6(items: Iterable) -> list:
    out = []
    for s in items:
        n = routes.parse_subnet(s) if isinstance(s, str) else s
        if n is not None and n.version == 6:
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


def pinnable_v6(addr: str, local_nets_v6: Iterable = (), vpn_nets_v6: Iterable = ()) -> bool:
    """True if `addr` is a peer IPv6 endpoint that must be pinned (/128) via the
    physical IPv6 gateway before ::/1 + 8000::/1 are installed on Wintun."""
    ip = _ipv6(addr)
    if ip is None or ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
        return False
    if any(ip in n for n in _nets_v6(local_nets_v6)):
        return False
    if any(ip in n for n in _nets_v6(vpn_nets_v6)):
        return False
    return True


def own_tunnel_ips(snap, options: dict, own: str = "") -> list:
    """The local tunnel adapter's own /32 IPv4 addresses (from InterfaceAddress,
    WintunAddress, or `own`'s /32 host Subnet)."""
    out = []
    opts = options or {}
    if not own:
        own_val = opts.get("Name", "")
        own = str(own_val[0] if isinstance(own_val, list) and own_val else (own_val or "")).strip()
    for key in ("InterfaceAddress", "WintunAddress"):
        v = opts.get(key)
        for item in (v if isinstance(v, (list, tuple)) else [v]):
            if not item:
                continue
            try:
                ifc = ipaddress.ip_interface(str(item).split()[0])
                if ifc.version == 4:
                    out.append(ipaddress.IPv4Network(f"{ifc.ip}/32"))
            except ValueError:
                continue
    if own:
        for s in getattr(snap, "subnets", []) or []:
            if getattr(s, "owner", "") != own:
                continue
            n = routes.parse_subnet(s.subnet)
            if n is not None and n.version == 4 and n.prefixlen == 32:
                out.append(n)
    return out


def vpn_networks(snap, options: dict) -> list:
    """Subnets locally configured on the tunnel adapter (InterfaceAddress,
    WintunAddress, AddressPool, and InterfaceRoute excluding default/split
    prefixes). Remote-announced `snap.subnets` are intentionally NOT trusted
    here so a peer announcing 0.0.0.0/1 + 128.0.0.0/1 (or a wide prefix
    covering a peer's public IP) cannot suppress /32 gateway pinning."""
    out = list(own_tunnel_ips(snap, options))
    opts = options or {}
    for key in ("InterfaceAddress", "WintunAddress"):
        v = opts.get(key)
        for item in (v if isinstance(v, (list, tuple)) else [v]):
            if not item:
                continue
            try:
                ifc = ipaddress.ip_interface(str(item).split()[0])
                if ifc.version == 4 and ifc.network.prefixlen > 0 \
                        and str(ifc.network) not in SPLIT:
                    out.append(ifc.network)
            except ValueError:
                continue
    pool = opts.get("AddressPool")
    for item in (pool if isinstance(pool, (list, tuple)) else [pool]):
        if not item:
            continue
        n = routes.parse_subnet(str(item).split()[0])
        if n is not None and n.version == 4 and n.prefixlen > 0 and str(n) not in SPLIT:
            out.append(n)
    for item in routes.values(opts):
        n = routes.parse_subnet(routes.destination(item))
        if n is not None and n.version == 4 and n.prefixlen > 0 \
                and str(n) not in SPLIT and str(n) != DEFAULT_V4:
            out.append(n)
    return out


def own_tunnel_ips_v6(snap, options: dict, own: str = "") -> list:
    """The local tunnel adapter's own /128 IPv6 addresses."""
    out = []
    opts = options or {}
    if not own:
        own_val = opts.get("Name", "")
        own = str(own_val[0] if isinstance(own_val, list) and own_val else (own_val or "")).strip()
    for key in ("InterfaceAddress", "WintunAddress"):
        v = opts.get(key)
        for item in (v if isinstance(v, (list, tuple)) else [v]):
            if not item:
                continue
            try:
                ifc = ipaddress.ip_interface(str(item).split()[0])
                if ifc.version == 6:
                    out.append(ipaddress.IPv6Network(f"{ifc.ip}/128"))
            except ValueError:
                continue
    if own:
        for s in getattr(snap, "subnets", []) or []:
            if getattr(s, "owner", "") != own:
                continue
            n = routes.parse_subnet(s.subnet)
            if n is not None and n.version == 6 and n.prefixlen == 128:
                out.append(n)
    return out


def vpn_networks_v6(snap, options: dict) -> list:
    """Locally configured IPv6 subnets on the tunnel adapter (excluding ::/0 and SPLIT_V6)."""
    out = list(own_tunnel_ips_v6(snap, options))
    opts = options or {}
    for key in ("InterfaceAddress", "WintunAddress"):
        v = opts.get(key)
        for item in (v if isinstance(v, (list, tuple)) else [v]):
            if not item:
                continue
            try:
                ifc = ipaddress.ip_interface(str(item).split()[0])
                if ifc.version == 6 and ifc.network.prefixlen > 0 \
                        and str(ifc.network) not in SPLIT_V6 and str(ifc.network) != DEFAULT_V6:
                    out.append(ifc.network)
            except ValueError:
                continue
    pool = opts.get("AddressPool")
    for item in (pool if isinstance(pool, (list, tuple)) else [pool]):
        if not item:
            continue
        n = routes.parse_subnet(str(item).split()[0])
        if n is not None and n.version == 6 and n.prefixlen > 0 \
                and str(n) not in SPLIT_V6 and str(n) != DEFAULT_V6:
            out.append(n)
    for item in routes.values(opts):
        n = routes.parse_subnet(routes.destination(item))
        if n is not None and n.version == 6 and n.prefixlen > 0 \
                and str(n) not in SPLIT_V6 and str(n) != DEFAULT_V6:
            out.append(n)
    return out


def neighbour_addresses_v6(snap, own: str) -> set[str]:
    out = set()
    for e in getattr(snap, "edges", []) or []:
        ip = _ipv6(e.address) if e.frm == own else None
        if ip:
            out.add(str(ip))
    return out


def snapshot_addresses_v6(snap, own: str, options: dict | None = None,
                          hosts: dict | None = None) -> set[str]:
    out = set()
    nodes = getattr(snap, "nodes", {}) or {}
    edges = getattr(snap, "edges", []) or []
    direct_peers = {e.to for e in edges if e.frm == own}

    def _skip_peer(peer_name: str) -> bool:
        if not peer_name or peer_name in direct_peers:
            return False
        nd_obj = nodes.get(peer_name)
        if nd_obj is not None and getattr(nd_obj, "no_direct", False):
            return True
        return transports.is_peer_no_direct(options, (hosts or {}).get(peer_name, ""), peer_name)

    for n in nodes.values():
        if n.name == own or n.is_self or _skip_peer(n.name):
            continue
        ip = _ipv6(n.address)
        if ip:
            out.add(str(ip))
    for e in edges:
        if e.to == own or _skip_peer(e.to):
            continue
        ip = _ipv6(e.address)
        if ip:
            out.add(str(ip))
    return out


def neighbour_addresses(snap, own: str) -> set[str]:
    """The addresses of this node's own meta connections: the edges that start
    at this node. A pin missing for one of these is exactly the loop, so the
    split routes are not installed until they are all pinned."""
    out = set()
    for e in getattr(snap, "edges", []) or []:
        ip = _ipv4(e.address) if e.frm == own else None
        if ip:
            out.add(str(ip))
    return out


def snapshot_addresses(snap, own: str, options: dict | None = None,
                       hosts: dict | None = None) -> set[str]:
    """Every IPv4 address the daemon knows for another node or edge: where it
    sends UDP to that node, and where each meta connection in the mesh runs,
    excluding peers marked no_direct unless we have an active direct edge to them."""
    out = set()
    nodes = getattr(snap, "nodes", {}) or {}
    edges = getattr(snap, "edges", []) or []
    direct_peers = {e.to for e in edges if e.frm == own}

    def _skip_peer(peer_name: str) -> bool:
        if not peer_name or peer_name in direct_peers:
            return False
        nd_obj = nodes.get(peer_name)
        if nd_obj is not None and getattr(nd_obj, "no_direct", False):
            return True
        return transports.is_peer_no_direct(options, (hosts or {}).get(peer_name, ""), peer_name)

    for n in nodes.values():
        if n.name == own or n.is_self or _skip_peer(n.name):
            continue
        ip = _ipv4(n.address)
        if ip:
            out.add(str(ip))
    for e in edges:
        # an edge towards this node carries this node's own public address
        if e.to == own or _skip_peer(e.to):
            continue
        ip = _ipv4(e.address)
        if ip:
            out.add(str(ip))
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
    names = transports.parse_node_list((options or {}).get("ConnectTo"))
    if not names:
        return []
    out = []
    for name in names:
        host_text = (hosts or {}).get(name, "")
        if transports.is_peer_no_direct(options, host_text, name):
            continue
        for a in host_addresses(host_text):
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


def choose_gateway_v6(table_v6: Iterable[Route], tunnel_ifindex: int | None) -> Gateway | None:
    """The physical IPv6 default route (::/0) with the lowest metric not on the tunnel adapter."""
    best = None
    for r in table_v6:
        if r.prefix != DEFAULT_V6 or r.ifindex == tunnel_ifindex:
            continue
        if best is None or r.metric < best.metric:
            best = r
    return Gateway(best.ifindex, best.nexthop) if best else None


def has_route(table: Iterable[Route], prefix: str, ifindex: int, via: str | None = None) -> bool:
    on_link = ("", "0.0.0.0", "::")
    want_on_link = via is not None and via in on_link
    return any(
        r.prefix == prefix and r.ifindex == ifindex
        and (
            via is None
            or (r.nexthop in on_link if want_on_link else r.nexthop == via)
        )
        for r in table
    )


def _has_ipv6_default_route(options: dict) -> bool:
    for item in routes.values(options or {}):
        n = routes.parse_subnet(routes.destination(item))
        if n is not None and n.version == 6 and str(n) in ("::/0", "::/1", "8000::/1"):
            return True
    return False


def _tunnel_dns_servers(options: dict) -> list[str]:
    opts = options or {}
    raw = opts.get("TunnelDns")
    if raw is not None:
        items = raw if isinstance(raw, (list, tuple)) else str(raw).replace(",", " ").split()
        out = [str(_ipv4(x)) for x in items if _ipv4(x)]
        return out
    return list(DEFAULT_TUNNEL_DNS)


def _resolve_with_timeout(fn: Callable[[str], list[str]], host: str, timeout: float) -> list[str]:
    if timeout <= 0:
        return fn(host)
    box: dict[str, object] = {}

    def _worker() -> None:
        try:
            box["res"] = fn(host)
        except BaseException as exc:
            box["err"] = exc

    th = threading.Thread(target=_worker, name=f"ft-dns-{host[:24]}", daemon=True)
    th.start()
    th.join(timeout)
    if th.is_alive():
        raise OSError(f"DNS lookup timed out after {timeout:.1f}s: {host}")
    if "err" in box:
        err = box["err"]
        if isinstance(err, OSError):
            raise err
        raise OSError(str(err))
    return list(box.get("res") or [])  # type: ignore[arg-type]


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

    def supports_ipv6(self) -> bool:
        return False

    def route_table_v6(self) -> list[Route]:
        return []

    def local_nets_v6(self) -> list[str]:
        return []

    def adapter_guid(self, ifindex: int) -> str:
        return ""

    def set_tunnel_dns(self, ifindex: int, servers: list[str]) -> tuple[bool, str]:
        return True, ""

    def clear_tunnel_dns(self, ifindex: int) -> tuple[bool, str]:
        return True, ""

    def clear_tunnel_dns_by_id(self, alias: str = "", guid: str = "") -> tuple[bool, str]:
        return True, ""


def _safe_clear_dns(
    system: System,
    dns_if: int | None,
    dns_guid: str = "",
    dns_alias: str = "",
    aliases: Iterable[str] = (),
) -> None:
    """Restore adapter DNS without ever wiping a foreign adapter that reused `dns_if`."""
    alias_list = [str(a) for a in aliases if a]
    if dns_alias and dns_alias not in alias_list:
        alias_list.insert(0, dns_alias)
    if dns_if is not None:
        cur_guid = system.adapter_guid(int(dns_if))
        if dns_guid:
            if cur_guid and cur_guid.lower() == dns_guid.lower():
                system.clear_tunnel_dns(int(dns_if))
                return
            cand_if = system.ifindex(alias_list) if alias_list else None
            if cand_if is not None:
                cand_guid = system.adapter_guid(int(cand_if))
                if not cand_guid or cand_guid.lower() == dns_guid.lower():
                    system.clear_tunnel_dns(int(cand_if))
                    return
            system.clear_tunnel_dns_by_id(dns_alias, dns_guid)
            return
        system.clear_tunnel_dns(int(dns_if))
        return
    if dns_alias or dns_guid:
        cand_if = system.ifindex(alias_list) if alias_list else None
        if cand_if is not None:
            cand_guid = system.adapter_guid(int(cand_if))
            if not dns_guid or not cand_guid or cand_guid.lower() == dns_guid.lower():
                system.clear_tunnel_dns(int(cand_if))
                return
        system.clear_tunnel_dns_by_id(dns_alias, dns_guid)


def cleanup_journal(journal_path: str, system: System | None,
                    aliases: Iterable[str] = ()) -> list[str]:
    """Remove any orphaned split routes, IPv6 leak-guard routes, DNS settings,
    and /32 + /128 gateway pins recorded by a previous session in `journal_path`."""
    if not journal_path or not os.path.isfile(journal_path):
        return []
    log: list[str] = []
    try:
        with open(journal_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        try:
            os.remove(journal_path)
        except OSError:
            pass
        return []
    if not isinstance(data, dict):
        try:
            os.remove(journal_path)
        except OSError:
            pass
        return []
    if system is not None:
        alias_list = list(aliases) or [str(a) for a in (data.get("aliases") or []) if a]
        split_if = data.get("split_if")
        if split_if is None and alias_list:
            split_if = system.ifindex(alias_list)
        if split_if is not None:
            idx = int(split_if)
            table = system.route_table()
            if data.get("split_if") is not None or any(has_route(table, p, idx) for p in SPLIT):
                for p in SPLIT:
                    ok, _ = system.delete_route(p, idx)
                    if ok:
                        log.append(f"full tunnel: cleaned journaled {p} (if {idx})")
        v6_if = data.get("v6_if")
        if v6_if is not None and system.supports_ipv6():
            for p6 in SPLIT_V6:
                system.delete_route(p6, int(v6_if))
        dns_if = data.get("dns_if")
        dns_guid = str(data.get("dns_guid") or "")
        dns_alias = str(data.get("dns_alias") or "")
        if dns_if is not None or dns_guid or dns_alias:
            _safe_clear_dns(
                system,
                int(dns_if) if dns_if is not None else None,
                dns_guid=dns_guid,
                dns_alias=dns_alias,
                aliases=alias_list,
            )
            log.append(f"full tunnel: cleaned journaled DNS ({dns_alias or dns_guid or dns_if})")
        for item in data.get("pins") or []:
            if not isinstance(item, dict) or not item.get("ip") or item.get("ifindex") is None:
                continue
            ip = str(item["ip"])
            via = str(item.get("via") or "")
            ok, _ = system.delete_route(f"{ip}/32", int(item["ifindex"]), via)
            if ok:
                log.append(f"full tunnel: cleaned journaled pin {ip}/32")
        for item in data.get("pins_v6") or []:
            if not isinstance(item, dict) or not item.get("ip") or item.get("ifindex") is None:
                continue
            ip6 = str(item["ip"])
            via6 = str(item.get("via") or "")
            ok6, _ = system.delete_route(f"{ip6}/128", int(item["ifindex"]), via6)
            if ok6:
                log.append(f"full tunnel: cleaned journaled pin {ip6}/128")
    try:
        os.remove(journal_path)
    except OSError:
        pass
    return log


@dataclass
class FullTunnel:
    net: str
    exit_node: str
    aliases: list[str]
    system: System
    clock: Callable[[], float] = time.monotonic
    journal_path: str = ""
    resolve_timeout: float = RESOLVE_TIMEOUT
    pins: dict = field(default_factory=dict)        # ipv4 -> Gateway it is pinned through
    pins_v6: dict = field(default_factory=dict)     # ipv6 -> Gateway it is pinned through
    split_if: int | None = None                     # adapter the split routes are on
    state: str = "starting"
    _resolved: dict = field(default_factory=dict)   # host -> (expiry, [ip])
    _v6_if: int | None = None
    _dns_if: int | None = None
    _dns_guid: str = ""
    _dns_alias: str = ""

    def _write_journal(
        self,
        *,
        extra_pins: dict | None = None,
        extra_pins_v6: dict | None = None,
        split_if: int | None = None,
        v6_if: int | None = None,
        dns_if: int | None = None,
        dns_guid: str | None = None,
        dns_alias: str | None = None,
    ) -> None:
        if not self.journal_path:
            return
        eff_pins = dict(self.pins)
        if extra_pins:
            eff_pins.update(extra_pins)
        eff_pins_v6 = dict(self.pins_v6)
        if extra_pins_v6:
            eff_pins_v6.update(extra_pins_v6)
        eff_split = self.split_if if split_if is None else split_if
        eff_v6 = self._v6_if if v6_if is None else v6_if
        eff_dns = self._dns_if if dns_if is None else dns_if
        eff_guid = self._dns_guid if dns_guid is None else dns_guid
        eff_alias = self._dns_alias if dns_alias is None else dns_alias
        if (
            eff_split is None
            and eff_v6 is None
            and eff_dns is None
            and not eff_guid
            and not eff_pins
            and not eff_pins_v6
        ):
            try:
                os.remove(self.journal_path)
            except OSError:
                pass
            return
        payload = {
            "split_if": eff_split,
            "v6_if": eff_v6,
            "dns_if": eff_dns,
            "dns_guid": eff_guid,
            "dns_alias": eff_alias,
            "aliases": list(self.aliases),
            "pins": [
                {"ip": ip, "ifindex": gw.ifindex, "via": gw.via}
                for ip, gw in sorted(eff_pins.items())
            ],
            "pins_v6": [
                {"ip": ip6, "ifindex": gw.ifindex, "via": gw.via}
                for ip6, gw in sorted(eff_pins_v6.items())
            ],
        }
        try:
            paths.write_private(self.journal_path, (json.dumps(payload, indent=2) + "\n").encode("utf-8"))
        except OSError:
            pass

    def _resolve_peer_ips(
        self,
        options: dict,
        hosts: dict,
        own: str = "",
        refresh_dns: bool = False,
    ) -> tuple[set[str], set[str], set[str]]:
        out_v4: set[str] = set()
        out_v6: set[str] = set()
        v6_only_ct: set[str] = set()
        now = self.clock()
        ct_targets = list(connect_to_hosts(options, hosts))
        extra_targets: list[str] = []
        for name, text in (hosts or {}).items():
            peer_name = str(name).strip()
            if own and peer_name == own:
                continue
            if transports.is_peer_no_direct(options, text, peer_name):
                continue
            for a in host_addresses(text):
                if a not in ct_targets and a not in extra_targets:
                    extra_targets.append(a)

        def _lookup_host(host: str) -> tuple[list[str], list[str]]:
            ip4 = _ipv4(host)
            if ip4:
                return [str(ip4)], []
            ip6 = _ipv6(host)
            if ip6:
                return [], [str(ip6)]
            exp, cached = self._resolved.get(host, (0.0, []))
            if refresh_dns or now >= exp:
                try:
                    raw_addrs = _resolve_with_timeout(
                        self.system.resolve, host, self.resolve_timeout
                    )
                    fresh: list[str] = []
                    for a in raw_addrs:
                        v4 = _ipv4(a)
                        v6 = _ipv6(a)
                        canon = str(v4) if v4 else (str(v6) if v6 else "")
                        if canon and canon not in fresh:
                            fresh.append(canon)
                    if fresh or not cached:
                        cached = fresh
                except OSError:
                    cached = cached or []   # keep the last answer while DNS is down
                self._resolved[host] = (now + RESOLVE_TTL, cached)
            v4s = [str(_ipv4(a)) for a in cached if _ipv4(a)]
            v6s = [str(_ipv6(a)) for a in cached if _ipv6(a)]
            return v4s, v6s

        for host in ct_targets:
            v4s, v6s = _lookup_host(host)
            out_v4.update(v4s)
            out_v6.update(v6s)
            if v6s and not v4s:
                v6_only_ct.update(v6s)
        for host in extra_targets:
            v4s, v6s = _lookup_host(host)
            out_v4.update(v4s)
            out_v6.update(v6s)
        return out_v4, out_v6, v6_only_ct

    def _connect_to_ips(self, options: dict, hosts: dict, own: str = "",
                        refresh_dns: bool = False) -> set[str]:
        v4s, _, _ = self._resolve_peer_ips(options, hosts, own, refresh_dns=refresh_dns)
        return v4s

    def _set_state(self, text: str, log: list[str]) -> None:
        if text != self.state:
            log.append(f"full tunnel: {text}")
        self.state = text

    def _remove_split(self, log: list[str]) -> None:
        if self._v6_if is not None:
            for p6 in SPLIT_V6:
                self.system.delete_route(p6, self._v6_if)
            self._v6_if = None
        if self._dns_if is not None or self._dns_guid:
            _safe_clear_dns(
                self.system,
                self._dns_if,
                dns_guid=self._dns_guid,
                dns_alias=self._dns_alias,
                aliases=self.aliases,
            )
            self._dns_if = None
            self._dns_guid = ""
            self._dns_alias = ""
        if self.split_if is None:
            self._write_journal()
            return
        for p in SPLIT:
            ok, msg = self.system.delete_route(p, self.split_if)
            log.append(f"full tunnel: removed {p}" if ok else f"full tunnel: removing {p}: {msg}")
        self.split_if = None
        self._write_journal()

    def _unpin_all_v6(self, log: list[str]) -> None:
        for ip6 in sorted(list(self.pins_v6)):
            old_gw6 = self.pins_v6.pop(ip6)
            ok6, msg6 = self.system.delete_route(f"{ip6}/128", old_gw6.ifindex, old_gw6.via)
            if not ok6:
                log.append(f"full tunnel: unpinning {ip6}: {msg6}")

    def step(self, snap, options: dict, hosts: dict, own: str,
             refresh_dns: bool = False) -> list[str]:
        """One reconciliation pass. Returns log lines for what changed."""
        log: list[str] = []
        sysm = self.system
        tunnel_if = sysm.ifindex(self.aliases)
        if tunnel_if is None:
            # tincd not up yet, or restarting: Windows took the adapter's
            # routes with it, so there is nothing of ours on it any more
            if self._dns_if is not None or self._dns_guid:
                _safe_clear_dns(
                    sysm,
                    self._dns_if,
                    dns_guid=self._dns_guid,
                    dns_alias=self._dns_alias,
                    aliases=self.aliases,
                )
            self.split_if = None
            self._v6_if = None
            self._dns_if = None
            self._dns_guid = ""
            self._dns_alias = ""
            self._write_journal()
            self._set_state("waiting for the tunnel adapter", log)
            return log
        if self.split_if is not None and self.split_if != tunnel_if:
            self.split_if = None     # a new adapter instance after a restart
            self._v6_if = None
            self._dns_if = None
            self._dns_guid = ""
            self._dns_alias = ""
        table = sysm.route_table()
        gw = choose_gateway(table, tunnel_if)
        if gw is None:
            self._remove_split(log)
            self._set_state("no physical default route (offline?)", log)
            return log

        local = sysm.local_nets()
        vpn = vpn_networks(snap, options)
        own_v4 = own_tunnel_ips(snap, options, own)
        ct_v4, ct_v6, v6_only_ct = self._resolve_peer_ips(
            options, hosts, own, refresh_dns=refresh_dns
        )
        # External peer endpoints on direct edges / ConnectTo must NEVER be
        # excluded by wider (< /32) VPN prefixes -- only skip local_nets or our
        # own /32 tunnel IP.
        must = {a for a in neighbour_addresses(snap, own) | ct_v4
                if pinnable(a, local, own_v4)}
        want = must | {a for a in snapshot_addresses(snap, own, options, hosts) if pinnable(a, local, vpn)}

        # Persist intended /32 pins to rollback journal BEFORE mutating OS routes
        intended_pins = {ip: gw for ip in want}
        if intended_pins != self.pins:
            self._write_journal(extra_pins=intended_pins)

        # 1. pins first, through the current physical gateway
        failed = {}
        for ip in sorted(want):
            prefix = f"{ip}/32"
            have = self.pins.get(ip)
            stale_on_gw = [
                r for r in table
                if r.prefix == prefix and r.ifindex == gw.ifindex
                and r.nexthop != (gw.via or "0.0.0.0")
            ]
            if have == gw and has_route(table, prefix, gw.ifindex, gw.via) and not stale_on_gw:
                continue
            if have is not None and have != gw:
                sysm.delete_route(prefix, have.ifindex, have.via)
            for sr in stale_on_gw:
                st_via = "" if sr.nexthop in ("", "0.0.0.0") else sr.nexthop
                if have is None or (have.ifindex, have.via) != (sr.ifindex, st_via):
                    sysm.delete_route(prefix, sr.ifindex, st_via)
            ok, msg = sysm.add_route(prefix, gw.ifindex, gw.via)
            if ok:
                self.pins[ip] = gw
                log.append(f"full tunnel: pinned {ip} via {gw.via or 'on-link'} (if {gw.ifindex})")
            else:
                self.pins.pop(ip, None)
                failed[ip] = msg

        # Prune stale pins for endpoints that moved or are no longer in the snapshot/config
        for ip in sorted(set(self.pins) - want):
            old_gw = self.pins.pop(ip)
            ok, msg = sysm.delete_route(f"{ip}/32", old_gw.ifindex, old_gw.via)
            log.append(f"full tunnel: unpinned stale {ip}" if ok else f"full tunnel: unpinning {ip}: {msg}")

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

        # Prepare IPv6 /128 endpoint bypass pins BEFORE ::/1 and 8000::/1
        want_split_v6 = sysm.supports_ipv6() and not _has_ipv6_default_route(options)
        allow_split_v6 = False
        if want_split_v6:
            table_v6 = sysm.route_table_v6()
            gw6 = choose_gateway_v6(table_v6, tunnel_if)
            local6 = sysm.local_nets_v6()
            vpn6 = vpn_networks_v6(snap, options)
            own_v6 = own_tunnel_ips_v6(snap, options, own)
            active_edges_v6 = {
                a for a in neighbour_addresses_v6(snap, own)
                if pinnable_v6(a, local6, own_v6)
            }
            must_v6_carrier = active_edges_v6 | {
                a for a in v6_only_ct if pinnable_v6(a, local6, own_v6)
            }
            must_v6_all = active_edges_v6 | {
                a for a in ct_v6 if pinnable_v6(a, local6, own_v6)
            }
            want_v6 = must_v6_all | {
                a for a in snapshot_addresses_v6(snap, own, options, hosts)
                if pinnable_v6(a, local6, vpn6)
            }
            if gw6 is not None:
                if want_v6:
                    self._write_journal(extra_pins_v6={ip6: gw6 for ip6 in want_v6})
                failed_v6 = {}
                for ip6 in sorted(want_v6):
                    prefix6 = f"{ip6}/128"
                    have6 = self.pins_v6.get(ip6)
                    stale6 = [
                        r for r in table_v6
                        if r.prefix == prefix6 and r.ifindex == gw6.ifindex
                        and (r.nexthop if r.nexthop not in ("", "::", "0.0.0.0") else "") != gw6.via
                    ]
                    if have6 == gw6 and has_route(table_v6, prefix6, gw6.ifindex, gw6.via) and not stale6:
                        continue
                    if have6 is not None and have6 != gw6:
                        sysm.delete_route(prefix6, have6.ifindex, have6.via)
                    for sr6 in stale6:
                        st_via6 = "" if sr6.nexthop in ("", "::", "0.0.0.0") else sr6.nexthop
                        if have6 is None or (have6.ifindex, have6.via) != (sr6.ifindex, st_via6):
                            sysm.delete_route(prefix6, sr6.ifindex, st_via6)
                    ok6, msg6 = sysm.add_route(prefix6, gw6.ifindex, gw6.via)
                    if ok6:
                        self.pins_v6[ip6] = gw6
                        log.append(f"full tunnel: pinned {ip6} via {gw6.via or 'on-link'} (if {gw6.ifindex})")
                    else:
                        self.pins_v6.pop(ip6, None)
                        failed_v6[ip6] = msg6
                for ip6 in sorted(set(self.pins_v6) - want_v6):
                    old_gw6 = self.pins_v6.pop(ip6)
                    ok6, msg6 = sysm.delete_route(f"{ip6}/128", old_gw6.ifindex, old_gw6.via)
                    log.append(
                        f"full tunnel: unpinned stale {ip6}"
                        if ok6 else f"full tunnel: unpinning {ip6}: {msg6}"
                    )
                missing_v6 = sorted(ip6 for ip6 in must_v6_all if ip6 in failed_v6)
                if missing_v6:
                    log.append(
                        f"full tunnel: skipping IPv6 split routes; could not pin "
                        f"{missing_v6[0]} ({failed_v6[missing_v6[0]]})"
                    )
                    allow_split_v6 = False
                else:
                    allow_split_v6 = True
            else:
                self._unpin_all_v6(log)
                if must_v6_carrier:
                    # Active carrier or IPv6-only ConnectTo endpoint uses IPv6 without a
                    # physical IPv6 default gateway to pin through: never loop it into Wintun!
                    log.append(
                        f"full tunnel: skipping IPv6 split routes; IPv6 endpoint "
                        f"{sorted(must_v6_carrier)[0]} has no physical IPv6 gateway to pin through"
                    )
                    allow_split_v6 = False
                else:
                    # Peer is reached over IPv4 and host has no physical v6 default gateway:
                    # safe to install ::/1 + 8000::/1 leak-guard routes on Wintun.
                    allow_split_v6 = True
        else:
            self._unpin_all_v6(log)

        dns_servers = _tunnel_dns_servers(options)
        tun_guid = sysm.adapter_guid(tunnel_if)
        tun_alias = self.aliases[0] if self.aliases else ""
        # Persist rollback journal BEFORE mutating split routes / adapter DNS
        self._write_journal(
            split_if=tunnel_if,
            v6_if=tunnel_if if allow_split_v6 else self._v6_if,
            dns_if=tunnel_if if dns_servers else self._dns_if,
            dns_guid=tun_guid if dns_servers else self._dns_guid,
            dns_alias=tun_alias if dns_servers else self._dns_alias,
        )

        for p in SPLIT:
            if has_route(table, p, tunnel_if):
                self.split_if = tunnel_if
            else:
                ok, msg = sysm.add_route(p, tunnel_if)
                if not ok:
                    self._remove_split(log)
                    self._set_state(f"not applied: adding {p}: {msg}", log)
                    return log
                self.split_if = tunnel_if
                log.append(f"full tunnel: added {p} on the tunnel adapter (if {tunnel_if})")
        if allow_split_v6:
            if self._v6_if != tunnel_if:
                v6_ok = True
                for p6 in SPLIT_V6:
                    ok6, _ = sysm.add_route(p6, tunnel_if)
                    if not ok6:
                        v6_ok = False
                if v6_ok:
                    self._v6_if = tunnel_if
                else:
                    for p6 in SPLIT_V6:
                        sysm.delete_route(p6, tunnel_if)
        elif self._v6_if is not None:
            for p6 in SPLIT_V6:
                sysm.delete_route(p6, self._v6_if)
            self._v6_if = None
        if dns_servers and self._dns_if != tunnel_if:
            ok_dns, _ = sysm.set_tunnel_dns(tunnel_if, dns_servers)
            if ok_dns:
                self._dns_if = tunnel_if
                self._dns_guid = tun_guid
                self._dns_alias = tun_alias
        self._write_journal()
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
        for ip6, gw6 in sorted(self.pins_v6.items()):
            ok6, msg6 = self.system.delete_route(f"{ip6}/128", gw6.ifindex, gw6.via)
            if not ok6:
                log.append(f"full tunnel: unpinning {ip6}: {msg6}")
        total_pins = len(self.pins) + len(self.pins_v6)
        if total_pins:
            log.append(f"full tunnel: removed {total_pins} pin(s)")
        self.pins.clear()
        self.pins_v6.clear()
        self._write_journal()
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
        self._lock = threading.Lock()
        self._daemon_errors = 0
        self._cleaned_up = False

    @property
    def exit_node(self) -> str:
        return self.ft.exit_node

    def _step(self) -> None:
        """Execute one serialized reconciliation pass, re-resolving peer DNS
        hostnames so DDNS endpoint changes update /32 and /128 bypass pins
        even while `split_if` is active."""
        with self._lock:
            if self._halt.is_set() or self._cleaned_up:
                return
            try:
                snap = self._snapshot()
                if getattr(snap, "error", ""):
                    self._daemon_errors += 1
                    self.ft.state = "waiting for the daemon"
                    if self._daemon_errors >= 2:
                        if self.ft.split_if is not None:
                            lines: list[str] = [
                                f"full tunnel: daemon unresponsive ({snap.error}) -- "
                                f"removing split routes (fail-open)"
                            ]
                            self.ft._remove_split(lines)
                            for line in lines:
                                self._log(line)
                        if (self.ft.pins or self.ft.pins_v6) and self.ft.system.ifindex(self.ft.aliases) is None:
                            for line in self.ft.stop():
                                self._log(line)
                            self.ft.state = "waiting for the daemon"
                else:
                    self._daemon_errors = 0
                    options, hosts, own = self._config()
                    for line in self.ft.step(snap, options, hosts, own, refresh_dns=True):
                        self._log(line)
            except Exception as e:     # never let one bad pass end the loop
                self._log(f"full tunnel: pass failed: {type(e).__name__}: {e}")

    def _cleanup(self) -> None:
        with self._lock:
            if self._cleaned_up:
                return
            self._cleaned_up = True
            try:
                for line in self.ft.stop():
                    self._log(line)
            except Exception as e:
                self._log(f"full tunnel: cleanup failed, routes may remain until reboot: "
                          f"{type(e).__name__}: {e}")
            self._log("full tunnel: off")

    def run(self) -> None:
        self._log(f"full tunnel: on, exit node {self.ft.exit_node}")
        while not self._halt.is_set():
            self._step()
            self._halt.wait(self.interval)
        self._cleanup()

    def stop(self, timeout: float = 15.0) -> None:
        self._halt.set()
        self.join(timeout)
        if not self.is_alive():
            self._cleanup()


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

        class _GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", ctypes.c_uint32),
                ("Data2", ctypes.c_uint16),
                ("Data3", ctypes.c_uint16),
                ("Data4", ctypes.c_ubyte * 8),
            ]

        class _SOCKADDR_IN6(ctypes.Structure):
            _fields_ = [
                ("sin6_family", ctypes.c_uint16),
                ("sin6_port", ctypes.c_uint16),
                ("sin6_flowinfo", ctypes.c_uint32),
                ("sin6_addr", ctypes.c_ubyte * 16),
                ("sin6_scope_id", ctypes.c_uint32),
            ]

        class _IP_ADDRESS_PREFIX6(ctypes.Structure):
            _fields_ = [
                ("Ipv6", _SOCKADDR_IN6),
                ("PrefixLength", ctypes.c_uint8),
                ("_pad", ctypes.c_uint8 * 3),
            ]

        class _MIB_IPFORWARD_ROW2(ctypes.Structure):
            _fields_ = [
                ("InterfaceLuid", ctypes.c_uint64),
                ("InterfaceIndex", ctypes.c_uint32),
                ("DestinationPrefix", _IP_ADDRESS_PREFIX6),
                ("NextHop", _SOCKADDR_IN6),
                ("SitePrefixLength", ctypes.c_uint8),
                ("_pad1", ctypes.c_uint8 * 3),
                ("ValidLifetime", ctypes.c_uint32),
                ("PreferredLifetime", ctypes.c_uint32),
                ("Metric", ctypes.c_uint32),
                ("Protocol", ctypes.c_uint32),
                ("Loopback", ctypes.c_uint8),
                ("AutoconfigureAddress", ctypes.c_uint8),
                ("Publish", ctypes.c_uint8),
                ("Immortal", ctypes.c_uint8),
                ("Age", ctypes.c_uint32),
                ("Origin", ctypes.c_uint32),
            ]

        self._ct = ctypes
        self._ROW = _ROW
        self._GUID = _GUID
        self._ROW6 = _MIB_IPFORWARD_ROW2
        self._lib = ctypes.WinDLL("iphlpapi.dll")
        self._lib.ConvertInterfaceAliasToLuid.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_uint64)]
        self._lib.ConvertInterfaceAliasToLuid.restype = ctypes.c_ulong
        self._lib.ConvertInterfaceLuidToIndex.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_ulong)]
        self._lib.ConvertInterfaceLuidToIndex.restype = ctypes.c_ulong
        self._lib.ConvertInterfaceIndexToLuid.argtypes = [ctypes.c_ulong, ctypes.POINTER(ctypes.c_uint64)]
        self._lib.ConvertInterfaceIndexToLuid.restype = ctypes.c_ulong
        self._lib.ConvertInterfaceLuidToGuid.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(_GUID)]
        self._lib.ConvertInterfaceLuidToGuid.restype = ctypes.c_ulong
        self._lib.GetIpForwardTable2.argtypes = [ctypes.c_uint16, ctypes.POINTER(ctypes.c_void_p)]
        self._lib.GetIpForwardTable2.restype = ctypes.c_ulong
        self._lib.FreeMibTable.argtypes = [ctypes.c_void_p]
        self._lib.FreeMibTable.restype = None

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
            if int(r.type) == 2:   # MIB_IPROUTE_TYPE_INVALID
                continue
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

    def adapter_guid(self, ifindex: int) -> str:
        ct = self._ct
        luid = ct.c_uint64(0)
        if self._lib.ConvertInterfaceIndexToLuid(int(ifindex), ct.byref(luid)) != 0 or not luid.value:
            return ""
        g = self._GUID()
        if self._lib.ConvertInterfaceLuidToGuid(ct.byref(luid), ct.byref(g)) != 0:
            return ""
        b = bytes(g.Data4)
        return (
            f"{{{g.Data1:08X}-{g.Data2:04X}-{g.Data3:04X}-"
            f"{b[0]:02X}{b[1]:02X}-{b[2]:02X}{b[3]:02X}{b[4]:02X}{b[5]:02X}{b[6]:02X}{b[7]:02X}}}"
        )

    def route_table_v6(self) -> list[Route]:
        ct = self._ct
        tbl = ct.c_void_p()
        if self._lib.GetIpForwardTable2(socket.AF_INET6, ct.byref(tbl)) != 0 or not tbl.value:
            return []
        try:
            count = ct.cast(tbl.value, ct.POINTER(ct.c_uint32))[0]
            rows = ct.cast(tbl.value + 8, ct.POINTER(self._ROW6))
            out: list[Route] = []
            for i in range(count):
                r = rows[i]
                if r.DestinationPrefix.Ipv6.sin6_family != socket.AF_INET6:
                    continue
                plen = int(r.DestinationPrefix.PrefixLength)
                if plen < 0 or plen > 128:
                    continue
                try:
                    dst = ipaddress.IPv6Address(bytes(r.DestinationPrefix.Ipv6.sin6_addr))
                    net = ipaddress.IPv6Network(f"{dst}/{plen}", strict=False)
                    nh = ipaddress.IPv6Address(bytes(r.NextHop.sin6_addr))
                except ValueError:
                    continue
                out.append(Route(str(net), str(nh), int(r.InterfaceIndex), int(r.Metric)))
            return out
        finally:
            self._lib.FreeMibTable(tbl)

    def local_nets_v6(self) -> list[str]:
        out: list[str] = []
        for r in self.route_table_v6():
            if r.nexthop != "::" or r.prefix in SPLIT_V6 or r.prefix == DEFAULT_V6:
                continue
            n = routes.parse_subnet(r.prefix)
            if n is not None and n.version == 6 and 0 < n.prefixlen < 128 and not n.is_link_local and not n.is_multicast:
                out.append(str(n))
        return sorted(set(out))

    def local_nets(self) -> list[str]:
        return routes.local_ipv4_subnets()

    def resolve(self, host: str) -> list[str]:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return sorted({i[4][0].split("%", 1)[0] for i in infos})

    def add_route(self, prefix: str, ifindex: int, via: str = "") -> tuple[bool, str]:
        try:
            add = routes.route_args("add", str(ifindex), prefix, via)
            update = routes.route_args("set", str(ifindex), prefix, via)
        except ValueError as e:
            return False, str(e)
        ok, msg = routes._netsh(add)
        if not ok:
            ok2, msg2 = routes._netsh(update)
            if ok2:
                return True, msg2
        return ok, msg

    def delete_route(self, prefix: str, ifindex: int, via: str = "") -> tuple[bool, str]:
        try:
            return routes._netsh(routes.route_args("delete", str(ifindex), prefix, via))
        except ValueError as e:
            return False, str(e)

    def supports_ipv6(self) -> bool:
        return True

    def set_tunnel_dns(self, ifindex: int, servers: list[str]) -> tuple[bool, str]:
        clean = [str(_ipv4(s)) for s in servers if _ipv4(s)]
        if not clean:
            return True, ""
        ok, msg = routes._netsh([
            "interface", "ipv4", "set", "dnsservers",
            f"name={int(ifindex)}", "static", clean[0], "primary", "validate=no",
        ])
        if not ok:
            return False, msg
        for extra in clean[1:]:
            routes._netsh([
                "interface", "ipv4", "add", "dnsservers",
                f"name={int(ifindex)}", extra, "validate=no",
            ])
        return True, msg

    def clear_tunnel_dns(self, ifindex: int) -> tuple[bool, str]:
        return routes._netsh([
            "interface", "ipv4", "delete", "dnsservers", f"name={int(ifindex)}", "all",
        ])

    def clear_tunnel_dns_by_id(self, alias: str = "", guid: str = "") -> tuple[bool, str]:
        ok, msg = True, ""
        if alias:
            ok, msg = routes._netsh([
                "interface", "ipv4", "delete", "dnsservers", f"name={alias}", "all",
            ])
        if guid and os.name == "nt":
            try:
                import winreg
                key_path = rf"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{guid}"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE) as k:
                    winreg.SetValueEx(k, "NameServer", 0, winreg.REG_SZ, "")
            except OSError:
                pass
        return ok, msg


def system() -> System | None:
    """The real System on Windows, None elsewhere (nothing to apply)."""
    if os.name != "nt":
        return None
    try:
        return Win32()
    except (OSError, AttributeError):
        return None
