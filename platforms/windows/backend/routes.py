"""
routes.py — turn a subnet another node announces into a route this machine uses.

tinc already knows how to forward a peer's subnet: the peer announced it and it
is in tinc's own routing table. What is missing is the other half — Windows has
no reason to hand those packets to the tunnel adapter in the first place. That
is one system route, and this module is the two things the GUI needs to manage
it: the config entry that makes it permanent, and the live call that makes it
take effect now.

The config entry is `InterfaceRoute`, the same option the daemon reads on every
platform (autoif.c on Linux, wintun_device.c on Windows). The daemon installs
those routes on the adapter when the network starts and Windows removes them
with the adapter when it stops, so a route into a peer's LAN never outlives the
tunnel that was the only way to reach it. The live call is `netsh`, used only so
that ticking a box does not need a restart; it writes `store=active`, so nothing
survives a reboot that the config would not have recreated anyway.

Everything above the Win32 line is pure and testable on any platform.
"""

from __future__ import annotations

import ipaddress
import os
import subprocess

OPTION = "InterfaceRoute"

# The default route is deliberately not offered as a one-click toggle. Sending
# everything through the tunnel also sends the tunnel's own packets through it
# unless the peer's endpoint is pinned to the physical gateway first, and an
# endpoint that moves (NAT rebind, address cache, a relayed peer with no direct
# endpoint at all) then takes the whole machine off the network. That is a
# feature with its own failure modes, not a checkbox.
FULL_TUNNEL = ("0.0.0.0/0", "::/0")


def parse_subnet(text: str):
    """The subnet as an ip_network, or None if it is not one. tinc prints a bare
    address for a host route, which is a valid /32 here."""
    try:
        return ipaddress.ip_network(str(text).strip(), strict=False)
    except (ValueError, TypeError):
        return None


def routable(subnet: str) -> bool:
    """True if a route to `subnet` is worth offering: a real network announced
    by a peer, not that peer's own address and not the default route."""
    net = parse_subnet(subnet)
    if net is None or str(net) in FULL_TUNNEL:
        return False
    return net.prefixlen < net.max_prefixlen


def why_not_routable(subnet: str) -> str:
    """The reason `routable` said no, for a tooltip. '' when it said yes."""
    net = parse_subnet(subnet)
    if net is None:
        return f"{subnet} is not a subnet this can route"
    if str(net) in FULL_TUNNEL:
        return ("A full tunnel is not a one-click toggle: everything, including this "
                "tunnel's own packets, would go through it unless the peer's endpoint "
                "is pinned to the physical gateway first.")
    if net.prefixlen >= net.max_prefixlen:
        return f"{subnet} is that node's own address, already reachable through the tunnel"
    return ""


def entry(subnet: str, via: str = "") -> str:
    """The InterfaceRoute value for this subnet: '<prefix>' or '<prefix> <ip>'.

    That second form is the documented one -- it is what `tinc join` writes from
    an invitation's Route line -- so it is what we write. The daemon also accepts
    '<prefix> via <ip>'; `destination()` reads both back.

    The nexthop is cosmetic on a tun interface (the kernel just hands the packet
    to the device) but it records which node the route is for, which is the thing
    the operator actually chose."""
    net = parse_subnet(subnet)
    dest = str(net) if net else str(subnet).strip()
    via = str(via or "").strip()
    return f"{dest} {via}" if via else dest


def destination(value: str) -> str:
    """The destination prefix of an InterfaceRoute value, ignoring any nexthop
    and either spelling of it."""
    dest = (str(value).split() or [""])[0].strip()
    net = parse_subnet(dest)
    return str(net) if net else dest


def values(options: dict) -> list[str]:
    """Every InterfaceRoute of this network, as a list (the option is
    VAR_MULTIPLE, so the YAML holds either one scalar or a list)."""
    val = options.get(OPTION)
    if val is None:
        return []
    if isinstance(val, (list, tuple)):
        return [str(v).strip() for v in val if str(v).strip()]
    return [str(val).strip()] if str(val).strip() else []


def has(options: dict, subnet: str) -> bool:
    want = destination(subnet)
    return any(destination(v) == want for v in values(options))


def add(options: dict, subnet: str, via: str = "") -> None:
    """Add (or replace) the route for `subnet`. Replacing matters: the same
    subnet announced by two nodes must not end up as two conflicting entries."""
    keep = [v for v in values(options) if destination(v) != destination(subnet)]
    keep.append(entry(subnet, via))
    _store(options, keep)


def remove(options: dict, subnet: str) -> None:
    _store(options, [v for v in values(options) if destination(v) != destination(subnet)])


def _store(options: dict, items: list[str]) -> None:
    """Write the list back the way the rest of the schema does: absent when
    empty, a scalar when there is one, a list when there are several."""
    if not items:
        options.pop(OPTION, None)
    elif len(items) == 1:
        options[OPTION] = items[0]
    else:
        options[OPTION] = items


def conflicts(subnet: str, local_nets) -> list[str]:
    """Local networks that overlap `subnet`. Adding the route anyway takes those
    addresses away from the interface that owns them — 192.168.1.0/24 announced
    by a peer, on a machine sitting on 192.168.1.0/24 at home, is the case that
    matters and it is not rare."""
    net = parse_subnet(subnet)
    if net is None:
        return []
    out = []
    for other in local_nets:
        o = other if not isinstance(other, str) else parse_subnet(other)
        if o is None or o.version != net.version:
            continue
        if net.overlaps(o):
            out.append(str(o))
    return out


# ---- Win32 -------------------------------------------------------------------

def local_ipv4_subnets() -> list[str]:
    """The IPv4 networks this machine is directly attached to (GetIpAddrTable),
    loopback and unconfigured adapters left out. [] off Windows, and [] rather
    than an exception if the API is unavailable: this only feeds a warning."""
    if os.name != "nt":
        return []
    try:
        import ctypes

        class _ROW(ctypes.Structure):
            _fields_ = [("dwAddr", ctypes.c_uint32), ("dwIndex", ctypes.c_uint32),
                        ("dwMask", ctypes.c_uint32), ("dwBCastAddr", ctypes.c_uint32),
                        ("dwReasmSize", ctypes.c_uint32), ("unused1", ctypes.c_ushort),
                        ("wType", ctypes.c_ushort)]

        lib = ctypes.WinDLL("iphlpapi.dll")
        size = ctypes.c_ulong(0)
        lib.GetIpAddrTable(None, ctypes.byref(size), False)
        buf = ctypes.create_string_buffer(max(size.value, 8))
        if lib.GetIpAddrTable(buf, ctypes.byref(size), False) != 0:
            return []
        count = ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint32))[0]
        rows = ctypes.cast(ctypes.byref(buf, 4), ctypes.POINTER(_ROW))
        out = []
        for i in range(count):
            addr, mask = rows[i].dwAddr, rows[i].dwMask
            if not addr or not mask:
                continue
            ip = ipaddress.IPv4Address(int(addr).to_bytes(4, "little"))
            nm = ipaddress.IPv4Address(int(mask).to_bytes(4, "little"))
            if ip.is_loopback or ip.is_unspecified:
                continue
            try:
                out.append(str(ipaddress.ip_network(f"{ip}/{nm}", strict=False)))
            except ValueError:
                continue
        return sorted(set(out))
    except Exception:
        return []


def _netsh(args: list[str], timeout: float = 15.0) -> tuple[bool, str]:
    try:
        p = subprocess.run(["netsh"] + args, capture_output=True, text=True, timeout=timeout,
                           stdin=subprocess.DEVNULL,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except OSError as e:
        return False, str(e)
    except subprocess.TimeoutExpired:
        return False, f"netsh timed out after {timeout:.0f}s"
    msg = (p.stdout + p.stderr).strip() or f"netsh exited {p.returncode}"
    return p.returncode == 0, msg


def route_args(verb: str, alias: str, subnet: str, via: str = "") -> list[str]:
    """`netsh interface ipvX <verb> route ...` arguments. ValueError if
    `subnet` is not a subnet or `via` (the next hop) is not an address of the
    same family: it reaches netsh as a value, not through a shell, but a bad
    value there is a failed or wrong route, so it is refused here."""
    net = parse_subnet(subnet)
    if net is None:
        raise ValueError(f"{subnet} is not a subnet")
    family = "ipv6" if net.version == 6 else "ipv4"
    args = ["interface", family, verb, "route", str(net), f"interface={alias}"]
    if via:
        try:
            hop = ipaddress.ip_address(via.strip())
        except ValueError:
            raise ValueError(f"next hop {via!r} is not an IP address") from None
        if hop.version != net.version:
            raise ValueError(f"next hop {hop} is not an IPv{net.version} address")
        args.append(f"nexthop={hop}")
    return args + ["store=active"]


def apply_now(alias: str, subnet: str, via: str = "") -> tuple[bool, str]:
    """Install the route on the live adapter so the tick takes effect without a
    restart. `store=active` on purpose: the config is what survives a reboot."""
    if os.name != "nt":
        return False, "live routes are only applied on Windows"
    try:
        add = route_args("add", alias, subnet, via)
        update = route_args("set", alias, subnet, via)
    except ValueError as e:
        return False, str(e)
    ok, msg = _netsh(add)
    if not ok:
        # An existing route is not a failure: the daemon may have installed it
        # already, or the operator may be re-ticking a box. `set` carries the
        # same next hop; without it the route kept whatever hop it had.
        ok2, msg2 = _netsh(update)
        if ok2:
            return True, msg2
        return False, msg
    return True, msg


def remove_now(alias: str, subnet: str) -> tuple[bool, str]:
    if os.name != "nt":
        return False, "live routes are only removed on Windows"
    net = parse_subnet(subnet)
    if net is None:
        return False, f"{subnet} is not a subnet"
    family = "ipv6" if net.version == 6 else "ipv4"
    return _netsh(["interface", family, "delete", "route", str(net),
                   f"interface={alias}", "store=active"])


def adapter_aliases(options: dict, net_name: str) -> list[str]:
    """Names the tunnel adapter may go by, most specific first — the same list
    runtime.py uses to find it for the MTU clamp."""
    out = []
    for key in ("WintunInterface", "Interface"):
        v = options.get(key)
        if v and str(v) not in out:
            out.append(str(v))
    if net_name and net_name not in out:
        out.append(net_name)
    return out
