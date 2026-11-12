"""
transports.py — the transport / circumvention option surface of tinc.yaml
(docs/config-schema.md, "transport selection & negotiation"), Qt-free so the
GUI panel and the tests share one definition.

Two lists, deliberately separate (ARCHITECTURE.md §4, decision 2):

  * `Transports`          — ACCEPT list: what this listener answers.
                            Default: every carrier compiled in.
  * `PreferredTransports` — DIAL preference, in order; the first carrier
                            present in the peer's accept list is used.
                            Default: [plain]. "Tick QUIC" changes this list
                            on the ticking side only.

Everything here is an ordinary `options:` key; the daemon owns defaults, the
editor writes only what the user changed (see yaml_config.save).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

CARRIERS: tuple[str, ...] = ("plain", "sf", "sftcp", "obfs", "https", "quic")
PREFER_CARRIERS: tuple[str, ...] = ("plain", "sf", "sftcp", "obfs", "https", "quic")
VALID_CARRIERS: tuple[str, ...] = ("plain", "sf", "sftcp", "obfs", "https", "ws", "quic", "h3", "dco")
MULTIPATH_MODES: tuple[str, ...] = ("off", "failover", "flowhash", "redundant", "split")

MULTIPATH_MODE_HELP = {
    "off": "Disabled: standard single-path connection",
    "failover": "Hot Standby (0-ms Failover): active primary link + warm backup links for seamless switching",
    "flowhash": "Flow Hash (ECMP): balance inner TCP/UDP 5-tuple flows across active links without packet reordering",
    "redundant": "Redundant (1+1): duplicate packets across active links for zero loss (SPTPS deduplicates on arrival)",
    "split": "Weighted Split: distribute packets across active links proportionally to uplink weights and RTT",
}

CARRIER_HELP = {
    "plain": "Plain tinc UDP/TCP (default, unchanged wire image)",
    "sf": "Single-flow UDP: control + data multiplexed on one UDP flow",
    "sftcp": "Single-flow TCP: control + data multiplexed on one TCP connection (no UDP)",
    "obfs": "Obfuscated UDP: keyed junk around the handshake, header shaping",
    "https": "HTTPS-mimicking front: TLS session, probers see a decoy site",
    "quic": "QUIC carrier: SPTPS over datagrams + one stream, migration-friendly",
}


@dataclass(frozen=True)
class OptionSpec:
    name: str
    kind: str            # carriers | int | bool | port | front_port | path | str | magic
    default: Any
    help: str
    group: str
    minimum: int = 0
    maximum: int = 0


TRANSPORT_OPTIONS: tuple[OptionSpec, ...] = (
    OptionSpec("Transports", "carriers", list(CARRIERS),
               "Accept list: carriers this node's listener answers (default: all)", "negotiation"),
    OptionSpec("PreferredTransports", "carriers", ["plain"],
               "Dial preference, in order; first one in the peer's accept list wins (default: plain)",
               "negotiation"),
    OptionSpec("DirectSeal", "bool", True,
               "Direct AEAD seal for single-port UDP transport (default: yes)", "negotiation"),
    OptionSpec("AllowPlainMeta", "bool", True,
               "Accept plain meta connections on the listen port (default: yes)", "negotiation"),
    OptionSpec("UdpMetaFallback", "bool", True,
               "Fall back to UDP meta when TCP is blocked (default: yes)", "negotiation"),
    OptionSpec("MultipathMode", "str", "off",
               "Application multipath mode: off, failover, flowhash, redundant, split", "negotiation"),
    OptionSpec("MultipathConnections", "int", 1,
               "Number of parallel connections per peer for multipath (1-8, default: 1)", "negotiation", 1, 8),
    OptionSpec("MultipathInterface", "str", "",
               "Multipath uplink specification (iface[:ip[:weight[:backup[:mark]]]])", "negotiation"),
    OptionSpec("ObfsPort", "front_port", 0,
               "UDP port for the obfuscated carrier; 0 = tinc UDP port (default)", "obfs"),
    OptionSpec("ObfsPortPublic", "front_port", 0,
               "External UDP port advertised in invitations for obfs (0 = ObfsPort)", "obfs"),
    OptionSpec("ObfsJunkPacketCount", "int", 0,
               "Junk datagrams sent around the handshake (0 = off)", "obfs", 0, 64),
    OptionSpec("ObfsJunkPacketMinSize", "int", 40, "Smallest junk datagram, bytes", "obfs", 1, 1400),
    OptionSpec("ObfsJunkPacketMaxSize", "int", 200, "Largest junk datagram, bytes", "obfs", 1, 1400),
    OptionSpec("ObfsInitHeaderJunkSize", "int", 0,
               "Junk bytes prepended to the handshake (0 = off)", "obfs", 0, 1024),
    OptionSpec("ObfsTransportHeaderJunkSize", "int", 0,
               "Junk bytes prepended to transport frames (0 = off)", "obfs", 0, 1024),
    OptionSpec("ObfsInitMagicHeader", "magic", 0,
               "Handshake magic header: 0 = off, or 31-bit integer (0..2147483647)", "obfs"),
    OptionSpec("ObfsTransportMagicHeader", "magic", 0,
               "Transport frame magic header: 0 = off, or 31-bit integer (0..2147483647)", "obfs"),
    # The core's key is HttpsPort (docs/config-schema.md). Until 2026-09-23 the
    # editor wrote `HttpsFront` / `HttpsFrontPort`, which no core reads: the
    # setting looked saved and did nothing. Empty ("") = daemon auto (443 on a
    # listening node, off when Port = 0).
    OptionSpec("HttpsPort", "front_port", "",
               "TCP port of the HTTPS front; empty = auto (443 if listening, off on Port=0), 0 = off", "https"),
    OptionSpec("HttpsPortPublic", "front_port", 0,
               "External TCP port advertised for the HTTPS front (0 = HttpsPort)", "https"),
    OptionSpec("HttpsSni", "str", "",
               "SNI hostname sent when dialing the HTTPS front", "https"),
    OptionSpec("TlsCert", "path", "",
               "Real certificate chain (PEM). Empty = self-signed, generated at first start", "https"),
    OptionSpec("TlsKey", "path", "", "Private key for TlsCert (PEM); required with TlsCert", "https"),
    OptionSpec("HttpsDecoyRoot", "path", "",
               "Static content served to probers (empty = built-in default page)", "https"),
    OptionSpec("HttpsDecoyUpstream", "str", "",
               "Or transparently proxy probers to this host:port or [ipv6]:port", "https"),
    OptionSpec("QuicPort", "front_port", "",
               "UDP port of the QUIC front; empty = auto (443 if listening, off on Port=0), 0 = off", "quic"),
    OptionSpec("QuicPortPublic", "front_port", 0,
               "External UDP port advertised for the QUIC front (0 = QuicPort)", "quic"),
)

SPEC_BY_NAME: dict[str, OptionSpec] = {o.name: o for o in TRANSPORT_OPTIONS}
GROUPS: tuple[str, ...] = ("negotiation", "obfs", "https", "quic")

_MAGIC_MAX = 0x7FFFFFFF
_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$")


def _valid_decoy_upstream(raw: str) -> bool:
    """Validate `HttpsDecoyUpstream` matching `decoy.c` (`host:port` or
    `[ipv6]:port` with port 1..65535; URLs with schemes and portless `[ipv6]`
    are rejected)."""
    s = (raw or "").strip()
    if not s or "://" in s or "/" in s or any(ch.isspace() for ch in s):
        return False
    if s.startswith("["):
        m = re.fullmatch(r"\[([^\[\]]+)\]:(\d{1,5})", s)
        if not m:
            return False
        host, port_s = m.group(1), m.group(2)
        try:
            ipaddress.IPv6Address(host)
            port = int(port_s)
        except ValueError:
            return False
        return 1 <= port <= 65535
    if "[" in s or "]" in s or s.count(":") != 1:
        return False
    host, port_s = s.rsplit(":", 1)
    if not host or not _HOST_RE.fullmatch(host) or not port_s.isdigit():
        return False
    port = int(port_s)
    return 1 <= port <= 65535


_CARRIER_ALIASES = {
    "sf-udp": "sf",
    "udp-sf": "sf",
    "sf-tcp": "sftcp",
    "tcp-sf": "sftcp",
}


def parse_carrier_list(value: Any) -> list[str]:
    """Accept a YAML list or a 'a, b c' string; returns lowercase names as given
    (validation reports unknown ones)."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        items = [str(x) for x in value]
    else:
        items = re.split(r"[,\s]+", str(value))
    out: list[str] = []
    for raw in items:
        s = raw.strip().lower()
        if s:
            out.append(_CARRIER_ALIASES.get(s, s))
    return out


def default_for(name: str) -> Any:
    spec = SPEC_BY_NAME[name]
    return list(spec.default) if isinstance(spec.default, list) else spec.default


def effective(options: dict) -> dict[str, Any]:
    """Every transport option with its effective value (file value or default)."""
    out: dict[str, Any] = {}
    for spec in TRANSPORT_OPTIONS:
        if spec.name in options:
            v = options[spec.name]
            out[spec.name] = parse_carrier_list(v) if spec.kind == "carriers" else v
        else:
            out[spec.name] = default_for(spec.name)
    return out


def _as_int(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _as_bool(v: Any) -> bool | None:
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("yes", "true", "1", "on"):
        return True
    if s in ("no", "false", "0", "off"):
        return False
    return None


def validate(options: dict) -> list[str]:
    """Validate the transport keys present in `options`. Returns a list of
    human-readable errors (empty = valid). Absent keys are fine: every option
    has a working daemon default (ARCHITECTURE principle 5)."""
    errors: list[str] = []
    for spec in TRANSPORT_OPTIONS:
        if spec.name not in options:
            continue
        v = options[spec.name]
        if spec.kind == "carriers":
            lst = parse_carrier_list(v)
            if not lst:
                errors.append(f"{spec.name}: must list at least one carrier ({', '.join(CARRIERS)})")
            unknown = [c for c in lst if c not in VALID_CARRIERS]
            if unknown:
                errors.append(f"{spec.name}: unknown carrier(s) {', '.join(unknown)}; "
                              f"valid: {', '.join(VALID_CARRIERS)}")
            if len(set(lst)) != len(lst):
                errors.append(f"{spec.name}: duplicate carrier")
        elif spec.kind in ("int", "port", "front_port"):
            if spec.kind == "front_port" and spec.default == "" and v in ("", None):
                continue
            n = _as_int(v)
            lo, hi = {"port": (1, 65535), "front_port": (0, 65535)}.get(spec.kind, (spec.minimum, spec.maximum))
            if n is None:
                errors.append(f"{spec.name}: must be an integer, got {v!r}")
            elif not (lo <= n <= hi):
                errors.append(f"{spec.name}: must be between {lo} and {hi}, got {n}")
        elif spec.kind == "bool":
            if _as_bool(v) is None:
                errors.append(f"{spec.name}: must be yes/no, got {v!r}")
        elif spec.kind == "magic":
            n = _as_int(v)
            if n is None or not (0 <= n <= _MAGIC_MAX):
                errors.append(f"{spec.name}: must be a single integer between 0 and {_MAGIC_MAX}, got {v!r}")
        elif spec.kind == "path":
            if v is not None and not isinstance(v, str):
                errors.append(f"{spec.name}: must be a path string")
        elif spec.kind == "str":
            if spec.name == "HttpsDecoyUpstream" and v and not _valid_decoy_upstream(str(v)):
                errors.append(f"{spec.name}: expected host:port or [ipv6]:port (no http:// scheme), got {v!r}")
            elif spec.name == "MultipathMode" and str(v).strip().lower() not in MULTIPATH_MODES:
                errors.append(f"{spec.name}: must be one of {', '.join(MULTIPATH_MODES)}, got {v!r}")
    lo = _as_int(options.get("ObfsJunkPacketMinSize", 40))
    hi = _as_int(options.get("ObfsJunkPacketMaxSize", 200))
    if lo is not None and hi is not None and lo > hi:
        errors.append("ObfsJunkPacketMinSize must be <= ObfsJunkPacketMaxSize")
    has_cert, has_key = bool(options.get("TlsCert")), bool(options.get("TlsKey"))
    if has_cert != has_key:
        errors.append("TlsCert and TlsKey must be set together (or both left empty for self-signed)")
    return errors


def changes(loaded: dict, edited: dict[str, Any]) -> dict[str, Any]:
    """Compute what the editor must write: {key: value} for keys whose edited
    value differs from what the file held, `None` meaning "remove the key".

    A key that was absent and whose edited value equals the daemon default is
    left absent — the file stays minimal and the daemon keeps owning the
    default. A key that was present and is edited back to the default is
    written explicitly (the user had pinned it on purpose)."""
    out: dict[str, Any] = {}
    for name, new in edited.items():
        spec = SPEC_BY_NAME.get(name)
        present = name in loaded
        old = loaded.get(name)
        if spec and spec.kind == "carriers":
            old_n = parse_carrier_list(old) if present else None
            new_n = parse_carrier_list(new)
        else:
            old_n, new_n = old, new
        if present:
            if spec is not None and spec.kind == "front_port" and spec.default == "" and new_n in ("", None):
                out[name] = None
            elif old_n != new_n:
                out[name] = new_n
        else:
            if spec is not None and new_n == default_for(name):
                continue
            if spec is not None and spec.kind in ("path", "str") and new_n in ("", None):
                continue
            if spec is not None and spec.kind == "front_port" and spec.default == "" and new_n in ("", None):
                continue
            out[name] = new_n
    return out


def apply_changes(options: dict, delta: dict[str, Any]) -> None:
    """Apply a `changes()` result to an options dict in place."""
    for k, v in delta.items():
        if v is None:
            options.pop(k, None)
        else:
            options[k] = v


_HOST_PREF_RE = re.compile(r"^[ \t]*PreferredTransports?[ \t]*=[ \t]*(.*)$", re.IGNORECASE | re.MULTILINE)


def host_preferred_transport(host_text: str) -> str:
    """Return the per-node PreferredTransports carrier pinned in `host_text`
    (e.g. 'quic', 'https', 'obfs', 'sf', 'plain'), or '' when none is set."""
    if not host_text:
        return ""
    for m in _HOST_PREF_RE.finditer(host_text):
        lst = parse_carrier_list(m.group(1))
        for c in lst:
            if c in VALID_CARRIERS:
                return c
    return ""


def set_host_preferred_transport(host_text: str, carrier: str) -> str:
    """Set or clear `PreferredTransports` in a peer's raw host-file text while
    preserving all other lines (keys, PEM blocks, Subnet, Address, Port)."""
    kept = [
        ln for ln in (host_text or "").splitlines()
        if not _HOST_PREF_RE.match(ln)
    ]
    c = (carrier or "").strip().lower()
    if c and c != "auto" and c in VALID_CARRIERS:
        kept.append(f"PreferredTransports = {c}")
    return "\n".join(kept).strip()


_HOST_DIRECT_RE = re.compile(r"^[ \t]*DirectConnect[ \t]*=[ \t]*(.*)$", re.IGNORECASE | re.MULTILINE)
_HOST_INDIRECT_RE = re.compile(r"^[ \t]*IndirectData[ \t]*=[ \t]*(.*)$", re.IGNORECASE | re.MULTILINE)


def parse_node_list(value: Any) -> list[str]:
    """Parse a space/comma/semicolon-separated node list or YAML list into unique node names."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        items = [str(x) for x in value]
    else:
        items = re.split(r"[\s,;]+", str(value))
    out: list[str] = []
    for raw in items:
        s = raw.strip()
        if s and s not in out:
            out.append(s)
    return out


def host_no_direct(host_text: str) -> bool:
    """Return True if `DirectConnect = no` is set in `host_text`."""
    if not host_text:
        return False
    res = False
    for m in _HOST_DIRECT_RE.finditer(host_text):
        b = _as_bool(m.group(1))
        if b is not None:
            res = not b
    return res


def set_host_no_direct(host_text: str, no_direct: bool) -> str:
    """Set `DirectConnect = no` (when no_direct is True) or remove DirectConnect
    from `host_text` while preserving all other lines (including IndirectData)."""
    if not host_text and not no_direct:
        return ""
    kept = [
        ln for ln in (host_text or "").splitlines()
        if not _HOST_DIRECT_RE.match(ln)
    ]
    if no_direct:
        kept.append("DirectConnect = no")
    return "\n".join(kept).strip()


def is_peer_no_direct(options: dict | None, host_text: str, peer_name: str) -> bool:
    """Return True if direct connections to `peer_name` are forbidden via
    `options['NoDirectNodes']` or `DirectConnect = no` in `host_text`."""
    if not peer_name:
        return False
    if options:
        nd_list = [n.lower() for n in parse_node_list(options.get("NoDirectNodes"))]
        if peer_name.strip().lower() in nd_list:
            return True
    return host_no_direct(host_text)


def set_peer_no_direct(options: dict, host_text: str, peer_name: str, no_direct: bool) -> str:
    """Enable or disable `no_direct` (relay-only mode) for `peer_name`.
    Updates `options['NoDirectNodes']` while preserving `ConnectTo` (so Relay Only
    acts as a higher-level override without destroying ConnectTo configuration),
    and returns the updated `host_text`."""
    peer = (peer_name or "").strip()
    if not peer:
        return host_text
    nd_list = parse_node_list(options.get("NoDirectNodes"))
    if no_direct:
        if not any(x.lower() == peer.lower() for x in nd_list):
            nd_list.append(peer)
    else:
        nd_list = [x for x in nd_list if x.lower() != peer.lower()]

    if nd_list:
        options["NoDirectNodes"] = nd_list
    else:
        options.pop("NoDirectNodes", None)

    if host_text or _HOST_DIRECT_RE.search(host_text or ""):
        return set_host_no_direct(host_text, no_direct)
    return host_text

