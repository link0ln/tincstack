"""
diagnostics.py — Local Telemetry & Incident Collector, Active Network Prober,
and Opt-In Remote Diagnostic Web Server for tincmgr.

When enabled by the user (off by default, behind an explicit security warning),
DiagWebServer listens on port 8655 (configurable) and registers the port with
each running tincd via `tinc diag-port <port>`. tincd's user-space in-tunnel
TCP bridge (core/tincd/src/diag.c) forwards incoming VPN TCP connections on
`<my-vpn-ip>:<port>` to `127.0.0.1:<port>`, making the WebUI reachable from any
node in the VPN mesh without weakening host firewall rules or breaking Android
UID routing.
"""

from __future__ import annotations

import base64
import copy
import faulthandler
import hmac
import http.cookies
import ipaddress
import json
import math
import os
import platform
import re
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
from collections import deque
from dataclasses import asdict, dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

import fulltunnel
import management
import paths
import routes
import transports
import yaml_config
from diag_webui import DIAG_WEBUI_HTML
from tinc_control import NetworkSnapshot, Node, TincControl, decode_status

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

DEFAULT_DIAG_PORT = 8655
DIAG_SESSION_COOKIE = "tinc_diag_sid"
DIAG_SESSION_TTL = 86400.0
DIAG_SESSION_MAX = 64
DIAG_CSRF_HEADER = "X-Diag-CSRF"
LOGIN_MAX_FAILURES = 5
LOGIN_MAX_LOCKOUT_SEC = 60.0
_DIAG_PASS_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
REDACTED_PLACEHOLDER = "***REDACTED***"
_PUBLIC_KEY_ENTRIES = frozenset({"tls_cert"})
_SECRET_OPTION_NAMES_LOWER = frozenset({
    "cloudflaretoken",
    "ed25519privatekey",
    "privatekey",
    "acme_account",
    "acmeaccount",
    "acmeaccountkey",
    "obfspassword",
    "obfsinitmagicheader",
    "obfstransportmagicheader",
    "proxy",
})
_FORBIDDEN_WEBUI_OPTIONS_LOWER = frozenset({"scriptsinterpreter", "scriptsextension"})
_CANON_MULTI_OPTIONS: dict[str, str] = {
    k.lower(): k for k in (
        "Transports", "PreferredTransports", "NoDirectNodes", "BlockedNodes",
        "ConnectTo", "Subnet", "Address", "InterfaceRoute", "InterfaceAddress",
        "Ifconfig", "AddressPool", "MultipathInterface", "BindToAddress",
        "ListenAddress", "LocalDiscoveryAddress",
    )
}


class WebUISecurityError(PermissionError):
    """Raised when a WebUI request attempts a forbidden privileged mutation."""
_NET_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_DNS_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

_settings_lock = threading.Lock()
_active_servers_lock = threading.Lock()
_active_servers: dict[str, "DiagWebServer"] = {}


def is_valid_net_name(net: str, app: yaml_config.AppConfig | None = None) -> bool:
    """Validate `net` against path traversal and (when `app` has networks) membership."""
    if not net or ".." in net or not _NET_NAME_RE.fullmatch(net):
        return False
    if app is not None and app.networks and net not in app.networks:
        return False
    return True


def is_valid_probe_host(host: str) -> bool:
    """Accept only a valid IPv4/IPv6 literal or DNS hostname; reject option flags."""
    if not host or len(host) > 253:
        return False
    if host[0] in ("-", "/") or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in host):
        return False
    unbracketed = host[1:-1] if (host.startswith("[") and host.endswith("]")) else host
    try:
        ipaddress.ip_address(unbracketed)
        return True
    except ValueError:
        pass
    if ":" in host or "[" in host or "]" in host:
        return False
    trimmed = host[:-1] if host.endswith(".") else host
    if not trimmed or ".." in trimmed:
        return False
    labels = trimmed.split(".")
    if all(lbl.isdigit() for lbl in labels):
        return False
    return all(bool(_DNS_LABEL_RE.fullmatch(lbl)) for lbl in labels)


def _is_secret_key_entry(key_name: str) -> bool:
    return key_name.strip().lower() not in _PUBLIC_KEY_ENTRIES


def _is_secret_option_name(opt_name: str) -> bool:
    return opt_name.strip().lower() in _SECRET_OPTION_NAMES_LOWER


def redact_host_text(host_text: str) -> str:
    """Mask any secret option lines accidentally placed inside a host file."""
    if not host_text:
        return ""
    out_lines: list[str] = []
    for raw in host_text.splitlines():
        if "=" in raw and not raw.lstrip().startswith("#"):
            k, _, _v = raw.partition("=")
            if _is_secret_option_name(k):
                out_lines.append(f"{k.strip()} = {REDACTED_PLACEHOLDER}")
                continue
        out_lines.append(raw)
    return "\n".join(out_lines) + ("\n" if host_text.endswith("\n") else "")


def select_node_vpn_ips(
    options: dict[str, Any] | None,
    host_text: str = "",
    snap_node: Node | None = None,
) -> list[str]:
    """Return ordered VPN host IPs for a node, strictly prioritizing `Ifconfig` /
    `InterfaceAddress` / `WintunAddress` host addresses and `/32` (`/128`) host
    `Subnet` entries while ignoring network prefixes like `10.0.0.0/24` or `0.0.0.0/0`."""
    found: list[str] = []

    def _add_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
        if ip_obj.is_unspecified or ip_obj.is_loopback or ip_obj.is_multicast:
            return
        s = str(ip_obj)
        if s not in found:
            found.append(s)

    if isinstance(options, dict):
        opts_ci = {str(k).strip().lower(): v for k, v in options.items()}
        for key_low in ("ifconfig", "interfaceaddress", "wintunaddress"):
            raw_val = opts_ci.get(key_low)
            vals = raw_val if isinstance(raw_val, (list, tuple)) else ([raw_val] if raw_val else [])
            for item in vals:
                parts = str(item).strip().split()
                if not parts:
                    continue
                tok = parts[0]
                try:
                    if "/" in tok:
                        ifc = ipaddress.ip_interface(tok)
                        if ifc.network.prefixlen == ifc.network.max_prefixlen or ifc.ip != ifc.network.network_address:
                            _add_ip(ifc.ip)
                    elif len(parts) >= 2:
                        try:
                            ifc = ipaddress.ip_interface(f"{tok}/{parts[1]}")
                            if ifc.network.prefixlen == ifc.network.max_prefixlen or ifc.ip != ifc.network.network_address:
                                _add_ip(ifc.ip)
                                continue
                        except ValueError:
                            pass
                        _add_ip(ipaddress.ip_address(tok))
                    else:
                        _add_ip(ipaddress.ip_address(tok))
                except ValueError:
                    continue

    if snap_node is not None and snap_node.vpn_address:
        try:
            _add_ip(ipaddress.ip_address(snap_node.vpn_address.split("/")[0].strip()))
        except ValueError:
            pass

    subnet_candidates: list[str] = []
    if snap_node is not None:
        subnet_candidates.extend(str(s) for s in (snap_node.subnets or []))
    if host_text:
        subnet_candidates.extend(parse_host_endpoints(host_text).get("subnets") or [])

    for sub in subnet_candidates:
        clean = str(sub).split("#", 1)[0].strip()
        if not clean:
            continue
        try:
            net = ipaddress.ip_network(clean, strict=False)
        except ValueError:
            continue
        if net.prefixlen == net.max_prefixlen:
            _add_ip(net.network_address)

    return found


def select_primary_vpn_ip(
    options: dict[str, Any] | None,
    host_text: str = "",
    snap_node: Node | None = None,
) -> str:
    ips = select_node_vpn_ips(options, host_text, snap_node)
    for ip in ips:
        if ":" not in ip:
            return ip
    return ips[0] if ips else ""


def _extract_forbidden_webui_opts(opts: dict[str, Any] | None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in (opts or {}).items():
        kl = str(k).strip().lower()
        if kl in _FORBIDDEN_WEBUI_OPTIONS_LOWER:
            out[kl] = v
    return out


def _normalize_multi_options(opts: dict[str, Any]) -> dict[str, Any]:
    """Normalize multi-value tinc options to canonical casing and list/scalar forms."""
    merged: dict[str, Any] = {}
    for raw_k, raw_v in opts.items():
        canon = _CANON_MULTI_OPTIONS.get(str(raw_k).strip().lower(), str(raw_k).strip())
        if canon in merged:
            prev = merged[canon]
            prev_list = list(prev) if isinstance(prev, list) else [prev]
            add_list = list(raw_v) if isinstance(raw_v, list) else [raw_v]
            merged[canon] = prev_list + add_list
        else:
            merged[canon] = raw_v
    for ck in ("Transports", "PreferredTransports"):
        if ck in merged:
            vals = transports.parse_carrier_list(merged[ck])
            if vals:
                merged[ck] = vals
            else:
                merged.pop(ck, None)
    for nk in ("NoDirectNodes", "BlockedNodes", "ConnectTo"):
        if nk in merged:
            vals = transports.parse_node_list(merged[nk])
            if not vals:
                merged.pop(nk, None)
            elif nk == "ConnectTo" and len(vals) == 1:
                merged[nk] = vals[0]
            else:
                merged[nk] = vals
    return merged


def redact_options_dict(opts: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in (opts or {}).items():
        if _is_secret_option_name(str(k)) and v not in (None, "", []):
            out[k] = REDACTED_PLACEHOLDER
        else:
            out[k] = copy.deepcopy(v)
    return out


def restore_redacted_host_text(new_text: str, orig_text: str) -> str:
    """Restore any `Key = ***REDACTED***` lines in `new_text` from `orig_text`."""
    if not new_text or REDACTED_PLACEHOLDER not in new_text:
        return new_text
    orig_map: dict[str, str] = {}
    for raw in (orig_text or "").splitlines():
        if "=" in raw and not raw.lstrip().startswith("#"):
            k, _, _v = raw.partition("=")
            if _is_secret_option_name(k):
                orig_map[k.strip().lower()] = raw
    out_lines: list[str] = []
    for raw in new_text.splitlines():
        if "=" in raw and not raw.lstrip().startswith("#"):
            k, _, v = raw.partition("=")
            if _is_secret_option_name(k) and v.strip() == REDACTED_PLACEHOLDER:
                orig_line = orig_map.get(k.strip().lower())
                if orig_line is not None:
                    out_lines.append(orig_line)
                continue
        out_lines.append(raw)
    return "\n".join(out_lines) + ("\n" if new_text.endswith("\n") else "")


def _norm_scripts_dict(scripts_obj: Any) -> dict[str, str]:
    if not isinstance(scripts_obj, dict):
        return {}
    return {
        str(k).strip(): str(v).rstrip("\r\n")
        for k, v in scripts_obj.items()
        if v is not None and str(v).strip() != ""
    }


def redact_yaml_document(doc: dict[str, Any]) -> dict[str, Any]:
    """Return a deep copy of `doc` with all secret keys/options replaced by REDACTED_PLACEHOLDER."""
    redacted = copy.deepcopy(doc or {})
    nets = redacted.get("networks")
    if isinstance(nets, dict):
        for _net_name, nd in nets.items():
            if not isinstance(nd, dict):
                continue
            keys = nd.get("keys")
            if isinstance(keys, dict):
                for kk, kv in list(keys.items()):
                    if _is_secret_key_entry(str(kk)) and kv not in (None, ""):
                        keys[kk] = REDACTED_PLACEHOLDER
            opts = nd.get("options")
            if isinstance(opts, dict):
                for ok, ov in list(opts.items()):
                    if _is_secret_option_name(str(ok)) and ov not in (None, "", []):
                        opts[ok] = REDACTED_PLACEHOLDER
            hosts = nd.get("hosts")
            if isinstance(hosts, dict):
                for hk, hv in list(hosts.items()):
                    if isinstance(hv, str):
                        hosts[hk] = redact_host_text(hv)
    return redacted


def restore_redacted_yaml_document(new_doc: dict[str, Any], orig_doc: dict[str, Any]) -> dict[str, Any]:
    """Restore REDACTED_PLACEHOLDER entries per-network from `orig_doc` so network A's
    secrets never overwrite network B's."""
    merged = copy.deepcopy(new_doc or {})
    new_nets = merged.get("networks")
    orig_nets = (orig_doc or {}).get("networks") if isinstance(orig_doc, dict) else {}
    if not isinstance(new_nets, dict):
        return merged
    if not isinstance(orig_nets, dict):
        orig_nets = {}
    for net_name, nd in new_nets.items():
        if not isinstance(nd, dict):
            continue
        orig_nd = orig_nets.get(net_name)
        orig_keys = orig_nd.get("keys") if isinstance(orig_nd, dict) else None
        orig_opts = orig_nd.get("options") if isinstance(orig_nd, dict) else None
        orig_hosts = orig_nd.get("hosts") if isinstance(orig_nd, dict) else None

        new_keys = nd.get("keys")
        if isinstance(new_keys, dict):
            orig_keys_ci = {str(k).lower(): v for k, v in (orig_keys or {}).items()} if isinstance(orig_keys, dict) else {}
            for kk, kv in list(new_keys.items()):
                if isinstance(kv, str) and kv.strip() == REDACTED_PLACEHOLDER:
                    if isinstance(orig_keys, dict) and kk in orig_keys:
                        new_keys[kk] = copy.deepcopy(orig_keys[kk])
                    elif str(kk).lower() in orig_keys_ci:
                        new_keys[kk] = copy.deepcopy(orig_keys_ci[str(kk).lower()])
                    else:
                        new_keys.pop(kk, None)

        new_opts = nd.get("options")
        if isinstance(new_opts, dict):
            orig_opts_ci = {str(k).lower(): v for k, v in (orig_opts or {}).items()} if isinstance(orig_opts, dict) else {}
            for ok, ov in list(new_opts.items()):
                if isinstance(ov, str) and ov.strip() == REDACTED_PLACEHOLDER:
                    if isinstance(orig_opts, dict) and ok in orig_opts:
                        new_opts[ok] = copy.deepcopy(orig_opts[ok])
                    elif str(ok).lower() in orig_opts_ci:
                        new_opts[ok] = copy.deepcopy(orig_opts_ci[str(ok).lower()])
                    else:
                        new_opts.pop(ok, None)

        new_hosts = nd.get("hosts")
        if isinstance(new_hosts, dict) and isinstance(orig_hosts, dict):
            for hk, hv in list(new_hosts.items()):
                if isinstance(hv, str) and isinstance(orig_hosts.get(hk), str):
                    new_hosts[hk] = restore_redacted_host_text(hv, orig_hosts[hk])
    return merged


SERIES_MAX_POINTS = 3600       # ~2.5 hours at 2.5s interval
INCIDENTS_MAX = 500
EVENTS_FILE_MAX_BYTES = 2 * 1024 * 1024
APP_LOG_FILE = "tincmgr.log"
CRASH_LOG_FILE = "tincmgr-crash.log"
LOG_MAX_BYTES = 2 * 1024 * 1024

_log_lock = threading.Lock()
_crash_fd: Any = None
_default_base_dir: str = ""
_default_collector: "TelemetryCollector | None" = None
_default_net_fn: Callable[[], str] | None = None


def app_log_path(base_dir: str = "") -> str:
    b = base_dir or _default_base_dir
    return os.path.join(b, APP_LOG_FILE) if b else ""


def crash_log_path(base_dir: str = "") -> str:
    b = base_dir or _default_base_dir
    return os.path.join(b, CRASH_LOG_FILE) if b else ""


def _append_rotated(path: str, text: str, max_bytes: int = LOG_MAX_BYTES) -> None:
    if not path:
        return
    with _log_lock:
        try:
            d = os.path.dirname(path)
            if d:
                os.makedirs(d, exist_ok=True)
            if os.path.isfile(path) and os.path.getsize(path) > max_bytes:
                with open(path, "rb") as rf:
                    rf.seek(-max_bytes // 2, os.SEEK_END)
                    tail = rf.read()
                nl = tail.find(b"\n")
                if nl >= 0:
                    tail = tail[nl + 1:]
                paths.write_private(path, tail)
            with paths.open_private_append(path) as f:
                f.write(text)
                f.flush()
        except OSError:
            pass


def log_app_event(message: str, level: str = "INFO", base_dir: str = "") -> None:
    """Append a timestamped event line to persistent tincmgr.log."""
    path = app_log_path(base_dir)
    if not path:
        return
    ts_str = time.strftime("%Y-%m-%d %H:%M:%S")
    tname = threading.current_thread().name
    line = f"{ts_str} [{level.upper()}] [pid={os.getpid()}:{tname}] {message.rstrip()}\n"
    _append_rotated(path, line)


def record_crash_trace(
    title: str,
    trace_text: str,
    base_dir: str = "",
    net: str = "",
    collector: "TelemetryCollector | None" = None,
    kind: str = "CRASH_TRACE",
) -> None:
    """Persist a full stacktrace / crash report to tincmgr-crash.log, tincmgr.log,
    and the active network's incident log."""
    bdir = base_dir or _default_base_dir
    col = collector or _default_collector
    target_net = net
    if not target_net and _default_net_fn is not None:
        try:
            target_net = _default_net_fn() or ""
        except Exception:
            target_net = ""
    if not target_net and col is not None:
        with col._lock:
            if col._latest_snap:
                target_net = next(iter(col._latest_snap))
            elif col._incidents:
                target_net = next(iter(col._incidents))

    ts_str = time.strftime("%Y-%m-%d %H:%M:%S")
    ver = management.current_version() or "dev"
    tname = threading.current_thread().name
    clean_trace = (trace_text or "").strip() or "(no traceback available)"
    block = (
        f"========================================================================\n"
        f"[{ts_str}] {kind}: {title}\n"
        f"Version: {ver} | OS: {platform.system()} {platform.release()} | "
        f"PID: {os.getpid()} | Thread: {tname} | Net: {target_net or 'none'}\n"
        f"------------------------------------------------------------------------\n"
        f"{clean_trace}\n"
        f"========================================================================\n\n"
    )
    if bdir:
        _append_rotated(crash_log_path(bdir), block)
        log_app_event(f"{kind}: {title}\n{clean_trace}", level="ERROR", base_dir=bdir)

    if col is not None and target_net:
        try:
            col.add_incident(
                net=target_net,
                kind=kind,
                severity="error",
                summary=f"{title}",
                details={"traceback": clean_trace, "thread": tname},
            )
        except Exception:
            pass


def clear_crash_log(base_dir: str = "") -> bool:
    path = crash_log_path(base_dir)
    if not path:
        return False
    with _log_lock:
        try:
            if os.path.isfile(path):
                paths.write_private(path, b"")
            return True
        except OSError:
            return False


def install_crash_handlers(
    base_dir: str,
    collector: "TelemetryCollector | None" = None,
    net_fn: Callable[[], str] | None = None,
) -> None:
    """Install faulthandler, sys.excepthook, and threading.excepthook so both
    native C++/Qt segfaults and unhandled Python/worker exceptions are saved to
    tincmgr-crash.log and tincmgr.log."""
    global _crash_fd, _default_base_dir, _default_collector, _default_net_fn
    _default_base_dir = base_dir
    if collector is not None:
        _default_collector = collector
    if net_fn is not None:
        _default_net_fn = net_fn

    if base_dir:
        try:
            os.makedirs(base_dir, exist_ok=True)
            cpath = crash_log_path(base_dir)
            if _crash_fd is None:
                _crash_fd = paths.open_private_append(cpath)
                faulthandler.enable(file=_crash_fd, all_threads=True)
        except Exception:
            pass

    def _sys_excepthook(exc_type: Any, exc_value: Any, exc_tb: Any) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_tb)
            return
        tb_str = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        title = f"Unhandled exception ({ getattr(exc_type, '__name__', str(exc_type)) }): {exc_value}"
        record_crash_trace(title, tb_str, kind="GUI_EXCEPTION")

    def _thread_excepthook(args: Any) -> None:
        tb_str = "".join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback))
        tname = getattr(args.thread, "name", "thread")
        title = f"Unhandled thread exception in '{tname}' ({getattr(args.exc_type, '__name__', '')}): {args.exc_value}"
        record_crash_trace(title, tb_str, kind="THREAD_EXCEPTION")

    sys.excepthook = _sys_excepthook
    if hasattr(threading, "excepthook"):
        threading.excepthook = _thread_excepthook

    ver = management.current_version() or "dev"
    log_app_event(f"tincmgr {ver} started (base_dir={base_dir})", level="INFO", base_dir=base_dir)


@dataclass
class IncidentEvent:
    ts: float
    net: str
    kind: str                  # e.g. UDP_FALLBACK, ONE_WAY_BLACKHOLE, SPTPS_KEY_WAIT, PMTU_DROP, RTT_SPIKE, PEER_DOWN, USER_MARK
    severity: str              # info | warn | error | mark
    peer: str = ""
    summary: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts": round(self.ts, 3),
            "time_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.ts)),
            "net": self.net,
            "kind": self.kind,
            "severity": self.severity,
            "peer": self.peer,
            "summary": self.summary,
            "message": self.summary,
            "details": self.details,
        }


@dataclass
class _PeerTrack:
    link: str = ""
    transport: str = ""
    nexthop: str = ""
    rtt: float = 0.0
    pmtu: int = 0
    rx_bytes: int = 0
    tx_bytes: int = 0
    reachable: bool = False
    validkey: bool = False
    udp_confirmed: bool = False
    tx_only_streak: int = 0
    key_wait_streak: int = 0
    initialized: bool = False


class TelemetryCollector:
    """Tracks per-network time-series metrics and automatically detects
    tunnel anomalies/incidents from periodic TincControl snapshots."""

    def __init__(self, base_dir: str) -> None:
        self.base_dir = base_dir
        self._lock = threading.Lock()
        # net -> deque of dict points
        self._series: dict[str, deque[dict[str, Any]]] = {}
        # net -> deque of IncidentEvent
        self._incidents: dict[str, deque[IncidentEvent]] = {}
        # (net, peer) -> _PeerTrack
        self._peer_state: dict[tuple[str, str], _PeerTrack] = {}
        # net -> last cumulative (ts, rx, tx)
        self._last_totals: dict[str, tuple[float, int, int]] = {}
        # net -> latest NetworkSnapshot and its monotonic/wall timestamp
        self._latest_snap: dict[str, NetworkSnapshot] = {}
        self._latest_snap_ts: dict[str, float] = {}
        self._load_persisted_events()

    def _events_path(self, net: str) -> str:
        if not is_valid_net_name(net):
            raise ValueError(f"Invalid network name: {net!r}")
        return os.path.join(self.base_dir, f"{net}-diag-events.jsonl")

    def _load_persisted_events(self) -> None:
        if not os.path.isdir(self.base_dir):
            return
        try:
            for fname in os.listdir(self.base_dir):
                if not fname.endswith("-diag-events.jsonl"):
                    continue
                net = fname[:-len("-diag-events.jsonl")]
                if not is_valid_net_name(net):
                    continue
                fpath = os.path.join(self.base_dir, fname)
                dq = self._incidents.setdefault(net, deque(maxlen=INCIDENTS_MAX))
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()[-INCIDENTS_MAX:]
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        dq.append(IncidentEvent(
                            ts=float(obj.get("ts", 0.0)),
                            net=str(obj.get("net", net)),
                            kind=str(obj.get("kind", "INFO")),
                            severity=str(obj.get("severity", "info")),
                            peer=str(obj.get("peer", "")),
                            summary=str(obj.get("summary") or obj.get("message") or ""),
                            details=dict(obj.get("details") or {}),
                        ))
                    except Exception:
                        pass
        except OSError:
            pass

    def _persist_event(self, ev: IncidentEvent) -> None:
        if not is_valid_net_name(ev.net):
            return
        path = self._events_path(ev.net)
        try:
            d = os.path.dirname(path)
            if d:
                os.makedirs(d, exist_ok=True)
            if os.path.isfile(path) and os.path.getsize(path) > EVENTS_FILE_MAX_BYTES:
                bak = path + ".1"
                try:
                    os.replace(path, bak)
                except OSError:
                    pass
            with paths.open_private_append(path) as f:
                f.write(json.dumps(ev.to_dict(), ensure_ascii=False) + "\n")
        except OSError:
            pass

    def clear_incidents(self, net: str) -> None:
        if not is_valid_net_name(net):
            raise ValueError(f"Invalid network name: {net!r}")
        with self._lock:
            self._incidents.pop(net, None)
        path = self._events_path(net)
        try:
            if os.path.isfile(path):
                os.remove(path)
        except OSError:
            pass

    def add_incident(self, net: str, kind: str, severity: str, summary: str,
                     peer: str = "", details: dict[str, Any] | None = None,
                     ts: float | None = None) -> IncidentEvent:
        ev = IncidentEvent(
            ts=ts if ts is not None else time.time(),
            net=net,
            kind=kind,
            severity=severity,
            peer=peer,
            summary=summary,
            details=details or {},
        )
        with self._lock:
            self._incidents.setdefault(net, deque(maxlen=INCIDENTS_MAX)).append(ev)
        self._persist_event(ev)
        return ev

    def record_user_mark(self, net: str, note: str = "") -> IncidentEvent:
        if not is_valid_net_name(net):
            raise ValueError(f"Invalid network name: {net!r}")
        with self._lock:
            snap = self._latest_snap.get(net)
        peer_summary = {}
        if snap and not snap.error:
            for name, n in snap.nodes.items():
                if not n.is_self:
                    peer_summary[name] = {
                        "link": n.link,
                        "transport": n.transport,
                        "via": n.nexthop,
                        "rtt_ms": round(n.rtt, 1),
                        "pmtu": n.pmtu,
                        "status": f"0x{n.status_hex}",
                        "rx_bytes": n.rx_bytes,
                        "tx_bytes": n.tx_bytes,
                    }
        msg = note.strip() if note.strip() else "User marked lag / anomaly moment"
        return self.add_incident(
            net=net,
            kind="USER_MARK",
            severity="mark",
            summary=msg,
            details={"note": msg, "peers": peer_summary},
        )

    def record_snapshot(self, net: str, snap: NetworkSnapshot, now: float | None = None) -> None:
        ts = now if now is not None else time.time()
        with self._lock:
            prev_snap = self._latest_snap.get(net)
            self._latest_snap[net] = snap
            self._latest_snap_ts[net] = ts

        if snap.error:
            if prev_snap is not None and not prev_snap.error:
                self.add_incident(
                    net=net,
                    kind="DAEMON_DOWN",
                    severity="error",
                    summary=f"Network '{net}' stopped or control socket unreachable: {snap.error}",
                    ts=ts,
                )
            return

        self_node = next((n.name for n in snap.nodes.values() if n.is_self), "")
        if prev_snap is not None and prev_snap.error:
            self.add_incident(
                net=net,
                kind="DAEMON_UP",
                severity="info",
                summary=f"Network '{net}' is running ({self_node or 'self'})",
                ts=ts,
            )

        total_rx = sum(n.rx_bytes for n in snap.nodes.values() if not n.is_self)
        total_tx = sum(n.tx_bytes for n in snap.nodes.values() if not n.is_self)

        rx_bps = 0.0
        tx_bps = 0.0
        with self._lock:
            prev_tot = self._last_totals.get(net)
            self._last_totals[net] = (ts, total_rx, total_tx)
        if prev_tot is not None:
            dt = ts - prev_tot[0]
            if dt > 0.2:
                rx_bps = max(0, total_rx - prev_tot[1]) * 8.0 / dt
                tx_bps = max(0, total_tx - prev_tot[2]) * 8.0 / dt

        peers_point: dict[str, dict[str, Any]] = {}
        peer_rtt: dict[str, float] = {}
        for name, n in snap.nodes.items():
            if n.is_self:
                continue
            peer_rtt[name] = round(n.rtt, 1)
            peers_point[name] = {
                "rtt": round(n.rtt, 1),
                "pmtu": n.pmtu,
                "link": n.link,
                "transport": n.transport,
                "via": n.nexthop,
                "rx": n.rx_bytes,
                "tx": n.tx_bytes,
            }
            self._analyze_peer(net, n, ts)

        point = {
            "ts": round(ts, 2),
            "rx_bps": round(rx_bps, 1),
            "tx_bps": round(tx_bps, 1),
            "rx_bytes": total_rx,
            "tx_bytes": total_tx,
            "peer_rtt": peer_rtt,
            "peers": peers_point,
        }
        with self._lock:
            self._series.setdefault(net, deque(maxlen=SERIES_MAX_POINTS)).append(point)

    def _analyze_peer(self, net: str, n: Node, ts: float) -> None:
        key = (net, n.name)
        with self._lock:
            st = self._peer_state.get(key)
            if st is None:
                st = _PeerTrack()
                self._peer_state[key] = st

        sdict = n.status if n.status else decode_status(n.status_hex)
        reachable = bool(sdict.get("reachable"))
        validkey = bool(sdict.get("validkey"))
        udp_confirmed = bool(sdict.get("udp_confirmed"))

        if not st.initialized:
            st.initialized = True
            st.link = n.link
            st.transport = n.transport
            st.nexthop = n.nexthop
            st.rtt = n.rtt
            st.pmtu = n.pmtu
            st.rx_bytes = n.rx_bytes
            st.tx_bytes = n.tx_bytes
            st.reachable = reachable
            st.validkey = validkey
            st.udp_confirmed = udp_confirmed
            return

        # 1. Reachability transitions
        if st.reachable and not reachable:
            self.add_incident(
                net=net, kind="PEER_DOWN", severity="error", peer=n.name,
                summary=f"Peer '{n.name}' became unreachable (was {st.link} via {st.transport or st.nexthop or 'mesh'})",
                details={"prev_link": st.link, "prev_transport": st.transport, "prev_rtt": st.rtt},
                ts=ts,
            )
        elif not st.reachable and reachable:
            self.add_incident(
                net=net, kind="PEER_UP", severity="info", peer=n.name,
                summary=f"Peer '{n.name}' is reachable ({n.link}, transport={n.transport or 'meta'}, via={n.nexthop or 'direct'})",
                details={"link": n.link, "transport": n.transport, "via": n.nexthop, "rtt": n.rtt, "pmtu": n.pmtu},
                ts=ts,
            )

        if reachable:
            # 2. UDP fallback detection (direct-udp -> direct-tcp or relay)
            if st.link == "direct-udp" and n.link in ("direct-tcp", "relay"):
                self.add_incident(
                    net=net, kind="UDP_FALLBACK", severity="warn", peer=n.name,
                    summary=f"Peer '{n.name}' fell back from direct UDP to {n.link} (via {n.nexthop or 'TCP'}, transport={n.transport or 'meta'})",
                    details={"prev_link": st.link, "new_link": n.link, "via": n.nexthop, "transport": n.transport, "status": f"0x{n.status_hex}"},
                    ts=ts,
                )
            elif st.link in ("direct-tcp", "relay") and n.link == "direct-udp":
                self.add_incident(
                    net=net, kind="UDP_RECOVERED", severity="info", peer=n.name,
                    summary=f"Peer '{n.name}' established direct UDP path (rtt={n.rtt:.0f}ms, pmtu={n.pmtu}, transport={n.transport or 'udp'})",
                    details={"prev_link": st.link, "rtt": n.rtt, "pmtu": n.pmtu, "transport": n.transport},
                    ts=ts,
                )

            # 3. Transport protocol change
            if st.transport and n.transport and st.transport != n.transport:
                self.add_incident(
                    net=net, kind="TRANSPORT_CHANGED", severity="info", peer=n.name,
                    summary=f"Peer '{n.name}' transport switched: {st.transport} → {n.transport}",
                    details={"prev_transport": st.transport, "new_transport": n.transport, "link": n.link},
                    ts=ts,
                )

            # 4. Relay / nexthop change
            if st.nexthop and n.nexthop and st.nexthop != n.nexthop:
                self.add_incident(
                    net=net, kind="ROUTE_VIA_CHANGED", severity="warn", peer=n.name,
                    summary=f"Peer '{n.name}' nexthop changed: {st.nexthop} → {n.nexthop} ({n.link})",
                    details={"prev_via": st.nexthop, "new_via": n.nexthop, "link": n.link},
                    ts=ts,
                )

            # 5. PMTU drop
            if st.pmtu > 0 and n.pmtu > 0 and (st.pmtu - n.pmtu >= 100 or (n.pmtu < 1280 and st.pmtu >= 1280)):
                self.add_incident(
                    net=net, kind="PMTU_DROP", severity="warn", peer=n.name,
                    summary=f"Peer '{n.name}' PMTU dropped from {st.pmtu} to {n.pmtu} bytes",
                    details={"prev_pmtu": st.pmtu, "new_pmtu": n.pmtu, "link": n.link, "transport": n.transport},
                    ts=ts,
                )

            # 6. RTT spike
            if st.rtt > 0 and n.rtt > 0:
                if (n.rtt - st.rtt >= 150.0 and n.rtt >= st.rtt * 2.2) or (n.rtt >= 450.0 and st.rtt < 250.0):
                    self.add_incident(
                        net=net, kind="RTT_SPIKE", severity="warn", peer=n.name,
                        summary=f"Peer '{n.name}' RTT spiked: {st.rtt:.0f} ms → {n.rtt:.0f} ms ({n.link})",
                        details={"prev_rtt": round(st.rtt, 1), "new_rtt": round(n.rtt, 1), "link": n.link, "transport": n.transport},
                        ts=ts,
                    )

            # 7. SPTPS key wait (reachable for multiple samples without validkey)
            if not validkey:
                st.key_wait_streak += 1
                if st.key_wait_streak == 3:
                    self.add_incident(
                        net=net, kind="SPTPS_KEY_WAIT", severity="warn", peer=n.name,
                        summary=f"Peer '{n.name}' is reachable in graph but has no valid SPTPS session key for >7s (status=0x{n.status_hex})",
                        details={"status": f"0x{n.status_hex}", "status_flags": sdict, "link": n.link, "via": n.nexthop},
                        ts=ts,
                    )
            else:
                st.key_wait_streak = 0

            # 8. One-way traffic blackhole (TX advancing while RX is completely frozen)
            rx_delta = n.rx_bytes - st.rx_bytes
            tx_delta = n.tx_bytes - st.tx_bytes
            if tx_delta >= 2048 and rx_delta == 0:
                st.tx_only_streak += 1
                if st.tx_only_streak == 4:
                    self.add_incident(
                        net=net, kind="ONE_WAY_BLACKHOLE", severity="warn", peer=n.name,
                        summary=f"Peer '{n.name}' shows one-way TX without RX replies for ~10s (TX +{tx_delta} B, RX +0 B, link={n.link})",
                        details={"tx_delta": tx_delta, "link": n.link, "transport": n.transport, "status": f"0x{n.status_hex}"},
                        ts=ts,
                    )
            elif rx_delta > 0:
                st.tx_only_streak = 0

        st.link = n.link
        st.transport = n.transport
        st.nexthop = n.nexthop
        st.rtt = n.rtt
        st.pmtu = n.pmtu
        st.rx_bytes = n.rx_bytes
        st.tx_bytes = n.tx_bytes
        st.reachable = reachable
        st.validkey = validkey
        st.udp_confirmed = udp_confirmed

    def get_series(self, net: str, max_points: int = 720) -> list[dict[str, Any]]:
        with self._lock:
            dq = self._series.get(net)
            if not dq:
                return []
            items = list(dq)
        if len(items) > max_points:
            items = items[-max_points:]
        return items

    def get_incidents(self, net: str, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            dq = self._incidents.get(net)
            if not dq:
                return []
            items = list(dq)[-limit:]
        items.reverse()
        return [ev.to_dict() for ev in items]

    def get_latest_snapshot(self, net: str) -> NetworkSnapshot | None:
        with self._lock:
            return self._latest_snap.get(net)

    def get_latest_snapshot_with_age(self, net: str, now: float | None = None) -> tuple[NetworkSnapshot | None, float]:
        t = now if now is not None else time.time()
        with self._lock:
            snap = self._latest_snap.get(net)
            ts = self._latest_snap_ts.get(net, 0.0)
        if snap is None:
            return None, float("inf")
        return snap, max(0.0, t - ts)


# ---------------------------------------------------------------------------
# Active Diagnostic Prober (in-tunnel + underlay + ports + DNS + OS routes)
# ---------------------------------------------------------------------------

def parse_host_endpoints(host_text: str) -> dict[str, Any]:
    """Extract Address, Port, HttpsPort, QuicPort, ObfsPort, Subnet, and PreferredTransport from a host block."""
    addresses: list[tuple[str, str]] = []
    port = 655
    https_port = 0
    quic_port = 0
    obfs_port = 0
    subnets: list[str] = []
    pref_transport = transports.host_preferred_transport(host_text)

    for raw in (host_text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or "=" not in line:
            continue
        k, v = [x.strip() for x in line.split("=", 1)]
        kl = k.lower()
        if kl == "address":
            parts = v.split()
            if parts:
                addresses.append((parts[0], parts[1] if len(parts) > 1 else ""))
        elif kl == "port":
            try:
                port = int(v.split()[0])
            except ValueError:
                pass
        elif kl == "httpsport":
            try:
                https_port = int(v.split()[0])
            except ValueError:
                pass
        elif kl == "quicport":
            try:
                quic_port = int(v.split()[0])
            except ValueError:
                pass
        elif kl == "obfsport":
            try:
                obfs_port = int(v.split()[0])
            except ValueError:
                pass
        elif kl == "subnet":
            subnets.append(v)

    return {
        "addresses": addresses,
        "configured_address": addresses[0][0] if addresses else "",
        "port": port,
        "https_port": https_port,
        "quic_port": quic_port,
        "obfs_port": obfs_port,
        "subnets": subnets,
        "preferred_transport": pref_transport or "auto",
    }


class ActiveProber:
    """Executes active diagnostic checks (in-tunnel and outer underlay)."""

    def __init__(self, tc: TincControl, app_fn: Callable[[], yaml_config.AppConfig],
                 base_dir: str, collector: TelemetryCollector | None = None) -> None:
        self.tc = tc
        self.app_fn = app_fn
        self.base_dir = base_dir
        self.collector = collector
        self._probe_sem = threading.BoundedSemaphore(2)

    def _cached_or_live_snapshot(self, net: str) -> NetworkSnapshot:
        if self.collector is not None:
            snap, age = self.collector.get_latest_snapshot_with_age(net)
            if snap is not None and not snap.error and age < 10.0:
                return snap
        return self.tc.snapshot(net)

    def _resolve_peer_vpn_ip(self, net: str, target: str) -> tuple[str, str]:
        """Resolve a peer name or IP to (vpn_ip, peer_label)."""
        target = target.strip()
        if not target:
            return "", ""
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", target):
            return target, target
        snap = self._cached_or_live_snapshot(net)
        if not snap.error and target in snap.nodes:
            ip = snap.nodes[target].vpn_address
            if ip:
                return ip.split("/")[0], target
        app = self.app_fn()
        nc = app.net(net) if app else None
        if nc and target in nc.hosts:
            ip = select_primary_vpn_ip(None, nc.hosts[target], None)
            if ip:
                return ip, target
        return target, target

    def _resolve_peer_outer_host(self, net: str, target: str) -> tuple[str, dict[str, Any]]:
        """Resolve a peer name or hostname/IP to (outer_host, endpoint_info)."""
        target = target.strip()
        app = self.app_fn()
        nc = app.net(net) if app else None
        if nc and target in nc.hosts:
            ep = parse_host_endpoints(nc.hosts[target])
            if ep["addresses"]:
                return ep["addresses"][0][0], ep
        snap = self._cached_or_live_snapshot(net)
        if not snap.error and target in snap.nodes:
            n = snap.nodes[target]
            if n.address and n.address not in ("local", "unknown", "0.0.0.0", "MYSELF"):
                return n.address, {
                    "addresses": [(n.address, n.port or "655")],
                    "port": int(n.port) if (n.port and n.port.isdigit()) else 655,
                    "https_port": 443,
                    "quic_port": 443,
                    "obfs_port": 0,
                    "subnets": n.subnets,
                    "preferred_transport": "auto",
                }
        if target.startswith("["):
            if "]:" in target:
                hpart, pstr = target[1:].rsplit("]:", 1)
                p = int(pstr) if pstr.isdigit() else 655
                return hpart, {"addresses": [(hpart, str(p))], "port": p, "https_port": p, "quic_port": p, "obfs_port": p, "subnets": [], "preferred_transport": "auto"}
            if target.endswith("]"):
                hpart = target[1:-1]
                return hpart, {"addresses": [(hpart, "")], "port": 655, "https_port": 443, "quic_port": 443, "obfs_port": 0, "subnets": [], "preferred_transport": "auto"}
        if target.count(":") == 1 and not target.startswith("["):
            host, pstr = target.rsplit(":", 1)
            p = int(pstr) if pstr.isdigit() else 655
            return host, {"addresses": [(host, str(p))], "port": p, "https_port": p, "quic_port": p, "obfs_port": p, "subnets": [], "preferred_transport": "auto"}
        return target, {"addresses": [(target, "")], "port": 655, "https_port": 443, "quic_port": 443, "obfs_port": 0, "subnets": [], "preferred_transport": "auto"}

    def run_probe(self, net: str, tool: str, params: dict[str, Any]) -> dict[str, Any]:
        if not self._probe_sem.acquire(blocking=False):
            msg = "Another diagnostic probe is already running — please wait for it to finish."
            return {"ok": False, "output": msg, "formatted": msg}
        try:
            return self._run_probe_impl(net, tool, params)
        finally:
            self._probe_sem.release()

    def _run_probe_impl(self, net: str, tool: str, params: dict[str, Any]) -> dict[str, Any]:
        # Normalize WebUI `kind` and API `tool` names
        kind = (tool or str(params.get("kind") or params.get("tool") or "")).strip()
        target = str(params.get("target") or params.get("dst_ip") or params.get("host") or params.get("peer") or "").strip()

        if kind in ("in-ping", "in_tunnel_ping"):
            ip, label = self._resolve_peer_vpn_ip(net, target)
            if not ip:
                msg = "Specify a peer name or VPN IPv4 address."
                return {"ok": False, "output": msg, "formatted": msg}
            count = max(1, min(int(params.get("count") or 4), 20))
            size = max(0, min(int(params.get("size") or 56), 1472))
            df = bool(params.get("df", False))
            res = self.tc.in_tunnel_ping(net, ip, count=count, size=size, df=df, timeout_ms=2000)
            lines = [f"=== In-Tunnel ICMP Ping to {label} ({ip}) — {count} probes, {size} bytes, DF={1 if df else 0} ==="]
            for r in res.get("samples", []):
                seq = r.get("seq")
                if r.get("replied"):
                    status = r.get("status")
                    rtt_ms = r.get("rtt_ms") or 0.0
                    from_ip = r.get("from_ip") or ip
                    node = r.get("node") or ""
                    node_str = f" [{node}]" if node and node != "-" else ""
                    if status == "echo_reply":
                        lines.append(f"  #{seq}: {size} bytes from {from_ip}{node_str}: ttl={r.get('ttl')} time={rtt_ms:.2f} ms")
                    elif status == "frag_needed":
                        lines.append(f"  #{seq}: FRAG_NEEDED from {from_ip}{node_str}: next-hop MTU={r.get('mtu')} ({rtt_ms:.2f} ms)")
                    elif status == "time_exceeded":
                        lines.append(f"  #{seq}: TTL_EXCEEDED at {from_ip}{node_str} ({rtt_ms:.2f} ms)")
                    else:
                        lines.append(f"  #{seq}: {status} from {from_ip}{node_str} ({rtt_ms:.2f} ms)")
                else:
                    lines.append(f"  #{seq}: timeout / {r.get('raw', 'no reply')}")
            lines.append("")
            lines.append(f"--- {label} ({ip}) ping statistics ---")
            lines.append(f"{res['sent']} packets transmitted, {res['received']} received, {res['loss_pct']}% packet loss")
            if res["received"] > 0 and res["min_ms"] is not None:
                lines.append(f"rtt min/avg/max/jitter = {res['min_ms']:.2f}/{res['avg_ms']:.2f}/{res['max_ms']:.2f}/{res['jitter_ms']:.2f} ms")
            out_str = "\n".join(lines)
            return {"ok": res["received"] > 0, "output": out_str, "formatted": out_str, "data": res}

        if kind in ("in-trace", "in_tunnel_trace"):
            ip, label = self._resolve_peer_vpn_ip(net, target)
            if not ip:
                msg = "Specify a peer name or VPN IPv4 address."
                return {"ok": False, "output": msg, "formatted": msg}
            max_hops = max(1, min(int(params.get("max_hops") or 12), 30))
            res = self.tc.in_tunnel_traceroute(net, ip, max_hops=max_hops, timeout_ms=1500)
            lines = [f"=== In-Tunnel Mesh Traceroute to {label} ({ip}), {max_hops} hops max ==="]
            for h in res.get("hops", []):
                ttl = h.get("hop")
                if h.get("from_ip"):
                    from_ip = h.get("from_ip", "?")
                    node = h.get("node", "")
                    node_str = f" ({node})" if node and node != "-" else ""
                    rtt_ms = h.get("rtt_ms") or 0.0
                    lines.append(f" {ttl:2d}  {from_ip}{node_str}  {rtt_ms:.2f} ms  [{h.get('status')}]")
                else:
                    lines.append(f" {ttl:2d}  * * *  ({h.get('status', 'timeout')})")
            out_str = "\n".join(lines)
            return {"ok": True, "output": out_str, "formatted": out_str, "data": res}

        if kind in ("in-pmtu", "in_tunnel_pmtu"):
            ip, label = self._resolve_peer_vpn_ip(net, target)
            if not ip:
                msg = "Specify a peer name or VPN IPv4 address."
                return {"ok": False, "output": msg, "formatted": msg}
            res = self.tc.in_tunnel_pmtu_sweep(net, ip, timeout_ms=1200)
            eff = res.get("max_working_ip_mtu", 0)
            lines = [
                f"=== In-Tunnel PMTU Discovery Sweep (DF=1) to {label} ({ip}) ===",
                f"Max Working IP MTU: {eff} bytes" + (f" (Reported Frag MTU: {res.get('reported_frag_mtu')})" if res.get("reported_frag_mtu") else ""),
                "",
                "Probe steps (DF=1):",
            ]
            for s in res.get("steps", []):
                sz = s.get("payload_bytes")
                ip_mtu = s.get("ip_mtu")
                if s.get("ok"):
                    lines.append(f"  payload={sz:4d} B (IP MTU {ip_mtu:4d} B) : PASS  ({(s.get('rtt_ms') or 0.0):.2f} ms)")
                else:
                    extra = f" [FRAG_NEEDED mtu={s.get('reported_mtu')}]" if s.get("status") == "frag_needed" else f" [{s.get('status', 'dropped')}]"
                    lines.append(f"  payload={sz:4d} B (IP MTU {ip_mtu:4d} B) : FAIL{extra}")
            out_str = "\n".join(lines)
            return {"ok": eff > 0, "output": out_str, "formatted": out_str, "data": res}

        if kind in ("out-ping", "underlay_ping"):
            peer_or_host = str(params.get("peer") or params.get("host") or target).strip()
            host, _ = self._resolve_peer_outer_host(net, peer_or_host)
            if not host:
                msg = "Specify a peer name, hostname, or outer IP address."
                return {"ok": False, "output": msg, "formatted": msg}
            if not is_valid_probe_host(host):
                msg = f"Invalid target host: {host!r}"
                return {"ok": False, "output": msg, "formatted": msg}
            count = max(1, min(int(params.get("count") or 4), 15))
            if sys.platform == "win32":
                cmd = ["ping", "-n", str(count), "-w", "2000", host]
            else:
                cmd = ["ping", "-c", str(count), "-W", "2", host]
            try:
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=count * 3 + 5,
                                   stdin=subprocess.DEVNULL, creationflags=_NO_WINDOW)
                out_str = f"$ {' '.join(cmd)}\n\n{(p.stdout + p.stderr).strip()}"
                return {"ok": p.returncode == 0, "output": out_str, "formatted": out_str}
            except Exception as e:
                msg = f"Outer ping failed: {e}"
                return {"ok": False, "output": msg, "formatted": msg}

        if kind in ("out-trace", "underlay_trace"):
            peer_or_host = str(params.get("peer") or params.get("host") or target).strip()
            host, _ = self._resolve_peer_outer_host(net, peer_or_host)
            if not host:
                msg = "Specify a peer name, hostname, or outer IP address."
                return {"ok": False, "output": msg, "formatted": msg}
            if not is_valid_probe_host(host):
                msg = f"Invalid target host: {host!r}"
                return {"ok": False, "output": msg, "formatted": msg}
            if sys.platform == "win32":
                cmd = ["tracert", "-d", "-h", "18", "-w", "1000", host]
            else:
                cmd = ["traceroute", "-n", "-m", "18", "-w", "1", host]
            try:
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=35,
                                   stdin=subprocess.DEVNULL, creationflags=_NO_WINDOW)
                out_str = f"$ {' '.join(cmd)}\n\n{(p.stdout + p.stderr).strip()}"
                return {"ok": p.returncode == 0, "output": out_str, "formatted": out_str}
            except FileNotFoundError:
                if sys.platform != "win32":
                    try:
                        p = subprocess.run(["tracepath", "-n", "-m", "18", host],
                                           capture_output=True, text=True, timeout=35, stdin=subprocess.DEVNULL)
                        out_str = (p.stdout + p.stderr).strip()
                        return {"ok": p.returncode == 0, "output": out_str, "formatted": out_str}
                    except Exception as e:
                        msg = f"Outer traceroute not available: {e}"
                        return {"ok": False, "output": msg, "formatted": msg}
                msg = "tracert command not found"
                return {"ok": False, "output": msg, "formatted": msg}
            except Exception as e:
                msg = f"Outer traceroute failed: {e}"
                return {"ok": False, "output": msg, "formatted": msg}

        if kind in ("ports", "port_probe"):
            peer_or_host = str(params.get("peer") or params.get("host") or target).strip()
            return self._probe_carrier_ports(net, peer_or_host)

        if kind in ("dns", "dns_lookup"):
            return self._probe_dns_and_cache(net)

        if kind in ("routes", "os_net"):
            return self._probe_os_routes(net)

        if kind in ("dump", "tinc_cmd"):
            item = str(params.get("cmd") or params.get("item") or "nodes").strip()
            if item == "fsck":
                res = self.tc.fsck(net)
                out_str = (res.stdout + res.stderr).strip() or "(no issues reported)"
                return {"ok": res.ok, "output": out_str, "formatted": out_str}
            if item.startswith("info:"):
                node = item.split(":", 1)[1].strip() or target
                res = self.tc.info(net, node)
                out_str = (res.stdout + res.stderr).strip()
                return {"ok": res.ok, "output": out_str, "formatted": out_str}
            res = self.tc.dump_raw(net, item)
            out_str = (res.stdout + res.stderr).strip()
            return {"ok": res.ok, "output": out_str, "formatted": out_str}

        msg = f"Unknown diagnostic tool: {kind}"
        return {"ok": False, "output": msg, "formatted": msg}

    def _probe_carrier_ports(self, net: str, target: str) -> dict[str, Any]:
        host, ep = self._resolve_peer_outer_host(net, target)
        if not host:
            msg = "Specify a peer name or host[:port]."
            return {"ok": False, "output": msg, "formatted": msg}
        if not is_valid_probe_host(host):
            msg = f"Invalid target host: {host!r}"
            return {"ok": False, "output": msg, "formatted": msg}
        lines = [f"=== Carrier & Transport Handshake Prober for '{target}' (host={host}) ==="]

        # 1. DNS Resolution (bounded timeout so slow resolvers never hang WebUI/export)
        t0 = time.perf_counter()
        ips: list[str] = []
        raw_ips = fulltunnel._resolve_with_timeout(
            lambda h: [i[4][0] for i in socket.getaddrinfo(h, None, socket.AF_UNSPEC, socket.SOCK_STREAM)],
            host,
            2.0,
        )
        for ip in raw_ips:
            if ip not in ips:
                ips.append(ip)
        if not ips:
            lines.append(f"[DNS] FAILED or timed out resolving {host}")
            out_str = "\n".join(lines)
            return {"ok": False, "output": out_str, "formatted": out_str}
        dns_ms = (time.perf_counter() - t0) * 1000.0
        lines.append(f"[DNS] {host} -> {', '.join(ips)} ({dns_ms:.1f} ms)")

        ip = ips[0]
        port = ep.get("port") or 655
        https_port = ep.get("https_port") or 0
        quic_port = ep.get("quic_port") or 0
        obfs_port = ep.get("obfs_port") or 0

        # 2. Plain TCP / Metaconnection Port
        if port > 0:
            t0 = time.perf_counter()
            try:
                with socket.create_connection((ip, port), timeout=3.0) as s:
                    tcp_ms = (time.perf_counter() - t0) * 1000.0
                    s.settimeout(1.5)
                    banner = ""
                    try:
                        data = s.recv(128)
                        banner = data.decode("utf-8", errors="replace").strip()
                    except Exception:
                        pass
                    lines.append(f"[TCP Port {port} (plain/meta)] OPEN — connect={tcp_ms:.1f} ms"
                                 + (f" | banner: {banner!r}" if banner else " | (no immediate banner — may share front port)"))
            except Exception as e:
                lines.append(f"[TCP Port {port} (plain/meta)] FAILED — {e}")

        # 3. HTTPS / TLS 1.3 Front Port
        tls_ports = [https_port] if https_port > 0 else ([443] if port != 443 else [port])
        for hp in tls_ports:
            if hp <= 0:
                continue
            t0 = time.perf_counter()
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    ctx.set_alpn_protocols(["h2", "http/1.1"])
                except Exception:
                    pass
                with socket.create_connection((ip, hp), timeout=3.0) as raw_sock:
                    tcp_ms = (time.perf_counter() - t0) * 1000.0
                    t1 = time.perf_counter()
                    with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
                        tls_ms = (time.perf_counter() - t1) * 1000.0
                        ver = ssock.version()
                        alpn = ssock.selected_alpn_protocol()
                        cipher = ssock.cipher()
                        lines.append(
                            f"[HTTPS/TLS Port {hp}] PASS — TCP={tcp_ms:.1f} ms, TLS={tls_ms:.1f} ms | "
                            f"version={ver}, ALPN={alpn or 'none'}, cipher={cipher[0] if cipher else '?'}"
                        )
            except Exception as e:
                lines.append(f"[HTTPS/TLS Port {hp}] FAILED — {e}")

        # 4. QUIC / Obfs UDP socket probe
        udp_ports: list[tuple[str, int]] = []
        if quic_port > 0:
            udp_ports.append(("QUIC UDP", quic_port))
        if obfs_port > 0:
            udp_ports.append(("Obfs UDP", obfs_port))
        if port > 0 and all(p != port for _, p in udp_ports):
            udp_ports.append(("Base UDP", port))
        for label, up in udp_ports:
            try:
                af = socket.AF_INET6 if ":" in ip else socket.AF_INET
                with socket.socket(af, socket.SOCK_DGRAM) as usock:
                    usock.settimeout(1.0)
                    usock.connect((ip, up))
                    usock.send(b"\x00")
                    try:
                        _ = usock.recv(64)
                        lines.append(f"[{label} Port {up}] UDP socket sent & received reply from {ip}:{up}")
                    except socket.timeout:
                        lines.append(f"[{label} Port {up}] UDP datagram transmitted to {ip}:{up} (no immediate ICMP port-unreachable; silent drop or waiting for valid crypto handshake)")
            except Exception as e:
                lines.append(f"[{label} Port {up}] UDP error to {ip}:{up} — {e}")

        out_str = "\n".join(lines)
        return {"ok": True, "output": out_str, "formatted": out_str}

    def _probe_dns_and_cache(self, net: str) -> dict[str, Any]:
        app = self.app_fn()
        if net and not is_valid_net_name(net, app):
            msg = f"Invalid network name: {net!r}"
            return {"ok": False, "output": msg, "formatted": msg}
        nc = app.net(net) if app else None
        lines = [f"=== DNS Resolution & Address Cache Inspector for '{net}' ==="]
        if nc:
            for hname, hbody in sorted(nc.hosts.items()):
                ep = parse_host_endpoints(hbody)
                if not ep["addresses"]:
                    continue
                for addr, port in ep["addresses"]:
                    clean_addr = addr[1:-1] if (addr.startswith("[") and addr.endswith("]")) else addr
                    if not is_valid_probe_host(clean_addr):
                        lines.append(f"  Host {hname:15s} : {addr}:{port or ep['port']} -> SKIPPED (invalid address)")
                        continue
                    t0 = time.perf_counter()
                    resolved = fulltunnel._resolve_with_timeout(
                        lambda h: sorted({i[4][0] for i in socket.getaddrinfo(h, None, socket.AF_UNSPEC, socket.SOCK_DGRAM)}),
                        clean_addr,
                        2.0,
                    )
                    ms = (time.perf_counter() - t0) * 1000.0
                    if resolved:
                        lines.append(f"  Host {hname:15s} : {addr}:{port or ep['port']} -> {', '.join(resolved)} ({ms:.1f} ms)")
                    else:
                        lines.append(f"  Host {hname:15s} : {addr}:{port or ep['port']} -> ERROR: DNS failed or timed out ({ms:.1f} ms)")

        rdir = os.path.join(self.base_dir, net)
        dns_state = os.path.join(rdir, "dnsrefresh.state")
        lines.append("")
        lines.append(f"--- dnsrefresh.state ({dns_state}) ---")
        if os.path.isfile(dns_state):
            try:
                with open(dns_state, "r", encoding="utf-8", errors="replace") as f:
                    lines.append(f.read().strip() or "(empty)")
            except OSError as e:
                lines.append(f"(read error: {e})")
        else:
            lines.append("(not present)")

        cache_dir = os.path.join(rdir, "address_cache")
        lines.append("")
        lines.append(f"--- address_cache ({cache_dir}) ---")
        if os.path.isdir(cache_dir):
            try:
                for fn in sorted(os.listdir(cache_dir)):
                    fp = os.path.join(cache_dir, fn)
                    if os.path.isfile(fp):
                        with open(fp, "r", encoding="utf-8", errors="replace") as f:
                            body = f.read().strip().replace("\n", " | ")
                        lines.append(f"  {fn}: {body}")
            except OSError as e:
                lines.append(f"(read error: {e})")
        else:
            lines.append("(not present)")

        out_str = "\n".join(lines)
        return {"ok": True, "output": out_str, "formatted": out_str}

    def _probe_os_routes(self, net: str) -> dict[str, Any]:
        lines = [f"=== OS Interfaces, Routing Table & ARP Inspector ({platform.system()}) ==="]
        if sys.platform == "win32":
            cmds = [
                ("IPv4 Route Table", ["route", "print", "-4"]),
                ("IP Configuration", ["ipconfig", "/all"]),
                ("ARP Cache", ["arp", "-a"]),
            ]
        else:
            cmds = [
                ("IP Addresses", ["ip", "-br", "addr"]),
                ("IPv4 Routes", ["ip", "route", "show"]),
                ("Neighbors / ARP", ["ip", "neigh", "show"]),
            ]
        for title, cmd in cmds:
            lines.append(f"\n--- {title} ({' '.join(cmd)}) ---")
            try:
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=6,
                                   stdin=subprocess.DEVNULL, creationflags=_NO_WINDOW)
                lines.append((p.stdout + p.stderr).strip())
            except Exception as e:
                lines.append(f"(failed: {e})")
        out_str = "\n".join(lines)
        return {"ok": True, "output": out_str, "formatted": out_str}


# ---------------------------------------------------------------------------
# Opt-In Remote Diagnostic HTTP Server
# ---------------------------------------------------------------------------

def _web_settings_path(base_dir: str) -> str:
    return os.path.join(base_dir, "diag_web.json")


def _settings_path(base_dir: str) -> str:
    return os.path.join(base_dir, "diag_settings.json")


def _generate_diag_password(length: int = 16) -> str:
    return "".join(secrets.choice(_DIAG_PASS_ALPHABET) for _ in range(length))


def _read_raw_diag_settings(path: str) -> dict[str, Any]:
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return {}


def _load_merged_diag_settings(base_dir: str) -> dict[str, Any]:
    primary = _read_raw_diag_settings(_web_settings_path(base_dir))
    legacy = _read_raw_diag_settings(_settings_path(base_dir))
    if primary:
        if not str(primary.get("password") or "").strip() and str(legacy.get("password") or "").strip():
            merged = dict(primary)
            merged["password"] = legacy["password"]
            return merged
        return primary
    return legacy


def _write_raw_diag_settings(base_dir: str, payload: dict[str, Any]) -> None:
    raw = (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    for p in (_web_settings_path(base_dir), _settings_path(base_dir)):
        paths.write_private(p, raw)


def ensure_diag_password(base_dir: str) -> str:
    """Ensure a persistent random password exists in `diag_web.json` / `diag_settings.json`
    (protected with `paths.private_sddl` on Windows / 0600 on POSIX) and return it."""
    if not base_dir:
        return ""
    with _settings_lock:
        data = _load_merged_diag_settings(base_dir)
        pwd = str(data.get("password") or "").strip()
        if pwd and os.path.isfile(_web_settings_path(base_dir)) and os.path.isfile(_settings_path(base_dir)):
            return pwd
        if not pwd:
            pwd = _generate_diag_password(16)
        payload = {
            "enabled": bool(data.get("enabled", False)),
            "port": int(data.get("port", DEFAULT_DIAG_PORT)),
            "password": pwd,
        }
        try:
            _write_raw_diag_settings(base_dir, payload)
        except OSError:
            pass
        return pwd


def load_diag_settings(base_dir: str, ensure_password: bool = True) -> dict[str, Any]:
    if not base_dir:
        return {"enabled": False, "port": DEFAULT_DIAG_PORT, "password": ""}
    with _settings_lock:
        data = _load_merged_diag_settings(base_dir)
        enabled = bool(data.get("enabled", False))
        try:
            port = int(data.get("port", DEFAULT_DIAG_PORT))
        except (TypeError, ValueError):
            port = DEFAULT_DIAG_PORT
        pwd = str(data.get("password") or "").strip()
    if ensure_password and not pwd:
        pwd = ensure_diag_password(base_dir)
    return {"enabled": enabled, "port": port, "password": pwd}


def save_diag_settings(base_dir: str, enabled: bool, port: int, password: str | None = None) -> None:
    if not base_dir:
        return
    with _settings_lock:
        data = _load_merged_diag_settings(base_dir)
        pwd = (password or "").strip() or str(data.get("password") or "").strip()
        if not pwd:
            pwd = _generate_diag_password(16)
        payload = {
            "enabled": bool(enabled),
            "port": int(port),
            "password": pwd,
        }
        try:
            _write_raw_diag_settings(base_dir, payload)
        except OSError:
            pass


def live_diag_port(base_dir: str) -> int:
    """Return the live listening port of the active `DiagWebServer` for `base_dir`,
    or 0 when disabled / not running."""
    if not base_dir:
        return 0
    key = os.path.normcase(os.path.abspath(base_dir))
    with _active_servers_lock:
        srv = _active_servers.get(key)
    if srv is not None and srv.enabled:
        return srv.port
    return 0


DIAG_LOGIN_HTML = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>tincstack — Вход в панель диагностики</title>
<style>
  :root {
    --bg: #0d1117;
    --panel: #161b22;
    --border: #30363d;
    --text: #e6edf3;
    --muted: #8b949e;
    --accent: #58a6ff;
    --green: #238636;
    --red: #f85149;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Ubuntu, sans-serif;
  }
  .login-card {
    width: 100%;
    max-width: 420px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 28px 26px;
    box-shadow: 0 12px 36px rgba(0, 0, 0, 0.55);
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 18px;
    font-weight: 700;
    margin-bottom: 8px;
  }
  .brand .bolt { color: var(--accent); font-size: 21px; }
  .subtitle {
    color: var(--muted);
    font-size: 13px;
    line-height: 1.5;
    margin-bottom: 20px;
  }
  .field-row {
    display: flex;
    gap: 8px;
    margin-bottom: 14px;
  }
  input[type="password"], input[type="text"] {
    flex: 1;
    background: var(--bg);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 9px 12px;
    font-size: 14px;
    font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
  }
  input:focus {
    outline: none;
    border-color: var(--accent);
  }
  button {
    background: #21262d;
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 9px 14px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
  }
  button:hover { background: #30363d; }
  .btn-submit {
    width: 100%;
    background: var(--green);
    border-color: rgba(240, 246, 252, 0.15);
    color: #fff;
    padding: 10px 16px;
    font-size: 14px;
  }
  .btn-submit:hover { background: #2ea043; }
  .err {
    display: none;
    margin-top: 12px;
    padding: 9px 11px;
    border-radius: 6px;
    border: 1px solid rgba(248, 81, 73, 0.45);
    background: rgba(248, 81, 73, 0.12);
    color: var(--red);
    font-size: 12.5px;
  }
</style>
</head>
<body>
  <form class="login-card" id="login-form">
    <div class="brand"><span class="bolt">⚡</span> <span>tincstack · Веб-панель диагностики</span></div>
    <div class="subtitle">
      Доступ защищён паролем. Скопируйте пароль из окна
      <b>Diagnostics &amp; Remote WebUI</b> в приложении <code>tincmgr</code>.
    </div>
    <div class="field-row">
      <input type="password" id="diag-pwd" placeholder="Пароль доступа / Password" autocomplete="current-password" autofocus required>
      <button type="button" id="toggle-vis" title="Показать или скрыть пароль">Показать</button>
    </div>
    <button type="submit" class="btn-submit" id="submit-btn">Войти в веб-панель</button>
    <div class="err" id="login-err"></div>
  </form>
<script>
(function() {
  const pwdInput = document.getElementById('diag-pwd');
  const toggleBtn = document.getElementById('toggle-vis');
  const form = document.getElementById('login-form');
  const errBox = document.getElementById('login-err');
  const submitBtn = document.getElementById('submit-btn');

  toggleBtn.addEventListener('click', function() {
    const show = pwdInput.type === 'password';
    pwdInput.type = show ? 'text' : 'password';
    toggleBtn.textContent = show ? 'Скрыть' : 'Показать';
  });

  form.addEventListener('submit', async function(ev) {
    ev.preventDefault();
    errBox.style.display = 'none';
    submitBtn.disabled = true;
    try {
      const r = await fetch('/api/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Diag-CSRF': '1'},
        credentials: 'same-origin',
        body: JSON.stringify({password: pwdInput.value || ''})
      });
      const data = await r.json().catch(() => ({}));
      if (r.ok && data.ok) {
        window.location.replace('/');
        return;
      }
      errBox.textContent = data.error || 'Неверный пароль доступа (Invalid password)';
      errBox.style.display = 'block';
      pwdInput.select();
    } catch (e) {
      errBox.textContent = 'Ошибка соединения: ' + e.message;
      errBox.style.display = 'block';
    } finally {
      submitBtn.disabled = false;
    }
  });
})();
</script>
</body>
</html>
"""


def tail_file(path: str, max_lines: int = 250) -> str:
    if not os.path.isfile(path):
        return ""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            chunk = min(size, 256 * 1024)
            f.seek(max(0, size - chunk), os.SEEK_SET)
            data = f.read().decode("utf-8", errors="replace")
        lines = data.splitlines()
        return "\n".join(lines[-max_lines:])
    except OSError:
        return ""


class DiagWebServer:
    """Embedded multi-threaded HTTP server serving the Diagnostic Single-Page
    WebUI and JSON API. Strictly OFF by default until enabled by the user."""

    def __init__(
        self,
        base_dir: str,
        tc: TincControl,
        collector: TelemetryCollector,
        prober: ActiveProber,
        app_fn: Callable[[], yaml_config.AppConfig],
        runtime: Any,
        action_handler: Callable[[str, str, dict[str, Any]], tuple[bool, str, dict[str, Any]]] | None = None,
        on_config_changed: Callable[[str, str], None] | None = None,
        on_lifecycle: Callable[[str, str, bool], None] | None = None,
    ) -> None:
        self.base_dir = base_dir
        self.tc = tc
        self.collector = collector
        self.prober = prober
        if getattr(self.prober, "collector", None) is None:
            self.prober.collector = collector
        self.app_fn = app_fn
        self.runtime = runtime
        self.action_handler = action_handler
        self.on_config_changed = on_config_changed
        self.on_lifecycle = on_lifecycle
        self._lock = threading.Lock()
        self._refresh_locks: dict[str, threading.Lock] = {}
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._closing_thread: threading.Thread | None = None
        self._port: int = DEFAULT_DIAG_PORT
        self._enabled: bool = False
        self._sessions: dict[str, float] = {}
        self._login_attempts: dict[str, tuple[int, float]] = {}
        self._config_baseline: dict[str, Any] | None = None
        self._fallback_password: str = _generate_diag_password(16)
        if self.base_dir:
            ensure_diag_password(self.base_dir)

    def get_password(self) -> str:
        if self.base_dir:
            return ensure_diag_password(self.base_dir)
        return self._fallback_password

    def _check_login_backoff(self, client_ip: str) -> int:
        """Return seconds remaining in login rate-limit lockout for `client_ip` (0 if allowed)."""
        now = time.monotonic()
        with self._lock:
            entry = self._login_attempts.get(client_ip)
            if not entry:
                return 0
            _fails, blocked_until = entry
            if blocked_until <= now:
                return 0
            return max(1, int(math.ceil(blocked_until - now)))

    def _record_login_result(self, client_ip: str, ok: bool) -> int:
        """Update failed-login counter for `client_ip`; return lockout seconds (>0 when 429)."""
        now = time.monotonic()
        with self._lock:
            if ok:
                self._login_attempts.pop(client_ip, None)
                return 0
            if len(self._login_attempts) >= 256 and client_ip not in self._login_attempts:
                oldest_ip = min(self._login_attempts, key=lambda k: self._login_attempts[k][1])
                self._login_attempts.pop(oldest_ip, None)
            prev_fails, _ = self._login_attempts.get(client_ip, (0, 0.0))
            fails = prev_fails + 1
            if fails >= LOGIN_MAX_FAILURES:
                delay = min(LOGIN_MAX_LOCKOUT_SEC, float(2 ** min(fails - LOGIN_MAX_FAILURES, 10)))
                self._login_attempts[client_ip] = (fails, now + delay)
                return max(1, int(math.ceil(delay)))
            self._login_attempts[client_ip] = (fails, 0.0)
            return 0

    def _create_session(self) -> str:
        now = time.time()
        sid = secrets.token_hex(32)
        with self._lock:
            expired = [k for k, exp in self._sessions.items() if exp <= now]
            for k in expired:
                self._sessions.pop(k, None)
            while len(self._sessions) >= DIAG_SESSION_MAX:
                oldest = min(self._sessions, key=self._sessions.get)  # type: ignore[arg-type]
                self._sessions.pop(oldest, None)
            self._sessions[sid] = now + DIAG_SESSION_TTL
        return sid

    def _validate_session(self, sid: str) -> bool:
        if not sid or len(sid) != 64:
            return False
        now = time.time()
        with self._lock:
            for k, exp in list(self._sessions.items()):
                if exp <= now:
                    self._sessions.pop(k, None)
            for k in self._sessions:
                if hmac.compare_digest(k, sid):
                    return True
        return False

    def _revoke_session(self, sid: str) -> None:
        if not sid:
            return
        with self._lock:
            for k in list(self._sessions.keys()):
                if hmac.compare_digest(k, sid):
                    self._sessions.pop(k, None)

    def _allowed_hosts(self) -> set[str]:
        allowed: set[str] = {"127.0.0.1", "localhost", "::1"}
        app = self.app_fn()
        if app:
            for net_name, nc in app.networks.items():
                snap = self.collector.get_latest_snapshot(net_name)
                self_snap_node: Node | None = None
                if snap and not snap.error:
                    for n in snap.nodes.values():
                        if n.is_self:
                            self_snap_node = n
                            break
                host_txt = nc.hosts.get(nc.node_name, "") if (nc.node_name and nc.node_name in nc.hosts) else ""
                for ip in select_node_vpn_ips(nc.options, host_txt, self_snap_node):
                    allowed.add(ip.lower())
        return allowed

    def _notify_config_changed(self, net: str, action: str) -> None:
        cb = self.on_config_changed
        if cb is not None:
            try:
                cb(net, action)
            except Exception:
                pass

    def _notify_lifecycle(self, net: str, action: str, ok: bool) -> None:
        cb = self.on_lifecycle
        if cb is not None:
            try:
                cb(net, action, ok)
            except Exception:
                pass

    @property
    def enabled(self) -> bool:
        with self._lock:
            return self._enabled and self._httpd is not None

    @property
    def port(self) -> int:
        with self._lock:
            return self._port

    def start(self, port: int = DEFAULT_DIAG_PORT) -> tuple[bool, str]:
        port = max(1024, min(int(port), 65535))
        if self.base_dir:
            ensure_diag_password(self.base_dir)
        with self._lock:
            if self._httpd is not None and self._port == port and self._enabled:
                self.sync_tincd_bridge()
                return True, f"Diagnostic server already running on port {port}"
            closing = self._closing_thread
        if closing is not None and closing.is_alive():
            closing.join(timeout=2.0)
        self.stop(wait=True, persist=False)

        server_ref = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                pass  # do not spam stderr

            def _send_json(self, obj: Any, status: int = 200, headers: dict[str, str] | None = None) -> None:
                body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                if headers:
                    for k, v in headers.items():
                        self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def _send_html(self, html: str, status: int = 200, headers: dict[str, str] | None = None) -> None:
                body = html.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                if headers:
                    for k, v in headers.items():
                        self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def _validate_host(self) -> tuple[bool, set[str]]:
                host_hdr = (self.headers.get("Host") or "").strip()
                allowed = server_ref._allowed_hosts()
                if not host_hdr or "@" in host_hdr or "/" in host_hdr or "\\" in host_hdr:
                    self._send_json({"ok": False, "error": "Invalid Host header"}, status=403)
                    return False, allowed
                try:
                    split_h = urllib.parse.urlsplit(f"//{host_hdr}")
                    req_host = (split_h.hostname or "").lower()
                    req_port = split_h.port
                except ValueError:
                    req_host = ""
                    req_port = None
                if not req_host or req_host not in allowed or req_port != server_ref.port:
                    self._send_json({"ok": False, "error": "Invalid Host header"}, status=403)
                    return False, allowed
                return True, allowed

            def _extract_session_cookie(self) -> str:
                raw_cookie = self.headers.get("Cookie") or ""
                if not raw_cookie:
                    return ""
                try:
                    jar = http.cookies.SimpleCookie()
                    jar.load(raw_cookie)
                    if DIAG_SESSION_COOKIE in jar:
                        return jar[DIAG_SESSION_COOKIE].value.strip()
                except Exception:
                    pass
                for part in raw_cookie.split(";"):
                    k, sep, v = part.strip().partition("=")
                    if sep and k.strip() == DIAG_SESSION_COOKIE:
                        return v.strip()
                return ""

            def _check_auth(self) -> tuple[bool, str]:
                expected = server_ref.get_password()
                if not expected:
                    return False, ""
                expected_b = expected.encode("utf-8")

                x_pwd = self.headers.get("X-Diag-Password")
                if x_pwd is not None:
                    if hmac.compare_digest(x_pwd.encode("utf-8"), expected_b):
                        return True, "header"
                    return False, ""

                auth_hdr = (self.headers.get("Authorization") or "").strip()
                if auth_hdr:
                    scheme, _, rest = auth_hdr.partition(" ")
                    scheme_low = scheme.lower()
                    rest = rest.strip()
                    if scheme_low == "bearer" and rest:
                        if hmac.compare_digest(rest.encode("utf-8"), expected_b):
                            return True, "header"
                        return False, ""
                    if scheme_low == "basic" and rest:
                        try:
                            decoded = base64.b64decode(rest, validate=False).decode("utf-8", errors="replace")
                            _user, sep, pw = decoded.partition(":")
                            cand = pw if sep else decoded
                            if hmac.compare_digest(cand.encode("utf-8"), expected_b):
                                return True, "header"
                        except Exception:
                            pass
                        return False, ""
                    return False, ""

                sid = self._extract_session_cookie()
                if sid and server_ref._validate_session(sid):
                    return True, "cookie"
                return False, ""

            def do_GET(self) -> None:
                ok_host, _ = self._validate_host()
                if not ok_host:
                    return
                parsed = urllib.parse.urlparse(self.path)
                authed, _ = self._check_auth()

                if parsed.path in ("/", "/index.html", "/login"):
                    if not authed:
                        self._send_html(DIAG_LOGIN_HTML)
                        return
                    self._send_html(DIAG_WEBUI_HTML)
                    return

                if not authed:
                    self._send_json(
                        {"ok": False, "auth_required": True, "error": "Authentication required"},
                        status=401,
                    )
                    return

                qs = urllib.parse.parse_qs(parsed.query)
                net = (qs.get("net", [""])[0] or "").strip()
                if net and not is_valid_net_name(net, server_ref.app_fn()):
                    self._send_json({"ok": False, "error": "Invalid network name"}, status=400)
                    return

                try:
                    if parsed.path == "/api/overview":
                        self._send_json(server_ref.build_overview(net))
                        return
                    if parsed.path == "/api/logs":
                        lines = max(1, min(int(qs.get("lines", ["250"])[0] or 250), 5000))
                        source = (qs.get("source", ["tincd"])[0] or "tincd").strip()
                        self._send_json(server_ref.build_logs(net, source=source, lines=lines))
                        return
                    if parsed.path == "/api/config":
                        self._send_json(server_ref.build_config(net))
                        return
                    if parsed.path == "/api/export":
                        bundle = server_ref.build_export_bundle(net)
                        safe_net = net if (net and is_valid_net_name(net)) else "all"
                        fname = f"tincstack-diag-{safe_net}-{int(time.time())}.json"
                        self._send_json(
                            bundle,
                            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
                        )
                        return
                except ValueError as e:
                    self._send_json({"ok": False, "error": str(e)}, status=400)
                    return
                self._send_json({"ok": False, "error": "Not found"}, status=404)

            def do_POST(self) -> None:
                ok_host, allowed_hosts = self._validate_host()
                if not ok_host:
                    return
                parsed = urllib.parse.urlparse(self.path)

                csrf_val = (self.headers.get(DIAG_CSRF_HEADER) or "").strip()
                if csrf_val != "1":
                    self._send_json(
                        {"ok": False, "error": f"Missing or invalid {DIAG_CSRF_HEADER} header"},
                        status=403,
                    )
                    return

                origin = (self.headers.get("Origin") or "").strip()
                referer = (self.headers.get("Referer") or "").strip()
                if origin:
                    if origin.lower() == "null":
                        self._send_json({"ok": False, "error": "Cross-origin POST rejected"}, status=403)
                        return
                    try:
                        parsed_orig = urllib.parse.urlparse(origin)
                        o_scheme = (parsed_orig.scheme or "").lower()
                        o_host = (parsed_orig.hostname or "").lower()
                        o_port = parsed_orig.port
                    except Exception:
                        o_scheme, o_host, o_port = "", "", None
                    if (
                        o_scheme not in ("http", "https")
                        or not o_host
                        or o_host not in allowed_hosts
                        or o_port != server_ref.port
                    ):
                        self._send_json({"ok": False, "error": "Cross-origin POST rejected"}, status=403)
                        return
                elif referer:
                    try:
                        parsed_ref = urllib.parse.urlparse(referer)
                        r_scheme = (parsed_ref.scheme or "").lower()
                        r_host = (parsed_ref.hostname or "").lower()
                        r_port = parsed_ref.port
                    except Exception:
                        r_scheme, r_host, r_port = "", "", None
                    if (
                        r_scheme not in ("http", "https")
                        or not r_host
                        or r_host not in allowed_hosts
                        or r_port != server_ref.port
                    ):
                        self._send_json({"ok": False, "error": "Cross-origin POST rejected"}, status=403)
                        return

                authed, auth_mode = self._check_auth()
                try:
                    length = int(self.headers.get("Content-Length", "0") or 0)
                except ValueError:
                    length = 0
                if length > 4 * 1024 * 1024:
                    self._send_json({"ok": False, "error": "Payload too large"}, status=413)
                    return
                raw = self.rfile.read(length) if length > 0 else b"{}"
                try:
                    payload = json.loads(raw.decode("utf-8", errors="replace"))
                    if not isinstance(payload, dict):
                        payload = {}
                except Exception:
                    payload = {}

                if parsed.path == "/api/login":
                    client_ip = str(self.client_address[0]) if self.client_address else "local"
                    wait_s = server_ref._check_login_backoff(client_ip)
                    if wait_s > 0:
                        self._send_json(
                            {
                                "ok": False,
                                "auth_required": True,
                                "error": f"Too many failed login attempts. Retry in {wait_s}s.",
                            },
                            status=429,
                            headers={"Retry-After": str(wait_s)},
                        )
                        return
                    provided = str(payload.get("password") or "")
                    expected = server_ref.get_password()
                    is_ok = bool(expected and hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8")))
                    lockout_s = server_ref._record_login_result(client_ip, is_ok)
                    if is_ok:
                        sid = server_ref._create_session()
                        cookie = f"{DIAG_SESSION_COOKIE}={sid}; HttpOnly; SameSite=Strict; Path=/"
                        self._send_json({"ok": True, "message": "Authenticated"}, headers={"Set-Cookie": cookie})
                    elif lockout_s > 0:
                        self._send_json(
                            {
                                "ok": False,
                                "auth_required": True,
                                "error": f"Too many failed login attempts. Retry in {lockout_s}s.",
                            },
                            status=429,
                            headers={"Retry-After": str(lockout_s)},
                        )
                    else:
                        self._send_json(
                            {"ok": False, "auth_required": True, "error": "Invalid password"},
                            status=401,
                        )
                    return

                if not authed:
                    self._send_json(
                        {"ok": False, "auth_required": True, "error": "Authentication required"},
                        status=401,
                    )
                    return

                if not origin and auth_mode != "header":
                    self._send_json(
                        {"ok": False, "error": "Missing Origin header on cookie-authenticated POST"},
                        status=403,
                    )
                    return

                if parsed.path == "/api/logout":
                    sid = self._extract_session_cookie()
                    server_ref._revoke_session(sid)
                    cookie = f"{DIAG_SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
                    self._send_json({"ok": True}, headers={"Set-Cookie": cookie})
                    return

                net = str(payload.get("net") or "").strip()
                if net and not is_valid_net_name(net, server_ref.app_fn()):
                    self._send_json({"ok": False, "error": "Invalid network name"}, status=400)
                    return

                if parsed.path == "/api/mark":
                    note = str(payload.get("note") or "")
                    target_net = net or server_ref._default_net()
                    if not target_net or not is_valid_net_name(target_net, server_ref.app_fn()):
                        self._send_json({"ok": False, "error": "No valid network configured"}, status=400)
                        return
                    ev = server_ref.collector.record_user_mark(target_net, note)
                    self._send_json({"ok": True, "message": "Метка затупа сохранена", "event": ev.to_dict()})
                    return

                if parsed.path == "/api/probe":
                    target_net = net or server_ref._default_net()
                    if target_net and not is_valid_net_name(target_net, server_ref.app_fn()):
                        self._send_json({"ok": False, "error": "Invalid network name"}, status=400)
                        return
                    tool = str(payload.get("tool") or payload.get("kind") or "").strip()
                    res = server_ref.prober.run_probe(target_net, tool, payload)
                    self._send_json(res)
                    return

                if parsed.path == "/api/action":
                    target_net = net or server_ref._default_net()
                    if target_net and not is_valid_net_name(target_net, server_ref.app_fn()):
                        self._send_json({"ok": False, "error": "Invalid network name"}, status=400)
                        return
                    action = str(payload.get("action") or "").strip()
                    try:
                        ok, msg, extra = server_ref.handle_action(target_net, action, payload)
                    except WebUISecurityError as e:
                        self._send_json({"ok": False, "error": str(e)}, status=403)
                        return
                    except ValueError as e:
                        self._send_json({"ok": False, "error": str(e)}, status=400)
                        return
                    extra_copy = dict(extra or {})
                    status_code = int(extra_copy.pop("_http_status", 200 if ok else 400))
                    resp = {"ok": ok, "message": msg}
                    if not ok:
                        resp.setdefault("error", msg)
                    resp.update(extra_copy)
                    self._send_json(resp, status=status_code)
                    return

                self._send_json({"ok": False, "error": "Not found"}, status=404)

        try:
            httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
            httpd.daemon_threads = True
        except OSError as e:
            return False, f"Could not bind port {port}: {e}"

        t = threading.Thread(
            target=httpd.serve_forever,
            kwargs={"poll_interval": 0.1},
            name=f"diag-http-{port}",
            daemon=True,
        )
        t.start()
        with self._lock:
            self._httpd = httpd
            self._thread = t
            self._port = port
            self._enabled = True
        if self.base_dir:
            with _active_servers_lock:
                _active_servers[os.path.normcase(os.path.abspath(self.base_dir))] = self
        save_diag_settings(self.base_dir, True, port)
        self.sync_tincd_bridge()
        return True, f"Diagnostic Web Server listening on port {port}"

    def stop(self, wait: bool = True, persist: bool = True) -> tuple[bool, str]:
        with self._lock:
            httpd = self._httpd
            self._httpd = None
            self._thread = None
            self._enabled = False
            port = self._port
            prev_closing = self._closing_thread
        if self.base_dir:
            key = os.path.normcase(os.path.abspath(self.base_dir))
            with _active_servers_lock:
                if _active_servers.get(key) is self:
                    _active_servers.pop(key, None)
        if persist:
            save_diag_settings(self.base_dir, False, port)
        self.sync_tincd_bridge()
        if httpd is not None:
            def _shutdown_server() -> None:
                try:
                    httpd.shutdown()
                    httpd.server_close()
                except Exception:
                    pass

            if wait:
                if prev_closing is not None and prev_closing.is_alive():
                    prev_closing.join(timeout=2.0)
                _shutdown_server()
            else:
                ct = threading.Thread(target=_shutdown_server, name="diag-http-stop", daemon=True)
                with self._lock:
                    self._closing_thread = ct
                ct.start()
        elif wait and prev_closing is not None and prev_closing.is_alive():
            prev_closing.join(timeout=2.0)
        return True, "Diagnostic Web Server stopped"

    def sync_tincd_bridge(self, specific_net: str | None = None, async_mode: bool = True) -> None:
        """Register or unregister the diagnostic bridge port with running tincd daemons."""
        active_port = self._port if self.enabled else 0
        app = self.app_fn()
        if not app:
            return
        nets = [specific_net] if specific_net else list(app.networks)

        def _do_sync() -> None:
            for attempt in range(6 if async_mode else 1):
                all_ok = True
                for net in nets:
                    if not net:
                        continue
                    try:
                        ok_bridge, _ = self.tc.diag_port(net, active_port, timeout=2.5)
                        if not ok_bridge and active_port > 0:
                            all_ok = False
                    except Exception:
                        if active_port > 0:
                            all_ok = False
                if all_ok:
                    break
                if async_mode and attempt < 5:
                    time.sleep(1.0)

        if async_mode:
            threading.Thread(target=_do_sync, name="diag-bridge-sync", daemon=True).start()
        else:
            _do_sync()

    def _net_refresh_lock(self, net: str) -> threading.Lock:
        with self._lock:
            lk = self._refresh_locks.get(net)
            if lk is None:
                lk = threading.Lock()
                self._refresh_locks[net] = lk
            return lk

    def _get_or_refresh_snapshot(self, net: str, max_age: float = 2.0) -> NetworkSnapshot | None:
        snap, age = self.collector.get_latest_snapshot_with_age(net)
        if snap is not None and age < max_age:
            return snap
        lk = self._net_refresh_lock(net)
        if snap is None:
            if lk.acquire(blocking=False):
                try:
                    s = self.tc.snapshot(net)
                    self.collector.record_snapshot(net, s)
                    return s
                finally:
                    lk.release()
            return self.collector.get_latest_snapshot(net)

        # Cached snapshot exists but is older than max_age: trigger a single-flight
        # background refresh and return the cached snapshot immediately (0 ms).
        if lk.acquire(blocking=False):
            def _bg() -> None:
                try:
                    s = self.tc.snapshot(net)
                    self.collector.record_snapshot(net, s)
                except Exception:
                    pass
                finally:
                    lk.release()
            threading.Thread(target=_bg, name=f"diag-snap-{net}", daemon=True).start()
        return snap

    def _default_net(self) -> str:
        app = self.app_fn()
        if not app or not app.networks:
            return ""
        return next(iter(app.networks))

    def get_vpn_urls(self) -> list[str]:
        """Return the list of reachable http://<vpn-ip>:<port>/ URLs for this client."""
        port = self.port
        urls: list[str] = []
        app = self.app_fn()
        if app:
            for net, nc in app.networks.items():
                snap = self.collector.get_latest_snapshot(net)
                self_snap_node: Node | None = None
                if snap and not snap.error:
                    for n in snap.nodes.values():
                        if n.is_self:
                            self_snap_node = n
                            break
                host_txt = nc.hosts.get(nc.node_name, "") if (nc.node_name and nc.node_name in nc.hosts) else ""
                for ip in select_node_vpn_ips(nc.options, host_txt, self_snap_node):
                    u = f"http://[{ip}]:{port}/" if ":" in ip else f"http://{ip}:{port}/"
                    if u not in urls:
                        urls.append(u)
        urls.append(f"http://127.0.0.1:{port}/")
        return urls

    def build_overview(self, net: str = "") -> dict[str, Any]:
        app = self.app_fn()
        if net and not is_valid_net_name(net, app):
            raise ValueError(f"Invalid network name: {net!r}")
        nets = list(app.networks) if app else []
        target_net = net if (net and net in nets) else (nets[0] if nets else "")
        if target_net and not is_valid_net_name(target_net):
            target_net = ""
        snap: NetworkSnapshot | None = None
        if target_net:
            snap = self._get_or_refresh_snapshot(target_net, max_age=2.0)

        nc = app.net(target_net) if (app and target_net) else None
        peer_configs: dict[str, Any] = {}
        if nc:
            for hname, hbody in nc.hosts.items():
                peer_configs[hname] = parse_host_endpoints(hbody)

        nodes_list: list[dict[str, Any]] = []
        my_vpn_ip = ""
        self_node = nc.node_name if nc else ""
        self_snap_node: Node | None = None
        total_rx = 0
        total_tx = 0
        if snap and not snap.error:
            for n in sorted(snap.nodes.values(), key=lambda x: (not x.is_self, x.name)):
                if n.is_self:
                    self_node = n.name
                    self_snap_node = n
                else:
                    total_rx += n.rx_bytes
                    total_tx += n.tx_bytes
                pcfg = peer_configs.get(n.name, {})
                sdict = n.status if n.status else decode_status(n.status_hex)
                is_nd = bool(
                    n.no_direct
                    or sdict.get("no_direct")
                    or (nc and transports.is_peer_no_direct(nc.options, nc.hosts.get(n.name, ""), n.name))
                )
                node_vpn = select_primary_vpn_ip(
                    nc.options if (nc and n.is_self) else None,
                    nc.hosts.get(n.name, "") if nc else "",
                    n,
                )
                diag_url = (
                    f"http://[{node_vpn}]:{self.port}/"
                    if (node_vpn and ":" in node_vpn)
                    else (f"http://{node_vpn}:{self.port}/" if node_vpn else "")
                )
                nodes_list.append({
                    "name": n.name,
                    "is_self": n.is_self,
                    "reachable": n.reachable,
                    "no_direct": is_nd,
                    "link": n.link,
                    "transport": n.transport,
                    "preferred_transport": pcfg.get("preferred_transport", "auto"),
                    "supported_transports": n.supported_transports,
                    "nexthop": n.nexthop,
                    "via": n.via,
                    "distance": n.distance,
                    "rtt": round(n.rtt, 1),
                    "pmtu": n.pmtu,
                    "pmtu_min": n.pmtu_min,
                    "pmtu_max": n.pmtu_max,
                    "rx_bytes": n.rx_bytes,
                    "tx_bytes": n.tx_bytes,
                    "rx_packets": n.rx_packets,
                    "tx_packets": n.tx_packets,
                    "address": n.address,
                    "configured_address": pcfg.get("configured_address", ""),
                    "port": n.port,
                    "vpn_address": node_vpn,
                    "subnets": n.subnets,
                    "routable_subnets": [s for s in n.subnets if routes.routable(s)],
                    "default_subnets": [s for s in n.subnets if routes.is_full_tunnel(s)],
                    "status_hex": f"0x{n.status_hex}",
                    "status": sdict,
                    "options_hex": f"0x{n.options}",
                    "has_host_block": bool(nc and n.name in nc.hosts),
                    "web_diag_url": diag_url,
                })

        my_vpn_ip = select_primary_vpn_ip(
            nc.options if nc else None,
            nc.hosts.get(self_node, "") if (nc and self_node) else "",
            self_snap_node,
        )

        active_routes: list[str] = []
        if nc:
            raw_ir = nc.options.get("InterfaceRoute")
            if isinstance(raw_ir, list):
                active_routes = [str(x) for x in raw_ir]
            elif isinstance(raw_ir, str) and raw_ir.strip():
                active_routes = [raw_ir.strip()]

        ft_exit = nc.full_tunnel if nc else ""
        ft_state = self.runtime.full_tunnel_state(target_net) if (self.runtime and target_net) else ""
        series = self.collector.get_series(target_net, max_points=600) if target_net else []
        last_pt = series[-1] if series else {"rx_bps": 0.0, "tx_bps": 0.0}
        ver = management.current_version() or "dev"

        c_path = crash_log_path(self.base_dir)
        has_crashes = bool(c_path and os.path.isfile(c_path) and os.path.getsize(c_path) > 0)

        return {
            "ok": True,
            "platform": "windows" if sys.platform == "win32" else sys.platform,
            "version": ver,
            "hostname": socket.gethostname(),
            "pid": os.getpid(),
            "diag_port": self.port,
            "networks": nets,
            "net": target_net,
            "current_net": target_net,
            "running": bool(snap and not snap.error),
            "error": snap.error if snap else "No network selected",
            "self_node": self_node,
            "self_vpn_ip": my_vpn_ip,
            "my_vpn_ip": my_vpn_ip,
            "has_crashes": has_crashes,
            "current_bw": {
                "rx_bps": last_pt.get("rx_bps", 0.0),
                "tx_bps": last_pt.get("tx_bps", 0.0),
                "total_rx": total_rx,
                "total_tx": total_tx,
            },
            "full_tunnel": ft_exit,
            "full_tunnel_info": {"exit_node": ft_exit, "state": ft_state},
            "os_summary": f"MTU: {(nc.wintun_mtu or 1400) if nc else 1400} · Routes: {len(active_routes)}" + (f" · FT: {ft_state}" if ft_state else ""),
            "system_info": {
                "OS": f"{platform.system()} {platform.release()}",
                "Hostname": socket.gethostname(),
                "Version": ver,
                "Elevated (Admin)": str(management.is_admin()),
                "Config Path": app.path if app else "",
                "Wintun MTU": str((nc.wintun_mtu or 1400) if nc else 1400),
                "Full Tunnel": f"{ft_exit} ({ft_state})" if ft_exit else "off",
                "Diag Bridge Port": str(self.port),
                "Crash Log": f"present ({os.path.getsize(c_path)} B)" if has_crashes else "clean",
            },
            "active_routes": active_routes,
            "nodes": nodes_list,
            "edges": [asdict(e) for e in (snap.edges if snap else [])],
            "connections": dict(snap.connections) if snap else {},
            "history": series,
            "series": series,
            "incidents": self.collector.get_incidents(target_net, limit=150) if target_net else [],
        }

    def build_logs(self, net: str = "", source: str = "tincd", lines: int = 250) -> dict[str, Any]:
        app = self.app_fn()
        if net and not is_valid_net_name(net, app):
            raise ValueError(f"Invalid network name: {net!r}")
        target_net = net or self._default_net()
        if target_net and not is_valid_net_name(target_net, app):
            target_net = ""
        tincd_log = os.path.join(self.base_dir, f"{target_net}-tincd.log") if target_net else ""
        global_mgr_log = app_log_path(self.base_dir)
        net_mgr_log = os.path.join(self.base_dir, f"{target_net}-tincmgr.log") if target_net else ""
        crash_log = crash_log_path(self.base_dir)
        ev_log = os.path.join(self.base_dir, f"{target_net}-diag-events.jsonl") if target_net else ""

        t_text = tail_file(tincd_log, max_lines=lines)
        m_global = tail_file(global_mgr_log, max_lines=lines)
        m_net = tail_file(net_mgr_log, max_lines=lines) if net_mgr_log else ""
        m_text = "\n".join(x for x in (m_net, m_global) if x).strip()
        c_text = tail_file(crash_log, max_lines=lines)
        e_text = tail_file(ev_log, max_lines=lines)

        if source == "tincd":
            selected = t_text
        elif source == "crash":
            selected = c_text or "(Сбоев и стектрейсов не зафиксировано — tincmgr-crash.log пуст)"
        elif source == "events":
            selected = e_text
        else:
            selected = m_text

        return {
            "ok": True,
            "net": target_net,
            "source": source,
            "text": selected,
            "tincd_log": t_text,
            "tincmgr_log": m_text,
            "crash_log": c_text,
            "has_crashes": bool(c_text.strip()),
        }

    def build_config(self, net: str = "") -> dict[str, Any]:
        app = self.app_fn()
        if net and not is_valid_net_name(net, app):
            raise ValueError(f"Invalid network name: {net!r}")
        target_net = net or self._default_net()
        if target_net and not is_valid_net_name(target_net, app):
            target_net = ""
        raw_yaml = ""
        with yaml_config._MEM_LOCK:
            nc = app.net(target_net) if (app and target_net) else None
            if app and app.path and os.path.isfile(app.path):
                try:
                    doc = yaml_config.read_document(app.path)
                    self._config_baseline = copy.deepcopy(doc)
                    raw_yaml = yaml_config.dump_text(redact_yaml_document(doc))
                except (yaml_config.ConfigError, OSError):
                    raw_yaml = ""
            elif app:
                doc = yaml_config.to_dict(app)
                self._config_baseline = copy.deepcopy(doc)
                raw_yaml = yaml_config.dump_text(redact_yaml_document(doc))
            tr_val = nc.options.get("Transports", "") if nc else ""
            pref_val = nc.options.get("PreferredTransports", "") if nc else ""
            if isinstance(tr_val, list):
                tr_val = ", ".join(str(x) for x in tr_val)
            if isinstance(pref_val, list):
                pref_val = ", ".join(str(x) for x in pref_val)
            safe_opts = redact_options_dict(nc.options) if nc else {}
            hosts_copy = {hk: redact_host_text(hv) for hk, hv in nc.hosts.items()} if nc else {}
            autostart = nc.autostart if nc else False
            wintun_mtu = (nc.wintun_mtu or 1400) if nc else 1400
            full_tunnel = nc.full_tunnel if nc else ""
        return {
            "ok": True,
            "net": target_net,
            "autostart": autostart,
            "wintun_mtu": wintun_mtu,
            "full_tunnel": full_tunnel,
            "transports": str(tr_val),
            "preferred_transports": str(pref_val),
            "options": safe_opts,
            "options_conf": yaml_config.options_to_conf(safe_opts) if nc else "",
            "hosts": hosts_copy,
            "raw_yaml": raw_yaml,
        }

    def build_export_bundle(self, net: str = "") -> dict[str, Any]:
        app = self.app_fn()
        if net and not is_valid_net_name(net, app):
            raise ValueError(f"Invalid network name: {net!r}")
        target_net = net or self._default_net()
        if target_net and not is_valid_net_name(target_net, app):
            target_net = ""
        cfg = self.build_config(target_net)
        # Scrub private keys and tokens from export bundle for safety
        cfg.pop("raw_yaml", None)
        cfg["options"] = redact_options_dict(dict(cfg.get("options") or {}))
        cfg["options_conf"] = yaml_config.options_to_conf(cfg["options"]) if cfg["options"] else ""
        cfg["hosts"] = {
            hk: redact_host_text(str(hv))
            for hk, hv in (cfg.get("hosts") or {}).items()
        }
        return {
            "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "overview": self.build_overview(target_net),
            "logs": self.build_logs(target_net, lines=500),
            "config": cfg,
            "dns_cache": self.prober.run_probe(target_net, "dns", {}),
            "os_routes": self.prober.run_probe(target_net, "routes", {}),
        }

    def _other_full_tunnel_net(self, app: yaml_config.AppConfig, target_net: str) -> str:
        if self.runtime and hasattr(self.runtime, "active_full_tunnel_net"):
            active = self.runtime.active_full_tunnel_net(exclude=target_net)
            if active:
                return active
        for nname, onc in app.networks.items():
            if nname != target_net and onc.full_tunnel:
                return nname
        return ""

    def _atomic_mutate(self, app: yaml_config.AppConfig, mutator: Callable[[yaml_config.AppConfig, dict], Any]) -> Any:
        res = yaml_config.atomic_update(app, mutator, baseline_doc=self._config_baseline)
        with yaml_config._MEM_LOCK:
            self._config_baseline = copy.deepcopy(app.baseline)
        return res

    def handle_action(self, net: str, action: str, payload: dict[str, Any]) -> tuple[bool, str, dict[str, Any]]:
        if self.action_handler is not None:
            return self.action_handler(net, action, payload)
        return self.default_action_handler(net, action, payload)

    def default_action_handler(self, net: str, action: str, payload: dict[str, Any]) -> tuple[bool, str, dict[str, Any]]:
        app = self.app_fn()
        if net and not is_valid_net_name(net, app):
            return False, f"Invalid network: {net}", {}
        nc = app.net(net) if (app and net) else None

        if action == "daemon":
            op = str(payload.get("op") or "").strip()
            if op in ("start", "stop", "restart", "reload", "debug"):
                action = op

        if action == "start" and self.runtime:
            ok, msg = self.runtime.start(net)
            self.sync_tincd_bridge(net)
            self._notify_lifecycle(net, "start", ok)
            if ok:
                self._notify_config_changed(net, "start")
            return ok, msg, {}
        if action == "stop" and self.runtime:
            ok, msg = self.runtime.stop(net)
            self._notify_lifecycle(net, "stop", ok)
            return ok, msg, {}
        if action == "restart" and self.runtime:
            ok, msg = self.runtime.restart(net)
            self.sync_tincd_bridge(net)
            self._notify_lifecycle(net, "restart", ok)
            if ok:
                self._notify_config_changed(net, "restart")
            return ok, msg, {}
        if action == "reload":
            res = self.tc.reload(net)
            return res.ok, (res.stdout + res.stderr).strip() or "reloaded", {}
        if action == "retry":
            res = self.tc.retry(net)
            return res.ok, (res.stdout + res.stderr).strip() or "retry triggered", {}
        if action == "purge":
            res = self.tc.purge(net)
            return res.ok, (res.stdout + res.stderr).strip() or "purged unreachable nodes", {}
        if action == "debug":
            level = int(payload.get("level") or 0)
            res = self.tc.set_debug(net, level)
            return res.ok, (res.stdout + res.stderr).strip() or f"debug level set to {level}", {}
        if action == "clear_incidents":
            if not is_valid_net_name(net, app):
                return False, "Invalid network name", {}
            self.collector.clear_incidents(net)
            return True, "Журнал инцидентов очищен", {}
        if action == "clear_crash_log":
            clear_crash_log(self.base_dir)
            log_app_event("Crash log cleared via Diagnostic WebUI", base_dir=self.base_dir)
            return True, "Журнал стектрейсов и сбоев очищен", {}
        if action == "peer_info":
            peer = str(payload.get("peer") or "").strip()
            res = self.tc.info(net, peer)
            out = (res.stdout + "\n" + res.stderr).strip()
            return res.ok, out or "no info", {"output": out}
        if action in ("reconnect_peer", "peer_reconnect"):
            peer = str(payload.get("peer") or "").strip()
            if not peer:
                return False, "Missing peer name", {}
            res = self.tc.switch_peer_transport(net, peer)
            return res.ok, f"Reconnected {peer}", {}
        if action in ("switch_transport", "peer_transport"):
            peer = str(payload.get("peer") or "").strip()
            carrier = str(payload.get("carrier") or payload.get("transport") or "auto").strip()
            if not nc or not peer:
                return False, "Invalid network or peer", {}

            def _mut_transport(cur_app: yaml_config.AppConfig, _disk: dict) -> None:
                cur_nc = cur_app.net(net)
                if not cur_nc:
                    raise ValueError("Network not found")
                cur_nc.hosts[peer] = transports.set_host_preferred_transport(cur_nc.hosts.get(peer, ""), carrier)
                if (carrier != "auto"
                        and not transports.is_peer_no_direct(cur_nc.options, cur_nc.hosts.get(peer, ""), peer)
                        and re.search(r"^[ \t]*Address[ \t]*=", cur_nc.hosts[peer], re.I | re.M)):
                    ct_list = transports.parse_node_list(cur_nc.options.get("ConnectTo"))
                    if peer not in ct_list:
                        ct_list.append(peer)
                    cur_nc.options["ConnectTo"] = ct_list[0] if len(ct_list) == 1 else ct_list

            try:
                self._atomic_mutate(app, _mut_transport)
            except (ValueError, yaml_config.ConfigError) as e:
                return False, str(e), {}
            self._notify_config_changed(net, action)
            res = self.tc.switch_peer_transport(net, peer)
            self.collector.add_incident(
                net=net, kind="USER_ACTION", severity="info", peer=peer,
                summary=f"Switched preferred transport for '{peer}' to '{carrier}' via Diagnostic WebUI",
            )
            return res.ok, f"Switched {peer} transport to {carrier}", {}
        if action in ("set_peer_direct", "toggle_no_direct"):
            peer = str(payload.get("peer") or "").strip()
            if not nc or not peer:
                return False, "Invalid network or peer", {}

            def _mut_direct(cur_app: yaml_config.AppConfig, _disk: dict) -> bool:
                cur_nc = cur_app.net(net)
                if not cur_nc:
                    raise ValueError("Network not found")
                if "no_direct" in payload:
                    nd_val = bool(payload.get("no_direct"))
                elif "direct" in payload:
                    nd_val = not bool(payload.get("direct"))
                else:
                    nd_val = not transports.is_peer_no_direct(cur_nc.options, cur_nc.hosts.get(peer, ""), peer)
                old_host = cur_nc.hosts.get(peer, "")
                new_host = transports.set_peer_no_direct(cur_nc.options, old_host, peer, nd_val)
                if peer in cur_nc.hosts or new_host:
                    cur_nc.hosts[peer] = new_host
                return nd_val

            try:
                no_direct = self._atomic_mutate(app, _mut_direct)
            except (ValueError, yaml_config.ConfigError) as e:
                return False, str(e), {}
            self._notify_config_changed(net, action)
            res = self.tc.reload(net)
            mode_str = "Relay only (no direct connect)" if no_direct else "Direct connect allowed"
            self.collector.add_incident(
                net=net, kind="USER_ACTION", severity="info", peer=peer,
                summary=f"Set '{peer}' direct connect policy to '{mode_str}' via Diagnostic WebUI",
            )
            return res.ok, f"{peer}: {mode_str}", {"no_direct": no_direct}
        if action == "toggle_route":
            if not nc:
                return False, "Network not found", {}
            subnet = str(payload.get("subnet") or "").strip()
            vpn_ip = str(payload.get("vpn_ip") or "").strip()
            enable = bool(payload.get("enable", True))

            def _mut_route(cur_app: yaml_config.AppConfig, _disk: dict) -> list[str]:
                cur_nc = cur_app.net(net)
                if not cur_nc:
                    raise ValueError("Network not found")
                if enable:
                    routes.add(cur_nc.options, subnet, vpn_ip)
                else:
                    routes.remove(cur_nc.options, subnet)
                return routes.adapter_aliases(cur_nc.options, net)

            try:
                alias = self._atomic_mutate(app, _mut_route)
            except (ValueError, yaml_config.ConfigError) as e:
                return False, str(e), {}
            self._notify_config_changed(net, action)
            if alias:
                if enable:
                    routes.apply_now(alias[0], subnet, vpn_ip)
                else:
                    routes.remove_now(alias[0], subnet)
            return True, f"Route {subnet} {'enabled' if enable else 'disabled'}", {}
        if action in ("toggle_full_tunnel", "full_tunnel"):
            if not nc:
                return False, "Network not found", {}
            peer = str(payload.get("peer") or "").strip()
            enable = bool(payload.get("enable", False))

            def _mut_ft(cur_app: yaml_config.AppConfig, _disk: dict) -> None:
                cur_nc = cur_app.net(net)
                if not cur_nc:
                    raise ValueError("Network not found")
                if enable and peer:
                    conflict = self._other_full_tunnel_net(cur_app, net)
                    if conflict:
                        raise ValueError(f"Full tunnel is already enabled on '{conflict}'")
                cur_nc.full_tunnel = peer if enable else ""

            try:
                self._atomic_mutate(app, _mut_ft)
            except (ValueError, yaml_config.ConfigError) as e:
                return False, str(e), {}
            self._notify_config_changed(net, action)
            msg = self.runtime.full_tunnel_sync(net) if self.runtime else "saved"
            return True, msg, {}
        if action in ("save_host", "peer_save_host"):
            if not nc:
                return False, "Network not found", {}
            host = str(payload.get("host") or payload.get("peer") or "").strip()
            content = str(payload.get("content") or payload.get("text") or "").rstrip("\n")
            if not host:
                return False, "Host name is empty", {}

            def _mut_save_host(cur_app: yaml_config.AppConfig, _disk: dict) -> None:
                cur_nc = cur_app.net(net)
                if not cur_nc:
                    raise ValueError("Network not found")
                restored_host = restore_redacted_host_text(content, cur_nc.hosts.get(host, ""))
                cur_nc.hosts[host] = restored_host
                blocked_list = [b for b in transports.parse_node_list(cur_nc.options.get("BlockedNodes")) if b != host]
                if blocked_list:
                    cur_nc.options["BlockedNodes"] = blocked_list
                else:
                    cur_nc.options.pop("BlockedNodes", None)

            try:
                self._atomic_mutate(app, _mut_save_host)
            except (ValueError, yaml_config.ConfigError) as e:
                return False, str(e), {}
            self._notify_config_changed(net, action)
            self.tc.reload(net)
            return True, f"Saved host '{host}'", {}
        if action == "delete_host":
            if not nc:
                return False, "Network not found", {}
            host = str(payload.get("host") or payload.get("peer") or "").strip()
            if not host:
                return False, "Host name is empty", {}

            def _mut_del_host(cur_app: yaml_config.AppConfig, _disk: dict) -> None:
                cur_nc = cur_app.net(net)
                if not cur_nc:
                    raise ValueError("Network not found")
                cur_nc.hosts.pop(host, None)
                ct_list = [c for c in transports.parse_node_list(cur_nc.options.get("ConnectTo")) if c != host]
                if ct_list:
                    cur_nc.options["ConnectTo"] = ct_list[0] if len(ct_list) == 1 else ct_list
                else:
                    cur_nc.options.pop("ConnectTo", None)
                blocked_list = transports.parse_node_list(cur_nc.options.get("BlockedNodes"))
                if host not in blocked_list:
                    blocked_list.append(host)
                cur_nc.options["BlockedNodes"] = blocked_list

            try:
                self._atomic_mutate(app, _mut_del_host)
            except (ValueError, yaml_config.ConfigError) as e:
                return False, str(e), {}
            self._notify_config_changed(net, action)
            self.tc.reload(net)
            return True, f"Deleted and blocked host '{host}'", {}
        if action == "save_settings":
            if not nc:
                return False, "Network not found", {}
            tr_str = str(payload.get("transports") or "").strip()
            pref_str = str(payload.get("preferred_transports") or "").strip()

            def _mut_settings(cur_app: yaml_config.AppConfig, _disk: dict) -> None:
                cur_nc = cur_app.net(net)
                if not cur_nc:
                    raise ValueError("Network not found")
                if "full_tunnel" in payload:
                    wanted_ft = str(payload.get("full_tunnel") or "").strip()
                    if wanted_ft:
                        conflict = self._other_full_tunnel_net(cur_app, net)
                        if conflict:
                            raise ValueError(f"Full tunnel is already enabled on '{conflict}'")
                cand_opts = copy.deepcopy(cur_nc.options)
                if tr_str:
                    cand_opts["Transports"] = transports.parse_carrier_list(tr_str)
                else:
                    cand_opts.pop("Transports", None)
                if pref_str:
                    cand_opts["PreferredTransports"] = transports.parse_carrier_list(pref_str)
                else:
                    cand_opts.pop("PreferredTransports", None)
                errs = transports.validate(cand_opts)
                if errs:
                    raise ValueError("; ".join(errs))
                cur_nc.options = cand_opts
                if "full_tunnel" in payload:
                    cur_nc.full_tunnel = str(payload.get("full_tunnel") or "").strip()

            try:
                self._atomic_mutate(app, _mut_settings)
            except (ValueError, yaml_config.ConfigError) as e:
                return False, str(e), {}
            self._notify_config_changed(net, action)
            self.tc.reload(net)
            if self.runtime:
                self.runtime.full_tunnel_sync(net)
            return True, "Настройки транспорта и маршрутизации сохранены", {}
        if action == "save_options":
            if not nc:
                return False, "Network not found", {}
            raw_opts_dict = payload.get("options")
            conf_text = str(payload.get("options_conf") or "")

            def _mut_options(cur_app: yaml_config.AppConfig, _disk: dict) -> None:
                cur_nc = cur_app.net(net)
                if not cur_nc:
                    raise ValueError("Network not found")
                parsed_opts = (
                    copy.deepcopy(raw_opts_dict)
                    if isinstance(raw_opts_dict, dict)
                    else yaml_config.conf_to_options(conf_text)
                )
                new_opts = _normalize_multi_options(parsed_opts)
                orig_ci = {str(k).lower(): v for k, v in cur_nc.options.items()}
                for ok, ov in list(new_opts.items()):
                    if _is_secret_option_name(str(ok)) and isinstance(ov, str) and ov.strip() == REDACTED_PLACEHOLDER:
                        if ok in cur_nc.options:
                            new_opts[ok] = copy.deepcopy(cur_nc.options[ok])
                        elif str(ok).lower() in orig_ci:
                            new_opts[ok] = copy.deepcopy(orig_ci[str(ok).lower()])
                        else:
                            new_opts.pop(ok, None)
                if _extract_forbidden_webui_opts(new_opts) != _extract_forbidden_webui_opts(cur_nc.options):
                    raise WebUISecurityError("Creating or modifying ScriptsInterpreter via WebUI is forbidden")
                errs = transports.validate(new_opts)
                if errs:
                    raise ValueError("; ".join(errs))
                cur_nc.options = new_opts
                if "autostart" in payload:
                    cur_nc.autostart = bool(payload["autostart"])
                if "wintun_mtu" in payload:
                    try:
                        cur_nc.wintun_mtu = int(payload["wintun_mtu"])
                    except ValueError:
                        pass

            try:
                self._atomic_mutate(app, _mut_options)
            except WebUISecurityError as e:
                return False, str(e), {"_http_status": 403}
            except (ValueError, yaml_config.ConfigError) as e:
                return False, str(e), {}
            self._notify_config_changed(net, action)
            self.tc.reload(net)
            return True, "Saved network options", {}
        if action == "save_raw_yaml":
            if not app:
                return False, "App config not loaded", {}
            raw_text = str(payload.get("raw_yaml") or "")
            try:
                incoming_doc = yaml_config.parse_text(raw_text, app.path)
            except yaml_config.ConfigError as e:
                return False, str(e), {}
            with yaml_config._MEM_LOCK:
                with yaml_config._file_lock(app.path):
                    try:
                        orig_doc = (
                            yaml_config.read_document(app.path)
                            if (app.path and os.path.isfile(app.path))
                            else yaml_config.to_dict(app)
                        )
                    except yaml_config.ConfigError as e:
                        return False, str(e), {}
                    orig_nets = orig_doc.get("networks") if isinstance(orig_doc, dict) else {}
                    if not isinstance(orig_nets, dict):
                        orig_nets = {}
                    in_nets = incoming_doc.get("networks") if isinstance(incoming_doc, dict) else {}
                    if not isinstance(in_nets, dict):
                        in_nets = {}
                    ft_nets: list[str] = []
                    for nname, nd in in_nets.items():
                        if not isinstance(nd, dict):
                            continue
                        orig_nd = orig_nets.get(nname) if isinstance(orig_nets.get(nname), dict) else {}
                        if _norm_scripts_dict(nd.get("scripts")) != _norm_scripts_dict(orig_nd.get("scripts")):
                            return (
                                False,
                                f"{nname}: Creating or modifying hook scripts via WebUI is forbidden",
                                {"_http_status": 403},
                            )
                        if _extract_forbidden_webui_opts(nd.get("options")) != _extract_forbidden_webui_opts(orig_nd.get("options")):
                            return (
                                False,
                                f"{nname}: Creating or modifying ScriptsInterpreter via WebUI is forbidden",
                                {"_http_status": 403},
                            )
                        if str(nd.get("full_tunnel") or "").strip():
                            ft_nets.append(nname)
                    if len(ft_nets) > 1:
                        return False, f"Full tunnel cannot be active on multiple networks ({', '.join(ft_nets)})", {}

                    restored_doc = restore_redacted_yaml_document(incoming_doc, orig_doc)
                    for nname, nd in (restored_doc.get("networks") or {}).items():
                        if isinstance(nd, dict):
                            errs = transports.validate(dict(nd.get("options") or {}))
                            if errs:
                                return False, f"{nname}: {'; '.join(errs)}", {}
                    base_doc = self._config_baseline if self._config_baseline is not None else app.baseline
                    if base_doc:
                        patch = yaml_config.diff_documents(base_doc, restored_doc)
                        merged = yaml_config.apply_patch(orig_doc, patch, base_doc) if patch else orig_doc
                    else:
                        merged = yaml_config._preserve_daemon_state_without_baseline(orig_doc, restored_doc)
                    try:
                        yaml_config.atomic_write_text(app.path, yaml_config.dump_text(merged))
                        yaml_config.refresh_in_place(app, merged)
                        self._config_baseline = copy.deepcopy(merged)
                    except (yaml_config.ConfigError, OSError) as e:
                        return False, str(e), {}
            self._notify_config_changed(net, action)
            if net:
                self.tc.reload(net)
            return True, "Saved tinc.yaml", {}
        if action == "invite":
            peer = str(payload.get("peer") or "").strip()
            if not peer:
                return False, "Invitee name required", {}
            res = self.tc.invite(net, peer)
            if not res.ok:
                return False, (res.stderr or res.stdout or "Invite failed"), {}
            return True, f"Invitation created for {peer}", {"invite_url": res.stdout, "output": res.stdout}

        return False, f"Unsupported action: {action}", {}
