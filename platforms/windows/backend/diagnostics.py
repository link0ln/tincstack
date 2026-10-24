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

import json
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
from collections import deque
from dataclasses import asdict, dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

import management
import routes
import transports
import yaml_config
from diag_webui import DIAG_WEBUI_HTML
from tinc_control import NetworkSnapshot, Node, TincControl, decode_status

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

DEFAULT_DIAG_PORT = 8655
SERIES_MAX_POINTS = 3600       # ~2.5 hours at 2.5s interval
INCIDENTS_MAX = 500
EVENTS_FILE_MAX_BYTES = 2 * 1024 * 1024


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
        return os.path.join(self.base_dir, f"{net}-diag-events.jsonl")

    def _load_persisted_events(self) -> None:
        if not os.path.isdir(self.base_dir):
            return
        try:
            for fname in os.listdir(self.base_dir):
                if not fname.endswith("-diag-events.jsonl"):
                    continue
                net = fname[:-len("-diag-events.jsonl")]
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
        path = self._events_path(ev.net)
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if os.path.isfile(path) and os.path.getsize(path) > EVENTS_FILE_MAX_BYTES:
                bak = path + ".1"
                try:
                    os.replace(path, bak)
                except OSError:
                    pass
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(ev.to_dict(), ensure_ascii=False) + "\n")
        except OSError:
            pass

    def clear_incidents(self, net: str) -> None:
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
            ep = parse_host_endpoints(nc.hosts[target])
            for sub in ep["subnets"]:
                ip = sub.split("/")[0].strip()
                if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip) and ip != "0.0.0.0":
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
        if ":" in target and not target.startswith("["):
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
            size = max(0, min(int(params.get("size") or 56), 9000))
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
        lines = [f"=== Carrier & Transport Handshake Prober for '{target}' (host={host}) ==="]

        # 1. DNS Resolution
        t0 = time.perf_counter()
        ips: list[str] = []
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for info in infos:
                ip = info[4][0]
                if ip not in ips:
                    ips.append(ip)
            dns_ms = (time.perf_counter() - t0) * 1000.0
            lines.append(f"[DNS] {host} -> {', '.join(ips)} ({dns_ms:.1f} ms)")
        except Exception as e:
            lines.append(f"[DNS] FAILED to resolve {host}: {e}")
            out_str = "\n".join(lines)
            return {"ok": False, "output": out_str, "formatted": out_str}

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
        nc = app.net(net) if app else None
        lines = [f"=== DNS Resolution & Address Cache Inspector for '{net}' ==="]
        if nc:
            for hname, hbody in sorted(nc.hosts.items()):
                ep = parse_host_endpoints(hbody)
                if not ep["addresses"]:
                    continue
                for addr, port in ep["addresses"]:
                    t0 = time.perf_counter()
                    try:
                        infos = socket.getaddrinfo(addr, None, socket.AF_UNSPEC, socket.SOCK_DGRAM)
                        ips = sorted({i[4][0] for i in infos})
                        ms = (time.perf_counter() - t0) * 1000.0
                        lines.append(f"  Host {hname:15s} : {addr}:{port or ep['port']} -> {', '.join(ips)} ({ms:.1f} ms)")
                    except Exception as e:
                        lines.append(f"  Host {hname:15s} : {addr}:{port or ep['port']} -> ERROR: {e}")

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

def _settings_path(base_dir: str) -> str:
    return os.path.join(base_dir, "diag_settings.json")


def load_diag_settings(base_dir: str) -> dict[str, Any]:
    path = _settings_path(base_dir)
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return {
                "enabled": bool(data.get("enabled", False)),
                "port": int(data.get("port", DEFAULT_DIAG_PORT)),
            }
        except Exception:
            pass
    return {"enabled": False, "port": DEFAULT_DIAG_PORT}


def save_diag_settings(base_dir: str, enabled: bool, port: int) -> None:
    path = _settings_path(base_dir)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"enabled": bool(enabled), "port": int(port)}, f, indent=2)
    except OSError:
        pass


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
        self._lock = threading.Lock()
        self._refresh_locks: dict[str, threading.Lock] = {}
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._port: int = DEFAULT_DIAG_PORT
        self._enabled: bool = False

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
        with self._lock:
            if self._httpd is not None and self._port == port and self._enabled:
                self.sync_tincd_bridge()
                return True, f"Diagnostic server already running on port {port}"
        self.stop()

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

            def _send_html(self, html: str, status: int = 200) -> None:
                body = html.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                parsed = urllib.parse.urlparse(self.path)
                qs = urllib.parse.parse_qs(parsed.query)
                net = (qs.get("net", [""])[0] or "").strip()

                if parsed.path in ("/", "/index.html"):
                    self._send_html(DIAG_WEBUI_HTML)
                    return
                if parsed.path == "/api/overview":
                    self._send_json(server_ref.build_overview(net))
                    return
                if parsed.path == "/api/logs":
                    lines = int(qs.get("lines", ["250"])[0] or 250)
                    source = (qs.get("source", ["tincd"])[0] or "tincd").strip()
                    self._send_json(server_ref.build_logs(net, source=source, lines=lines))
                    return
                if parsed.path == "/api/config":
                    self._send_json(server_ref.build_config(net))
                    return
                if parsed.path == "/api/export":
                    bundle = server_ref.build_export_bundle(net)
                    fname = f"tincstack-diag-{net or 'all'}-{int(time.time())}.json"
                    self._send_json(
                        bundle,
                        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
                    )
                    return
                self._send_json({"ok": False, "error": "Not found"}, status=404)

            def do_POST(self) -> None:
                parsed = urllib.parse.urlparse(self.path)
                length = int(self.headers.get("Content-Length", "0") or 0)
                raw = self.rfile.read(length) if length > 0 else b"{}"
                try:
                    payload = json.loads(raw.decode("utf-8", errors="replace"))
                except Exception:
                    payload = {}

                net = str(payload.get("net") or "").strip()
                if parsed.path == "/api/mark":
                    note = str(payload.get("note") or "")
                    target_net = net or server_ref._default_net()
                    if not target_net:
                        self._send_json({"ok": False, "error": "No network configured"}, status=400)
                        return
                    ev = server_ref.collector.record_user_mark(target_net, note)
                    self._send_json({"ok": True, "message": "Метка затупа сохранена", "event": ev.to_dict()})
                    return

                if parsed.path == "/api/probe":
                    target_net = net or server_ref._default_net()
                    tool = str(payload.get("tool") or payload.get("kind") or "").strip()
                    res = server_ref.prober.run_probe(target_net, tool, payload)
                    self._send_json(res)
                    return

                if parsed.path == "/api/action":
                    target_net = net or server_ref._default_net()
                    action = str(payload.get("action") or "").strip()
                    ok, msg, extra = server_ref.handle_action(target_net, action, payload)
                    resp = {"ok": ok, "message": msg}
                    resp.update(extra)
                    self._send_json(resp, status=200 if ok else 400)
                    return

                self._send_json({"ok": False, "error": "Not found"}, status=404)

        try:
            httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
            httpd.daemon_threads = True
        except OSError as e:
            return False, f"Could not bind port {port}: {e}"

        t = threading.Thread(target=httpd.serve_forever, name=f"diag-http-{port}", daemon=True)
        t.start()
        with self._lock:
            self._httpd = httpd
            self._thread = t
            self._port = port
            self._enabled = True
        save_diag_settings(self.base_dir, True, port)
        self.sync_tincd_bridge()
        return True, f"Diagnostic Web Server listening on port {port}"

    def stop(self) -> tuple[bool, str]:
        with self._lock:
            httpd = self._httpd
            self._httpd = None
            self._thread = None
            self._enabled = False
            port = self._port
        save_diag_settings(self.base_dir, False, port)
        self.sync_tincd_bridge()
        if httpd is not None:
            try:
                httpd.shutdown()
                httpd.server_close()
            except Exception:
                pass
        return True, "Diagnostic Web Server stopped"

    def sync_tincd_bridge(self, specific_net: str | None = None, async_mode: bool = True) -> None:
        """Register or unregister the diagnostic bridge port with running tincd daemons."""
        active_port = self._port if self.enabled else 0
        app = self.app_fn()
        if not app:
            return
        nets = [specific_net] if specific_net else list(app.networks)

        def _do_sync() -> None:
            for net in nets:
                if not net:
                    continue
                try:
                    self.tc.diag_port(net, active_port, timeout=2.5)
                except Exception:
                    pass

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
            for net in app.networks:
                snap = self.collector.get_latest_snapshot(net)
                if snap and not snap.error:
                    for n in snap.nodes.values():
                        if n.is_self and n.vpn_address:
                            u = f"http://{n.vpn_address.split('/')[0]}:{port}/"
                            if u not in urls:
                                urls.append(u)
                nc = app.net(net)
                if nc and nc.node_name and nc.node_name in nc.hosts:
                    ep = parse_host_endpoints(nc.hosts[nc.node_name])
                    for sub in ep["subnets"]:
                        ip = sub.split("/")[0].strip()
                        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip) and ip != "0.0.0.0":
                            u = f"http://{ip}:{port}/"
                            if u not in urls:
                                urls.append(u)
        urls.append(f"http://127.0.0.1:{port}/")
        return urls

    def build_overview(self, net: str = "") -> dict[str, Any]:
        app = self.app_fn()
        nets = list(app.networks) if app else []
        target_net = net if (net and net in nets) else (nets[0] if nets else "")
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
        total_rx = 0
        total_tx = 0
        if snap and not snap.error:
            for n in sorted(snap.nodes.values(), key=lambda x: (not x.is_self, x.name)):
                if n.is_self:
                    self_node = n.name
                    if n.vpn_address:
                        my_vpn_ip = n.vpn_address
                else:
                    total_rx += n.rx_bytes
                    total_tx += n.tx_bytes
                pcfg = peer_configs.get(n.name, {})
                sdict = n.status if n.status else decode_status(n.status_hex)
                nodes_list.append({
                    "name": n.name,
                    "is_self": n.is_self,
                    "reachable": n.reachable,
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
                    "vpn_address": n.vpn_address,
                    "subnets": n.subnets,
                    "routable_subnets": [s for s in n.subnets if routes.routable(s)],
                    "default_subnets": [s for s in n.subnets if routes.is_full_tunnel(s)],
                    "status_hex": f"0x{n.status_hex}",
                    "status": sdict,
                    "options_hex": f"0x{n.options}",
                    "has_host_block": bool(nc and n.name in nc.hosts),
                    "web_diag_url": f"http://{n.vpn_address.split('/')[0]}:{self.port}/" if n.vpn_address else "",
                })

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
            "current_bw": {
                "rx_bps": last_pt.get("rx_bps", 0.0),
                "tx_bps": last_pt.get("tx_bps", 0.0),
                "total_rx": total_rx,
                "total_tx": total_tx,
            },
            "full_tunnel": ft_exit,
            "full_tunnel_info": {"exit_node": ft_exit, "state": ft_state},
            "os_summary": f"MTU: {nc.wintun_mtu if nc else 1400} · Routes: {len(active_routes)}" + (f" · FT: {ft_state}" if ft_state else ""),
            "system_info": {
                "OS": f"{platform.system()} {platform.release()}",
                "Hostname": socket.gethostname(),
                "Version": ver,
                "Elevated (Admin)": str(management.is_admin()),
                "Config Path": app.path if app else "",
                "Wintun MTU": str(nc.wintun_mtu if nc else 1400),
                "Full Tunnel": f"{ft_exit} ({ft_state})" if ft_exit else "off",
                "Diag Bridge Port": str(self.port),
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
        target_net = net or self._default_net()
        tincd_log = os.path.join(self.base_dir, f"{target_net}-tincd.log") if target_net else ""
        mgr_log = os.path.join(self.base_dir, f"{target_net}-tincmgr.log") if target_net else ""
        ev_log = os.path.join(self.base_dir, f"{target_net}-diag-events.jsonl") if target_net else ""
        t_text = tail_file(tincd_log, max_lines=lines)
        m_text = tail_file(mgr_log, max_lines=lines)
        e_text = tail_file(ev_log, max_lines=lines)
        selected = t_text if source == "tincd" else (e_text if source == "events" else m_text)
        return {
            "ok": True,
            "net": target_net,
            "source": source,
            "text": selected,
            "tincd_log": t_text,
            "tincmgr_log": m_text,
        }

    def build_config(self, net: str = "") -> dict[str, Any]:
        app = self.app_fn()
        target_net = net or self._default_net()
        nc = app.net(target_net) if (app and target_net) else None
        raw_yaml = ""
        if app and os.path.isfile(app.path):
            try:
                with open(app.path, "r", encoding="utf-8", errors="replace") as f:
                    raw_yaml = f.read()
            except OSError:
                pass
        tr_val = nc.options.get("Transports", "") if nc else ""
        pref_val = nc.options.get("PreferredTransports", "") if nc else ""
        if isinstance(tr_val, list):
            tr_val = ", ".join(str(x) for x in tr_val)
        if isinstance(pref_val, list):
            pref_val = ", ".join(str(x) for x in pref_val)
        return {
            "ok": True,
            "net": target_net,
            "autostart": nc.autostart if nc else False,
            "wintun_mtu": nc.wintun_mtu if nc else 1400,
            "full_tunnel": nc.full_tunnel if nc else "",
            "transports": str(tr_val),
            "preferred_transports": str(pref_val),
            "options": dict(nc.options) if nc else {},
            "options_conf": yaml_config.options_to_conf(nc.options) if nc else "",
            "hosts": dict(nc.hosts) if nc else {},
            "raw_yaml": raw_yaml,
        }

    def build_export_bundle(self, net: str = "") -> dict[str, Any]:
        target_net = net or self._default_net()
        cfg = self.build_config(target_net)
        # Scrub private keys and tokens from export bundle for safety
        cfg.pop("raw_yaml", None)
        opts = dict(cfg.get("options") or {})
        if "CloudflareToken" in opts:
            opts["CloudflareToken"] = "***REDACTED***"
        cfg["options"] = opts
        return {
            "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "overview": self.build_overview(target_net),
            "logs": self.build_logs(target_net, lines=500),
            "config": cfg,
            "dns_cache": self.prober.run_probe(target_net, "dns", {}),
            "os_routes": self.prober.run_probe(target_net, "routes", {}),
        }

    def handle_action(self, net: str, action: str, payload: dict[str, Any]) -> tuple[bool, str, dict[str, Any]]:
        if self.action_handler is not None:
            return self.action_handler(net, action, payload)
        return self.default_action_handler(net, action, payload)

    def default_action_handler(self, net: str, action: str, payload: dict[str, Any]) -> tuple[bool, str, dict[str, Any]]:
        app = self.app_fn()
        nc = app.net(net) if (app and net) else None

        if action == "daemon":
            op = str(payload.get("op") or "").strip()
            if op in ("start", "stop", "restart", "reload", "debug"):
                action = op

        if action == "start" and self.runtime:
            ok, msg = self.runtime.start(net)
            self.sync_tincd_bridge(net)
            return ok, msg, {}
        if action == "stop" and self.runtime:
            ok, msg = self.runtime.stop(net)
            return ok, msg, {}
        if action == "restart" and self.runtime:
            ok, msg = self.runtime.restart(net)
            self.sync_tincd_bridge(net)
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
            self.collector.clear_incidents(net)
            return True, "Журнал инцидентов очищен", {}
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
            if peer not in nc.hosts and os.path.exists(app.path):
                try:
                    yaml_config.refresh_in_place(app, yaml_config.read_document(app.path))
                except Exception:
                    pass
            nc.hosts[peer] = transports.set_host_preferred_transport(nc.hosts.get(peer, ""), carrier)
            if carrier != "auto" and re.search(r"^[ \t]*Address[ \t]*=", nc.hosts[peer], re.I | re.M):
                ct = nc.options.get("ConnectTo")
                if isinstance(ct, list):
                    if peer not in ct:
                        ct.append(peer)
                elif isinstance(ct, str) and ct.strip():
                    if ct.strip() != peer:
                        nc.options["ConnectTo"] = [ct.strip(), peer]
                else:
                    nc.options["ConnectTo"] = peer
            yaml_config.save(app)
            res = self.tc.switch_peer_transport(net, peer)
            self.collector.add_incident(
                net=net, kind="USER_ACTION", severity="info", peer=peer,
                summary=f"Switched preferred transport for '{peer}' to '{carrier}' via Diagnostic WebUI",
            )
            return res.ok, f"Switched {peer} transport to {carrier}", {}
        if action == "toggle_route":
            if not nc:
                return False, "Network not found", {}
            subnet = str(payload.get("subnet") or "").strip()
            vpn_ip = str(payload.get("vpn_ip") or "").strip()
            enable = bool(payload.get("enable", True))
            if enable:
                routes.add(nc.options, subnet, vpn_ip)
            else:
                routes.remove(nc.options, subnet)
            yaml_config.save(app)
            alias = routes.adapter_aliases(nc.options, net)
            if alias:
                if enable:
                    routes.apply_now(alias[0], subnet, vpn_ip)
                else:
                    routes.remove_now(alias[0], subnet)
            return True, f"Route {subnet} {'enabled' if enable else 'disabled'}", {}
        if action == "toggle_full_tunnel":
            if not nc:
                return False, "Network not found", {}
            peer = str(payload.get("peer") or "").strip()
            enable = bool(payload.get("enable", False))
            nc.full_tunnel = peer if enable else ""
            yaml_config.save(app)
            msg = self.runtime.full_tunnel_sync(net) if self.runtime else "saved"
            return True, msg, {}
        if action in ("save_host", "peer_save_host"):
            if not nc:
                return False, "Network not found", {}
            host = str(payload.get("host") or payload.get("peer") or "").strip()
            content = str(payload.get("content") or payload.get("text") or "").rstrip("\n")
            if not host:
                return False, "Host name is empty", {}
            nc.hosts[host] = content
            yaml_config.save(app)
            self.tc.reload(net)
            return True, f"Saved host '{host}'", {}
        if action == "delete_host":
            if not nc:
                return False, "Network not found", {}
            host = str(payload.get("host") or payload.get("peer") or "").strip()
            nc.hosts.pop(host, None)
            yaml_config.save(app)
            self.tc.reload(net)
            return True, f"Deleted host '{host}'", {}
        if action == "save_settings":
            if not nc:
                return False, "Network not found", {}
            tr_str = str(payload.get("transports") or "").strip()
            pref_str = str(payload.get("preferred_transports") or "").strip()
            if tr_str:
                nc.options["Transports"] = transports.parse_carrier_list(tr_str)
            else:
                nc.options.pop("Transports", None)
            if pref_str:
                nc.options["PreferredTransports"] = transports.parse_carrier_list(pref_str)
            else:
                nc.options.pop("PreferredTransports", None)
            if "full_tunnel" in payload:
                nc.full_tunnel = str(payload.get("full_tunnel") or "").strip()
            errs = transports.validate(nc.options)
            if errs:
                return False, "; ".join(errs), {}
            yaml_config.save(app)
            self.tc.reload(net)
            if self.runtime:
                self.runtime.full_tunnel_sync(net)
            return True, "Настройки транспорта и маршрутизации сохранены", {}
        if action == "save_options":
            if not nc:
                return False, "Network not found", {}
            conf_text = str(payload.get("options_conf") or "")
            new_opts = yaml_config.conf_to_options(conf_text)
            for k in ("Transports", "PreferredTransports"):
                if k in new_opts:
                    new_opts[k] = transports.parse_carrier_list(new_opts[k])
            errs = transports.validate(new_opts)
            if errs:
                return False, "; ".join(errs), {}
            nc.options = new_opts
            if "autostart" in payload:
                nc.autostart = bool(payload["autostart"])
            if "wintun_mtu" in payload:
                try:
                    nc.wintun_mtu = int(payload["wintun_mtu"])
                except ValueError:
                    pass
            yaml_config.save(app)
            self.tc.reload(net)
            return True, "Saved network options", {}
        if action == "save_raw_yaml":
            if not app:
                return False, "App config not loaded", {}
            raw_text = str(payload.get("raw_yaml") or "")
            yaml_config.save_text(app.path, raw_text)
            yaml_config.refresh_in_place(app, yaml_config.read_document(app.path))
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
