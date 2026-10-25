"""
tincmgr — single-binary Windows manager for the tincstack core (YAML-native).

One tinc.yaml describes every network; the bundled core tincd reads/writes it
directly (zero-config materialisation, learned peer keys). The app autostarts
the configured networks on launch (elevated) and offers an interactive config
editor so you never have to hand-edit YAML.

Tabs:
  * Peers & Traffic — live peer table + per-network throughput graph
  * Network         — tinc.conf options (catalog of known options), nodes/hosts,
                      keys, autostart; raw YAML as a fallback.
  * Transports      — accept list / dial preference / obfs / HTTPS front / QUIC
                      (docs/config-schema.md); writes only the keys you change.
Toolbar: Start / Stop / Restart, Invite…, Join…, Certificate…, run-at-startup,
Reload.

Every tinc/tincd subprocess runs on a worker thread (gui/workers.py); the Qt
thread never blocks on the daemon. A malformed tinc.yaml opens the window with
an error banner instead of crashing.

Run from source (dev):   python main.py     (needs PySide6, pyqtgraph, pyyaml)
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
import time
from collections import deque
from typing import Any, Callable

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "backend"))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import paths  # noqa: E402
import routes  # noqa: E402
import transports  # noqa: E402
import updates  # noqa: E402
import diagnostics  # noqa: E402
import yaml_config  # noqa: E402
from yaml_config import AppConfig, ConfigError, NetworkCfg, options_to_conf, conf_to_options  # noqa: E402
from runtime import Runtime  # noqa: E402
from tinc_control import TincControl, NetworkSnapshot, parse_cert_expiry  # noqa: E402
import management  # noqa: E402

from PySide6 import QtCore, QtGui, QtWidgets  # noqa: E402
import pyqtgraph as pg  # noqa: E402

from gui.workers import WorkerPool  # noqa: E402
from gui.dialogs import InviteDialog, JoinDialog, RawYamlDialog  # noqa: E402
from gui.cert_dialog import CertDialog  # noqa: E402
from gui.diag_dialog import DiagnosticsDialog  # noqa: E402
from gui.transports_panel import TransportsPanel  # noqa: E402

REFRESH_MS = 2500
HIST_MAX = 12000          # ~8h of 2.5s samples per network

LINK_COLORS = {
    "direct-udp": "#1e8e3e", "direct-tcp": "#b8860b", "relay": "#e8710a",
    "down": "#9aa0a6", "self": "#1a73e8",
}
LINK_LABEL = {
    "direct-udp": "● direct UDP", "direct-tcp": "◐ direct TCP", "relay": "↻ relay",
    "down": "○ down", "self": "★ this node",
}
TRANSPORT_COLORS = {
    "quic": "#1e8e3e", "https": "#1a73e8", "obfs": "#9334e6",
    "sf": "#e8710a", "plain": "#5f6368", "udp": "#1e8e3e",
}
TRANSPORT_CHOICES = [
    ("auto", "Auto (network default)"),
    ("quic", "quic — QUIC (UDP / HTTP/3)"),
    ("https", "https — HTTPS / TLS 1.3 (TCP)"),
    ("obfs", "obfs — Obfuscated UDP"),
    ("sf", "sf — Single-flow UDP"),
    ("plain", "plain — Plain tinc TCP/UDP"),
]

# catalog of known tinc options for the interactive editor:
#   (name, kind, choices, help)   kind in {str,int,bool,enum}
KNOWN_OPTIONS = [
    ("Name", "str", None, "This node's name — must match one of the host entries below"),
    ("Mode", "enum", ["router", "switch", "hub"], "How tinc forwards packets (router = L3)"),
    ("Port", "int", None, "Listen port (founding node: 655; invitees: 0 = ephemeral, better behind NAT)"),
    ("AddressFamily", "enum", ["ipv4", "ipv6", "any"], "Which IP family to use"),
    ("AutoConnect", "bool", None, "Automatically maintain connections to keep the mesh joined"),
    ("ConnectTo", "str", None, "Name of a node to connect to (add several for multiple)"),
    ("AddressPool", "str", None, "Network the inviter assigns invitee IPs from, e.g. 10.210.0.0/24"),
    ("Interface", "str", None, "OS network interface name to use"),
    ("DeviceType", "enum", ["wintun", "tap", "tun", "dummy"], "Adapter backend (wintun = WireGuard tunnel, Windows)"),
    ("WintunAddress", "str", None, "CIDR auto-assigned to the Wintun adapter, e.g. 10.0.0.1/24 (Windows)"),
    ("WintunInterface", "str", None, "Wintun adapter name (collision-safe)"),
    ("wintun_mtu", "int", None, "tincmgr: MTU forced on the Wintun adapter at start via the Win32 API (0 = 1400). Stored in YAML, NOT sent to tinc.conf."),
    ("InterfaceAddress", "str", None, "Address for the tunnel adapter, e.g. 10.200.240.2/24 (absent = this node's own Subnet)"),
    ("InterfaceRoute", "str", None, "Route through the tunnel: '<prefix> [gateway]', e.g. 192.168.1.0/24 10.200.240.7. One per route; the Peers tab's Route buttons write these."),
    ("LocalDiscovery", "bool", None, "Find peers on the same LAN and connect directly"),
    ("DirectOnly", "bool", None, "Only send packets directly to peers, never via intermediate relays"),
    ("Forwarding", "enum", ["internal", "kernel", "off"], "How packets are forwarded (default: internal)"),
    ("Broadcast", "enum", ["mst", "direct", "no"], "How broadcast packets are propagated"),
    ("ClampMSS", "bool", None, "Clamp TCP MSS of inner packets to path MTU (default: yes)"),
    ("DecrementTTL", "bool", None, "Decrement IP TTL of forwarded packets"),
    ("PriorityInheritance", "bool", None, "Inherit IP TOS/DSCP priority on outer UDP packets"),
    ("UDPDiscovery", "bool", None, "Probe direct UDP reachability (default: yes)"),
    ("UDPDiscoveryKeepaliveInterval", "int", None, "Seconds between UDP keepalives once direct UDP works"),
    ("UDPDiscoveryInterval", "int", None, "Seconds between UDP discovery probes"),
    ("UDPDiscoveryTimeout", "int", None, "Seconds before an unresponsive direct UDP path is declared dead"),
    ("UDPRebindOnWake", "bool", None, "Re-bind the UDP socket after sleep/resume (core feature)"),
    ("UDPDiscoveryBurst", "int", None, "UDP hole-punching probes per round while unconfirmed (core feature)"),
    ("MTUInfoInterval", "int", None, "Seconds between MTU_INFO updates"),
    ("UDPInfoInterval", "int", None, "Seconds between UDP_INFO updates"),
    ("TCPOnly", "bool", None, "Tunnel only over TCP (forces relay; no UDP)"),
    ("IndirectData", "bool", None, "This node is only reachable via a relay"),
    ("PMTUDiscovery", "bool", None, "Discover the path MTU automatically"),
    ("Compression", "int", None, "Compression level 0-11 (0 = off)"),
    ("PingInterval", "int", None, "Seconds between keepalive pings"),
    ("PingTimeout", "int", None, "Seconds before an unresponsive peer is considered down"),
    ("AddressDiscovery", "bool", None, "Allow tinc invite to query external address if Address is unset"),
    ("DiagPort", "int", None, "In-tunnel TCP diagnostic bridge port (0 = disabled, e.g. 8655)"),
    # certificate issuance (tinc cert; see the Certificate… toolbar button)
    ("CertDomain", "str", None, "Public DNS name this node presents on https/quic, e.g. vpn.example.com"),
    ("CloudflareToken", "str", None, "Cloudflare API token with Zone:Read + Zone:DNS:Edit on that domain's zone"),
    ("CloudflareApi", "str", None, "Cloudflare API base URL override (optional)"),
    ("AcmeContact", "str", None, "mailto: address the CA uses for expiry warnings (optional)"),
    ("AcmeDirectory", "str", None, "ACME directory URL (default: Let's Encrypt production)"),
    ("AcmeCaFile", "str", None, "Custom CA bundle path for ACME/Cloudflare HTTPS requests (optional)"),
    ("AcmeRenewDays", "int", None, "Renew when fewer than this many days are left (default 30)"),
    ("AcmePropagation", "int", None, "Seconds to wait for DNS challenge propagation (default 15)"),
    ("AcmePollTimeout", "int", None, "Seconds to poll ACME challenge validation before timing out"),
] + [
    (spec.name,
     {"carriers": "str", "int": "int", "port": "int", "front_port": "int", "bool": "bool", "path": "str",
      "str": "str", "magic": "str"}[spec.kind],
     None, spec.help + "  (see the Transports tab)")
    for spec in transports.TRANSPORT_OPTIONS
]
KNOWN_BY_NAME = {o[0]: o for o in KNOWN_OPTIONS}
AGG = [("1 s", 1), ("10 s", 10), ("1 min", 60), ("5 min", 300), ("1 h", 3600)]


def human_bytes(n: int) -> str:
    f = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if f < 1024 or u == "TB":
            return f"{f:.0f} {u}" if u == "B" else f"{f:.1f} {u}"
        f /= 1024
    return f"{f:.1f} TB"


# ---- Peers + persistent throughput graph -------------------------------------

class PeersTab(QtWidgets.QWidget):
    COLS = ["Peer", "Link", "Transport", "Via", "Dist", "RTT ms", "PMTU", "RX", "TX", "Subnets", "Route here"]
    FULL_TUNNEL_LABEL = "all traffic ({})"     # the Route here toggle for an announced default route

    def __init__(self, tc: TincControl, nets_fn: Callable[[], list[str]], pool: WorkerPool,
                 on_running: Callable[[dict[str, bool]], None], ctx: Any = None) -> None:
        super().__init__()
        self.ctx = ctx
        # peer name -> (signature, widget): the table is rebuilt every tick, and
        # a button recreated under the pointer is a button that cannot be
        # clicked. Rebuild a cell only when what it shows actually changed.
        self._route_cells: dict[str, tuple[tuple, QtWidgets.QWidget]] = {}
        self._transport_cells: dict[str, tuple[tuple, QtWidgets.QWidget]] = {}
        self.tc = tc
        self.nets_fn = nets_fn
        self.pool = pool
        self.on_running = on_running
        self.net: str | None = None
        # per-network history of cumulative totals: net -> deque[(epoch, rx, tx)]
        self.hist: dict[str, deque] = {}
        self._snaps: dict[str, NetworkSnapshot] = {}
        self._follow = True

        v = QtWidgets.QVBoxLayout(self)
        self.table = QtWidgets.QTableWidget(0, len(self.COLS))
        self.table.setHorizontalHeaderLabels(self.COLS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)
        self.table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._on_table_context_menu)
        v.addWidget(self.table, stretch=3)

        ctl = QtWidgets.QHBoxLayout()
        ctl.addWidget(QtWidgets.QLabel("Aggregate:"))
        self.agg = QtWidgets.QComboBox()
        for label, _ in AGG:
            self.agg.addItem(label)
        self.agg.setCurrentIndex(0)
        self.agg.currentIndexChanged.connect(self._redraw)
        ctl.addWidget(self.agg)
        self.follow_cb = QtWidgets.QCheckBox("Follow latest")
        self.follow_cb.setChecked(True)
        self.follow_cb.toggled.connect(self._set_follow)
        ctl.addWidget(self.follow_cb)
        ctl.addStretch()
        v.addLayout(ctl)

        pg.setConfigOptions(antialias=True)
        self.plot = pg.PlotWidget(axisItems={"bottom": pg.DateAxisItem()})
        self.plot.setBackground("#1e1e1e")
        self.plot.showGrid(x=True, y=True, alpha=0.3)
        self.plot.setLabel("left", "Throughput", units="bps")
        self.plot.addLegend()
        self.c_rx = self.plot.plot(pen=pg.mkPen("#1e8e3e", width=2), name="RX")
        self.c_tx = self.plot.plot(pen=pg.mkPen("#1a73e8", width=2), name="TX")
        v.addWidget(self.plot, stretch=2)

    def _set_follow(self, on: bool) -> None:
        self._follow = on
        if on:
            self._redraw()

    def set_network(self, net: str | None) -> None:
        self.net = net
        self._route_cells.clear()
        self._transport_cells.clear()
        if net:
            self.hist.setdefault(net, deque(maxlen=HIST_MAX))
        self._table(self._snaps.get(net) if net else None)
        self._redraw()

    # -- sampling: subprocesses on a worker, UI update on the Qt thread --
    def sample_async(self) -> None:
        """Sample ALL networks (so history is continuous even off-screen);
        skipped if the previous sample is still running."""
        nets = list(self.nets_fn())
        self.pool.run(self._collect, nets, tag="sample", on_done=self._apply)

    def _collect(self, nets: list[str]) -> dict[str, NetworkSnapshot]:
        return {net: self.tc.snapshot(net) for net in nets}

    def _apply(self, snaps: dict[str, NetworkSnapshot]) -> None:
        now = time.time()
        running_map: dict[str, bool] = {}
        for net, snap in snaps.items():
            if snap.error and self.ctx and self.ctx.rt.has_live_process(net):
                # Transient control socket hiccup while tincd child process is alive:
                # keep the previous snapshot and running state instead of flipping UI to stopped.
                running_map[net] = True
                if net not in self._snaps:
                    self._snaps[net] = snap
                continue
            self._snaps[net] = snap
            running_map[net] = not snap.error
            if self.ctx and hasattr(self.ctx, "diag_collector"):
                self.ctx.diag_collector.record_snapshot(net, snap, now)
            if snap.error:
                continue
            rx = sum(n.rx_bytes for n in snap.nodes.values() if not n.is_self)
            tx = sum(n.tx_bytes for n in snap.nodes.values() if not n.is_self)
            self.hist.setdefault(net, deque(maxlen=HIST_MAX)).append((now, rx, tx))
        self.on_running(running_map)
        if self.net:
            self._table(self._snaps.get(self.net))
            self._redraw()

    def _table(self, snap: NetworkSnapshot | None) -> None:
        if snap is None or snap.error:
            self._route_cells.clear()
            self._transport_cells.clear()
            self.table.setRowCount(1)
            it = QtWidgets.QTableWidgetItem("not running" + (f" / {snap.error}" if snap else ""))
            it.setForeground(QtGui.QColor("#9aa0a6"))
            self.table.setItem(0, 0, it)
            self.table.setSpan(0, 0, 1, len(self.COLS))
            return
        self.table.setSpan(0, 0, 1, 1)
        nodes = sorted(snap.nodes.values(), key=lambda n: (not n.is_self, n.name))
        self.table.setRowCount(len(nodes))
        for r, n in enumerate(nodes):
            link = n.link
            via = "" if n.is_self or link.startswith("direct") else n.nexthop
            tr_text = "—" if n.is_self else (n.transport or "—")
            cells = [n.name, LINK_LABEL.get(link, link), tr_text, via,
                     "" if n.distance < 0 else str(n.distance),
                     f"{n.rtt:.0f}" if n.rtt > 0 else "",
                     str(n.pmtu) if n.pmtu else "",
                     human_bytes(n.rx_bytes), human_bytes(n.tx_bytes),
                     ", ".join(n.subnets), ""]
            for c, val in enumerate(cells):
                it = QtWidgets.QTableWidgetItem(val)
                if c == 1:
                    it.setForeground(QtGui.QColor(LINK_COLORS.get(link, "#000")))
                    f = it.font(); f.setBold(True); it.setFont(f)
                elif c == 2 and n.transport:
                    it.setForeground(QtGui.QColor(TRANSPORT_COLORS.get(n.transport, "#5f6368")))
                    f = it.font(); f.setBold(True); it.setFont(f)
                self.table.setItem(r, c, it)
            self._transport_cell(r, n)
            self._route_cell(r, n)
        live_names = {n.name for n in nodes}
        for name in [k for k in self._route_cells if k not in live_names]:
            self._route_cells.pop(name, None)
        for name in [k for k in self._transport_cells if k not in live_names]:
            self._transport_cells.pop(name, None)
        self.table.resizeColumnsToContents()

    # -- per-node transport display and quick-access protocol switcher ---------

    def _peer_preferred_transport(self, peer_name: str) -> str:
        nc = self.ctx.app.net(self.net) if (self.ctx and self.net) else None
        if not nc:
            return ""
        return transports.host_preferred_transport(nc.hosts.get(peer_name, ""))

    def _build_transport_menu(self, parent: QtWidgets.QWidget, n) -> QtWidgets.QMenu:
        menu = QtWidgets.QMenu(parent)
        pref = self._peer_preferred_transport(n.name) or "auto"
        for code, title in TRANSPORT_CHOICES:
            suffix = ""
            if code != "auto" and n.supported_transports and code not in n.supported_transports:
                suffix = "  (not advertised)"
            act = menu.addAction(title + suffix)
            act.setCheckable(True)
            act.setChecked(pref == code)
            act.triggered.connect(lambda _checked=False, p=n.name, c=code: self._set_peer_transport(p, c))
            if code == "auto":
                menu.addSeparator()
        menu.addSeparator()
        rec = menu.addAction(f"⟳ Reconnect {n.name} now")
        rec.triggered.connect(lambda _checked=False, p=n.name: self._reconnect_peer(p))
        return menu

    def _transport_cell(self, row: int, n) -> None:
        col = 2
        if n.is_self or self.ctx is None:
            self._transport_cells.pop(n.name, None)
            self.table.removeCellWidget(row, col)
            return
        pref = self._peer_preferred_transport(n.name)
        active = n.transport or ""
        supported = tuple(n.supported_transports or ())
        sig = (active, pref, supported)
        cached = self._transport_cells.get(n.name)
        if cached and cached[0] == sig:
            self.table.setCellWidget(row, col, cached[1])
            return
        w = QtWidgets.QWidget()
        lay = QtWidgets.QHBoxLayout(w)
        lay.setContentsMargins(2, 0, 2, 0)
        lay.setSpacing(2)
        btn = QtWidgets.QToolButton()
        btn.setPopupMode(QtWidgets.QToolButton.InstantPopup)
        if pref:
            if active and active == pref:
                label = f"📌 {active} ▾"
            elif active:
                label = f"{active} (📌 {pref}) ▾"
            else:
                label = f"— (📌 {pref}) ▾"
        else:
            label = f"{active} ▾" if active else "auto ▾"
        btn.setText(label)
        color = TRANSPORT_COLORS.get(active or pref, "#5f6368")
        btn.setStyleSheet(f"QToolButton {{ color: {color}; font-weight: bold; padding: 1px 6px; }}")
        sup_str = ", ".join(supported) if supported else "unknown"
        btn.setToolTip(
            f"Active transport to {n.name}: {active or 'none (down/relayed)'}\n"
            f"Pinned preference for {n.name}: {pref or 'auto (network default)'}\n"
            f"Peer accepts: {sup_str}\n\n"
            f"Click to switch transport protocol (quic, https, obfs, sf, plain, auto) "
            f"for {n.name} and reconnect immediately."
        )
        btn.setMenu(self._build_transport_menu(btn, n))
        lay.addWidget(btn)
        lay.addStretch()
        self._transport_cells[n.name] = (sig, w)
        self.table.setCellWidget(row, col, w)

    def _on_table_context_menu(self, pos: QtCore.QPoint) -> None:
        if not self.ctx or not self.net:
            return
        row = self.table.rowAt(pos.y())
        if row < 0:
            return
        item = self.table.item(row, 0)
        if not item:
            return
        peer_name = item.text()
        snap = self._snaps.get(self.net)
        n = snap.nodes.get(peer_name) if snap else None
        if not n or n.is_self:
            return
        menu = self._build_transport_menu(self.table, n)
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def _set_peer_transport(self, peer_name: str, carrier: str) -> None:
        ctx, net = self.ctx, self.net
        nc = ctx.app.net(net) if (ctx and net) else None
        if nc is None:
            return
        if peer_name not in nc.hosts and os.path.exists(ctx.app.path):
            try:
                yaml_config.refresh_in_place(ctx.app, yaml_config.read_document(ctx.app.path))
            except Exception:
                pass
        old_host = nc.hosts.get(peer_name, "")
        nc.hosts[peer_name] = transports.set_host_preferred_transport(old_host, carrier)
        # If the user pinned a specific transport for a peer that has an Address
        # in its host block, make sure ConnectTo includes it so tincd dials it directly.
        if carrier != "auto" and re.search(r"^[ \t]*Address[ \t]*=", nc.hosts[peer_name], re.I | re.M):
            ct = nc.options.get("ConnectTo")
            if isinstance(ct, list):
                if peer_name not in ct:
                    ct.append(peer_name)
            elif isinstance(ct, str) and ct.strip():
                if ct.strip() != peer_name:
                    nc.options["ConnectTo"] = [ct.strip(), peer_name]
            else:
                nc.options["ConnectTo"] = peer_name
        if not ctx.save_config():
            nc.hosts[peer_name] = old_host
            self._transport_cells.pop(peer_name, None)
            self._table(self._snaps.get(net))
            return
        if hasattr(ctx, "network"):
            ctx.network.reload()
        self._transport_cells.pop(peer_name, None)
        self._table(self._snaps.get(net))
        desc = "auto (default)" if carrier == "auto" else carrier
        if not ctx._running.get(net, False):
            ctx.status(f"{peer_name}: transport set to {desc} (will apply when '{net}' starts)")
            return
        ctx.status(f"{peer_name}: switching transport to {desc}…")

        def done(_res: Any) -> None:
            ctx.status(f"{peer_name}: transport switched to {desc} — reconnecting")
            self.sample_async()

        ctx.pool.run(self.tc.switch_peer_transport, net, peer_name,
                     tag=f"switch-tr-{net}-{peer_name}", on_done=done,
                     on_error=lambda m: ctx.status(f"{peer_name}: switch failed: {m}"))

    def _reconnect_peer(self, peer_name: str) -> None:
        ctx, net = self.ctx, self.net
        if not ctx or not net or not ctx._running.get(net, False):
            return
        ctx.status(f"Reconnecting {peer_name}…")
        ctx.pool.run(self.tc.switch_peer_transport, net, peer_name,
                     tag=f"switch-tr-{net}-{peer_name}",
                     on_done=lambda _r: (ctx.status(f"Reconnected {peer_name}"), self.sample_async()),
                     on_error=lambda m: ctx.status(f"Reconnect {peer_name} failed: {m}"))

    # -- routes to the subnets a peer announces --------------------------------

    def _options(self) -> dict | None:
        nc = self.ctx.app.net(self.net) if (self.ctx and self.net) else None
        return nc.options if nc else None

    def _route_cell(self, row: int, n) -> None:
        """One toggle per subnet this peer announces that this machine can
        route: an InterfaceRoute toggle for a network (ticked = routed through
        the tunnel), and the full-tunnel toggle for a default route (ticked =
        all IPv4 traffic goes out through this peer, fulltunnel.py)."""
        col = len(self.COLS) - 1
        options = self._options()
        nc = self.ctx.app.net(self.net) if (self.ctx and self.net) else None
        mine = n.is_self or options is None
        subnets = [] if mine else [s for s in n.subnets if routes.routable(s)]
        defaults = [] if mine else [s for s in n.subnets if routes.is_full_tunnel(s)]
        exit_on = bool(nc and nc.full_tunnel == n.name)
        ft_state = self.ctx.rt.full_tunnel_state(self.net) if (exit_on and self.ctx) else ""
        sig = (tuple(subnets), tuple(routes.has(options, s) for s in subnets) if options else (),
               tuple(defaults), exit_on, ft_state)
        cached = self._route_cells.get(n.name)
        if cached and cached[0] == sig:
            self.table.setCellWidget(row, col, cached[1])
            return
        if not subnets and not defaults:
            self._route_cells.pop(n.name, None)
            self.table.removeCellWidget(row, col)
            return
        w = QtWidgets.QWidget()
        lay = QtWidgets.QHBoxLayout(w)
        lay.setContentsMargins(2, 0, 2, 0)
        lay.setSpacing(4)
        for sub in subnets:
            b = QtWidgets.QToolButton()
            b.setText(sub)
            b.setCheckable(True)
            b.setChecked(routes.has(options, sub))
            b.setToolTip(f"Send this machine's traffic for {sub} through {n.name} "
                         f"({n.vpn_address or 'the tunnel'}).\n"
                         f"Saved as InterfaceRoute, so the daemon restores it every start "
                         f"and Windows drops it when the network stops.")
            b.clicked.connect(lambda checked, s=sub, node=n: self._toggle_route(node, s, checked))
            lay.addWidget(b)
        for sub in defaults:
            b = QtWidgets.QToolButton()
            b.setText(self.FULL_TUNNEL_LABEL.format(sub))
            b.setCheckable(True)
            if routes.parse_subnet(sub).version == 6:
                b.setEnabled(False)
                b.setToolTip(f"{n.name} announces an IPv6 default route. This client "
                             f"sends only IPv4 through a full tunnel so far.")
            else:
                b.setChecked(exit_on)
                b.setToolTip(
                    f"Send ALL of this machine's IPv4 traffic out through {n.name}.\n"
                    f"The addresses of the peers tincd talks to are pinned to the "
                    f"physical gateway first, then 0.0.0.0/1 and 128.0.0.0/1 go on the "
                    f"tunnel adapter; kept up to date while the network runs.\n"
                    f"While {n.name} is unreachable the routes are taken off, so the "
                    f"machine keeps its own connection. DNS and IPv6 are not changed."
                    + (f"\n\nNow: {ft_state}" if ft_state else ""))
                b.clicked.connect(lambda checked, node=n: self._toggle_full_tunnel(node, checked))
            lay.addWidget(b)
        lay.addStretch()
        self._route_cells[n.name] = (sig, w)
        self.table.setCellWidget(row, col, w)

    def _toggle_full_tunnel(self, node, on: bool) -> None:
        """Make `node` this network's exit for all IPv4 traffic, or stop. One
        exit per network: choosing another node moves it there. The setting is
        `full_tunnel` in tinc.yaml; Runtime applies and maintains the routes."""
        ctx, net = self.ctx, self.net
        nc = ctx.app.net(net) if (ctx and net) else None
        if nc is None:
            return
        prev = nc.full_tunnel
        nc.full_tunnel = node.name if on else ""
        self._route_cells.clear()          # the previous exit's toggle changes too
        if not ctx.save_config():
            nc.full_tunnel = prev
            self._table(self._snaps.get(net))
            return
        ctx.status(f"all traffic through {node.name}: applying…" if on else "full tunnel: turning off…")

        def done(msg: str) -> None:
            ctx.status(msg)
            self._route_cells.clear()
            self._table(self._snaps.get(net))
        ctx.pool.run(ctx.rt.full_tunnel_sync, net, tag=f"fulltunnel-{net}", on_done=done,
                     on_error=lambda m: ctx.status(f"full tunnel: {m}"))
        self._table(self._snaps.get(net))

    def _toggle_route(self, node, subnet: str, on: bool) -> None:
        options = self._options()
        if options is None:
            return
        ctx, net = self.ctx, self.net
        if on:
            clash = routes.conflicts(subnet, routes.local_ipv4_subnets())
            if clash and QtWidgets.QMessageBox.question(
                    self, "Route conflict",
                    f"{subnet} overlaps a network this machine is already on "
                    f"({', '.join(clash)}).\n\nAdding the route takes those addresses away from "
                    f"the adapter that owns them — your own LAN would go through the tunnel "
                    f"instead.\n\nAdd it anyway?") != QtWidgets.QMessageBox.Yes:
                self._route_cells.pop(node.name, None)
                self._table(self._snaps.get(net))
                return
            routes.add(options, subnet, node.vpn_address)
        else:
            routes.remove(options, subnet)
        if not ctx.save_config():
            self._route_cells.pop(node.name, None)
            self._table(self._snaps.get(net))
            return
        self._route_cells.pop(node.name, None)
        verb = "added" if on else "removed"
        if not ctx._running.get(net, False):
            ctx.status(f"route to {subnet} {verb} — it is installed when '{net}' starts")
            return
        alias = routes.adapter_aliases(options, net)
        ok, msg = ((routes.apply_now(alias[0], subnet, node.vpn_address) if on
                    else routes.remove_now(alias[0], subnet)) if alias else (False, "no adapter name"))
        ctx.status(f"route to {subnet} {verb}" if ok
                   else f"route to {subnet} {verb} in the config, but not applied live: {msg}")

    def _redraw(self) -> None:
        samples = list(self.hist.get(self.net, ()))
        if len(samples) < 2:
            self.c_rx.setData([], []); self.c_tx.setData([], [])
            return
        w = AGG[self.agg.currentIndex()][1]
        # keep the last cumulative sample in each time bucket
        buckets: dict[int, tuple[float, int, int]] = {}
        for t, rx, tx in samples:
            buckets[int(t // w)] = (t, rx, tx)
        keys = sorted(buckets)
        ts, rxr, txr = [], [], []
        for i in range(1, len(keys)):
            t0, rx0, tx0 = buckets[keys[i - 1]]
            t1, rx1, tx1 = buckets[keys[i]]
            dt = t1 - t0
            if dt <= 0:
                continue
            ts.append(t1)
            rxr.append(max(0, rx1 - rx0) * 8 / dt)
            txr.append(max(0, tx1 - tx0) * 8 / dt)
        self.c_rx.setData(ts, rxr)
        self.c_tx.setData(ts, txr)
        if self._follow and ts:
            span = max(60, min(ts[-1] - ts[0], 1800))
            self.plot.setXRange(ts[-1] - span, ts[-1], padding=0.02)
            self.plot.enableAutoRange(axis="y")


# ---- interactive Network editor (options + nodes + keys) ---------------------

class OptionDialog(QtWidgets.QDialog):
    """Pick a known option (or a custom one) to add."""
    def __init__(self, parent: QtWidgets.QWidget | None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Add option")
        self.resize(460, 140)
        form = QtWidgets.QFormLayout(self)
        self.combo = QtWidgets.QComboBox()
        for name, kind, choices, helptext in KNOWN_OPTIONS:
            self.combo.addItem(name)
            self.combo.setItemData(self.combo.count() - 1, helptext, QtCore.Qt.ToolTipRole)
        self.combo.setEditable(True)   # allow custom option names too
        self.combo.currentTextChanged.connect(self._on_change)
        form.addRow("Option:", self.combo)
        self.help = QtWidgets.QLabel(); self.help.setWordWrap(True); self.help.setStyleSheet("color:#9aa0a6;")
        form.addRow("", self.help)
        bb = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        bb.accepted.connect(self.accept); bb.rejected.connect(self.reject)
        form.addRow(bb)
        self._on_change(self.combo.currentText())

    def _on_change(self, name: str) -> None:
        o = KNOWN_BY_NAME.get(name)
        self.help.setText(o[3] if o else "Custom option")

    def chosen(self) -> str:
        return self.combo.currentText().strip()


class NetworkTab(QtWidgets.QWidget):
    def __init__(self, ctx: "MainWindow") -> None:
        super().__init__()
        self.ctx = ctx
        root = QtWidgets.QVBoxLayout(self)
        split = QtWidgets.QHBoxLayout()

        # -- left: options --
        left = QtWidgets.QVBoxLayout()
        head = QtWidgets.QHBoxLayout()
        head.addWidget(QtWidgets.QLabel("<b>tinc.conf options</b>"))
        self.autostart = QtWidgets.QCheckBox("Autostart")
        head.addStretch(); head.addWidget(self.autostart)
        left.addLayout(head)
        self.opts = QtWidgets.QTableWidget(0, 2)
        self.opts.setHorizontalHeaderLabels(["Option", "Value"])
        self.opts.horizontalHeader().setStretchLastSection(True)
        self.opts.verticalHeader().setVisible(False)
        left.addWidget(self.opts)
        orow = QtWidgets.QHBoxLayout()
        ab = QtWidgets.QPushButton("➕ Add option"); ab.clicked.connect(self._add_opt)
        rb = QtWidgets.QPushButton("➖ Remove"); rb.clicked.connect(self._del_opt)
        orow.addWidget(ab); orow.addWidget(rb); orow.addStretch()
        left.addLayout(orow)

        # -- this node's private-key identity (generate / paste) --
        sep = QtWidgets.QFrame(); sep.setFrameShape(QtWidgets.QFrame.HLine)
        left.addSpacing(4); left.addWidget(sep)
        left.addWidget(QtWidgets.QLabel("<b>Private keys</b> · this node"))
        krow = QtWidgets.QHBoxLayout()
        gk = QtWidgets.QPushButton("🔑 Generate"); gk.clicked.connect(self._genkeys)
        gk.setToolTip("Re-key this node (Ed25519+RSA) and refresh its public host file (Subnet is kept).\n"
                      "A fresh network needs no keys: the daemon generates them on first start.\n"
                      "Overwrites existing keys — afterwards you MUST re-invite / re-share your host\n"
                      "file, or peers reject you.")
        ik = QtWidgets.QPushButton("📥 Import (paste)"); ik.clicked.connect(self._import_keys)
        ik.setToolTip("Paste existing Ed25519/RSA PRIVATE key PEM to restore this node's identity.\n"
                      "The matching public host file must also be present.")
        krow.addWidget(gk); krow.addWidget(ik); krow.addStretch()
        left.addLayout(krow)
        hint = QtWidgets.QLabel("secret identity — one per network; generated by the daemon if absent")
        hint.setStyleSheet("color:#9aa0a6;")
        left.addWidget(hint)
        split.addLayout(left, stretch=3)

        # -- right: nodes/hosts --
        right = QtWidgets.QVBoxLayout()
        right.addWidget(QtWidgets.QLabel("<b>Nodes (hosts)</b>"))
        self.nodes = QtWidgets.QListWidget()
        self.nodes.currentItemChanged.connect(self._show_host)
        right.addWidget(self.nodes, stretch=1)
        nrow = QtWidgets.QHBoxLayout()
        for label, slot, tip in [
                ("Add/Save", self._save_host, "Save the text below as this node's host file"),
                ("Del", self._del_host, "Delete the selected node's host file"),
                ("Import host", self._import_host, "Import a peer's PUBLIC host file from disk"),
                ("Export host", self._export_host,
                 "Export the selected node's PUBLIC host file to disk (share it with peers)")]:
            b = QtWidgets.QPushButton(label); b.clicked.connect(slot); b.setToolTip(tip); nrow.addWidget(b)
        right.addLayout(nrow)
        right.addWidget(QtWidgets.QLabel("Node name:"))
        self.host_name = QtWidgets.QLineEdit()
        right.addWidget(self.host_name)
        self.host_edit = QtWidgets.QPlainTextEdit()
        self.host_edit.setFont(QtGui.QFont("Consolas" if os.name == "nt" else "Monospace", 9))
        right.addWidget(self.host_edit, stretch=2)
        split.addLayout(right, stretch=2)
        root.addLayout(split)

        # bottom bar
        bar = QtWidgets.QHBoxLayout()
        sb = QtWidgets.QPushButton("💾 Save config"); sb.clicked.connect(self._save_all)
        rb2 = QtWidgets.QPushButton("Reload"); rb2.clicked.connect(self.reload)
        yb = QtWidgets.QPushButton("Raw YAML…"); yb.clicked.connect(self.ctx.open_raw_yaml)
        bar.addWidget(sb); bar.addWidget(rb2); bar.addWidget(yb); bar.addStretch()
        root.addLayout(bar)

    # --- helpers ---
    def set_network(self, net: str | None) -> None:
        self.reload()

    def reload(self) -> None:
        nc = self.ctx.cur_netcfg()
        self.opts.setRowCount(0)
        self.nodes.clear()
        self.host_name.clear(); self.host_edit.clear()
        if not nc:
            return
        self.autostart.setChecked(nc.autostart)
        for line in options_to_conf(nc.options).splitlines():
            if " = " in line:
                k, v = line.split(" = ", 1)
                self._add_row(k.strip(), v.strip())
        # tincmgr-only field, surfaced as an editable row alongside the tinc options
        self._add_row("wintun_mtu", str(nc.wintun_mtu))
        for hn in sorted(nc.hosts):
            tag = "🔑" if nc.node_name == hn else "   "
            it = QtWidgets.QListWidgetItem(f"{tag} {hn}")
            it.setData(QtCore.Qt.UserRole, hn)
            self.nodes.addItem(it)

    def _add_row(self, key: str, value: str) -> None:
        r = self.opts.rowCount()
        self.opts.insertRow(r)
        kitem = QtWidgets.QTableWidgetItem(key)
        o = KNOWN_BY_NAME.get(key)
        if o:
            kitem.setToolTip(o[3])
        self.opts.setItem(r, 0, kitem)
        # value: combo for enum/bool, else editable text
        if o and o[1] == "enum":
            cb = QtWidgets.QComboBox(); cb.addItems(o[2])
            if value in o[2]:
                cb.setCurrentText(value)
            self.opts.setCellWidget(r, 1, cb)
        elif o and o[1] == "bool":
            cb = QtWidgets.QComboBox(); cb.addItems(["yes", "no"])
            cb.setCurrentText("yes" if str(value).lower() in ("yes", "true", "1") else "no")
            self.opts.setCellWidget(r, 1, cb)
        else:
            self.opts.setItem(r, 1, QtWidgets.QTableWidgetItem(value))

    def _row_value(self, r: int) -> str:
        w = self.opts.cellWidget(r, 1)
        if isinstance(w, QtWidgets.QComboBox):
            return w.currentText()
        it = self.opts.item(r, 1)
        return it.text() if it else ""

    def _add_opt(self) -> None:
        if not self.ctx.cur_netcfg():
            return
        dlg = OptionDialog(self)
        if dlg.exec() == QtWidgets.QDialog.Accepted and dlg.chosen():
            name = dlg.chosen()
            o = KNOWN_BY_NAME.get(name)
            default = "yes" if (o and o[1] == "bool") else (o[2][0] if (o and o[1] == "enum") else "")
            self._add_row(name, default)

    def _del_opt(self) -> None:
        r = self.opts.currentRow()
        if r >= 0:
            self.opts.removeRow(r)

    def _show_host(self) -> None:
        nc = self.ctx.cur_netcfg(); it = self.nodes.currentItem()
        if not nc or not it:
            return
        name = it.data(QtCore.Qt.UserRole)
        self.host_name.setText(name)
        self.host_edit.setPlainText(nc.hosts.get(name, ""))

    def _save_host(self) -> None:
        nc = self.ctx.cur_netcfg()
        if not nc:
            return
        name = self.host_name.text().strip()
        if not name:
            self.ctx.status("node name is empty"); return
        nc.hosts[name] = self.host_edit.toPlainText().rstrip("\n")
        blocked = nc.options.get("BlockedNodes")
        if isinstance(blocked, list) and name in blocked:
            blocked.remove(name)
            if not blocked:
                nc.options.pop("BlockedNodes", None)
        elif isinstance(blocked, str) and blocked.strip() == name:
            nc.options.pop("BlockedNodes", None)
        self.ctx.save_config(f"saved host {name}"); self.reload()

    def _del_host(self) -> None:
        nc = self.ctx.cur_netcfg(); name = self.host_name.text().strip()
        if not nc or name not in nc.hosts:
            return
        if QtWidgets.QMessageBox.question(self, "Delete node", f"Delete host '{name}'?") == QtWidgets.QMessageBox.Yes:
            nc.hosts.pop(name, None)
            blocked = nc.options.get("BlockedNodes")
            if isinstance(blocked, list):
                if name not in blocked:
                    blocked.append(name)
            elif isinstance(blocked, str) and blocked.strip():
                if blocked.strip() != name:
                    nc.options["BlockedNodes"] = [blocked.strip(), name]
            else:
                nc.options["BlockedNodes"] = [name]
            self.ctx.save_config(f"deleted host {name}"); self.reload()

    def _import_host(self) -> None:
        nc = self.ctx.cur_netcfg()
        if not nc:
            return
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Import host file")
        if path:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                nc.hosts[os.path.basename(path)] = f.read().rstrip("\n")
            self.ctx.save_config(f"imported {os.path.basename(path)}"); self.reload()

    def _export_host(self) -> None:
        nc = self.ctx.cur_netcfg(); name = self.host_name.text().strip()
        if not nc:
            return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export host file", name)
        if path:
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(nc.hosts.get(name, ""))
            self.ctx.status(f"exported {name}")

    def _genkeys(self) -> None:
        self.ctx.genkeys()

    def _import_keys(self) -> None:
        """Paste existing private-key PEM block(s) → fold into the network's keys:."""
        nc = self.ctx.cur_netcfg()
        if not nc:
            return
        dlg = QtWidgets.QDialog(self); dlg.setWindowTitle("Import private keys"); dlg.resize(680, 520)
        lay = QtWidgets.QVBoxLayout(dlg)
        lay.addWidget(QtWidgets.QLabel(
            "Paste the Ed25519 and/or RSA <b>private</b> key PEM block(s) — the contents of "
            "ed25519_key.priv / rsa_key.priv. Both may be pasted together."))
        ed = QtWidgets.QPlainTextEdit(); ed.setFont(QtGui.QFont("Consolas" if os.name == "nt" else "Monospace", 10))
        ed.setPlaceholderText(
            "-----BEGIN ED25519 PRIVATE KEY-----\n...\n-----END ED25519 PRIVATE KEY-----\n"
            "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----")
        lay.addWidget(ed, stretch=1)
        info = QtWidgets.QLabel(); info.setStyleSheet("color:#9aa0a6;")
        lay.addWidget(info)

        def parse(text: str) -> dict[str, str]:
            found = {}
            for ykey, tag in (("ed25519_priv", "ED25519"), ("rsa_priv", "RSA")):
                m = re.search(rf"-----BEGIN {tag} PRIVATE KEY-----.*?-----END {tag} PRIVATE KEY-----",
                              text, re.DOTALL)
                if m:
                    found[ykey] = m.group(0).strip()
            return found

        def refresh() -> None:
            f = parse(ed.toPlainText())
            info.setText("detected:   ed25519 %s     rsa %s" % (
                "✓" if "ed25519_priv" in f else "—", "✓" if "rsa_priv" in f else "—"))
        ed.textChanged.connect(refresh); refresh()

        bb = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Save | QtWidgets.QDialogButtonBox.Cancel)
        lay.addWidget(bb); bb.rejected.connect(dlg.reject)

        def save() -> None:
            found = parse(ed.toPlainText())
            if not found:
                QtWidgets.QMessageBox.warning(dlg, "Import keys",
                    "No private-key block found.\nExpected -----BEGIN ED25519 PRIVATE KEY----- "
                    "and/or -----BEGIN RSA PRIVATE KEY-----.")
                return
            clash = sorted(k for k in found if nc.keys.get(k))
            if clash and QtWidgets.QMessageBox.question(
                    dlg, "Import keys",
                    f"'{self.ctx.cur_net()}' already has {' and '.join(clash)}. Overwrite?"
                    ) != QtWidgets.QMessageBox.Yes:
                return
            nc.keys.update(found)
            self.ctx.save_config("imported keys: " + ", ".join(sorted(found)))
            node = nc.node_name
            host = nc.hosts.get(node, "")
            if "Ed25519PublicKey" in host and "RSA PUBLIC KEY" in host:
                note = (f"Private keys imported for '{node}'.\n\nThis node already has a public "
                        f"host file — make sure its public keys MATCH the private keys you just "
                        f"pasted (same identity), or peers will reject this node.")
            else:
                note = (f"Private keys imported for '{node}', but this node has no matching public "
                        f"host file yet.\n\nPaste your PUBLIC host file into the node editor on the "
                        f"right (select '{node}' → paste → Add/Save) — the public key can't be "
                        f"derived here from the private key, and peers need it.")
            QtWidgets.QMessageBox.information(dlg, "Keys imported", note)
            dlg.accept(); self.reload()

        bb.accepted.connect(save)
        dlg.exec()

    def _save_all(self) -> None:
        nc = self.ctx.cur_netcfg()
        if not nc:
            return
        lines = []
        mtu = 0
        for r in range(self.opts.rowCount()):
            kit = self.opts.item(r, 0)
            if not kit or not kit.text().strip():
                continue
            key = kit.text().strip()
            val = self._row_value(r)
            if key == "wintun_mtu":            # tincmgr field — keep it out of tinc.conf
                try:
                    mtu = int(str(val).strip() or "0")
                except ValueError:
                    mtu = 0
                continue
            lines.append(f"{key} = {val}")
        new_opts = conf_to_options("\n".join(lines))
        # keep list-valued transport keys as lists (the table shows them joined)
        for k in ("Transports", "PreferredTransports"):
            if k in new_opts:
                new_opts[k] = transports.parse_carrier_list(new_opts[k])
        errs = transports.validate(new_opts)
        if errs:
            self.ctx.status("not saved: " + "; ".join(errs))
            return
        nc.options = new_opts
        nc.autostart = self.autostart.isChecked()
        nc.wintun_mtu = mtu
        self.ctx.save_config("config saved (restart network to apply)")


# ---- Transports tab -----------------------------------------------------------

class TransportsTab(QtWidgets.QWidget):
    def __init__(self, ctx: "MainWindow") -> None:
        super().__init__()
        self.ctx = ctx
        root = QtWidgets.QVBoxLayout(self)
        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        self.panel = TransportsPanel()
        scroll.setWidget(self.panel)
        root.addWidget(scroll, stretch=1)
        self.error_lbl = QtWidgets.QLabel("")
        self.error_lbl.setWordWrap(True)
        self.error_lbl.setStyleSheet("color:#d93025;")
        root.addWidget(self.error_lbl)
        bar = QtWidgets.QHBoxLayout()
        self.save_btn = QtWidgets.QPushButton("💾 Save transports")
        self.save_btn.clicked.connect(self.save)
        rb = QtWidgets.QPushButton("Reload")
        rb.clicked.connect(self.reload)
        bar.addWidget(self.save_btn); bar.addWidget(rb); bar.addStretch()
        root.addLayout(bar)
        self.panel.changed.connect(self._preview)

    def set_network(self, net: str | None) -> None:
        self.reload()

    def reload(self) -> None:
        nc = self.ctx.cur_netcfg()
        self.panel.setEnabled(nc is not None)
        self.panel.load(nc.options if nc else {})
        self.error_lbl.setText("")

    def _preview(self) -> None:
        errs = self.panel.errors()
        if errs:
            self.error_lbl.setText("; ".join(errs))
            return
        delta = self.panel.changes()
        self.error_lbl.setText("" if not delta else
                               "will write: " + ", ".join(f"{k}={v}" for k, v in delta.items()))

    def save(self) -> bool:
        nc = self.ctx.cur_netcfg()
        if not nc:
            return False
        errs = self.panel.errors()
        if errs:
            self.error_lbl.setText("; ".join(errs))
            self.ctx.status("transports not saved: fix the errors first")
            return False
        delta = self.panel.changes()
        if not delta:
            self.ctx.status("transports: no changes")
            return True
        transports.apply_changes(nc.options, delta)
        self.ctx.save_config("transports saved: " + ", ".join(delta) + " (restart network to apply)")
        self.reload()
        return True


# ---- main window -------------------------------------------------------------

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, cfg_path: str, runner: Any = None, autostart: bool = True) -> None:
        super().__init__()
        self.admin = management.is_admin()
        self.pool = WorkerPool(self)
        self._running: dict[str, bool] = {}
        self._wanted_running: dict[str, bool] = {}
        self._last_autorestart: dict[str, float] = {}
        self.load_error = ""
        self.app = self._load(cfg_path)
        self.rt = Runtime(self.app)
        self.tc = TincControl(tinc_exe=self.rt.tinc, yaml_path=self.app.path, runner=runner)
        self.diag_collector = diagnostics.TelemetryCollector(self.rt.base)
        self.diag_prober = diagnostics.ActiveProber(self.tc, lambda: self.app, self.rt.base)
        self.diag_server = diagnostics.DiagWebServer(
            self.rt.base, self.tc, self.diag_collector, self.diag_prober, lambda: self.app, self.rt
        )

        ver = management.current_version()
        ver_str = f" {ver}" if ver else ""
        self.setWindowTitle(f"tincmgr{ver_str}" + ("  [admin]" if self.admin else "  [not elevated]"))
        self.resize(1180, 780)
        self._build_toolbar()

        central = QtWidgets.QWidget(); self.setCentralWidget(central)
        outer = QtWidgets.QVBoxLayout(central)
        self.banner = QtWidgets.QFrame()
        self.banner.setObjectName("errorBanner")
        self.banner.setStyleSheet(
            "QFrame#errorBanner{background:#3b1818;border:1px solid #d93025;border-radius:6px;}"
        )
        bl = QtWidgets.QHBoxLayout(self.banner)
        self.banner_lbl = QtWidgets.QLabel("")
        self.banner_lbl.setWordWrap(True)
        self.banner_lbl.setStyleSheet("color:#fad2cf;background:transparent;border:none;")
        bl.addWidget(self.banner_lbl, stretch=1)
        fix = QtWidgets.QPushButton("Open raw YAML…"); fix.clicked.connect(self.open_raw_yaml)
        retry = QtWidgets.QPushButton("Reload"); retry.clicked.connect(self.reload_config)
        bl.addWidget(fix); bl.addWidget(retry)
        self.banner.hide()
        outer.addWidget(self.banner)

        h = QtWidgets.QHBoxLayout()
        left = QtWidgets.QVBoxLayout()
        left.addWidget(QtWidgets.QLabel("<b>Networks</b>"))
        self.net_list = QtWidgets.QListWidget()
        self.net_list.setMaximumWidth(220)
        self.net_list.currentItemChanged.connect(self._on_net_changed)
        left.addWidget(self.net_list)
        nb = QtWidgets.QHBoxLayout()
        addn = QtWidgets.QPushButton("＋"); addn.setToolTip("Add network"); addn.clicked.connect(self._add_net)
        deln = QtWidgets.QPushButton("－"); deln.setToolTip("Remove network"); deln.clicked.connect(self._del_net)
        nb.addWidget(addn); nb.addWidget(deln); left.addLayout(nb)
        h.addLayout(left)

        self.tabs = QtWidgets.QTabWidget()
        self.peers = PeersTab(self.tc, lambda: list(self.app.networks), self.pool,
                              self._on_running, ctx=self)
        self.network = NetworkTab(self)
        self.transports = TransportsTab(self)
        self.tabs.addTab(self.peers, "Peers && Traffic")
        self.tabs.addTab(self.network, "Network")
        self.tabs.addTab(self.transports, "Transports")
        h.addWidget(self.tabs, stretch=1)
        outer.addLayout(h, stretch=1)

        self.statusBar()
        self._status_hold_until = 0.0
        self.timer = QtCore.QTimer(self)
        self.timer.setInterval(REFRESH_MS)
        self.timer.timeout.connect(self._tick)
        self.timer.start()
        self.cert_timer = QtCore.QTimer(self)
        self.cert_timer.setInterval(self.CERT_WATCH_MS)
        self.cert_timer.timeout.connect(self._cert_watch)
        self.cert_timer.start()
        self.update_timer = QtCore.QTimer(self)
        self.update_timer.setInterval(updates.CHECK_MIN_SECS * 1000)
        self.update_timer.timeout.connect(self._update_check_start)
        self.update_timer.start()
        self._quitting = False
        self._update_banner = None
        self._available_update: updates.Release | None = None
        self._build_tray()
        self._show_load_error()
        self.reload_networks()
        self.peers.sample_async()
        self._update_check_start()
        if autostart:
            QtCore.QTimer.singleShot(300, self._autostart)

    # -- config loading with the malformed-YAML guard --
    def _load(self, cfg_path: str) -> AppConfig:
        try:
            app = yaml_config.load(cfg_path)
            self.load_error = ""
            return app
        except ConfigError as e:
            self.load_error = str(e)
            return AppConfig(path=cfg_path)

    def _show_load_error(self) -> None:
        if self.load_error:
            self.banner_lbl.setText(f"<b>tinc.yaml could not be read — networks are not managed until "
                                    f"it is fixed.</b><br>{self.load_error}")
            self.banner.show()
        else:
            self.banner.hide()

    # tray
    def _make_icon(self) -> QtGui.QIcon:
        pm = QtGui.QPixmap(32, 32)
        pm.fill(QtCore.Qt.transparent)
        p = QtGui.QPainter(pm)
        p.setRenderHint(QtGui.QPainter.Antialiasing)
        p.setBrush(QtGui.QColor("#1e8e3e"))
        p.setPen(QtGui.QPen(QtGui.QColor("#0b3d1a"), 2))
        p.drawEllipse(4, 4, 24, 24)
        p.setPen(QtGui.QColor("white"))
        f = p.font(); f.setBold(True); f.setPointSize(13); p.setFont(f)
        p.drawText(pm.rect(), QtCore.Qt.AlignCenter, "t")
        p.end()
        return QtGui.QIcon(pm)

    def _build_tray(self) -> None:
        icon = self._make_icon()
        self.setWindowIcon(icon)
        if not QtWidgets.QSystemTrayIcon.isSystemTrayAvailable():
            self.tray = None
            return
        ver = management.current_version()
        self.tray = QtWidgets.QSystemTrayIcon(icon, self)
        self.tray.setToolTip(f"tincmgr {ver}" if ver else "tincmgr")
        menu = QtWidgets.QMenu()
        menu.addAction("Show window", self._show_window)
        self.net_menu = menu.addMenu("Networks")
        self.net_menu.aboutToShow.connect(self._rebuild_net_menu)
        menu.addSeparator()
        menu.addAction("⚡ Mark Lag / Issue Now", self.mark_lag_quick)
        menu.addAction("🩺 Diagnostics & Web Panel…", self.open_diagnostics)
        menu.addAction("Check for updates…", self.check_updates_manual)
        menu.addSeparator()
        menu.addAction("Exit", self._quit_app)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self._tray_activated)
        self.tray.show()

    def _tray_activated(self, reason: Any) -> None:
        if reason in (QtWidgets.QSystemTrayIcon.DoubleClick, QtWidgets.QSystemTrayIcon.Trigger):
            self._show_window()

    def _show_window(self) -> None:
        self.showNormal(); self.raise_(); self.activateWindow()

    def _rebuild_net_menu(self) -> None:
        self.net_menu.clear()
        for name in self.app.networks:
            running = self._running.get(name, False)
            act = self.net_menu.addAction(("● " if running else "○ ") + name)
            act.setCheckable(True); act.setChecked(running)
            act.triggered.connect(lambda checked, n=name: self._tray_toggle_net(n, checked))

    def _tray_toggle_net(self, name: str, checked: bool) -> None:
        if not self.admin:
            if self.tray:
                self.tray.showMessage("tincmgr", "Elevation needed to change networks",
                                      QtWidgets.QSystemTrayIcon.Warning, 2500)
            return
        self._lifecycle(self.rt.start if checked else self.rt.stop, name, "start" if checked else "stop")

    def _quit_app(self) -> None:
        self._quitting = True
        self.close()

    # context API for tabs
    def cur_net(self) -> str | None:
        it = self.net_list.currentItem()
        return it.data(QtCore.Qt.UserRole) if it else None

    def cur_netcfg(self) -> NetworkCfg | None:
        n = self.cur_net()
        return self.app.net(n) if n else None

    def status(self, msg: str, hold_secs: float = 5.0) -> None:
        if hold_secs > 0:
            self._status_hold_until = time.time() + hold_secs
        self.statusBar().showMessage(msg)

    def refresh_startup_async(self, exe: str) -> None:
        """management.refresh_startup_task() on a worker: it runs schtasks
        (one /query, /create and PowerShell when migrating) and may copy the
        whole app tree into Program Files -- seconds the window must not
        freeze for at every start."""
        self.pool.run(management.refresh_startup_task, exe, tag="startup-task",
                      on_done=lambda n: self.status(n) if n else None,
                      on_error=lambda m: self.status(f"run-at-startup: {m[:100]}"))

    def save_config(self, msg: str = "") -> bool:
        try:
            yaml_config.save(self.app)
        except (ConfigError, OSError) as e:
            self.load_error = f"save failed: {e}"
            self._show_load_error()
            self.status(f"NOT saved: {e}")
            return False
        if msg:
            self.status(msg)
        return True

    def reload_config(self) -> None:
        cur = self.cur_net()
        self.app = self._load(self.app.path)
        self.rt.app = self.app
        self._show_load_error()
        self.reload_networks()
        if cur:
            self._select_net(cur)
        self._on_net_changed()

    def open_raw_yaml(self) -> None:
        dlg = RawYamlDialog(self, self.app.path, yaml_config.save_text, self.load_error)
        dlg.saved.connect(self.reload_config)
        dlg.exec()

    def genkeys(self) -> None:
        net = self.cur_net()
        if not net:
            return
        nc = self.app.net(net)
        if nc.keys and QtWidgets.QMessageBox.question(
                self, "Generate keys", f"'{net}' already has keys. Overwrite?") != QtWidgets.QMessageBox.Yes:
            return
        self.status(f"genkeys {net}: running tinc generate-keys…")

        def done(result: tuple[bool, str]) -> None:
            ok, msg = result
            if not ok:
                self.status(f"genkeys {net}: {msg}")
                return
            self.save_config(f"genkeys {net}: {msg}")
            self.network.reload()
            node = nc.node_name
            no_subnet = "" if "Subnet" in nc.hosts.get(node, "") else (
                "\n• NOTE: this node has no Subnet line — add one, or it won't be routable.")
            QtWidgets.QMessageBox.information(
                self, "Keys generated",
                f"New identity generated for '{node}'.\n\n"
                f"• Public keys were refreshed in this node's host file (Subnet kept).\n"
                f"• Peers still have your OLD public key and will REJECT this node until you "
                f"re-share your host file (Export host → send to peers, or re-invite).\n"
                f"• The previous private keys were overwritten and can't be recovered.{no_subnet}")
        self.pool.run(self.rt.generate_keys, net, tag=f"genkeys-{net}", on_done=done,
                      on_error=lambda m: self.status(f"genkeys {net}: {m}"))

    # toolbar
    def _build_toolbar(self) -> None:
        tb = self.addToolBar("Actions"); tb.setMovable(False)
        tb.addAction("▶ Start", self._start)
        tb.addAction("■ Stop", self._stop)
        tb.addAction("⟳ Restart", self._restart)
        tb.addSeparator()
        self.invite_act = tb.addAction("✉ Invite…", self.open_invite)
        self.join_act = tb.addAction("⤵ Join…", self.open_join)
        self.cert_act = tb.addAction("🔐 Certificate…", self.open_cert)
        self.cert_act.setToolTip("TLS certificate for the https/quic transports: replace the "
                                 "self-signed one with a real certificate for a domain, using a "
                                 "Cloudflare API token.")
        tb.addSeparator()
        self.mark_act = tb.addAction("⚡ Mark Lag", self.mark_lag_quick)
        self.mark_act.setToolTip("Record an instant anomaly/lag marker in the local diagnostic log "
                                 "with current peer RTT, PMTU, and transport state.")
        self.diag_act = tb.addAction("🩺 Diagnostics…", self.open_diagnostics)
        self._sync_diag_action()
        tb.addSeparator()
        self.startup_radio = QtWidgets.QRadioButton()
        self.startup_radio.setAutoExclusive(False)   # standalone on/off, not a group
        self.startup_radio.setToolTip("Green = enabled, red = disabled. Creates a logon "
                                      "Scheduled Task (elevated, no UAC prompt) that launches "
                                      "tincmgr at Windows startup.")
        self.startup_radio.toggled.connect(self._toggle_startup)
        tb.addWidget(self.startup_radio)
        self._sync_startup_radio()
        tb.addAction("📁 Open folder", self._open_folder)
        tb.addAction("↻ Reload config", self.reload_config)
        self.update_act = tb.addAction("🔄 Check updates", self.check_updates_manual)
        self.update_act.setToolTip("Check GitHub Releases for a newer tincmgr build and install it in place.")
        if not self.admin:
            tb.addSeparator()
            tb.addAction("🛡 Run as admin", self._elevate)

    def _sync_diag_action(self) -> None:
        if not hasattr(self, "diag_act"):
            return
        if hasattr(self, "diag_server") and self.diag_server.enabled:
            self.diag_act.setText(f"🩺 Diag ON (:{self.diag_server.port})")
            self.diag_act.setToolTip(
                f"Remote Diagnostic Web Server is ENABLED on port {self.diag_server.port}.\n"
                f"Click to open WebUI, view incidents, or disable the server."
            )
        else:
            self.diag_act.setText("🩺 Diagnostics…")
            self.diag_act.setToolTip(
                "Open Diagnostics & Remote Web Panel (view detected tunnel anomalies, "
                "enable/disable the in-VPN diagnostic web server)."
            )

    def mark_lag_quick(self) -> None:
        net = self.cur_net()
        if not net:
            self.status("Select a network first to mark a lag event.")
            return
        ev = self.diag_collector.record_user_mark(net, "User clicked 'Mark Lag' in tincmgr")
        self.status(f"⚡ Marked lag event for '{net}' at {ev.to_dict()['time_str']}")

    def open_diagnostics(self) -> DiagnosticsDialog:
        dlg = DiagnosticsDialog(self, self.diag_server, self.diag_collector, self.cur_net())
        dlg.state_changed.connect(self._sync_diag_action)
        dlg.exec()
        self._sync_diag_action()
        return dlg

    def _open_folder(self) -> None:
        if os.path.isdir(self.rt.base):
            QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(self.rt.base))

    # -- invite / join --
    def open_invite(self) -> InviteDialog | None:
        net = self.cur_net()
        if not net:
            self.status("select a network to invite into")
            return None
        if not self._running.get(net, False):
            self.status(f"'{net}' is not running — start it first (the daemon issues the invitation)")
        dlg = InviteDialog(self, net, self.tc.invite, self.pool)
        dlg.exec()
        return dlg

    def open_cert(self) -> CertDialog | None:
        net = self.cur_net()
        nc = self.cur_netcfg()
        if not net or not nc:
            self.status("select a network first")
            return None
        dlg = CertDialog(self, net, nc.options, self._save_cert_options,
                         self.tc.cert_status, self.tc.cert_check, self.tc.cert_issue, self.pool)
        dlg.saved.connect(self.reload_networks)
        dlg.exec()
        self._cert_watch()          # a renewal just happened, or did not
        return dlg

    def _save_cert_options(self, values: dict) -> bool:
        """Write the certificate options of the selected network. An empty value
        removes the key: clearing the token has to actually disable ACME, not
        leave an empty string that then fails the token sanity check."""
        nc = self.cur_netcfg()
        if not nc:
            return False
        for key, value in values.items():
            if value:
                nc.options[key] = value
            else:
                nc.options.pop(key, None)
        return self.save_config(f"certificate settings saved for '{self.cur_net()}'")

    def open_join(self) -> JoinDialog | None:
        dlg = JoinDialog(self, list(self.app.networks), self.tc.join, self.pool)
        dlg.joined.connect(self._on_joined)
        dlg.exec()
        return dlg

    def _on_joined(self, net: str) -> None:
        self.reload_config()
        if net:
            self._select_net(net)
        self.status(f"joined {net or 'network'} — select it and Start")

    def reload_networks(self) -> None:
        cur = self.cur_net()
        self.net_list.blockSignals(True)
        self.net_list.clear()
        for name in self.app.networks:
            running = self._running.get(name, False)
            auto = self.app.net(name).autostart
            label = f"{name}   [{'running' if running else 'stopped'}]" + ("  ★" if auto else "")
            it = QtWidgets.QListWidgetItem(label)
            it.setData(QtCore.Qt.UserRole, name)
            it.setForeground(QtGui.QColor("#1e8e3e" if running else "#9aa0a6"))
            self.net_list.addItem(it)
        self.net_list.blockSignals(False)
        if not (cur and self._select_net(cur)) and self.net_list.count():
            self.net_list.setCurrentRow(0)

    def _on_running(self, running: dict[str, bool]) -> None:
        """Called from the sampler (Qt thread) with fresh running flags."""
        prev = dict(self._running)
        changed = any(self._running.get(n) != v for n, v in running.items())
        self._running.update(running)
        if changed:
            self.reload_networks()
        now = time.time()
        # a running network with a full tunnel configured but no maintainer
        # (its daemon outlived a previous manager, or was started elsewhere)
        for net, up in running.items():
            nc = self.app.net(net)
            if up and self.admin and nc and nc.full_tunnel and not self.rt.full_tunnel_state(net):
                self.pool.run(self.rt.full_tunnel_sync, net, tag=f"fulltunnel-{net}")
            # If tincd exited unexpectedly while the network was supposed to be running,
            # automatically restart it so the user does not have to manually start it again.
            if (not up and prev.get(net, False) and self._wanted_running.get(net, False)
                    and self.admin and not self.quitting_or_busy(net)
                    and (now - self._last_autorestart.get(net, 0.0)) >= 10.0):
                self._last_autorestart[net] = now
                self._lifecycle(self.rt.start, net, "auto-restart")

    def quitting_or_busy(self, net: str) -> bool:
        return bool(getattr(self, "_quitting", False) or self.pool.busy(f"life-{net}"))

    def _select_net(self, name: str) -> bool:
        for i in range(self.net_list.count()):
            if self.net_list.item(i).data(QtCore.Qt.UserRole) == name:
                self.net_list.setCurrentRow(i)
                return True
        return False

    def _on_net_changed(self, *_: Any) -> None:
        net = self.cur_net()
        self.peers.set_network(net)
        self.network.set_network(net)
        self.transports.set_network(net)
        self._cert_watch()

    # -- certificate expiry --
    # Nothing renews the front's certificate on its own: `tinc cert renew` is a
    # command, and on Windows there is nothing running it. The daemon warns in
    # its log once a day, which nobody reads; this is the same warning where the
    # operator is actually looking, with the button that fixes it right there.
    CERT_WATCH_MS = 6 * 3600 * 1000

    def _cert_threshold(self, nc: NetworkCfg) -> int:
        try:
            return max(1, int(str(nc.options.get("AcmeRenewDays", 30)).strip()))
        except (TypeError, ValueError):
            return 30

    def _cert_watch(self) -> None:
        """One `tinc cert status` for the selected network — a local config read,
        no network — whenever ACME is configured for it."""
        net, nc = self.cur_net(), self.cur_netcfg()
        if not net or not nc or not str(nc.options.get("CertDomain", "")).strip():
            self._cert_badge(None, 30)
            return
        threshold = self._cert_threshold(nc)
        self.pool.run(self.tc.cert_status, net, tag="cert-watch",
                      on_done=lambda res, n=net, t=threshold: self._cert_seen(n, t, res),
                      on_error=lambda _msg: None)

    def _cert_seen(self, net: str, threshold: int, res: Any) -> None:
        if net != self.cur_net():
            return
        text = f"{getattr(res, 'stdout', '')}\n{getattr(res, 'stderr', '')}"
        self._cert_badge(parse_cert_expiry(text), threshold)

    # -- update check (GitHub Releases; at most one network poll per 3 h) ----

    def _update_check_start(self) -> None:
        if not management.is_frozen():
            return                       # a dev run never phones home automatically
        updates.cleanup_old_workdirs()
        installed = management.current_version()
        last = updates.read_last_check(management.state_dir())
        now = time.time()
        self.pool.run(
            updates.check,
            installed,
            now,
            last,
            tag="update-check",
            on_done=lambda rel, lm=last, t=now: self._update_seen(rel, lm, t),
            on_error=lambda _msg: None,
        )

    def check_updates_manual(self) -> None:
        """Triggered by the user clicking 'Check updates' in the toolbar or tray."""
        if self._available_update is not None and self._update_banner is not None and self._update_banner.isHidden():
            self._update_banner.show()
        installed = management.current_version()
        self.status("Checking GitHub Releases for updates…", hold_secs=10.0)
        if hasattr(self, "update_act"):
            self.update_act.setEnabled(False)
        self.pool.run(
            updates.check_detailed,
            installed,
            tag="update-check-manual",
            on_done=lambda res, cur=installed: self._update_manual_done(res, cur),
            on_error=lambda msg: self._update_manual_done(("error", None, msg), installed),
        )

    def _update_manual_done(self, res: tuple[str, updates.Release | None, str],
                            installed: str | None) -> None:
        from datetime import datetime, timezone
        if hasattr(self, "update_act"):
            self.update_act.setEnabled(True)
        status, rel, detail = res
        if status in ("update", "up_to_date"):
            updates.write_last_check(management.state_dir(), datetime.now(timezone.utc).isoformat())
        if status == "update" and rel is not None:
            self._show_update_banner(rel)
            self._show_window()
            cur_note = f" (installed: {installed})" if installed else ""
            self.status(f"New version available: {rel.version}{cur_note}", hold_secs=10.0)
            return
        if status == "up_to_date":
            ver_note = detail or installed or "latest"
            self.status(f"Up to date ({ver_note})", hold_secs=8.0)
            QtWidgets.QMessageBox.information(
                self, "Check for updates",
                f"You are running the latest version ({ver_note})."
            )
            return
        self.status(f"Update check failed: {detail}", hold_secs=8.0)
        QtWidgets.QMessageBox.warning(
            self, "Check for updates",
            f"Could not check for updates:\n{detail}"
        )

    def _update_seen(self, rel: updates.Release | None, last_marker: str | None = None,
                     checked_at: float | None = None) -> None:
        from datetime import datetime, timezone
        due = True
        if last_marker and checked_at is not None:
            try:
                due = (checked_at - datetime.fromisoformat(last_marker).timestamp()) >= updates.CHECK_MIN_SECS
            except ValueError:
                due = True
        if due or rel is not None:
            updates.write_last_check(management.state_dir(), datetime.now(timezone.utc).isoformat())
        if rel is None:
            return
        self._show_update_banner(rel)
        if self.tray:
            self.tray.showMessage(
                "tincmgr",
                f"A new version is available: {rel.version}. Open the window to update.",
                QtWidgets.QSystemTrayIcon.Information, 8000)

    def _show_update_banner(self, rel: updates.Release) -> None:
        self._available_update = rel
        if hasattr(self, "update_act"):
            self.update_act.setText(f"⬆ Update ({rel.version})")
        if self._update_banner is not None:
            self._update_banner.deleteLater()
        bar = QtWidgets.QFrame()
        bar.setObjectName("updateBanner")
        bar.setStyleSheet(
            "QFrame#updateBanner{background:#16243a;border:1px solid #2b6cb0;border-radius:6px;}"
        )
        bl = QtWidgets.QHBoxLayout(bar)
        bl.setContentsMargins(12, 8, 12, 8)
        cur = management.current_version()
        cur_txt = f" (current: {cur})" if cur else ""
        lbl = QtWidgets.QLabel(f"<span style='color:#60a5fa;font-weight:bold;'>⬆ A new version is available: "
                               f"{rel.version}{cur_txt}.</span> "
                               f"<span style='color:#e2e8f0;'>The update is downloaded, verified against its "
                               f"SHA-256 checksum and installed by the elevated installer, then tincmgr "
                               f"restarts automatically.</span>")
        lbl.setStyleSheet("color:#e2e8f0;background:transparent;border:none;")
        lbl.setWordWrap(True)
        bl.addWidget(lbl, stretch=1)
        go = QtWidgets.QPushButton("Update now")
        go.setCursor(QtCore.Qt.PointingHandCursor)
        go.setStyleSheet(
            "QPushButton{background:#1a73e8;color:#ffffff;font-weight:bold;border:none;"
            "border-radius:4px;padding:6px 14px;}"
            "QPushButton:hover{background:#2563eb;}"
        )
        go.clicked.connect(lambda: self._update_install(rel))
        later = QtWidgets.QPushButton("Later")
        later.setCursor(QtCore.Qt.PointingHandCursor)
        later.setStyleSheet(
            "QPushButton{background:#28374d;color:#cbd5e1;border:1px solid #3e526d;"
            "border-radius:4px;padding:6px 12px;}"
            "QPushButton:hover{background:#334155;color:#ffffff;}"
        )
        later.clicked.connect(bar.hide)
        bl.addWidget(go); bl.addWidget(later)
        self.outer_layout().insertWidget(1, bar)
        self._update_banner = bar

    def outer_layout(self) -> QtWidgets.QVBoxLayout:
        # the banner sits above the tab area, like the load-error banner
        central = self.centralWidget()
        return central.layout()

    def _update_install(self, rel: updates.Release) -> None:
        import shutil
        self.status(f"Downloading {rel.version}…", hold_secs=60.0)
        workdir = tempfile.mkdtemp(prefix="tincmgr-update-")
        self.pool.run(updates.fetch, rel, workdir, tag="update-fetch",
                      on_done=lambda r: self._update_run(rel, r, workdir),
                      on_error=lambda msg, wd=workdir: (shutil.rmtree(wd, ignore_errors=True), self._update_failed(msg)))

    def _update_run(self, rel: updates.Release, extracted: tuple[str, str], workdir: str) -> None:
        import shutil
        exe, zpath = extracted
        try:
            if zpath and os.path.isfile(zpath):
                os.unlink(zpath)
        except OSError:
            pass
        self.status(f"Installing {rel.version}… (elevation prompt)", hold_secs=60.0)
        # Launch the downloaded single-file tincmgr.exe asynchronously with
        # --self-install --wait-pid <our PID> --relaunch so this process can
        # stop its tunnels and exit first, releasing all locks on Program Files
        # before the installer swaps the new tree in and restarts the GUI.
        def do_install() -> str:
            try:
                if not management.is_frozen():
                    raise OSError("only the built tincmgr.exe can update in place")
                management.check_downgrade(rel.version, management.installed_version())
                target = management.start_self_update(
                    exe, rel.version, caller_pid=os.getpid(), caller_exe=sys.executable
                )
                if self.admin:
                    try:
                        self.rt.stop_all()
                    except Exception:
                        pass
                return target
            except BaseException:
                shutil.rmtree(workdir, ignore_errors=True)
                raise
        self.pool.run(do_install, tag="update-install",
                      on_done=lambda target: self._update_restart(target),
                      on_error=self._update_failed)

    def _update_restart(self, target: str) -> None:
        self.status(f"Installing into {target}; restarting…", hold_secs=30.0)
        self._quitting = True
        self.timer.stop()
        self.cert_timer.stop()
        self.update_timer.stop()
        if getattr(self, "tray", None):
            self.tray.hide()
        QtCore.QTimer.singleShot(250, lambda: os._exit(0))

    def _update_failed(self, msg: str) -> None:
        self.status("", hold_secs=0.0)
        QtWidgets.QMessageBox.warning(self, "Update", f"The update did not complete:\n{msg}")

    def _cert_badge(self, days: int | None, threshold: int) -> None:
        """Mark the toolbar action when the certificate is running out. Silent
        the rest of the time: a badge that is always there is not a badge."""
        if not hasattr(self, "cert_act"):
            return
        base = "TLS certificate for the https/quic transports: replace the self-signed one " \
               "with a real certificate for a domain, using a Cloudflare API token."
        if days is None or days > threshold:
            self.cert_act.setText("🔐 Certificate…")
            self.cert_act.setToolTip(base)
            return
        if days < 0:
            self.cert_act.setText(f"⚠ Certificate EXPIRED ({-days} d)")
            note = (f"The certificate expired {-days} days ago. Peers still connect (they pin the "
                    "fingerprint), but the front now looks broken to anything else. Open this and "
                    "press “Issue / renew”.")
        else:
            self.cert_act.setText(f"⚠ Certificate: {days} d left")
            note = (f"The certificate expires in {days} days and nothing renews it automatically on "
                    "Windows. Open this and press “Issue / renew”.")
        self.cert_act.setToolTip(f"{note}\n\n{base}")
        self.status(note.split(".")[0] + ".")

    # actions
    def _need_admin(self) -> bool:
        if not self.admin:
            self.status("Needs elevation — click '🛡 Run as admin'.")
            return True
        return False

    def _autostart(self) -> None:
        if self.load_error:
            return
        autos = [n for n, nc in self.app.networks.items() if nc.autostart]
        if not autos:
            return
        if not self.admin:
            self.status(f"{len(autos)} network(s) set to autostart — elevation needed.")
            return
        for n in autos:
            self._wanted_running[n] = True
        self.status("autostart: " + ", ".join(autos))

        def done(results: list[tuple[str, bool, str]]) -> None:
            for n, ok, _m in results:
                self._wanted_running[n] = ok
            self.status("autostart: " + "; ".join(f"{n}: {m}" for n, _ok, m in results))
            self.peers.sample_async()
        self.pool.run(self.rt.start_autostart, tag="autostart", on_done=done,
                      on_error=lambda m: self.status(f"autostart failed: {m}"))

    def _lifecycle(self, fn: Callable[[str], tuple[bool, str]], net: str, label: str) -> None:
        self.status(f"{label} {net}…")

        def done(result: tuple[bool, str]) -> None:
            _ok, msg = result
            self.status(f"{label} {net}: {msg}")
            self.peers.sample_async()
        if self.pool.run(fn, net, tag=f"life-{net}", on_done=done,
                         on_error=lambda m: self.status(f"{label} {net}: {m}")) is None:
            self.status(f"{net}: previous start/stop still running")

    def _start(self) -> None:
        net = self.cur_net()
        if net and not self._need_admin():
            self._wanted_running[net] = True
            self._lifecycle(self.rt.start, net, "start")

    def _stop(self) -> None:
        net = self.cur_net()
        if net and not self._need_admin():
            self._wanted_running[net] = False
            self._lifecycle(self.rt.stop, net, "stop")

    def _restart(self) -> None:
        net = self.cur_net()
        if net and not self._need_admin():
            self._wanted_running[net] = True
            self._lifecycle(self.rt.restart, net, "restart")

    def _sync_startup_radio(self) -> None:
        # `schtasks /query` is a subprocess: ask on a worker, show on return
        if not self.startup_radio.text():
            self.startup_radio.setText("  Run at Windows startup: …  ")
        self.pool.run(management.startup_task_enabled, on_done=self._show_startup_state)

    def _show_startup_state(self, on: bool) -> None:
        self.startup_radio.blockSignals(True)
        self.startup_radio.setChecked(on)
        self.startup_radio.blockSignals(False)
        self.startup_radio.setText("  Run at Windows startup: " + ("ON" if on else "OFF") + "  ")
        col = "#1e8e3e" if on else "#d93025"   # green = enabled, red = disabled
        self.startup_radio.setStyleSheet(
            "QRadioButton{color:%s;font-weight:bold;}"
            "QRadioButton::indicator{width:13px;height:13px;border-radius:7px;"
            "border:1px solid #333;}"
            "QRadioButton::indicator:checked{background:#1e8e3e;}"
            "QRadioButton::indicator:unchecked{background:#d93025;}" % col)

    def _toggle_startup(self, checked: bool) -> None:
        if not self.admin:
            self.status("Setting startup needs elevation.")
            self._sync_startup_radio(); return
        exe = sys.executable if paths.is_frozen() else None
        if not exe:
            self.status("Run-at-startup only works for the built tincmgr.exe.")
            self._sync_startup_radio(); return
        # schtasks, and installing the app tree into Program Files: not on the Qt thread
        def done(res: tuple[bool, str]) -> None:
            ok, msg = res
            self.status(("enabled" if checked else "disabled") + f" run-at-startup: {'ok' if ok else msg[:80]}")
            self._sync_startup_radio()

        def failed(msg: str) -> None:
            self.status(f"run-at-startup failed: {msg[:80]}")
            self._sync_startup_radio()

        self.status(("enabling" if checked else "disabling") + " run-at-startup…")
        self.pool.run(management.set_startup_task, checked, exe, tag="startup-task",
                      on_done=done, on_error=failed)

    def _elevate(self) -> None:
        if management.relaunch_self_elevated():
            self.status("Relaunching elevated…")
            QtCore.QTimer.singleShot(600, QtWidgets.QApplication.quit)
        else:
            self.status("Elevation cancelled/failed.")

    def _add_net(self) -> None:
        name, ok = QtWidgets.QInputDialog.getText(self, "Add network", "Network name:")
        name = name.strip()
        if ok and name and name not in self.app.networks:
            # empty stanza on purpose: the daemon materialises Name/Mode/Port/
            # AddressPool/keys on first start (zero-config, M1)
            self.app.networks[name] = NetworkCfg(name=name)
            if self.save_config(f"added network {name} — Start it to let the daemon generate its identity"):
                self.reload_networks(); self._select_net(name)

    def _del_net(self) -> None:
        net = self.cur_net()
        if not net:
            return
        if QtWidgets.QMessageBox.question(self, "Remove network", f"Remove '{net}' from the config?") == QtWidgets.QMessageBox.Yes:
            if self._running.get(net) and self.admin:
                self.pool.run(self.rt.stop, net, tag=f"life-{net}")
            self.app.networks.pop(net, None)
            self._running.pop(net, None)
            self.save_config(f"removed network {net}"); self.reload_networks()

    def _tick(self) -> None:
        self.peers.sample_async()
        if not self.load_error and time.time() >= getattr(self, "_status_hold_until", 0.0):
            ver = management.current_version()
            ver_part = f"version: {ver}  |  " if ver else ""
            self.statusBar().showMessage(
                f"{ver_part}config: {self.app.path}  |  admin: {self.admin}  |  {time.strftime('%H:%M:%S')}"
            )

    def closeEvent(self, ev: QtGui.QCloseEvent) -> None:
        # the X button minimizes to the tray (VPNs keep running); only Exit quits
        if not self._quitting and getattr(self, "tray", None):
            ev.ignore()
            self.hide()
            self.tray.showMessage("tincmgr", "Minimised to the tray — networks keep running.",
                                  QtWidgets.QSystemTrayIcon.Information, 2000)
            return
        self.timer.stop()
        if hasattr(self, "cert_timer"):
            self.cert_timer.stop()
        if hasattr(self, "update_timer"):
            self.update_timer.stop()
        if hasattr(self, "diag_server"):
            try:
                self.diag_server.stop()
            except Exception:
                pass
        if self.admin:
            try:
                self.rt.stop_all()      # exit path: blocking is acceptable here
            except Exception:
                pass
        self.pool.wait_all(5000)
        if getattr(self, "tray", None):
            self.tray.hide()
        super().closeEvent(ev)
        QtWidgets.QApplication.quit()


def _ensure_config() -> tuple[str | None, str]:
    """(config path, status note). Elevated on Windows the config lives in the
    admin-only folder (paths.adopt_config); an unelevated run keeps the old
    search, because nothing it reads can raise its privileges."""
    legacy = paths.find_config()
    prot = paths.protected_dir() if management.is_admin() else None
    if prot:
        try:
            return paths.adopt_config(os.path.join(prot, paths.CONFIG_BASENAMES[0]), legacy)
        except OSError as e:
            return None, f"cannot use {prot}: {e}"
    if legacy:
        return legacy, ""
    dest = paths.default_config_path()
    try:
        yaml_config.atomic_write_text(dest, "networks: {}\n")
        return dest, ""
    except OSError as e:
        return None, str(e)


def _selftest_report(w: "MainWindow", cfg: str, note: str, extra: list[str]) -> None:
    """TINCMGR_SELFTEST_MS: the headless probe (build-exe.sh, and on Windows)."""
    import glob
    import tempfile
    b = paths.bundle()
    temp = tempfile.gettempdir()
    lines = ["SELFTEST OK", f"frozen={paths.is_frozen()}", f"admin={w.admin}",
             f"exe={sys.executable}", f"meipass={getattr(sys, '_MEIPASS', None)}",
             f"bundle_version={b.version if b else None}",
             f"temp_mei={sorted(os.path.basename(p) for p in glob.glob(os.path.join(temp, '_MEI*')))}",
             f"config={cfg}", f"networks={list(w.app.networks)}",
             f"load_error={w.load_error!r}", f"tincd={paths.tincd_exe()}",
             f"tincd_exists={os.path.isfile(paths.tincd_exe())}",
             f"staged_tincd={w.rt.tincd}", f"note={note!r}"] + extra
    logp = os.environ.get("TINCMGR_SELFTEST_LOG") or os.path.join(temp, "tincmgr_selftest.log")
    try:
        with open(logp, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except OSError:
        pass
    print("\n".join(lines), flush=True)


def main() -> None:
    # The install manifest is compiled into the onefile's archive, which is
    # read from the exe on disk lazily: import it now, before a long-running
    # session gives anyone time to swap the exe under us (paths.bundle()).
    paths.bundle()
    if "--self-install" in sys.argv[1:]:
        args = sys.argv[1:]
        wait_pid = 0
        replace_exe = ""
        relaunch = "--relaunch" in args
        if "--wait-pid" in args:
            idx = args.index("--wait-pid")
            if idx + 1 < len(args):
                try:
                    wait_pid = int(args[idx + 1])
                except ValueError:
                    wait_pid = 0
        if "--replace-exe" in args:
            idx = args.index("--replace-exe")
            if idx + 1 < len(args):
                replace_exe = args[idx + 1].strip('"')
        try:
            if wait_pid > 0:
                management.wait_for_pid(wait_pid, timeout=15.0)
            target = management.install_self(sys.executable, retry_secs=10.0 if wait_pid > 0 else 0.0)
            if replace_exe:
                management.replace_standalone_exe(sys.executable, replace_exe, retry_secs=10.0)
            if relaunch:
                management.launch_detached(target)
            print(f"installed: {target}")
            sys.exit(0)
        except (OSError, management.DowngradeRefused) as e:
            print(f"error: {e}", file=sys.stderr)
            sys.exit(1)

    # always run elevated on Windows: relaunch via UAC if we're not (the built
    # exe is uac_admin so this only fires for a dev/python run)
    if sys.platform == "win32" and not management.is_admin() and not os.environ.get("TINCMGR_SELFTEST_MS"):
        if management.relaunch_self_elevated():
            sys.exit(0)

    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setQuitOnLastWindowClosed(False)   # closing the window minimizes to tray
    cfg, note = _ensure_config()
    if not cfg:
        QtWidgets.QMessageBox.critical(None, "tincmgr", "No tinc.yaml found and could not create one."
                                       + (f"\n\n{note}" if note else ""))
        sys.exit(1)
    w = MainWindow(cfg)
    w.show()
    note = "; ".join(n for n in (note, w.rt.stage_note) if n)
    ok, msg = paths.binaries_present()
    if not ok:
        w.status(msg)
    elif note:
        w.status(note)
    if sys.platform == "win32" and w.admin and paths.is_frozen():
        w.refresh_startup_async(sys.executable)
    selftest = os.environ.get("TINCMGR_SELFTEST_MS")
    if selftest:
        extra: list[str] = []
        if os.environ.get("TINCMGR_SELFTEST_INSTALL") == "1":
            # build-exe.sh: install this build the way run-at-startup does,
            # then the smoke test runs the installed onedir copy
            try:
                extra.append(f"installed={management.install_self(sys.executable)}")
                extra.append(f"installed_version={management.installed_version()}")
            except OSError as e:
                extra.append(f"install_error={e}")
        _selftest_report(w, cfg, note, extra)
        QtCore.QTimer.singleShot(int(selftest), w._quit_app)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
