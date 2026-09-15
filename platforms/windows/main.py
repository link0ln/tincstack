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
Toolbar: Start / Stop / Restart, Invite…, Join…, run-at-startup, Reload.

Every tinc/tincd subprocess runs on a worker thread (gui/workers.py); the Qt
thread never blocks on the daemon. A malformed tinc.yaml opens the window with
an error banner instead of crashing.

Run from source (dev):   python main.py     (needs PySide6, pyqtgraph, pyyaml)
"""

from __future__ import annotations

import os
import re
import sys
import time
from collections import deque
from typing import Any, Callable

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "backend"))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import paths  # noqa: E402
import transports  # noqa: E402
import yaml_config  # noqa: E402
from yaml_config import AppConfig, ConfigError, NetworkCfg, options_to_conf, conf_to_options  # noqa: E402
from runtime import Runtime  # noqa: E402
from tinc_control import TincControl, NetworkSnapshot  # noqa: E402
import management  # noqa: E402

from PySide6 import QtCore, QtGui, QtWidgets  # noqa: E402
import pyqtgraph as pg  # noqa: E402

from gui.workers import WorkerPool  # noqa: E402
from gui.dialogs import InviteDialog, JoinDialog, RawYamlDialog  # noqa: E402
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
    ("LocalDiscovery", "bool", None, "Find peers on the same LAN and connect directly"),
    ("UDPRebindOnWake", "bool", None, "Re-bind the UDP socket after sleep/resume (core feature)"),
    ("UDPDiscoveryBurst", "int", None, "UDP hole-punching probes per round while unconfirmed (core feature)"),
    ("TCPOnly", "bool", None, "Tunnel only over TCP (forces relay; no UDP)"),
    ("IndirectData", "bool", None, "This node is only reachable via a relay"),
    ("PMTUDiscovery", "bool", None, "Discover the path MTU automatically"),
    ("Compression", "int", None, "Compression level 0-11 (0 = off)"),
    ("PingInterval", "int", None, "Seconds between keepalive pings"),
    ("PingTimeout", "int", None, "Seconds before an unresponsive peer is considered down"),
] + [
    (spec.name,
     {"carriers": "str", "int": "int", "port": "int", "bool": "bool", "path": "str",
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
    COLS = ["Peer", "Link", "Via", "Dist", "RTT ms", "PMTU", "RX", "TX", "Subnets"]

    def __init__(self, tc: TincControl, nets_fn: Callable[[], list[str]], pool: WorkerPool,
                 on_running: Callable[[dict[str, bool]], None]) -> None:
        super().__init__()
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
        for net, snap in snaps.items():
            self._snaps[net] = snap
            if snap.error:
                continue
            rx = sum(n.rx_bytes for n in snap.nodes.values() if not n.is_self)
            tx = sum(n.tx_bytes for n in snap.nodes.values() if not n.is_self)
            self.hist.setdefault(net, deque(maxlen=HIST_MAX)).append((now, rx, tx))
        self.on_running({net: not snap.error for net, snap in snaps.items()})
        if self.net:
            self._table(self._snaps.get(self.net))
            self._redraw()

    def _table(self, snap: NetworkSnapshot | None) -> None:
        if snap is None or snap.error:
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
            cells = [n.name, LINK_LABEL.get(link, link), via,
                     "" if n.distance < 0 else str(n.distance),
                     f"{n.rtt:.0f}" if n.rtt > 0 else "",
                     str(n.pmtu) if n.pmtu else "",
                     human_bytes(n.rx_bytes), human_bytes(n.tx_bytes),
                     ", ".join(n.subnets)]
            for c, val in enumerate(cells):
                it = QtWidgets.QTableWidgetItem(val)
                if c == 1:
                    it.setForeground(QtGui.QColor(LINK_COLORS.get(link, "#000")))
                    f = it.font(); f.setBold(True); it.setFont(f)
                self.table.setItem(r, c, it)
        self.table.resizeColumnsToContents()

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
        self.ctx.save_config(f"saved host {name}"); self.reload()

    def _del_host(self) -> None:
        nc = self.ctx.cur_netcfg(); name = self.host_name.text().strip()
        if not nc or name not in nc.hosts:
            return
        if QtWidgets.QMessageBox.question(self, "Delete node", f"Delete host '{name}'?") == QtWidgets.QMessageBox.Yes:
            nc.hosts.pop(name, None); self.ctx.save_config(f"deleted host {name}"); self.reload()

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
        self.load_error = ""
        self.app = self._load(cfg_path)
        self.rt = Runtime(self.app)
        self.tc = TincControl(tinc_exe=self.rt.tinc, yaml_path=self.app.path, runner=runner)

        self.setWindowTitle("tincmgr" + ("  [admin]" if self.admin else "  [not elevated]"))
        self.resize(1180, 780)
        self._build_toolbar()

        central = QtWidgets.QWidget(); self.setCentralWidget(central)
        outer = QtWidgets.QVBoxLayout(central)
        self.banner = QtWidgets.QFrame()
        self.banner.setStyleSheet("QFrame{background:#fce8e6;border:1px solid #d93025;border-radius:4px;}")
        bl = QtWidgets.QHBoxLayout(self.banner)
        self.banner_lbl = QtWidgets.QLabel("")
        self.banner_lbl.setWordWrap(True)
        self.banner_lbl.setStyleSheet("color:#a50e0e;")
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
        self.peers = PeersTab(self.tc, lambda: list(self.app.networks), self.pool, self._on_running)
        self.network = NetworkTab(self)
        self.transports = TransportsTab(self)
        self.tabs.addTab(self.peers, "Peers && Traffic")
        self.tabs.addTab(self.network, "Network")
        self.tabs.addTab(self.transports, "Transports")
        h.addWidget(self.tabs, stretch=1)
        outer.addLayout(h, stretch=1)

        self.statusBar()
        self.timer = QtCore.QTimer(self)
        self.timer.setInterval(REFRESH_MS)
        self.timer.timeout.connect(self._tick)
        self.timer.start()
        self._quitting = False
        self._build_tray()
        self._show_load_error()
        self.reload_networks()
        self.peers.sample_async()
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
        self.tray = QtWidgets.QSystemTrayIcon(icon, self)
        self.tray.setToolTip("tincmgr")
        menu = QtWidgets.QMenu()
        menu.addAction("Show window", self._show_window)
        self.net_menu = menu.addMenu("Networks")
        self.net_menu.aboutToShow.connect(self._rebuild_net_menu)
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

    def status(self, msg: str) -> None:
        self.statusBar().showMessage(msg)

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
        if not self.admin:
            tb.addSeparator()
            tb.addAction("🛡 Run as admin", self._elevate)

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
        changed = any(self._running.get(n) != v for n, v in running.items())
        self._running.update(running)
        if changed:
            self.reload_networks()

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
        self.status("autostart: " + ", ".join(autos))

        def done(results: list[tuple[str, bool, str]]) -> None:
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
            self._lifecycle(self.rt.start, net, "start")

    def _stop(self) -> None:
        net = self.cur_net()
        if net and not self._need_admin():
            self._lifecycle(self.rt.stop, net, "stop")

    def _restart(self) -> None:
        net = self.cur_net()
        if net and not self._need_admin():
            self._lifecycle(self.rt.restart, net, "restart")

    def _sync_startup_radio(self) -> None:
        on = management.startup_task_enabled()
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
        ok, msg = management.set_startup_task(checked, exe)
        self.status(("enabled" if checked else "disabled") + f" run-at-startup: {'ok' if ok else msg[:80]}")
        self._sync_startup_radio()

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
        if not self.load_error:
            self.status(f"config: {self.app.path}  |  admin: {self.admin}  |  {time.strftime('%H:%M:%S')}")

    def closeEvent(self, ev: QtGui.QCloseEvent) -> None:
        # the X button minimizes to the tray (VPNs keep running); only Exit quits
        if not self._quitting and getattr(self, "tray", None):
            ev.ignore()
            self.hide()
            self.tray.showMessage("tincmgr", "Minimised to the tray — networks keep running.",
                                  QtWidgets.QSystemTrayIcon.Information, 2000)
            return
        self.timer.stop()
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


def _ensure_config() -> str | None:
    p = paths.find_config()
    if p:
        return p
    dest = paths.default_config_path()
    try:
        yaml_config.atomic_write_text(dest, "networks: {}\n")
        return dest
    except OSError:
        return None


def main() -> None:
    # always run elevated on Windows: relaunch via UAC if we're not (the built
    # exe is uac_admin so this only fires for a dev/python run)
    if sys.platform == "win32" and not management.is_admin() and not os.environ.get("TINCMGR_SELFTEST_MS"):
        if management.relaunch_self_elevated():
            sys.exit(0)

    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setQuitOnLastWindowClosed(False)   # closing the window minimizes to tray
    cfg = _ensure_config()
    if not cfg:
        QtWidgets.QMessageBox.critical(None, "tincmgr", "No tinc.yaml found and could not create one.")
        sys.exit(1)
    w = MainWindow(cfg)
    w.show()
    ok, msg = paths.binaries_present()
    if not ok:
        w.status(msg)
    selftest = os.environ.get("TINCMGR_SELFTEST_MS")
    if selftest:
        import tempfile
        logp = os.environ.get("TINCMGR_SELFTEST_LOG") or os.path.join(tempfile.gettempdir(), "tincmgr_selftest.log")
        lines = ["SELFTEST OK", f"frozen={paths.is_frozen()}", f"admin={w.admin}",
                 f"config={cfg}", f"networks={list(w.app.networks)}",
                 f"load_error={w.load_error!r}", f"tincd={paths.tincd_exe()}",
                 f"tincd_exists={os.path.isfile(paths.tincd_exe())}"]
        try:
            with open(logp, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        except OSError:
            pass
        print("\n".join(lines), flush=True)
        QtCore.QTimer.singleShot(int(selftest), w._quit_app)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
