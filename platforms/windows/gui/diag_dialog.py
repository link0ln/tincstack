"""
diag_dialog.py — Diagnostic Web Server & Incident Monitor dialog for tincmgr.

Provides an opt-in toggle (with an explicit security warning confirmation) to
start/stop the embedded Diagnostic Web Server (DiagWebServer), copy its VPN URL
or open it in the browser, mark a lag/freeze moment with one click, and view
recent automatically detected tunnel incidents.
"""

from __future__ import annotations

import os
from typing import Any

from PySide6 import QtCore, QtGui, QtWidgets

import diagnostics

_MONO = QtGui.QFont("Consolas" if os.name == "nt" else "Monospace", 9)

SECURITY_WARNING_TITLE = "Enable Remote Diagnostic Web Server?"
SECURITY_WARNING_TEXT = (
    "<b>Security Warning — Full Remote Client Control Over VPN</b><br><br>"
    "Enabling the Diagnostic Web Server opens an HTTP interface (without password "
    "authentication) accessible to <b>any peer inside your VPN network</b> via "
    "<code>http://&lt;your-vpn-ip&gt;:&lt;port&gt;/</code> as well as locally on "
    "<code>127.0.0.1</code>.<br><br>"
    "Anyone who can reach this port over the VPN will be able to:"
    "<ul>"
    "<li>View live traffic graphs, RTT/PMTU metrics, and daemon logs</li>"
    "<li>Run in-tunnel &amp; outer network probes (ping, traceroute, PMTU, port checks)</li>"
    "<li>Switch transport protocols, modify routes, and edit network configuration</li>"
    "<li>Start, stop, or restart the VPN daemon</li>"
    "</ul>"
    "<b>Only enable this feature if you trust all nodes in your VPN mesh, and disable "
    "it when you finish troubleshooting.</b><br><br>"
    "Do you understand the risks and want to enable the Diagnostic Web Server now?"
)


class DiagnosticsDialog(QtWidgets.QDialog):
    """Manage the opt-in Diagnostic Web Server and inspect/mark incidents."""

    state_changed = QtCore.Signal()

    def __init__(
        self,
        parent: QtWidgets.QWidget | None,
        server: diagnostics.DiagWebServer,
        collector: diagnostics.TelemetryCollector,
        net: str | None,
        skip_confirm: bool = False,
    ) -> None:
        super().__init__(parent)
        self.server = server
        self.collector = collector
        self.net = net or ""
        self.skip_confirm = skip_confirm
        self.setWindowTitle("Diagnostics & Remote Web Panel")
        self.resize(760, 560)

        lay = QtWidgets.QVBoxLayout(self)

        # -- Security notice banner --
        warn_box = QtWidgets.QFrame()
        warn_box.setObjectName("diagWarnBanner")
        warn_box.setStyleSheet(
            "QFrame#diagWarnBanner { background: #2d2412; border: 1px solid #d97706; border-radius: 6px; }"
        )
        wl = QtWidgets.QVBoxLayout(warn_box)
        wlbl = QtWidgets.QLabel(
            "<b>⚠ Remote Diagnostic Web Panel (Opt-In)</b><br>"
            "When enabled, this client serves a full diagnostic &amp; control WebUI over the VPN "
            "(bridged by <code>tincd</code> from <code>http://&lt;vpn-ip&gt;:&lt;port&gt;/</code> to "
            "<code>127.0.0.1:&lt;port&gt;</code>). Keep it <b>OFF</b> during normal operation and "
            "enable it only while diagnosing network issues."
        )
        wlbl.setWordWrap(True)
        wlbl.setStyleSheet("color: #fef3c7; background: transparent; border: none;")
        wl.addWidget(wlbl)
        lay.addWidget(warn_box)

        # -- Server controls group --
        srv_group = QtWidgets.QGroupBox("Diagnostic HTTP Server")
        sgrid = QtWidgets.QGridLayout(srv_group)

        self.status_lbl = QtWidgets.QLabel("")
        sgrid.addWidget(QtWidgets.QLabel("Status:"), 0, 0)
        sgrid.addWidget(self.status_lbl, 0, 1)

        self.port_spin = QtWidgets.QSpinBox()
        self.port_spin.setRange(1024, 65535)
        cfg = diagnostics.load_diag_settings(self.server.base_dir)
        self.port_spin.setValue(int(cfg.get("port") or self.server.port or diagnostics.DEFAULT_DIAG_PORT))
        sgrid.addWidget(QtWidgets.QLabel("Port:"), 0, 2)
        sgrid.addWidget(self.port_spin, 0, 3)

        self.toggle_btn = QtWidgets.QPushButton("")
        self.toggle_btn.clicked.connect(self.toggle_server)
        sgrid.addWidget(self.toggle_btn, 0, 4)

        sgrid.addWidget(QtWidgets.QLabel("VPN / Local URL:"), 1, 0)
        self.url_edit = QtWidgets.QLineEdit()
        self.url_edit.setReadOnly(True)
        self.url_edit.setFont(_MONO)
        sgrid.addWidget(self.url_edit, 1, 1, 1, 2)

        self.copy_btn = QtWidgets.QPushButton("📋 Copy URL")
        self.copy_btn.clicked.connect(self.copy_url)
        sgrid.addWidget(self.copy_btn, 1, 3)

        self.open_btn = QtWidgets.QPushButton("🌐 Open WebUI")
        self.open_btn.clicked.connect(self.open_browser)
        sgrid.addWidget(self.open_btn, 1, 4)

        lay.addWidget(srv_group)

        # -- Quick "Mark Lag" section --
        mark_group = QtWidgets.QGroupBox("Quick Incident Marker (Local Telemetry Always Active)")
        mlay = QtWidgets.QHBoxLayout(mark_group)
        self.note_edit = QtWidgets.QLineEdit()
        self.note_edit.setPlaceholderText(
            "Optional note (e.g. 'RDP froze for 5s', 'voice call dropped', 'slow HTTP load')…"
        )
        self.mark_btn = QtWidgets.QPushButton("⚡ Mark Lag / Issue Now")
        self.mark_btn.setStyleSheet("font-weight: bold; padding: 4px 10px;")
        self.mark_btn.clicked.connect(self.mark_now)
        mlay.addWidget(self.note_edit, stretch=1)
        mlay.addWidget(self.mark_btn)
        lay.addWidget(mark_group)

        # -- Recent incidents list --
        inc_head = QtWidgets.QHBoxLayout()
        inc_head.addWidget(QtWidgets.QLabel(
            f"<b>Recent Detected Anomalies &amp; Marks ({self.net or 'no network'})</b>"
        ))
        inc_head.addStretch()
        ref_btn = QtWidgets.QPushButton("↻ Refresh")
        ref_btn.clicked.connect(self.refresh_incidents)
        inc_head.addWidget(ref_btn)
        lay.addLayout(inc_head)

        self.inc_table = QtWidgets.QTableWidget(0, 4)
        self.inc_table.setHorizontalHeaderLabels(["Time", "Type", "Peer", "Summary"])
        self.inc_table.verticalHeader().setVisible(False)
        self.inc_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.inc_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.inc_table.horizontalHeader().setStretchLastSection(True)
        self.inc_table.setAlternatingRowColors(True)
        lay.addWidget(self.inc_table, stretch=1)

        bb = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Close)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

        self.refresh_ui()
        self.refresh_incidents()

    def confirm_enable(self) -> bool:
        if self.skip_confirm:
            return True
        box = QtWidgets.QMessageBox(self)
        box.setIcon(QtWidgets.QMessageBox.Warning)
        box.setWindowTitle(SECURITY_WARNING_TITLE)
        box.setTextFormat(QtCore.Qt.RichText)
        box.setText(SECURITY_WARNING_TEXT)
        box.setStandardButtons(QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
        box.setDefaultButton(QtWidgets.QMessageBox.No)
        return box.exec() == QtWidgets.QMessageBox.Yes

    def toggle_server(self) -> None:
        if self.server.enabled:
            self.server.stop()
        else:
            if not self.confirm_enable():
                return
            ok, msg = self.server.start(self.port_spin.value())
            if not ok:
                QtWidgets.QMessageBox.warning(self, "Diagnostic Web Server", msg)
        self.refresh_ui()
        self.state_changed.emit()

    def refresh_ui(self) -> None:
        on = self.server.enabled
        self.port_spin.setEnabled(not on)
        if on:
            self.status_lbl.setText(f"<b style='color:#1e8e3e;'>● ENABLED (listening on port {self.server.port})</b>")
            self.toggle_btn.setText("■ Disable Server")
            urls = self.server.get_vpn_urls()
            self.url_edit.setText("  |  ".join(urls))
            self.copy_btn.setEnabled(True)
            self.open_btn.setEnabled(True)
        else:
            self.status_lbl.setText("<b style='color:#9aa0a6;'>○ DISABLED (off)</b>")
            self.toggle_btn.setText("▶ Enable Server…")
            self.url_edit.setText("(enable the server to access the WebUI over VPN or localhost)")
            self.copy_btn.setEnabled(False)
            self.open_btn.setEnabled(False)

    def copy_url(self) -> None:
        urls = self.server.get_vpn_urls()
        if urls:
            QtWidgets.QApplication.clipboard().setText(urls[0])

    def open_browser(self) -> None:
        if not self.server.enabled:
            return
        url = f"http://127.0.0.1:{self.server.port}/"
        if self.net:
            url += f"?net={self.net}"
        QtGui.QDesktopServices.openUrl(QtCore.QUrl(url))

    def mark_now(self) -> None:
        if not self.net:
            return
        note = self.note_edit.text().strip()
        self.collector.record_user_mark(self.net, note)
        self.note_edit.clear()
        self.refresh_incidents()

    def refresh_incidents(self) -> None:
        if not self.net:
            self.inc_table.setRowCount(0)
            return
        items = self.collector.get_incidents(self.net, limit=100)
        self.inc_table.setRowCount(len(items))
        colors = {
            "error": "#d93025",
            "warn": "#e8710a",
            "mark": "#9334e6",
            "info": "#1a73e8",
        }
        for r, ev in enumerate(items):
            t_it = QtWidgets.QTableWidgetItem(str(ev.get("time_str", "")))
            k_it = QtWidgets.QTableWidgetItem(str(ev.get("kind", "")))
            k_it.setForeground(QtGui.QColor(colors.get(str(ev.get("severity", "info")), "#5f6368")))
            f = k_it.font()
            f.setBold(True)
            k_it.setFont(f)
            p_it = QtWidgets.QTableWidgetItem(str(ev.get("peer", "") or "—"))
            s_it = QtWidgets.QTableWidgetItem(str(ev.get("summary", "")))
            self.inc_table.setItem(r, 0, t_it)
            self.inc_table.setItem(r, 1, k_it)
            self.inc_table.setItem(r, 2, p_it)
            self.inc_table.setItem(r, 3, s_it)
        self.inc_table.resizeColumnsToContents()
