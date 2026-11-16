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
    "<b>Security Warning — Remote Client Control Over VPN</b><br><br>"
    "Enabling the Diagnostic Web Server opens a password-protected HTTP interface "
    "accessible to peers inside your VPN network via "
    "<code>http://&lt;your-vpn-ip&gt;:&lt;port&gt;/</code> as well as locally on "
    "<code>127.0.0.1</code>.<br><br>"
    "Anyone with the access password shown in this dialog will be able to:"
    "<ul>"
    "<li>View live traffic graphs, RTT/PMTU metrics, and daemon logs</li>"
    "<li>Run in-tunnel &amp; outer network probes (ping, traceroute, PMTU, port checks)</li>"
    "<li>Switch transport protocols, modify routes, and edit network configuration</li>"
    "<li>Start, stop, or restart the VPN daemon</li>"
    "</ul>"
    "<b>Keep the access password confidential and disable the server when you finish "
    "troubleshooting.</b><br><br>"
    "Do you understand the risks and want to enable the Diagnostic Web Server now?"
)


class _DoctorPoolPanel(QtWidgets.QWidget):
    """Doctor & multipath connection pool inspector inside DiagnosticsDialog."""

    def __init__(
        self,
        server: DiagWebServer | None,
        net: str,
        pool: Any,
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.server = server
        self.net = net
        self.pool = pool

        lay = QtWidgets.QVBoxLayout(self)
        top = QtWidgets.QHBoxLayout()
        self.summary_lbl = QtWidgets.QLabel("Doctor status: not run yet")
        self.summary_lbl.setWordWrap(True)
        top.addWidget(self.summary_lbl, stretch=1)

        self.run_btn = QtWidgets.QPushButton("🩺 Run Doctor")
        self.probe_btn = QtWidgets.QPushButton("📡 Deep Probe")
        self.fix_btn = QtWidgets.QPushButton("🛠 Auto-Fix")
        self.recycle_btn = QtWidgets.QPushButton("⚡ Recycle Slow")
        self.run_btn.clicked.connect(lambda: self.run_doctor(probe=False, fix=False))
        self.probe_btn.clicked.connect(lambda: self.run_doctor(probe=True, fix=False))
        self.fix_btn.clicked.connect(lambda: self.run_doctor(probe=True, fix=True))
        self.recycle_btn.clicked.connect(self.recycle_slow_legs)
        for btn in (self.run_btn, self.probe_btn, self.fix_btn, self.recycle_btn):
            top.addWidget(btn)
        lay.addLayout(top)

        self.pool_table = QtWidgets.QTableWidget(0, 8)
        self.pool_table.setHorizontalHeaderLabels(
            ["Peer", "Role", "Carrier", "Endpoint", "Score", "RTT (ms)", "Pacing", "State"]
        )
        self.pool_table.verticalHeader().setVisible(False)
        self.pool_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.pool_table.horizontalHeader().setStretchLastSection(True)
        lay.addWidget(self.pool_table, stretch=2)

        self.issues_view = QtWidgets.QPlainTextEdit()
        self.issues_view.setReadOnly(True)
        self.issues_view.setFont(_MONO)
        self.issues_view.setMaximumHeight(130)
        lay.addWidget(self.issues_view, stretch=1)

    def _set_busy(self, busy: bool) -> None:
        for btn in (self.run_btn, self.probe_btn, self.fix_btn, self.recycle_btn):
            btn.setEnabled(not busy)

    def run_doctor(self, probe: bool = False, fix: bool = False) -> None:
        if self.server is None:
            self.summary_lbl.setText("Doctor unavailable: diagnostics server is None")
            return
        self._set_busy(True)
        self.summary_lbl.setText("Running tinc doctor…")
        if self.pool is not None:
            self.pool.run(
                self.server.build_doctor,
                self.net,
                probe,
                fix,
                tag=f"gui-doctor-{self.net}",
                on_done=self._apply_doctor,
                on_error=lambda m: (self._set_busy(False), self.summary_lbl.setText(f"Doctor failed: {m}")),
            )
            return
        try:
            res = self.server.build_doctor(self.net, probe=probe, fix=fix)
        except Exception as exc:
            self._set_busy(False)
            self.summary_lbl.setText(f"Doctor failed: {exc}")
            return
        self._apply_doctor(res)

    def _apply_doctor(self, res: dict[str, Any]) -> None:
        self._set_busy(False)
        status = str(res.get("status") or ("OK" if res.get("ok") else "ERROR"))
        mode = str(res.get("multipath_mode") or "-")
        conns = list(res.get("connections") or [])
        issues = list(res.get("issues") or [])
        err = str(res.get("error") or "").strip()
        summary = f"Status: {status} | mode={mode} | legs={len(conns)} | issues={len(issues)}"
        if err:
            summary += f" | error={err}"
        self.summary_lbl.setText(summary)

        self.pool_table.setRowCount(len(conns))
        for r, cn in enumerate(conns):
            rtt_ms = cn.get("rtt_ms")
            min_rtt = cn.get("min_rtt_ms")
            rtt_str = f"{rtt_ms:.1f}/{min_rtt:.1f}" if isinstance(rtt_ms, (int, float)) and isinstance(min_rtt, (int, float)) else "-"
            pm = cn.get("pacing_mbps")
            pcap = cn.get("pacing_cap_mbps")
            if isinstance(pm, (int, float)) and isinstance(pcap, (int, float)) and pcap > 0:
                pacing_str = f"{pm:.1f}/{pcap:.1f}M"
            elif isinstance(pm, (int, float)) and pm > 0:
                pacing_str = f"{pm:.1f}M"
            else:
                pacing_str = "auto"
            flags = []
            if cn.get("active"):
                flags.append("ACTIVE")
            if cn.get("canary"):
                flags.append("CANARY")
            if cn.get("degraded"):
                flags.append("DEGRADED")
            vals = [
                str(cn.get("peer") or ""),
                str(cn.get("role") or ""),
                str(cn.get("carrier") or ""),
                str(cn.get("ep") or ""),
                str(cn.get("score") if cn.get("score") is not None else "-"),
                rtt_str,
                pacing_str,
                " ".join(flags) or ("idle" if cn.get("verified") else "unverified"),
            ]
            for c, val in enumerate(vals):
                self.pool_table.setItem(r, c, QtWidgets.QTableWidgetItem(val))

        if issues:
            lines = [
                f"[{it.get('severity', '?')}] {it.get('component', '')} {it.get('peer', '')}: "
                f"{it.get('message', '')} ({it.get('hint', '')})"
                for it in issues
            ]
            self.issues_view.setPlainText("\n".join(lines))
        else:
            self.issues_view.setPlainText("[OK] No transport, routing, buffer, or reachability issues detected.")

    def recycle_slow_legs(self) -> None:
        if self.server is None:
            return
        self._set_busy(True)
        if self.pool is not None:
            self.pool.run(
                self.server.handle_action,
                self.net,
                "multipath_recycle",
                {"peer": "all", "mode": "slow"},
                tag=f"gui-mp-recycle-{self.net}",
                on_done=lambda res: (
                    self._set_busy(False),
                    self.summary_lbl.setText(str(res[1]) if len(res) > 1 else "Recycled slow legs"),
                    self.run_doctor(probe=False, fix=False),
                ),
                on_error=lambda m: (self._set_busy(False), self.summary_lbl.setText(f"Recycle failed: {m}")),
            )
            return
        _ok, msg, _extra = self.server.handle_action(self.net, "multipath_recycle", {"peer": "all", "mode": "slow"})
        self._set_busy(False)
        self.summary_lbl.setText(msg)


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
        pool: Any = None,
    ) -> None:
        super().__init__(parent)
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_DeleteOnClose, True)
        self.server = server
        self.collector = collector
        self.net = net or ""
        self.skip_confirm = skip_confirm
        self.pool = pool
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

        sgrid.addWidget(QtWidgets.QLabel("Access Password:"), 2, 0)
        self.pass_edit = QtWidgets.QLineEdit()
        self.pass_edit.setReadOnly(True)
        self.pass_edit.setFont(_MONO)
        self.pass_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.pass_edit.setText(self.server.get_password())
        sgrid.addWidget(self.pass_edit, 2, 1, 1, 2)

        self.show_pass_btn = QtWidgets.QPushButton("👁 Show")
        self.show_pass_btn.setCheckable(True)
        self.show_pass_btn.toggled.connect(self.toggle_password_visibility)
        sgrid.addWidget(self.show_pass_btn, 2, 3)

        self.copy_pass_btn = QtWidgets.QPushButton("📋 Copy Password")
        self.copy_pass_btn.clicked.connect(self.copy_password)
        sgrid.addWidget(self.copy_pass_btn, 2, 4)

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

        # -- Tabs for Incidents and Stacktraces / Logs --
        self.diag_tabs = QtWidgets.QTabWidget()

        # Tab 1: Recent incidents list
        inc_page = QtWidgets.QWidget()
        inc_lay = QtWidgets.QVBoxLayout(inc_page)
        inc_head = QtWidgets.QHBoxLayout()
        inc_head.addWidget(QtWidgets.QLabel(
            f"<b>Recent Detected Anomalies &amp; Marks ({self.net or 'no network'})</b>"
        ))
        inc_head.addStretch()
        ref_btn = QtWidgets.QPushButton("↻ Refresh")
        ref_btn.clicked.connect(self.refresh_incidents)
        inc_head.addWidget(ref_btn)
        inc_lay.addLayout(inc_head)

        self.inc_table = QtWidgets.QTableWidget(0, 4)
        self.inc_table.setHorizontalHeaderLabels(["Time", "Type", "Peer", "Summary"])
        self.inc_table.verticalHeader().setVisible(False)
        self.inc_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.inc_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.inc_table.horizontalHeader().setStretchLastSection(True)
        self.inc_table.setAlternatingRowColors(True)
        inc_lay.addWidget(self.inc_table, stretch=1)
        self.diag_tabs.addTab(inc_page, "⚠️ Incidents & Anomalies")

        # Tab 2: Stacktraces & Logs viewer
        log_page = QtWidgets.QWidget()
        log_lay = QtWidgets.QVBoxLayout(log_page)
        log_bar = QtWidgets.QHBoxLayout()
        log_bar.addWidget(QtWidgets.QLabel("Log source:"))
        self.log_source_combo = QtWidgets.QComboBox()
        self.log_source_combo.addItem("💥 Crash & Stacktraces (tincmgr-crash.log)", "crash")
        self.log_source_combo.addItem("📋 Application Log (tincmgr.log)", "app")
        self.log_source_combo.addItem("🖧 Daemon Log (tincd.log)", "tincd")
        self.log_source_combo.addItem("⚡ Incident Events (JSONL)", "events")
        self.log_source_combo.currentIndexChanged.connect(self.refresh_logs)
        log_bar.addWidget(self.log_source_combo, stretch=1)

        self.ref_log_btn = QtWidgets.QPushButton("↻ Refresh")
        self.ref_log_btn.clicked.connect(self.refresh_logs)
        log_bar.addWidget(self.ref_log_btn)

        self.copy_log_btn = QtWidgets.QPushButton("📋 Copy")
        self.copy_log_btn.clicked.connect(self.copy_logs)
        log_bar.addWidget(self.copy_log_btn)

        self.clear_crash_btn = QtWidgets.QPushButton("🧹 Clear Crash Log")
        self.clear_crash_btn.clicked.connect(self.clear_crashes)
        log_bar.addWidget(self.clear_crash_btn)
        log_lay.addLayout(log_bar)

        self.log_view = QtWidgets.QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(_MONO)
        log_lay.addWidget(self.log_view, stretch=1)
        self.diag_tabs.addTab(log_page, "💥 Stacktraces & Logs")

        self.doctor_panel = _DoctorPoolPanel(self.server, self.net, self.pool, self)
        self.pool_table = self.doctor_panel.pool_table
        self.run_doctor = self.doctor_panel.run_doctor
        self.recycle_slow_legs = self.doctor_panel.recycle_slow_legs
        self.diag_tabs.addTab(self.doctor_panel, "🩺 Doctor & Pool")

        lay.addWidget(self.diag_tabs, stretch=1)

        bb = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Close)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

        self.refresh_ui()
        self.refresh_incidents()
        self.refresh_logs()

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
            self.server.stop(wait=False)
            self.refresh_ui()
            self.state_changed.emit()
            return
        if not self.confirm_enable():
            return
        port = self.port_spin.value()
        if self.pool is not None:
            self.toggle_btn.setEnabled(False)

            def _on_started(res: tuple[bool, str]) -> None:
                ok, msg = res
                self.toggle_btn.setEnabled(True)
                if not ok:
                    QtWidgets.QMessageBox.warning(self, "Diagnostic Web Server", msg)
                self.refresh_ui()
                self.state_changed.emit()

            self.pool.run(self.server.start, port, on_done=_on_started, tag="diag-server-toggle")
            return
        ok, msg = self.server.start(port)
        if not ok:
            QtWidgets.QMessageBox.warning(self, "Diagnostic Web Server", msg)
        self.refresh_ui()
        self.state_changed.emit()

    def refresh_ui(self) -> None:
        self.pass_edit.setText(self.server.get_password())
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

    def toggle_password_visibility(self, checked: bool) -> None:
        if checked:
            self.pass_edit.setEchoMode(QtWidgets.QLineEdit.Normal)
            self.show_pass_btn.setText("🙈 Hide")
        else:
            self.pass_edit.setEchoMode(QtWidgets.QLineEdit.Password)
            self.show_pass_btn.setText("👁 Show")

    def copy_password(self) -> None:
        pwd = self.server.get_password()
        if pwd:
            QtWidgets.QApplication.clipboard().setText(pwd)

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

    def refresh_logs(self) -> None:
        src = str(self.log_source_combo.currentData() or "crash")
        if self.pool is not None:
            self.pool.run(
                self.server.build_logs,
                self.net,
                source=src,
                lines=350,
                on_done=lambda res: self.log_view.setPlainText((res or {}).get("text") or "(empty)"),
                tag="diag-logs-refresh",
                rerun=True,
            )
            return
        res = self.server.build_logs(self.net, source=src, lines=350)
        self.log_view.setPlainText(res.get("text") or "(empty)")

    def copy_logs(self) -> None:
        QtWidgets.QApplication.clipboard().setText(self.log_view.toPlainText())

    def clear_crashes(self) -> None:
        diagnostics.clear_crash_log(self.server.base_dir)
        self.refresh_logs()
