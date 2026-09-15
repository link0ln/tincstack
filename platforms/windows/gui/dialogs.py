"""
dialogs.py — Invite, Join and raw-YAML dialogs.

Invite/Join drive the M2 CLI contract (`tinc -c tinc.yaml invite <name>` /
`tinc -c tinc.yaml join <string>`) through a callable, off the Qt thread via
WorkerPool, and surface stderr verbatim (address-discovery warnings, join
errors). Errors are shown inline, never in a modal box, so the dialogs are
testable offscreen.
"""

from __future__ import annotations

import os
from typing import Callable

from PySide6 import QtCore, QtGui, QtWidgets

from tinc_control import CommandResult
from gui.workers import WorkerPool

InviteFn = Callable[[str, str], CommandResult]
JoinFn = Callable[[str | None, str], CommandResult]

_MONO = QtGui.QFont("Consolas" if os.name == "nt" else "Monospace", 10)


def _panel(parent: QtWidgets.QWidget, placeholder: str) -> QtWidgets.QPlainTextEdit:
    p = QtWidgets.QPlainTextEdit(parent)
    p.setReadOnly(True)
    p.setFont(_MONO)
    p.setPlaceholderText(placeholder)
    p.setMaximumBlockCount(2000)
    return p


class InviteDialog(QtWidgets.QDialog):
    """Issue an invitation for a new peer of `net`."""

    def __init__(self, parent: QtWidgets.QWidget | None, net: str, invite_fn: InviteFn,
                 pool: WorkerPool) -> None:
        super().__init__(parent)
        self.net = net
        self.invite_fn = invite_fn
        self.pool = pool
        self.result: CommandResult | None = None
        self.setWindowTitle(f"Invite a peer into '{net}'")
        self.resize(640, 420)

        lay = QtWidgets.QVBoxLayout(self)
        lay.addWidget(QtWidgets.QLabel(
            f"Creates a one-line invitation for a new node of <b>{net}</b>. Send the string to the "
            f"peer; it joins with <i>Join…</i> (or <code>tinc join</code>) and gets its address, "
            f"routes and transport settings from this node. The network must be running."))
        form = QtWidgets.QFormLayout()
        self.name_edit = QtWidgets.QLineEdit()
        self.name_edit.setPlaceholderText("new node's name (letters, digits, _)")
        self.name_edit.setValidator(QtGui.QRegularExpressionValidator(
            QtCore.QRegularExpression(r"[A-Za-z0-9_]{1,64}"), self))
        form.addRow("Node name:", self.name_edit)
        lay.addLayout(form)

        row = QtWidgets.QHBoxLayout()
        self.run_btn = QtWidgets.QPushButton("✉ Create invitation")
        self.run_btn.clicked.connect(self.start)
        row.addWidget(self.run_btn)
        self.status_lbl = QtWidgets.QLabel("")
        row.addWidget(self.status_lbl, stretch=1)
        lay.addLayout(row)

        lay.addWidget(QtWidgets.QLabel("Invitation (one line):"))
        rrow = QtWidgets.QHBoxLayout()
        self.result_edit = QtWidgets.QLineEdit()
        self.result_edit.setReadOnly(True)
        self.result_edit.setFont(_MONO)
        rrow.addWidget(self.result_edit, stretch=1)
        self.copy_btn = QtWidgets.QPushButton("📋 Copy")
        self.copy_btn.setEnabled(False)
        self.copy_btn.clicked.connect(self.copy)
        rrow.addWidget(self.copy_btn)
        lay.addLayout(rrow)

        lay.addWidget(QtWidgets.QLabel("Daemon / CLI messages (stderr):"))
        self.stderr_view = _panel(self, "warnings such as the address used for the invitation appear here")
        lay.addWidget(self.stderr_view, stretch=1)

        bb = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Close)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)
        self.name_edit.returnPressed.connect(self.start)
        self.name_edit.setFocus()

    def start(self) -> None:
        name = self.name_edit.text().strip()
        if not name:
            self.status_lbl.setText("enter a node name")
            return
        self.run_btn.setEnabled(False)
        self.copy_btn.setEnabled(False)
        self.result_edit.clear()
        self.stderr_view.clear()
        self.status_lbl.setText("running tinc invite… (the GUI stays responsive)")
        self.pool.run(self.invite_fn, self.net, name, on_done=self._done, on_error=self._error)

    def _done(self, res: CommandResult) -> None:
        self.result = res
        self.run_btn.setEnabled(True)
        self.stderr_view.setPlainText(res.stderr)
        if res.ok and res.stdout:
            line = res.stdout.splitlines()[-1].strip()
            self.result_edit.setText(line)
            self.copy_btn.setEnabled(True)
            self.status_lbl.setText("invitation created — copy and send it to the peer")
        else:
            self.status_lbl.setText(f"tinc invite failed (rc={res.rc}) — see messages below")
            if not res.stderr:
                self.stderr_view.setPlainText(res.stdout or "(no output)")

    def _error(self, msg: str) -> None:
        self.run_btn.setEnabled(True)
        self.status_lbl.setText("could not run tinc")
        self.stderr_view.setPlainText(msg)

    def copy(self) -> None:
        QtWidgets.QApplication.clipboard().setText(self.result_edit.text())
        self.status_lbl.setText("copied to clipboard")


class JoinDialog(QtWidgets.QDialog):
    """Join a network from a pasted invitation string; on success the caller
    reloads the config (the CLI wrote the new network into tinc.yaml)."""

    joined = QtCore.Signal(str)   # network name used (may be "" = CLI default)

    def __init__(self, parent: QtWidgets.QWidget | None, existing: list[str], join_fn: JoinFn,
                 pool: WorkerPool) -> None:
        super().__init__(parent)
        self.existing = list(existing)
        self.join_fn = join_fn
        self.pool = pool
        self.result: CommandResult | None = None
        self.setWindowTitle("Join a network from an invitation")
        self.resize(640, 440)

        lay = QtWidgets.QVBoxLayout(self)
        lay.addWidget(QtWidgets.QLabel(
            "Paste the invitation string you received. <code>tinc join</code> contacts the inviter, "
            "creates this node's identity and writes the new network into <b>tinc.yaml</b> "
            "(address from the inviter's pool, routes, transports, certificate fingerprint)."))
        form = QtWidgets.QFormLayout()
        self.net_edit = QtWidgets.QLineEdit()
        self.net_edit.setPlaceholderText("optional — network name to create (default: tincstack)")
        self.net_edit.setValidator(QtGui.QRegularExpressionValidator(
            QtCore.QRegularExpression(r"[A-Za-z0-9_\-]{0,64}"), self))
        form.addRow("Network name:", self.net_edit)
        lay.addLayout(form)
        lay.addWidget(QtWidgets.QLabel("Invitation:"))
        self.invite_edit = QtWidgets.QPlainTextEdit()
        self.invite_edit.setFont(_MONO)
        self.invite_edit.setPlaceholderText("host:port/AbCdEf…")
        self.invite_edit.setMaximumHeight(70)
        lay.addWidget(self.invite_edit)

        row = QtWidgets.QHBoxLayout()
        self.run_btn = QtWidgets.QPushButton("⤵ Join")
        self.run_btn.clicked.connect(self.start)
        row.addWidget(self.run_btn)
        self.status_lbl = QtWidgets.QLabel("")
        row.addWidget(self.status_lbl, stretch=1)
        lay.addLayout(row)

        lay.addWidget(QtWidgets.QLabel("Output:"))
        self.output_view = _panel(self, "tinc join output (stdout + stderr) appears here")
        lay.addWidget(self.output_view, stretch=1)

        bb = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Close)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)
        self.invite_edit.setFocus()

    def start(self) -> None:
        inv = self.invite_edit.toPlainText().strip()
        net = self.net_edit.text().strip() or None
        if not inv:
            self.status_lbl.setText("paste an invitation first")
            return
        if " " in inv or "\n" in inv:
            self.status_lbl.setText("an invitation is a single token — check the paste")
            return
        if net and net in self.existing:
            self.status_lbl.setText(f"network '{net}' already exists in tinc.yaml — pick another name")
            return
        self.run_btn.setEnabled(False)
        self.output_view.clear()
        self.status_lbl.setText("running tinc join… (contacting the inviter)")
        self.pool.run(self.join_fn, net, inv, on_done=lambda r: self._done(net, r),
                      on_error=self._error)

    def _done(self, net: str | None, res: CommandResult) -> None:
        self.result = res
        self.run_btn.setEnabled(True)
        text = "\n".join(t for t in (res.stdout, res.stderr) if t)
        self.output_view.setPlainText(text or "(no output)")
        if res.ok:
            self.status_lbl.setText("joined — the network was written to tinc.yaml")
            self.joined.emit(net or "")
        else:
            self.status_lbl.setText(f"tinc join failed (rc={res.rc}) — see output")

    def _error(self, msg: str) -> None:
        self.run_btn.setEnabled(True)
        self.status_lbl.setText("could not run tinc")
        self.output_view.setPlainText(msg)


class RawYamlDialog(QtWidgets.QDialog):
    """Edit tinc.yaml as text. The save validates the document and writes it
    atomically (yaml_config.save_text); parse errors are shown inline."""

    saved = QtCore.Signal()

    def __init__(self, parent: QtWidgets.QWidget | None, path: str,
                 save_fn: Callable[[str, str], None], load_error: str = "") -> None:
        super().__init__(parent)
        self.path = path
        self.save_fn = save_fn
        self.setWindowTitle(f"Raw {os.path.basename(path)}")
        self.resize(760, 620)
        lay = QtWidgets.QVBoxLayout(self)
        self.editor = QtWidgets.QPlainTextEdit()
        self.editor.setFont(_MONO)
        try:
            with open(path, encoding="utf-8") as f:
                self.editor.setPlainText(f.read())
        except OSError as e:
            self.editor.setPlainText(f"# {e}")
        lay.addWidget(self.editor, stretch=1)
        self.error_lbl = QtWidgets.QLabel(load_error)
        self.error_lbl.setWordWrap(True)
        self.error_lbl.setStyleSheet("color:#d93025;")
        lay.addWidget(self.error_lbl)
        bb = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Save | QtWidgets.QDialogButtonBox.Close)
        bb.accepted.connect(self.save)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def save(self) -> None:
        try:
            self.save_fn(self.path, self.editor.toPlainText())
        except Exception as e:  # ConfigError / OSError
            self.error_lbl.setText(str(e))
            return
        self.error_lbl.setText("")
        self.saved.emit()
        self.accept()
