"""
cert_dialog.py — the TLS certificate of a network: what it is, and how to
replace the self-signed one with a real certificate from an ACME CA.

Why this exists in the GUI at all: the https and quic carriers present the node
certificate, and by default it is self-signed. Peers do not care (they pin the
fingerprint), but anything that validates a chain does, and a self-signed
certificate is exactly what an observer does not expect to see on a real HTTPS
service. An operator who owns a domain in Cloudflare can get a real one here.

Everything the CLI reports is shown verbatim, including every failure in the
`tinc cert` taxonomy: a token that is not a token, a token without the rights,
a token with rights on a different zone, a CA that would not validate the
record. The code (`cloudflare-permission`, `acme-challenge`, ...) is printed
next to the sentence so a support request can quote it.

The two long-running actions run on the WorkerPool, never on the Qt thread.
"""

from __future__ import annotations

import os
from typing import Callable

from PySide6 import QtCore, QtGui, QtWidgets

from tinc_control import CommandResult, parse_cert_failure
from gui.workers import WorkerPool

CertFn = Callable[..., CommandResult]

_MONO = QtGui.QFont("Consolas" if os.name == "nt" else "Monospace", 10)

# The options this dialog owns. They live in the network's options block and
# are deliberately not propagated by an invitation: the token is a credential
# and the domain belongs to one node.
FIELDS = [
    ("CertDomain", "Domain", "vpn.example.com",
     "The public name this node presents. A record for it must live in a "
     "Cloudflare zone the token below can edit."),
    ("CloudflareToken", "Cloudflare API token", "",
     "Create it at dash.cloudflare.com/profile/api-tokens with the "
     "\"Edit zone DNS\" template, scoped to this domain's zone. "
     "A Global API Key is not a token and will not work."),
    ("AcmeContact", "Contact (optional)", "mailto:you@example.com",
     "Address the CA uses for expiry warnings."),
]


class CertDialog(QtWidgets.QDialog):
    """Read and change a network's certificate settings, and issue or renew."""

    saved = QtCore.Signal()

    def __init__(self, parent: QtWidgets.QWidget | None, net: str, options: dict,
                 save_fn: Callable[[dict], bool], status_fn: CertFn, check_fn: CertFn,
                 issue_fn: CertFn, pool: WorkerPool) -> None:
        super().__init__(parent)
        self.net = net
        self.options = options
        self.save_fn = save_fn
        self.status_fn = status_fn
        self.check_fn = check_fn
        self.issue_fn = issue_fn
        self.pool = pool
        self.last: CommandResult | None = None
        self._after_refresh: tuple[str, str] = ("", "")
        self.setWindowTitle(f"TLS certificate — '{net}'")
        self.resize(760, 620)

        lay = QtWidgets.QVBoxLayout(self)
        lay.addWidget(QtWidgets.QLabel(
            "The <b>https</b> and <b>quic</b> transports present this certificate. Without a "
            "domain and a Cloudflare token it is self-signed, which is fine for peers (they pin "
            "its fingerprint) but is not trusted by anything else."))

        form = QtWidgets.QFormLayout()
        self.edits: dict[str, QtWidgets.QLineEdit] = {}
        for key, label, placeholder, help_text in FIELDS:
            ed = QtWidgets.QLineEdit(str(options.get(key, "") or ""))
            ed.setPlaceholderText(placeholder)
            ed.setToolTip(help_text)
            if key == "CloudflareToken":
                ed.setEchoMode(QtWidgets.QLineEdit.Password)
            self.edits[key] = ed
            form.addRow(label + ":", ed)
        self.show_token = QtWidgets.QCheckBox("Show the token")
        self.show_token.toggled.connect(self._toggle_token)
        form.addRow("", self.show_token)
        lay.addLayout(form)

        row = QtWidgets.QHBoxLayout()
        self.save_btn = QtWidgets.QPushButton("💾 Save settings")
        self.save_btn.clicked.connect(self.save)
        self.check_btn = QtWidgets.QPushButton("🔎 Check token")
        self.check_btn.setToolTip("Asks Cloudflare whether the token works and whether it can see "
                                  "the zone that contains the domain. Creates nothing.")
        self.check_btn.clicked.connect(self.check)
        self.issue_btn = QtWidgets.QPushButton("🔐 Issue / renew certificate")
        self.issue_btn.setToolTip("Writes a DNS challenge record, waits for the CA to validate it, "
                                  "stores the certificate, and removes the record again. "
                                  "Takes up to a few minutes.")
        self.issue_btn.clicked.connect(self.issue)
        self.force_box = QtWidgets.QCheckBox("replace even if still valid")
        self.staging_box = QtWidgets.QCheckBox("staging CA (test, not trusted)")
        for w in (self.save_btn, self.check_btn, self.issue_btn, self.force_box, self.staging_box):
            row.addWidget(w)
        row.addStretch()
        lay.addLayout(row)

        self.status_lbl = QtWidgets.QLabel("")
        self.status_lbl.setWordWrap(True)
        lay.addWidget(self.status_lbl)

        self.hint_lbl = QtWidgets.QLabel("")
        self.hint_lbl.setWordWrap(True)
        self.hint_lbl.setStyleSheet("color: #5f6368;")
        lay.addWidget(self.hint_lbl)

        lay.addWidget(QtWidgets.QLabel("Output of <code>tinc cert</code>:"))
        self.log = QtWidgets.QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setFont(_MONO)
        self.log.setMaximumBlockCount(4000)
        lay.addWidget(self.log, stretch=1)

        bb = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Close)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

        self.refresh()

    # -- helpers ----------------------------------------------------------
    def _toggle_token(self, on: bool) -> None:
        self.edits["CloudflareToken"].setEchoMode(
            QtWidgets.QLineEdit.Normal if on else QtWidgets.QLineEdit.Password)

    def values(self) -> dict:
        return {k: e.text().strip() for k, e in self.edits.items()}

    def _busy(self, on: bool, what: str = "") -> None:
        for b in (self.save_btn, self.check_btn, self.issue_btn):
            b.setEnabled(not on)
        if on:
            self._say(what, "#1a73e8")

    def _say(self, text: str, color: str = "") -> None:
        self.status_lbl.setText(text)
        self.status_lbl.setStyleSheet(f"color: {color};" if color else "")

    def _append(self, res: CommandResult) -> None:
        for stream in (res.stderr, res.stdout):
            if stream:
                self.log.appendPlainText(stream)

    # -- actions ----------------------------------------------------------
    def save(self) -> bool:
        """Write the three options back. An empty field removes the option, so
        clearing the token really does disable ACME rather than storing ""."""
        if self.save_fn(self.values()):
            self._say("settings saved", "#1e8e3e")
            self.saved.emit()
            return True
        self._say("settings could not be saved — see the main window", "#d93025")
        return False

    def refresh(self, then_say: str = "", then_color: str = "") -> None:
        """Re-read the stored certificate. `then_say` survives the refresh: the
        outcome of an issue must not be wiped by the status read that follows it."""
        self._after_refresh = (then_say, then_color)
        self._busy(True, "reading the stored certificate…")
        self.pool.run(self.status_fn, self.net, on_done=self._status_done, on_error=self._failed)

    def check(self) -> None:
        if not self.save():
            return
        self.log.clear()
        self._busy(True, "asking Cloudflare about the token…")
        self.pool.run(self.check_fn, self.net, on_done=self._cert_done, on_error=self._failed)

    def issue(self) -> None:
        if not self.save():
            return
        self.log.clear()
        self._busy(True, "talking to the CA — this can take a few minutes…")
        self.pool.run(self.issue_fn, self.net, self.force_box.isChecked(),
                      self.staging_box.isChecked(), on_done=self._issue_done,
                      on_error=self._failed)

    # -- results ----------------------------------------------------------
    def _status_done(self, res: CommandResult) -> None:
        self._busy(False)
        self.last = res
        text = (res.stdout or res.stderr or "").strip()
        say, color = self._after_refresh
        if say:
            # this read followed an issue: keep its transcript, add the new state
            self.log.appendPlainText("\n--- the certificate now stored ---\n" + text)
        else:
            self.log.setPlainText(text)
            self.hint_lbl.setText("")
        self._say(say, color)

    def _cert_done(self, res: CommandResult) -> None:
        self._busy(False)
        self.last = res
        self._append(res)
        if res.ok:
            self._say("the token works and it can see the zone for this domain", "#1e8e3e")
            self.hint_lbl.setText("")
        else:
            self._report_failure(res)

    def _issue_done(self, res: CommandResult) -> None:
        self._busy(False)
        self.last = res
        self._append(res)
        if res.ok:
            self.hint_lbl.setText("")
            self.refresh("certificate stored — peers holding the old TlsFingerprint need the new one "
                         "(re-issue their invitation, or update their host record)", "#1e8e3e")
        else:
            self._report_failure(res)

    def _report_failure(self, res: CommandResult) -> None:
        code, detail, hint = parse_cert_failure(res.stderr + "\n" + res.stdout)
        if code:
            self._say(f"{code}: {detail}", "#d93025")
            self.hint_lbl.setText(hint)
        else:
            self._say(f"tinc cert failed (rc={res.rc}) — see the output below", "#d93025")
            self.hint_lbl.setText("")

    def _failed(self, msg: str) -> None:
        self._busy(False)
        self._say("could not run tinc", "#d93025")
        self.log.appendPlainText(msg)
