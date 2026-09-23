"""
transports_panel.py — editor for the transport / circumvention options
(backend/transports.py is the schema; this is only the widgets).

`load(options)` fills the widgets from the file's values (daemon defaults for
absent keys); `changes()` returns exactly the keys the user changed, so the
save path writes nothing else (the daemon owns the file and its defaults).
"""

from __future__ import annotations

from typing import Any

from PySide6 import QtCore, QtWidgets

import transports as tr


class TransportsPanel(QtWidgets.QWidget):
    changed = QtCore.Signal()

    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self._loaded: dict[str, Any] = {}
        root = QtWidgets.QVBoxLayout(self)

        # -- negotiation: accept list + dial preference --
        neg = QtWidgets.QGroupBox("Transport negotiation  (ARCHITECTURE §4 — one side's tick is enough)")
        ng = QtWidgets.QGridLayout(neg)
        ng.addWidget(QtWidgets.QLabel("<b>Accept</b> (Transports) — what this node's listener answers:"), 0, 0)
        ng.addWidget(QtWidgets.QLabel("<b>Prefer</b> (PreferredTransports) — what this node dials, in order:"), 0, 1)
        self.accept: dict[str, QtWidgets.QCheckBox] = {}
        abox = QtWidgets.QVBoxLayout()
        for c in tr.CARRIERS:
            cb = QtWidgets.QCheckBox(c)
            cb.setToolTip(tr.CARRIER_HELP[c])
            cb.toggled.connect(self.changed)
            self.accept[c] = cb
            abox.addWidget(cb)
        abox.addStretch()
        ng.addLayout(abox, 1, 0)
        pbox = QtWidgets.QHBoxLayout()
        self.prefer = QtWidgets.QListWidget()
        self.prefer.setToolTip("Checked carriers are tried top to bottom; the first one in the peer's "
                               "accept list wins. Tick 'quic' and move it up to prefer QUIC.")
        for c in tr.CARRIERS:
            it = QtWidgets.QListWidgetItem(c)
            it.setFlags(it.flags() | QtCore.Qt.ItemIsUserCheckable)
            it.setCheckState(QtCore.Qt.Unchecked)
            it.setToolTip(tr.CARRIER_HELP[c])
            self.prefer.addItem(it)
        self.prefer.itemChanged.connect(lambda _it: self.changed.emit())
        pbox.addWidget(self.prefer)
        ud = QtWidgets.QVBoxLayout()
        self.up_btn = QtWidgets.QPushButton("▲")
        self.down_btn = QtWidgets.QPushButton("▼")
        self.up_btn.clicked.connect(lambda: self._move(-1))
        self.down_btn.clicked.connect(lambda: self._move(+1))
        ud.addWidget(self.up_btn)
        ud.addWidget(self.down_btn)
        ud.addStretch()
        pbox.addLayout(ud)
        ng.addLayout(pbox, 1, 1)
        root.addWidget(neg)

        # -- obfs --
        obfs = QtWidgets.QGroupBox("Obfuscated UDP (carrier 'obfs')")
        of = QtWidgets.QFormLayout(obfs)
        self.spins: dict[str, QtWidgets.QSpinBox] = {}
        for name in ("ObfsJunkPacketCount", "ObfsJunkPacketMinSize", "ObfsJunkPacketMaxSize",
                     "ObfsInitHeaderJunkSize"):
            spec = tr.SPEC_BY_NAME[name]
            sb = QtWidgets.QSpinBox()
            sb.setRange(spec.minimum, spec.maximum)
            sb.setToolTip(spec.help)
            sb.valueChanged.connect(self.changed)
            self.spins[name] = sb
            of.addRow(name + ":", sb)
        self.magic = QtWidgets.QLineEdit()
        self.magic.setPlaceholderText("0 = off, N, or MIN-MAX")
        self.magic.setToolTip(tr.SPEC_BY_NAME["ObfsInitMagicHeader"].help)
        self.magic.textChanged.connect(self.changed)
        of.addRow("ObfsInitMagicHeader:", self.magic)
        root.addWidget(obfs)

        # -- https front --
        https = QtWidgets.QGroupBox("HTTPS front (carrier 'https'; the decoy on the listen port is default-on)")
        hf = QtWidgets.QFormLayout(https)
        self.https_port = QtWidgets.QSpinBox()
        self.https_port.setRange(0, 65535)
        self.https_port.setSpecialValueText("0 (off)")
        self.https_port.setToolTip(tr.SPEC_BY_NAME["HttpsPort"].help)
        self.https_port.valueChanged.connect(self.changed)
        hf.addRow("HttpsPort:", self.https_port)
        self.paths: dict[str, QtWidgets.QLineEdit] = {}
        for name in ("TlsCert", "TlsKey", "HttpsDecoyRoot"):
            row = QtWidgets.QHBoxLayout()
            le = QtWidgets.QLineEdit()
            le.setPlaceholderText(tr.SPEC_BY_NAME[name].help)
            le.textChanged.connect(self.changed)
            b = QtWidgets.QPushButton("…")
            b.setFixedWidth(28)
            b.clicked.connect(lambda _c, n=name: self._browse(n))
            row.addWidget(le, stretch=1)
            row.addWidget(b)
            self.paths[name] = le
            hf.addRow(name + ":", row)
        self.decoy_upstream = QtWidgets.QLineEdit()
        self.decoy_upstream.setPlaceholderText(tr.SPEC_BY_NAME["HttpsDecoyUpstream"].help)
        self.decoy_upstream.textChanged.connect(self.changed)
        hf.addRow("HttpsDecoyUpstream:", self.decoy_upstream)
        root.addWidget(https)

        # -- quic --
        quic = QtWidgets.QGroupBox("QUIC (carrier 'quic'; certificate shared with the HTTPS front)")
        qf = QtWidgets.QFormLayout(quic)
        self.quic_port = QtWidgets.QSpinBox()
        self.quic_port.setRange(1, 65535)
        self.quic_port.valueChanged.connect(self.changed)
        qf.addRow("QuicPort:", self.quic_port)
        root.addWidget(quic)
        root.addStretch()
        self.load({})

    # -- helpers --
    def _browse(self, name: str) -> None:
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, name) if name != "HttpsDecoyRoot" \
            else (QtWidgets.QFileDialog.getExistingDirectory(self, name), "")
        if path:
            self.paths[name].setText(path)

    def _move(self, delta: int) -> None:
        r = self.prefer.currentRow()
        if r < 0 or not (0 <= r + delta < self.prefer.count()):
            return
        it = self.prefer.takeItem(r)
        self.prefer.insertItem(r + delta, it)
        self.prefer.setCurrentRow(r + delta)
        self.changed.emit()

    def _set_prefer(self, order: list[str]) -> None:
        """Rebuild the preference list: checked carriers in `order` first, then
        the rest unchecked in canonical order."""
        self.prefer.blockSignals(True)
        self.prefer.clear()
        for c in list(order) + [c for c in tr.CARRIERS if c not in order]:
            if c not in tr.CARRIERS:
                continue
            it = QtWidgets.QListWidgetItem(c)
            it.setFlags(it.flags() | QtCore.Qt.ItemIsUserCheckable)
            it.setCheckState(QtCore.Qt.Checked if c in order else QtCore.Qt.Unchecked)
            it.setToolTip(tr.CARRIER_HELP[c])
            self.prefer.addItem(it)
        self.prefer.blockSignals(False)

    # -- public API --
    def load(self, options: dict) -> None:
        self._loaded = dict(options)
        eff = tr.effective(options)
        self.blockSignals(True)
        for c, cb in self.accept.items():
            cb.setChecked(c in eff["Transports"])
        self._set_prefer(eff["PreferredTransports"])
        for name, sb in self.spins.items():
            v = eff[name]
            sb.setValue(int(v) if str(v).lstrip("-").isdigit() else sb.minimum())
        self.magic.setText(str(eff["ObfsInitMagicHeader"]))
        self.https_port.setValue(int(eff["HttpsPort"]) if str(eff["HttpsPort"]).isdigit() else 443)
        for name, le in self.paths.items():
            le.setText(str(eff[name] or ""))
        self.decoy_upstream.setText(str(eff["HttpsDecoyUpstream"] or ""))
        self.quic_port.setValue(int(eff["QuicPort"]) if str(eff["QuicPort"]).isdigit() else 443)
        self.blockSignals(False)

    def preferred(self) -> list[str]:
        out = []
        for i in range(self.prefer.count()):
            it = self.prefer.item(i)
            if it.checkState() == QtCore.Qt.Checked:
                out.append(it.text())
        return out

    def set_prefer_quic(self, on: bool) -> None:
        """The 'tick QUIC' knob (decision 2): put quic first in the dial
        preference (keeping plain as the fallback) or drop it."""
        order = [c for c in self.preferred() if c != "quic"]
        if on:
            order = ["quic"] + order
            if "plain" not in order:
                order.append("plain")
        self._set_prefer(order or ["plain"])
        self.changed.emit()

    def edited(self) -> dict[str, Any]:
        """Every transport option as the widgets show it now."""
        out: dict[str, Any] = {
            "Transports": [c for c in tr.CARRIERS if self.accept[c].isChecked()],
            "PreferredTransports": self.preferred(),
            "ObfsInitMagicHeader": self.magic.text().strip() or "0",
            "HttpsPort": self.https_port.value(),
            "HttpsDecoyUpstream": self.decoy_upstream.text().strip(),
            "QuicPort": self.quic_port.value(),
        }
        for name, sb in self.spins.items():
            out[name] = sb.value()
        for name, le in self.paths.items():
            out[name] = le.text().strip()
        m = out["ObfsInitMagicHeader"]
        if m.isdigit():
            out["ObfsInitMagicHeader"] = int(m)
        return out

    def errors(self) -> list[str]:
        return tr.validate(self.edited())

    def changes(self) -> dict[str, Any]:
        """Only what the user changed relative to the loaded options."""
        return tr.changes(self._loaded, self.edited())
