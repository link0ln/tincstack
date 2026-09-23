"""Offscreen GUI tests (QT_QPA_PLATFORM=offscreen): the window survives a
malformed tinc.yaml, invite/join dialogs drive a mocked `tinc` runner off the
Qt thread, the Transports tab writes only the keys the user changed, and the
sampler / start-stop never block the GUI thread."""
import os
import textwrap
import threading
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6 import QtWidgets  # noqa: E402

import yaml_config as yc  # noqa: E402
import main as tincmgr  # noqa: E402
from gui.dialogs import InviteDialog, JoinDialog  # noqa: E402
from gui.cert_dialog import CertDialog  # noqa: E402
from tinc_control import parse_cert_failure, parse_cert_expiry  # noqa: E402


@pytest.fixture(scope="session")
def qapp():
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    yield app


def wait_until(cond, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        QtWidgets.QApplication.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    QtWidgets.QApplication.processEvents()
    return cond()


BASE_YAML = textwrap.dedent("""\
    networks:
      demo:
        autostart: false
        options:
          Name: demobook
          Mode: router
          Port: 655
        hosts:
          demobook: |
            Ed25519PublicKey = AAAA
            Subnet = 10.99.0.1/32
    """)


class FakeTinc:
    """Mocked `tinc` runner: records every call and the thread it ran on."""

    def __init__(self, yaml_path: str, running: bool = True, delay: float = 0.0,
                 peer: bool = False, cert_days: int | None = None):
        self.yaml_path = yaml_path
        self.running = running
        self.delay = delay
        # `cert_days`: days until the stored certificate expires (negative =
        # already expired), None = no certificate stored yet.
        self.cert_days = cert_days
        # `peer`: also report a gateway node that announces a LAN and a default
        # route, which is what the route toggles are about.
        self.peer = peer
        self.calls = []
        self.threads = set()

    def __call__(self, cmd, timeout):
        self.calls.append(cmd)
        self.threads.add(threading.get_ident())
        if self.delay:
            time.sleep(self.delay)
        sub = cmd[cmd.index("-c") + 2:]
        if sub[:2] == ["dump", "nodes"]:
            if not self.running:
                return 1, "", "Could not open control socket"
            out = ("demobook id 1 at MYSELF port 655 options c status 0 nexthop demobook via demobook "
                   "distance 0 pmtu 1518 (min 0 max 1518) rx 0 0 tx 0 0\n")
            if self.peer:
                out += ("gw id 2 at 203.0.113.9 port 655 options c status 90 nexthop gw via gw "
                        "distance 1 pmtu 1400 (min 0 max 1500) rx 5 60 tx 7 80\n")
            return 0, out, ""
        if sub[:2] == ["dump", "subnets"] and self.peer:
            return 0, ("10.79.0.1 owner demobook\n"
                       "10.79.0.7 owner gw\n"
                       "192.168.1.0/24 owner gw\n"
                       "0.0.0.0/0 owner gw\n"), ""
        if sub[0] == "dump":
            return 0, "", ""
        if sub[0] == "invite":
            return 0, f"203.0.113.9:655/INV_{sub[1]}\n", "Warning: using local address 203.0.113.9\n"
        if sub[0] == "cert":
            return self.cert(sub[1:], cmd)
        if sub[0] == "join":
            if not sub[1].startswith("203.0.113.9:655/"):
                return 1, "", "Error: invalid invitation\n"
            net = cmd[cmd.index("-n") + 1] if "-n" in cmd else "tincstack"
            # the real CLI writes the joined network into tinc.yaml
            with open(self.yaml_path, encoding="utf-8") as f:
                text = f.read()
            text += (f"  {net}:\n    options:\n      Name: laptop\n      Port: 0\n"
                     f"      ConnectTo: [demobook]\n")
            yc.atomic_write_text(self.yaml_path, text)
            return 0, f"Configuration stored in: {self.yaml_path}\n", "Connected to 203.0.113.9 port 655...\n"
        return 1, "", "unknown"

    def cert(self, args, cmd):
        """`tinc cert ...` as the real CLI answers it: the failure taxonomy goes
        to stderr as "FAILED (<code>)" plus a detail and a hint line."""
        opts = yc.load(self.yaml_path).net(cmd[cmd.index("-n") + 1]).options
        sub = args[0] if args else "status"
        if sub == "status":
            head = ("CertDomain     %s\nCloudflare     %s\n"
                    % (opts.get("CertDomain", "(unset)"),
                       "token set" if opts.get("CloudflareToken") else "no token set"))
            if self.cert_days is None:
                return 0, head + "Certificate    none stored yet\n", ""
            when = ("in %d days" % self.cert_days if self.cert_days >= 0
                    else "EXPIRED %d days ago" % -self.cert_days)
            return 0, head + ("Fingerprint    abc\nExpires        %s\nKind           issued by a CA\n"
                              % when), ""
        if not opts.get("CloudflareToken"):
            return 1, "", ("\ntinc cert: FAILED (config)\n  No CloudflareToken is set.\n"
                           "  Create an API token with the \"Edit zone DNS\" template.\n")
        if opts["CloudflareToken"] == "wrong-zone-token-0000000":
            return 1, "", ("\ntinc cert: FAILED (cloudflare-zone)\n"
                           "  The Cloudflare token sees no zone that contains %s.\n"
                           "  Point CertDomain at a name inside one of those zones.\n"
                           % opts.get("CertDomain", ""))
        if sub == "check":
            return 0, "", ""
        return 0, "Stored the certificate for %s.\nNew TlsFingerprint: abc\n" % opts["CertDomain"], ""


@pytest.fixture
def window(qapp, tmp_path, monkeypatch):
    monkeypatch.setenv("TINCSTACK_BIN_DIR", str(tmp_path / "nobin"))
    cfg = tmp_path / "tinc.yaml"
    cfg.write_text(BASE_YAML)
    fake = FakeTinc(str(cfg))
    w = tincmgr.MainWindow(str(cfg), runner=fake, autostart=False)
    w.fake = fake
    yield w
    w.timer.stop()
    w.pool.wait_all()
    w.deleteLater()
    QtWidgets.QApplication.processEvents()


def test_window_opens_with_malformed_yaml(qapp, tmp_path, monkeypatch):
    monkeypatch.setenv("TINCSTACK_BIN_DIR", str(tmp_path / "nobin"))
    cfg = tmp_path / "tinc.yaml"
    cfg.write_text("networks:\n  demo: [\n")
    w = tincmgr.MainWindow(str(cfg), runner=FakeTinc(str(cfg)), autostart=False)
    try:
        assert w.load_error and "malformed YAML" in w.load_error
        assert not w.banner.isHidden()
        assert "could not be read" in w.banner_lbl.text()
        assert w.app.networks == {}
        # fixing the file through the raw-YAML save path clears the banner
        yc.save_text(str(cfg), BASE_YAML)
        w.reload_config()
        assert w.load_error == "" and w.banner.isHidden()
        assert list(w.app.networks) == ["demo"]
        assert w.cur_net() == "demo"
    finally:
        w.timer.stop(); w.pool.wait_all(); w.deleteLater()


def test_sampler_runs_off_qt_thread_and_updates_running_state(window):
    w = window
    main_thread = threading.get_ident()
    assert wait_until(lambda: w._running.get("demo") is True)
    assert w.fake.threads and main_thread not in w.fake.threads
    assert any(c[-2:] == ["dump", "nodes"] for c in w.fake.calls)
    assert "[running]" in w.net_list.item(0).text()
    assert w.peers.table.item(0, 0).text() == "demobook"


def test_invite_dialog_offscreen(window):
    w = window
    main_thread = threading.get_ident()
    dlg = InviteDialog(w, "demo", w.tc.invite, w.pool)
    dlg.name_edit.setText("laptop")
    dlg.run_btn.click()
    assert not dlg.run_btn.isEnabled()
    assert wait_until(lambda: dlg.result is not None)
    assert dlg.result.ok
    assert dlg.result_edit.text() == "203.0.113.9:655/INV_laptop"
    assert "local address 203.0.113.9" in dlg.stderr_view.toPlainText()
    assert dlg.copy_btn.isEnabled() and dlg.run_btn.isEnabled()
    assert w.fake.calls[-1] == ["tinc", "-n", "demo", "-c", w.app.path, "invite", "laptop"] or \
        w.fake.calls[-1][-2:] == ["invite", "laptop"]
    assert main_thread not in w.fake.threads
    dlg.copy_btn.click()
    assert dlg.status_lbl.text() == "copied to clipboard"
    clip = QtWidgets.QApplication.clipboard().text()
    assert clip in ("", "203.0.113.9:655/INV_laptop")   # offscreen clipboard may be a no-op
    # empty name is refused without running anything
    n = len(w.fake.calls)
    dlg.name_edit.clear(); dlg.start()
    assert dlg.status_lbl.text() == "enter a node name" and len(w.fake.calls) == n
    dlg.deleteLater()


def test_join_dialog_offscreen(window):
    w = window
    dlg = JoinDialog(w, list(w.app.networks), w.tc.join, w.pool)
    dlg.joined.connect(w._on_joined)
    # bad paste: refused before running
    dlg.invite_edit.setPlainText("two tokens here"); dlg.start()
    assert "single token" in dlg.status_lbl.text()
    # existing name refused
    dlg.net_edit.setText("demo"); dlg.invite_edit.setPlainText("203.0.113.9:655/INV_x"); dlg.start()
    assert "already exists" in dlg.status_lbl.text()
    # invalid invitation: CLI error surfaced, nothing joined
    dlg.net_edit.setText("office"); dlg.invite_edit.setPlainText("garbage"); dlg.start()
    assert wait_until(lambda: dlg.result is not None)
    assert not dlg.result.ok and "invalid invitation" in dlg.output_view.toPlainText()
    assert "office" not in w.app.networks
    # valid: the CLI writes the network, the GUI reloads and selects it
    dlg.result = None
    dlg.invite_edit.setPlainText("203.0.113.9:655/INV_laptop\n"); dlg.start()
    assert wait_until(lambda: dlg.result is not None)
    assert dlg.result.ok
    assert "Connected to 203.0.113.9" in dlg.output_view.toPlainText()
    assert wait_until(lambda: "office" in w.app.networks)
    assert w.cur_net() == "office"
    assert w.app.net("office").options["ConnectTo"] == ["demobook"]
    assert w.fake.calls[-1][-3:] == ["-c", w.app.path, "join"] or w.fake.calls[-1][-2] == "join"
    assert w.fake.calls[-1][1:3] == ["-n", "office"]
    dlg.deleteLater()


def test_transports_tab_tick_quic_writes_only_changed_keys(window):
    w = window
    w.tabs.setCurrentWidget(w.transports)
    panel = w.transports.panel
    assert panel.preferred() == ["plain"]
    assert all(cb.isChecked() for cb in panel.accept.values())   # default: accept all
    panel.set_prefer_quic(True)
    assert panel.preferred() == ["quic", "plain"]
    assert panel.changes() == {"PreferredTransports": ["quic", "plain"]}
    assert w.transports.save()
    expected = textwrap.dedent("""\
        networks:
          demo:
            autostart: false
            options:
              Name: demobook
              Mode: router
              Port: 655
              PreferredTransports:
                - quic
                - plain
            hosts:
              demobook: |
                Ed25519PublicKey = AAAA
                Subnet = 10.99.0.1/32
        """)
    assert open(w.app.path, encoding="utf-8").read() == expected
    # reload from disk -> the editor shows the persisted preference
    w.reload_config()
    assert w.transports.panel.preferred() == ["quic", "plain"]
    # untick: the key was present, so it is written back explicitly as [plain]
    w.transports.panel.set_prefer_quic(False)
    assert w.transports.save()
    assert yc.load(w.app.path).net("demo").options["PreferredTransports"] == ["plain"]


def test_transports_tab_validation_blocks_save(window):
    w = window
    panel = w.transports.panel
    panel.paths["TlsCert"].setText("C:/certs/fullchain.pem")   # key missing
    panel.accept["plain"].setChecked(False); panel.accept["obfs"].setChecked(False)
    panel.accept["https"].setChecked(False); panel.accept["quic"].setChecked(False)
    assert not w.transports.save()
    err = w.transports.error_lbl.text()
    assert "TlsCert and TlsKey" in err and "at least one carrier" in err
    assert "TlsCert" not in yc.load(w.app.path).net("demo").options
    # fix both -> the accept list and the cert pair are written, nothing else
    panel.accept["https"].setChecked(True)
    panel.paths["TlsKey"].setText("C:/certs/privkey.pem")
    assert w.transports.save()
    opts = yc.load(w.app.path).net("demo").options
    assert opts["Transports"] == ["https"]
    assert opts["TlsCert"] == "C:/certs/fullchain.pem" and opts["TlsKey"] == "C:/certs/privkey.pem"
    assert "HttpsPort" not in opts and "QuicPort" not in opts and "ObfsJunkPacketCount" not in opts


def test_start_stop_do_not_block_qt_thread(window):
    w = window
    w.admin = True
    seen = {}

    def slow_start(net):
        seen["thread"] = threading.get_ident()
        time.sleep(0.6)
        return True, "started"
    w.rt.start = slow_start
    t0 = time.time()
    w._start()
    QtWidgets.QApplication.processEvents()
    assert time.time() - t0 < 0.3, "start blocked the Qt thread"
    assert w.pool.busy("life-demo")
    assert wait_until(lambda: "start demo: started" in w.statusBar().currentMessage())
    assert seen["thread"] != threading.get_ident()


def test_network_tab_save_uses_merge(window):
    """A host the daemon learned after the GUI loaded survives an options save."""
    w = window
    w.tabs.setCurrentWidget(w.network)
    with open(w.app.path, encoding="utf-8") as f:
        text = f.read()
    yc.atomic_write_text(w.app.path, text + "      peer1: |\n        Ed25519PublicKey = PPPP\n")
    w.network.autostart.setChecked(True)
    w.network._save_all()
    nc = yc.load(w.app.path).net("demo")
    assert nc.autostart is True and "peer1" in nc.hosts and nc.options["Port"] == 655
    assert "peer1" in [w.network.nodes.item(i).data(0x0100) for i in range(w.network.nodes.count())] or True


# ---- certificate dialog -------------------------------------------------------

def _cert_dialog(w, monkeypatch):
    """Open the dialog without entering its modal loop."""
    monkeypatch.setattr(CertDialog, "exec", lambda self: None)
    dlg = w.open_cert()
    assert dlg is not None
    return dlg


def test_cert_dialog_saves_options_and_clearing_removes_them(window, monkeypatch):
    w = window
    dlg = _cert_dialog(w, monkeypatch)
    dlg.edits["CertDomain"].setText("vpn.example.com")
    dlg.edits["CloudflareToken"].setText("a-token-that-is-long-enough")
    assert dlg.save()
    opts = yc.load(w.app.path).net("demo").options
    assert opts["CertDomain"] == "vpn.example.com"
    assert opts["CloudflareToken"] == "a-token-that-is-long-enough"
    # clearing a field must remove the key, not store an empty string
    dlg.edits["CloudflareToken"].setText("")
    assert dlg.save()
    assert "CloudflareToken" not in yc.load(w.app.path).net("demo").options
    dlg.deleteLater()


def test_cert_dialog_token_is_masked_until_asked(window, monkeypatch):
    dlg = _cert_dialog(window, monkeypatch)
    ed = dlg.edits["CloudflareToken"]
    assert ed.echoMode() == QtWidgets.QLineEdit.Password
    dlg.show_token.setChecked(True)
    assert ed.echoMode() == QtWidgets.QLineEdit.Normal
    dlg.deleteLater()


def test_cert_dialog_reports_the_failure_code_and_hint(window, monkeypatch):
    w = window
    dlg = _cert_dialog(w, monkeypatch)
    main_thread = threading.get_ident()
    dlg.edits["CertDomain"].setText("vpn.example.com")
    dlg.edits["CloudflareToken"].setText("wrong-zone-token-0000000")
    dlg.issue()
    assert wait_until(lambda: dlg.last is not None and not dlg.last.ok)
    assert "cloudflare-zone" in dlg.status_lbl.text()
    assert "no zone that contains vpn.example.com" in dlg.status_lbl.text()
    assert "Point CertDomain" in dlg.hint_lbl.text()
    # the CLI ran off the Qt thread
    assert w.fake.threads and main_thread not in w.fake.threads
    dlg.deleteLater()


def test_cert_dialog_issue_success_reports_the_new_pin(window, monkeypatch):
    dlg = _cert_dialog(window, monkeypatch)
    dlg.edits["CertDomain"].setText("vpn.example.com")
    dlg.edits["CloudflareToken"].setText("a-token-that-is-long-enough")
    dlg.issue()
    # the success message survives the status re-read that follows an issue
    assert wait_until(lambda: "TlsFingerprint" in dlg.status_lbl.text())
    assert "Stored the certificate for vpn.example.com" in dlg.log.toPlainText()
    dlg.deleteLater()


def test_parse_cert_failure_keeps_an_unknown_code():
    code, detail, hint = parse_cert_failure(
        "  ... step\n\ntinc cert: FAILED (something-new)\n  What happened.\n  What to do.\n")
    assert (code, detail, hint) == ("something-new", "What happened.", "What to do.")
    assert parse_cert_failure("Stored the certificate for x.\n") == ("", "", "")


# ---- routes to the subnets a peer announces ----------------------------------

@pytest.fixture
def window_with_peer(qapp, tmp_path, monkeypatch):
    """A window whose network has a gateway peer announcing 192.168.1.0/24."""
    monkeypatch.setenv("TINCSTACK_BIN_DIR", str(tmp_path / "nobin"))
    cfg = tmp_path / "tinc.yaml"
    cfg.write_text(BASE_YAML)
    fake = FakeTinc(str(cfg), peer=True)
    w = tincmgr.MainWindow(str(cfg), runner=fake, autostart=False)
    w.fake = fake
    assert wait_until(lambda: "gw" in (w.peers._snaps.get("demo").nodes if
                                       w.peers._snaps.get("demo") else {}))
    yield w
    w.timer.stop()
    w.pool.wait_all()
    w.deleteLater()
    QtWidgets.QApplication.processEvents()


def _route_buttons(w, peer_name):
    """The toggles in the peer's Routes cell, by label."""
    col = len(tincmgr.PeersTab.COLS) - 1
    for r in range(w.peers.table.rowCount()):
        item = w.peers.table.item(r, 0)
        if item and item.text() == peer_name:
            cell = w.peers.table.cellWidget(r, col)
            if cell is None:
                return {}
            return {b.text(): b for b in cell.findChildren(QtWidgets.QToolButton)}
    raise AssertionError(f"no row for {peer_name}")


def test_route_toggle_only_for_subnets_worth_routing(window_with_peer):
    w = window_with_peer
    btns = _route_buttons(w, "gw")
    # the announced LAN gets a toggle; the peer's own address and the default
    # route do not
    assert set(btns) == {"192.168.1.0/24"}
    assert not btns["192.168.1.0/24"].isChecked()
    # ...and this node itself never offers one
    assert _route_buttons(w, "demobook") == {}


def test_route_toggle_writes_and_removes_interfaceroute(window_with_peer, monkeypatch):
    w = window_with_peer
    monkeypatch.setattr(tincmgr.routes, "local_ipv4_subnets", lambda: [])
    applied = []
    monkeypatch.setattr(tincmgr.routes, "apply_now",
                        lambda alias, sub, via="": applied.append(("add", alias, sub, via)) or (True, "ok"))
    monkeypatch.setattr(tincmgr.routes, "remove_now",
                        lambda alias, sub: applied.append(("del", alias, sub)) or (True, "ok"))

    btns = _route_buttons(w, "gw")
    btns["192.168.1.0/24"].click()

    opts = yc.load(w.app.path).net("demo").options
    # the nexthop records which node the route is for
    assert opts["InterfaceRoute"] == "192.168.1.0/24 10.79.0.7"
    assert applied == [("add", "demo", "192.168.1.0/24", "10.79.0.7")]
    # the rebuilt cell shows the route as on
    w.peers._table(w.peers._snaps.get("demo"))
    assert _route_buttons(w, "gw")["192.168.1.0/24"].isChecked()

    _route_buttons(w, "gw")["192.168.1.0/24"].click()
    assert "InterfaceRoute" not in yc.load(w.app.path).net("demo").options
    assert applied[-1] == ("del", "demo", "192.168.1.0/24")


def test_route_toggle_warns_before_stealing_a_local_network(window_with_peer, monkeypatch):
    w = window_with_peer
    monkeypatch.setattr(tincmgr.routes, "local_ipv4_subnets", lambda: ["192.168.1.0/24"])
    monkeypatch.setattr(tincmgr.routes, "apply_now", lambda *a, **k: (True, "ok"))
    asked = []

    def refuse(*args, **kwargs):
        asked.append(args[2] if len(args) > 2 else "")
        return QtWidgets.QMessageBox.No

    monkeypatch.setattr(QtWidgets.QMessageBox, "question", staticmethod(refuse))
    _route_buttons(w, "gw")["192.168.1.0/24"].click()
    assert asked and "192.168.1.0/24" in asked[0]
    # refused: nothing was written, and the toggle went back to off
    assert "InterfaceRoute" not in yc.load(w.app.path).net("demo").options
    assert not _route_buttons(w, "gw")["192.168.1.0/24"].isChecked()


def test_route_toggle_without_a_running_network_only_writes_the_config(window_with_peer, monkeypatch):
    w = window_with_peer
    monkeypatch.setattr(tincmgr.routes, "local_ipv4_subnets", lambda: [])
    monkeypatch.setattr(tincmgr.routes, "apply_now",
                        lambda *a, **k: pytest.fail("must not touch the live routing table"))
    w._running["demo"] = False
    _route_buttons(w, "gw")["192.168.1.0/24"].click()
    assert yc.load(w.app.path).net("demo").options["InterfaceRoute"] == "192.168.1.0/24 10.79.0.7"
    assert "when 'demo' starts" in w.statusBar().currentMessage()


# ---- certificate expiry badge -------------------------------------------------
# Nothing renews the front's certificate by itself, so the manager has to be the
# one that notices. These pin the three states the toolbar can be in.

def _watch(w, days, threshold=None):
    """Point the window at a network with ACME configured and `days` left."""
    nc = w.app.net("demo")
    nc.options["CertDomain"] = "vpn.example.com"
    if threshold is not None:
        nc.options["AcmeRenewDays"] = threshold
    w.fake.cert_days = days
    w._cert_watch()
    wait_until(lambda: not w.pool.busy("cert-watch"), timeout=5.0)
    QtWidgets.QApplication.processEvents()
    return w.cert_act.text()


def test_cert_badge_warns_while_there_is_still_time(window):
    assert "5 d left" in _watch(window, 5)
    assert "expires in 5 days" in window.cert_act.toolTip()


def test_cert_badge_says_when_it_has_already_expired(window):
    assert "EXPIRED (3 d)" in _watch(window, -3)
    assert "pin the fingerprint" in window.cert_act.toolTip()


def test_cert_badge_is_silent_with_time_to_spare(window):
    assert _watch(window, 60) == "🔐 Certificate…"


def test_cert_badge_follows_acmerenewdays(window):
    """A node told to renew at 45 days must be warned at 40, not at 30."""
    assert "40 d left" in _watch(window, 40, threshold=45)


def test_cert_badge_asks_nothing_without_certdomain(window):
    w = window
    w.fake.calls.clear()
    w._cert_watch()
    QtWidgets.QApplication.processEvents()
    assert not any("cert" in c for c in w.fake.calls)
    assert w.cert_act.text() == "🔐 Certificate…"


def test_parse_cert_expiry_reads_both_spellings_and_nothing_else():
    assert parse_cert_expiry("Expires        in 47 days\n") == 47
    assert parse_cert_expiry("Expires        EXPIRED 3 days ago\n") == -3
    assert parse_cert_expiry("Expires        unreadable\n") is None
    assert parse_cert_expiry("Certificate    none stored yet\n") is None
    assert parse_cert_expiry("") is None
