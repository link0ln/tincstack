"""Unit & integration tests for the local TelemetryCollector, automatic
anomaly detection, ActiveProber, DiagWebServer HTTP API, and DiagnosticsDialog."""

from __future__ import annotations

import json
import os
import socket
import textwrap
import urllib.request

import pytest

import diagnostics
import yaml_config
from tinc_control import Edge, NetworkSnapshot, Node, TincControl, decode_status


def _make_snap(
    peer_status_hex: str = "0092",
    transport: str = "quic",
    nexthop: str = "ruvds",
    distance: int = 1,
    rtt: float = 25.0,
    pmtu: int = 1400,
    rx_bytes: int = 1000,
    tx_bytes: int = 1000,
    error: str = "",
) -> NetworkSnapshot:
    snap = NetworkSnapshot(net="vpn1", error=error)
    if error:
        return snap
    snap.nodes["book"] = Node(
        name="book",
        node_id="1",
        address="MYSELF",
        port="655",
        status_hex="0018",
        status=decode_status("0018"),
        nexthop="book",
        via="book",
        distance=0,
        pmtu=1500,
        rx_bytes=0,
        tx_bytes=0,
        subnets=["10.200.0.2/32"],
    )
    snap.nodes["ruvds"] = Node(
        name="ruvds",
        node_id="2",
        address="198.51.100.10",
        port="443",
        status_hex=peer_status_hex,
        status=decode_status(peer_status_hex),
        nexthop=nexthop,
        via=nexthop,
        distance=distance,
        pmtu=pmtu,
        rx_bytes=rx_bytes,
        tx_bytes=tx_bytes,
        rtt=rtt,
        subnets=["10.200.0.1/32", "0.0.0.0/0"],
        transport=transport,
        supported_transports=["plain", "obfs", "https", "quic"],
    )
    snap.edges.append(Edge(frm="book", to="ruvds", address="198.51.100.10", port="443", weight=int(rtt)))
    return snap


def test_telemetry_collector_detects_anomalies_and_persists(tmp_path):
    col = diagnostics.TelemetryCollector(str(tmp_path))

    # Note on STATUS_BITS in tinc_control.py:
    # bit1 (0x0002) = validkey, bit4 (0x0010) = reachable, bit7 (0x0080) = udp_confirmed
    # So 0x0092 = validkey + reachable + udp_confirmed -> link == "direct-udp"
    # And 0x0012 = validkey + reachable (no udp_confirmed) -> link == "direct-tcp"

    # 1. Initial baseline snapshot: direct-udp (0x0092), quic, rtt=25, pmtu=1400
    col.record_snapshot("vpn1", _make_snap(peer_status_hex="0092", transport="quic", rtt=25.0, pmtu=1400, rx_bytes=1000, tx_bytes=1000), now=1000.0)
    assert len(col.get_series("vpn1")) == 1
    assert col.get_incidents("vpn1") == []

    # 2. UDP fallback (0x0012 -> direct-tcp because udp_confirmed bit 0x0080 dropped) + transport changed (quic -> https)
    col.record_snapshot("vpn1", _make_snap(peer_status_hex="0012", transport="https", rtt=30.0, pmtu=1400, rx_bytes=2000, tx_bytes=2000), now=1002.5)
    kinds = [e["kind"] for e in col.get_incidents("vpn1")]
    assert "UDP_FALLBACK" in kinds
    assert "TRANSPORT_CHANGED" in kinds

    # 3. PMTU drop (1400 -> 1200) and RTT spike (30 -> 260 ms)
    col.record_snapshot("vpn1", _make_snap(peer_status_hex="0092", transport="https", rtt=260.0, pmtu=1200, rx_bytes=3000, tx_bytes=3000), now=1005.0)
    kinds = [e["kind"] for e in col.get_incidents("vpn1")]
    assert "UDP_RECOVERED" in kinds
    assert "PMTU_DROP" in kinds
    assert "RTT_SPIKE" in kinds

    # 4. Route via changed (ruvds -> relay2)
    col.record_snapshot("vpn1", _make_snap(peer_status_hex="0092", nexthop="relay2", distance=2, rtt=260.0, pmtu=1200, rx_bytes=4000, tx_bytes=4000), now=1007.5)
    kinds = [e["kind"] for e in col.get_incidents("vpn1")]
    assert "ROUTE_VIA_CHANGED" in kinds

    # 5. SPTPS key wait (reachable 0x0010 without validkey 0x0002 for 3 ticks)
    for i in range(3):
        col.record_snapshot("vpn1", _make_snap(peer_status_hex="0010", rtt=40.0, pmtu=1400, rx_bytes=5000, tx_bytes=5000), now=1010.0 + i * 2.5)
    kinds = [e["kind"] for e in col.get_incidents("vpn1")]
    assert "SPTPS_KEY_WAIT" in kinds

    # 6. One-way blackhole (TX increases by >=2048 B while RX stays constant for 4 ticks)
    tx_val = 10000
    for i in range(4):
        tx_val += 4096
        col.record_snapshot("vpn1", _make_snap(peer_status_hex="0092", rx_bytes=5000, tx_bytes=tx_val), now=1020.0 + i * 2.5)
    kinds = [e["kind"] for e in col.get_incidents("vpn1")]
    assert "ONE_WAY_BLACKHOLE" in kinds

    # 7. Peer down & up
    col.record_snapshot("vpn1", _make_snap(peer_status_hex="0000", rx_bytes=5000, tx_bytes=tx_val), now=1035.0)
    assert "PEER_DOWN" in [e["kind"] for e in col.get_incidents("vpn1")]
    col.record_snapshot("vpn1", _make_snap(peer_status_hex="0092", rx_bytes=6000, tx_bytes=tx_val + 100), now=1037.5)
    assert "PEER_UP" in [e["kind"] for e in col.get_incidents("vpn1")]

    # 8. User mark & JSONL persistence reload
    mark = col.record_user_mark("vpn1", "Voice call froze")
    assert mark.kind == "USER_MARK"
    assert "ruvds" in mark.details["peers"]

    col2 = diagnostics.TelemetryCollector(str(tmp_path))
    reloaded = col2.get_incidents("vpn1")
    assert any(e["kind"] == "USER_MARK" and e["summary"] == "Voice call froze" for e in reloaded)


def test_tinc_control_in_tunnel_probes():
    calls: list[list[str]] = []

    def fake_runner(cmd: list[str], timeout: float) -> tuple[int, str, str]:
        calls.append(cmd)
        sub = cmd[cmd.index("-c") + 2:]
        if sub[0] == "diag-port":
            return 0, f"{sub[1] if len(sub) > 1 else '8655'}\n", ""
        if sub[0] == "diag-ping":
            dst, size, ttl, df = sub[1], int(sub[2]), int(sub[3]), int(sub[4])
            if ttl == 1 and dst == "10.200.0.9":
                return 0, "OK from=10.200.0.1 node=ruvds type=11 code=0 rtt_ms=12.45 ttl=64 mtu=0\n", ""
            if df == 1 and size > 1352:
                return 0, "OK from=10.200.0.1 node=ruvds type=3 code=4 rtt_ms=5.10 ttl=64 mtu=1380\n", ""
            return 0, f"OK from={dst} node=peerX type=0 code=0 rtt_ms=18.50 ttl=63 mtu=0\n", ""
        return 0, "", ""

    tc = TincControl(tinc_exe="tinc", yaml_path="/tmp/tinc.yaml", runner=fake_runner)

    ok_port, actual_port = tc.diag_port("vpn1", 8655)
    assert ok_port and actual_port == 8655

    ping_summary = tc.in_tunnel_ping("vpn1", "10.200.0.9", count=3, size=56, df=False)
    assert ping_summary["sent"] == 3
    assert ping_summary["received"] == 3
    assert ping_summary["loss_pct"] == 0.0
    assert ping_summary["avg_ms"] == pytest.approx(18.5)

    trace_summary = tc.in_tunnel_traceroute("vpn1", "10.200.0.9", max_hops=4)
    assert len(trace_summary["hops"]) == 2
    assert trace_summary["hops"][0]["status"] == "time_exceeded"
    assert trace_summary["hops"][0]["node"] == "ruvds"
    assert trace_summary["hops"][1]["status"] == "echo_reply"

    pmtu_summary = tc.in_tunnel_pmtu_sweep("vpn1", "10.200.0.9")
    assert pmtu_summary["max_working_ip_mtu"] == 1368  # 1340 payload + 28
    assert pmtu_summary["reported_frag_mtu"] == 1380


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_diag_web_server_http_api(tmp_path):
    yaml_path = str(tmp_path / "tinc.yaml")
    yaml_config.save_text(
        yaml_path,
        textwrap.dedent("""\
            networks:
              vpn1:
                autostart: false
                options:
                  Name: book
                  Mode: router
                  Port: 655
                hosts:
                  book: |
                    Ed25519PublicKey = AAAA
                    Subnet = 10.200.0.2/32
                  ruvds: |
                    Address = 127.0.0.1
                    Port = 655
                    HttpsPort = 443
                    QuicPort = 443
                    Ed25519PublicKey = BBBB
                    Subnet = 10.200.0.1/32
            """),
    )
    app_cfg = yaml_config.load(yaml_path)
    recorded_cmds: list[list[str]] = []

    def fake_runner(cmd: list[str], timeout: float) -> tuple[int, str, str]:
        recorded_cmds.append(cmd)
        sub = cmd[cmd.index("-c") + 2:]
        if sub[:2] == ["dump", "nodes"]:
            return 0, (
                "book id 1 at MYSELF port 655 options c status 0018 nexthop book via book distance 0 pmtu 1500 (min 0 max 1500) rx 0 0 tx 0 0\n"
                "ruvds id 2 at 127.0.0.1 port 443 options c status 0092 nexthop ruvds via ruvds distance 1 pmtu 1400 (min 0 max 1500) rx 10 5000 tx 12 6000\n"
            ), ""
        if sub[:2] == ["dump", "subnets"]:
            return 0, "10.200.0.2/32 owner book\n10.200.0.1/32 owner ruvds\n", ""
        if sub[:2] == ["dump", "edges"]:
            return 0, "book to ruvds at 127.0.0.1 port 443 options c weight 22\n", ""
        if sub[:2] == ["dump", "connections"]:
            return 0, "ruvds at 127.0.0.1 port 443 options c socket 5 status 002a outbuf 0/0/0 transport quic supported plain,obfs,https,quic\n", ""
        if sub[0] == "diag-ping":
            return 0, "OK from=10.200.0.1 node=ruvds type=0 code=0 rtt_ms=12.0 ttl=64 mtu=0\n", ""
        return 0, "OK\n", ""

    tc = TincControl(tinc_exe="tinc", yaml_path=yaml_path, runner=fake_runner)
    col = diagnostics.TelemetryCollector(str(tmp_path))
    prober = diagnostics.ActiveProber(tc, lambda: app_cfg, str(tmp_path))
    srv = diagnostics.DiagWebServer(str(tmp_path), tc, col, prober, lambda: app_cfg, runtime=None)

    # Server is strictly OFF by default
    assert not srv.enabled

    port = _free_port()
    ok, _ = srv.start(port)
    assert ok
    assert srv.enabled
    assert srv.port == port

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        # 1. GET / serves the Single-Page WebUI HTML
        with opener.open(f"http://127.0.0.1:{port}/", timeout=3.0) as resp:
            html = resp.read().decode("utf-8")
            assert "tincstack" in html
            assert "In-Tunnel" in html

        # 2. GET /api/overview returns snapshot, nodes, series, incidents
        with opener.open(f"http://127.0.0.1:{port}/api/overview?net=vpn1", timeout=3.0) as resp:
            ov = json.loads(resp.read().decode("utf-8"))
            assert ov["ok"] is True
            assert ov["current_net"] == "vpn1"
            assert ov["my_vpn_ip"] == "10.200.0.2"
            assert any(n["name"] == "ruvds" and n["transport"] == "quic" for n in ov["nodes"])

        # 3. POST /api/mark records a user lag marker
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/mark",
            data=json.dumps({"net": "vpn1", "note": "Lag spike during test"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with opener.open(req, timeout=3.0) as resp:
            mres = json.loads(resp.read().decode("utf-8"))
            assert mres["ok"] is True
            assert mres["event"]["kind"] == "USER_MARK"

        # 4. POST /api/probe executes in_tunnel_ping
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/probe",
            data=json.dumps({"net": "vpn1", "kind": "in_tunnel_ping", "dst_ip": "ruvds", "count": 2, "size": 56}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with opener.open(req, timeout=3.0) as resp:
            pres = json.loads(resp.read().decode("utf-8"))
            assert pres["ok"] is True
            assert "In-Tunnel ICMP Ping to ruvds (10.200.0.1)" in pres["formatted"]

        # 5. POST /api/action switches transport for peer (supports both peer_transport and switch_transport)
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/action",
            data=json.dumps({"net": "vpn1", "action": "peer_transport", "peer": "ruvds", "transport": "obfs"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with opener.open(req, timeout=3.0) as resp:
            ares = json.loads(resp.read().decode("utf-8"))
            assert ares["ok"] is True
            assert "PreferredTransports = obfs" in app_cfg.net("vpn1").hosts["ruvds"]

        # 6. GET /api/export returns full diagnostic bundle with redacted secrets
        with opener.open(f"http://127.0.0.1:{port}/api/export?net=vpn1", timeout=3.0) as resp:
            bundle = json.loads(resp.read().decode("utf-8"))
            assert "overview" in bundle
            assert "logs" in bundle
            assert "raw_yaml" not in bundle["config"]
    finally:
        srv.stop()
        assert not srv.enabled


def test_diagnostics_dialog_qt(tmp_path):
    QtWidgets = pytest.importorskip("PySide6.QtWidgets")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    from gui.diag_dialog import DiagnosticsDialog

    yaml_path = str(tmp_path / "tinc.yaml")
    yaml_config.save_text(yaml_path, "networks:\n  vpn1:\n    options:\n      Name: book\n")
    app_cfg = yaml_config.load(yaml_path)
    tc = TincControl(tinc_exe="tinc", yaml_path=yaml_path, runner=lambda c, t: (0, "", ""))
    col = diagnostics.TelemetryCollector(str(tmp_path))
    prober = diagnostics.ActiveProber(tc, lambda: app_cfg, str(tmp_path))
    srv = diagnostics.DiagWebServer(str(tmp_path), tc, col, prober, lambda: app_cfg, runtime=None)

    port = _free_port()
    dlg = DiagnosticsDialog(None, srv, col, "vpn1", skip_confirm=True)
    dlg.port_spin.setValue(port)
    dlg.toggle_server()
    assert srv.enabled
    dlg.note_edit.setText("UI mark")
    dlg.mark_now()
    assert dlg.inc_table.rowCount() == 1
    dlg.toggle_server()
    assert not srv.enabled
