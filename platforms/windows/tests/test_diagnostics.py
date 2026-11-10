"""Unit & integration tests for the local TelemetryCollector, automatic
anomaly detection, ActiveProber, DiagWebServer HTTP API, and DiagnosticsDialog."""

from __future__ import annotations

import base64
import json
import os
import socket
import stat
import sys
import textwrap
import urllib.error
import urllib.request

import pytest

import diagnostics
import yaml_config
from diag_webui import DIAG_WEBUI_HTML
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

    # Server is strictly OFF by default, and persistent random password is generated & reused
    assert not srv.enabled
    pwd = srv.get_password()
    assert len(pwd) == 16
    assert diagnostics.ensure_diag_password(str(tmp_path)) == pwd
    assert diagnostics.load_diag_settings(str(tmp_path))["password"] == pwd
    if sys.platform != "win32":
        st_mode = stat.S_IMODE(os.stat(tmp_path / "diag_settings.json").st_mode)
        assert st_mode == 0o600

    port = _free_port()
    ok, _ = srv.start(port)
    assert ok
    assert srv.enabled
    assert srv.port == port
    assert diagnostics.live_diag_port(str(tmp_path)) == port
    assert srv.get_password() == pwd

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    auth_hdrs = {"Content-Type": "application/json", "X-Diag-Password": pwd}
    try:
        # 0a. Unauthenticated GET / serves the self-contained login page, NOT the WebUI
        with opener.open(f"http://127.0.0.1:{port}/", timeout=3.0) as resp:
            login_html = resp.read().decode("utf-8")
            assert "login-form" in login_html
            assert "/api/login" in login_html
            assert "In-Tunnel" not in login_html

        # 0b. Unauthenticated GET /api/overview returns 401 JSON
        with pytest.raises(urllib.error.HTTPError) as ei:
            opener.open(f"http://127.0.0.1:{port}/api/overview?net=vpn1", timeout=3.0)
        assert ei.value.code == 401
        err_body = json.loads(ei.value.read().decode("utf-8"))
        assert err_body["ok"] is False and err_body["auth_required"] is True

        # 0c. POST /api/login rejects wrong password (401) and issues HttpOnly session cookie on right password
        bad_login = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/login",
            data=json.dumps({"password": "wrong-password"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as ei_bad:
            opener.open(bad_login, timeout=3.0)
        assert ei_bad.value.code == 401

        good_login = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/login",
            data=json.dumps({"password": pwd}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}"},
            method="POST",
        )
        with opener.open(good_login, timeout=3.0) as resp:
            set_cookie = resp.headers.get("Set-Cookie") or ""
            assert "tinc_diag_sid=" in set_cookie
            assert "HttpOnly" in set_cookie and "SameSite=Strict" in set_cookie
            cookie_pair = set_cookie.split(";", 1)[0]

        # 1. Cookie-authenticated GET / serves the Single-Page WebUI HTML
        req_root = urllib.request.Request(
            f"http://127.0.0.1:{port}/",
            headers={"Cookie": cookie_pair},
        )
        with opener.open(req_root, timeout=3.0) as resp:
            html = resp.read().decode("utf-8")
            assert "tincstack" in html
            assert "In-Tunnel" in html
            assert "logoutDiag" in html

        # 1b. Cookie-authenticated POST without Origin is rejected (CSRF protection -> 403),
        #     while POST with matching Origin succeeds, and /api/logout revokes the session!
        csrf_req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/mark",
            data=json.dumps({"net": "vpn1", "note": "missing origin"}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Cookie": cookie_pair},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as ei_csrf:
            opener.open(csrf_req, timeout=3.0)
        assert ei_csrf.value.code == 403

        logout_req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/logout",
            data=b"{}",
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie_pair,
                "Origin": f"http://127.0.0.1:{port}",
            },
            method="POST",
        )
        with opener.open(logout_req, timeout=3.0) as resp:
            assert json.loads(resp.read().decode("utf-8"))["ok"] is True

        # Revoked cookie can no longer access /api/overview
        revoked_req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/overview?net=vpn1",
            headers={"Cookie": cookie_pair},
        )
        with pytest.raises(urllib.error.HTTPError) as ei_rev:
            opener.open(revoked_req, timeout=3.0)
        assert ei_rev.value.code == 401

        # 2. GET /api/overview with Bearer / Basic / X-Diag-Password returns snapshot, nodes, series, incidents
        basic_tok = base64.b64encode(f"admin:{pwd}".encode("utf-8")).decode("ascii")
        for hdr in ({"Authorization": f"Bearer {pwd}"}, {"Authorization": f"Basic {basic_tok}"}, {"X-Diag-Password": pwd}):
            req_ov = urllib.request.Request(f"http://127.0.0.1:{port}/api/overview?net=vpn1", headers=hdr)
            with opener.open(req_ov, timeout=3.0) as resp:
                ov = json.loads(resp.read().decode("utf-8"))
                assert ov["ok"] is True
                assert ov["current_net"] == "vpn1"
                assert ov["my_vpn_ip"] == "10.200.0.2"
                assert any(n["name"] == "ruvds" and n["transport"] == "quic" for n in ov["nodes"])

        # 3. POST /api/mark records a user lag marker
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/mark",
            data=json.dumps({"net": "vpn1", "note": "Lag spike during test"}).encode("utf-8"),
            headers=auth_hdrs,
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
            headers=auth_hdrs,
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
            headers=auth_hdrs,
            method="POST",
        )
        with opener.open(req, timeout=3.0) as resp:
            ares = json.loads(resp.read().decode("utf-8"))
            assert ares["ok"] is True
            assert "PreferredTransports = obfs" in app_cfg.net("vpn1").hosts["ruvds"]

        # 6. Crash & app logging endpoints (/api/logs?source=crash, /api/logs?source=app, clear_crash_log)
        diagnostics.log_app_event("Test app log entry", base_dir=str(tmp_path))
        diagnostics.record_crash_trace(
            "Simulated protocol switch exception",
            "Traceback (most recent call last):\n  File 'main.py', line 400, in _set_peer_transport\nRuntimeError: test crash",
            base_dir=str(tmp_path),
            net="vpn1",
            collector=col,
            kind="GUI_EXCEPTION",
        )
        req_clogs = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/logs?net=vpn1&source=crash",
            headers={"X-Diag-Password": pwd},
        )
        with opener.open(req_clogs, timeout=3.0) as resp:
            clogs = json.loads(resp.read().decode("utf-8"))
            assert clogs["ok"] is True
            assert clogs["has_crashes"] is True
            assert "Simulated protocol switch exception" in clogs["text"]
            assert "RuntimeError: test crash" in clogs["text"]

        req_alogs = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/logs?net=vpn1&source=app",
            headers={"X-Diag-Password": pwd},
        )
        with opener.open(req_alogs, timeout=3.0) as resp:
            alogs = json.loads(resp.read().decode("utf-8"))
            assert alogs["ok"] is True
            assert "Test app log entry" in alogs["text"]

        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/action",
            data=json.dumps({"net": "vpn1", "action": "clear_crash_log"}).encode("utf-8"),
            headers=auth_hdrs,
            method="POST",
        )
        with opener.open(req, timeout=3.0) as resp:
            cres = json.loads(resp.read().decode("utf-8"))
            assert cres["ok"] is True

        req_clogs2 = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/logs?net=vpn1&source=crash",
            headers={"X-Diag-Password": pwd},
        )
        with opener.open(req_clogs2, timeout=3.0) as resp:
            clogs2 = json.loads(resp.read().decode("utf-8"))
            assert clogs2["has_crashes"] is False

        # 7. GET /api/export returns full diagnostic bundle with redacted secrets
        req_exp = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/export?net=vpn1",
            headers={"X-Diag-Password": pwd},
        )
        with opener.open(req_exp, timeout=3.0) as resp:
            bundle = json.loads(resp.read().decode("utf-8"))
            assert "overview" in bundle
            assert "logs" in bundle
            assert "raw_yaml" not in bundle["config"]
    finally:
        srv.stop()
        assert not srv.enabled
        assert diagnostics.live_diag_port(str(tmp_path)) == 0

    # Password is reused across server / app restarts
    srv2 = diagnostics.DiagWebServer(str(tmp_path), tc, col, prober, lambda: app_cfg, runtime=None)
    assert srv2.get_password() == pwd


def test_diag_yaml_redaction_and_per_network_restore(tmp_path):
    """WL-01: structured YAML redaction hides multi-line PEM keys/tokens while keeping
    public tls_cert, and save_raw_yaml restores secrets per-network without mixing them."""
    yaml_path = str(tmp_path / "tinc.yaml")
    yaml_config.save_text(
        yaml_path,
        textwrap.dedent("""\
            networks:
              vpnA:
                options:
                  Name: nodeA
                  Port: 655
                  CloudflareToken: cf-secret-token-AAA
                  Ed25519PrivateKey: inline-ed-priv-AAA
                keys:
                  ed25519_priv: |
                    -----BEGIN ED25519 PRIVATE KEY-----
                    SECRET_ED_LINE_AAA
                    -----END ED25519 PRIVATE KEY-----
                  rsa_priv: |
                    -----BEGIN RSA PRIVATE KEY-----
                    SECRET_RSA_LINE_AAA
                    -----END RSA PRIVATE KEY-----
                  tls_key: |
                    -----BEGIN PRIVATE KEY-----
                    SECRET_TLS_KEY_AAA
                    -----END PRIVATE KEY-----
                  acme_account: |
                    -----BEGIN EC PRIVATE KEY-----
                    SECRET_ACME_AAA
                    -----END EC PRIVATE KEY-----
                  tls_cert: |
                    -----BEGIN CERTIFICATE-----
                    PUBLIC_CERT_AAA
                    -----END CERTIFICATE-----
              vpnB:
                options:
                  Name: nodeB
                  Port: 656
                  CloudflareToken: cf-secret-token-BBB
                  PrivateKey: inline-rsa-priv-BBB
                keys:
                  ed25519_priv: |
                    -----BEGIN ED25519 PRIVATE KEY-----
                    SECRET_ED_LINE_BBB
                    -----END ED25519 PRIVATE KEY-----
            """),
    )
    app_cfg = yaml_config.load(yaml_path)
    tc = TincControl(tinc_exe="tinc", yaml_path=yaml_path, runner=lambda c, t: (0, "", ""))
    col = diagnostics.TelemetryCollector(str(tmp_path))
    prober = diagnostics.ActiveProber(tc, lambda: app_cfg, str(tmp_path))
    srv = diagnostics.DiagWebServer(str(tmp_path), tc, col, prober, lambda: app_cfg, runtime=None)

    cfg_view = srv.build_config("vpnA")
    raw_redacted = cfg_view["raw_yaml"]
    for leaked in (
        "SECRET_ED_LINE_AAA",
        "SECRET_RSA_LINE_AAA",
        "SECRET_TLS_KEY_AAA",
        "SECRET_ACME_AAA",
        "SECRET_ED_LINE_BBB",
        "cf-secret-token-AAA",
        "cf-secret-token-BBB",
        "inline-ed-priv-AAA",
        "inline-rsa-priv-BBB",
    ):
        assert leaked not in raw_redacted
        assert leaked not in json.dumps(cfg_view["options"])
    assert "PUBLIC_CERT_AAA" in raw_redacted
    assert cfg_view["options"]["CloudflareToken"] == "***REDACTED***"

    edited_yaml = raw_redacted.replace("Port: 655", "Port: 1655")
    ok, msg, _ = srv.default_action_handler("vpnA", "save_raw_yaml", {"raw_yaml": edited_yaml})
    assert ok, msg

    saved = yaml_config.load(yaml_path)
    assert saved.net("vpnA").options["Port"] == 1655
    assert saved.net("vpnA").options["CloudflareToken"] == "cf-secret-token-AAA"
    assert saved.net("vpnB").options["CloudflareToken"] == "cf-secret-token-BBB"
    assert "SECRET_ED_LINE_AAA" in saved.net("vpnA").keys["ed25519_priv"]
    assert "SECRET_TLS_KEY_AAA" in saved.net("vpnA").keys["tls_key"]
    assert "SECRET_ACME_AAA" in saved.net("vpnA").keys["acme_account"]
    assert "SECRET_ED_LINE_BBB" in saved.net("vpnB").keys["ed25519_priv"]


def test_diag_host_origin_and_net_traversal_guards(tmp_path):
    """WL-04 & WL-06: DNS-rebinding Host check (including IPv6 [::1]), Origin check,
    and strict `net` traversal validation."""
    yaml_path = str(tmp_path / "tinc.yaml")
    yaml_config.save_text(yaml_path, "networks:\n  vpn1:\n    options:\n      Name: book\n")
    app_cfg = yaml_config.load(yaml_path)
    tc = TincControl(tinc_exe="tinc", yaml_path=yaml_path, runner=lambda c, t: (0, "", ""))
    col = diagnostics.TelemetryCollector(str(tmp_path))
    prober = diagnostics.ActiveProber(tc, lambda: app_cfg, str(tmp_path))
    srv = diagnostics.DiagWebServer(str(tmp_path), tc, col, prober, lambda: app_cfg, runtime=None)
    pwd = srv.get_password()

    with pytest.raises(ValueError):
        col.record_user_mark("../traversal", "nope")
    with pytest.raises(ValueError):
        srv.build_logs("../traversal")

    port = _free_port()
    ok, _ = srv.start(port)
    assert ok
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        # DNS rebinding Host rejected on GET (403)
        req_rebind = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/overview?net=vpn1",
            headers={"Host": f"evil.rebind.test:{port}", "X-Diag-Password": pwd},
        )
        with pytest.raises(urllib.error.HTTPError) as ei_host:
            opener.open(req_rebind, timeout=3.0)
        assert ei_host.value.code == 403

        # IPv6 bracketed Host [::1]:port is accepted (200)
        req_v6 = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/overview?net=vpn1",
            headers={"Host": f"[::1]:{port}", "X-Diag-Password": pwd},
        )
        with opener.open(req_v6, timeout=3.0) as resp:
            assert json.loads(resp.read().decode("utf-8"))["ok"] is True

        # Untrusted Origin rejected on POST (403)
        req_bad_origin = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/mark",
            data=json.dumps({"net": "vpn1", "note": "x"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-Diag-Password": pwd,
                "Origin": "http://evil.example",
            },
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as ei_orig:
            opener.open(req_bad_origin, timeout=3.0)
        assert ei_orig.value.code == 403

        # Traversal or unknown network name rejected with HTTP 400
        for bad_net in ("../etc", "..", "unknown_net"):
            req_bad_net = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/logs?net={bad_net}",
                headers={"X-Diag-Password": pwd},
            )
            with pytest.raises(urllib.error.HTTPError) as ei_net:
                opener.open(req_bad_net, timeout=3.0)
            assert ei_net.value.code == 400
    finally:
        srv.stop()


def test_diag_webui_no_inline_xss_and_probe_host_validation(tmp_path):
    """WL-05 & WL-13: WebUI avoids inline JS string interpolations, and ActiveProber
    rejects option-flag / whitespace injection in probe targets."""
    for unsafe_pattern in (
        "setPeerTransport('${",
        "togglePeerDirect('${",
        "editPeerHost('${",
        "showPeerInfo('${",
        "savePeerHost('${",
        "deletePeerHost('${",
        "reconnectPeer('${",
        "toggleRoute('${",
        "toggleFullTunnel('${",
    ):
        assert unsafe_pattern not in DIAG_WEBUI_HTML

    for valid in ("1.1.1.1", "2001:4860:4860::8888", "[2001:db8::1]", "vpn.example.com", "my-node"):
        assert diagnostics.is_valid_probe_host(valid), valid
    for invalid in ("", "-w", "/t", "8.8.8.8 -t", "127.0.0.1\nx", "123.456", "bad..host"):
        assert not diagnostics.is_valid_probe_host(invalid), invalid

    yaml_path = str(tmp_path / "tinc.yaml")
    yaml_config.save_text(yaml_path, "networks:\n  vpn1:\n    options:\n      Name: book\n")
    app_cfg = yaml_config.load(yaml_path)
    tc = TincControl(tinc_exe="tinc", yaml_path=yaml_path, runner=lambda c, t: (0, "", ""))
    prober = diagnostics.ActiveProber(tc, lambda: app_cfg, str(tmp_path))
    assert prober.run_probe("vpn1", "out-ping", {"target": "-t"})["ok"] is False
    assert prober.run_probe("vpn1", "out-trace", {"target": "/d"})["ok"] is False


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
    assert dlg.pass_edit.text() == srv.get_password()
    assert len(dlg.pass_edit.text()) == 16
    assert dlg.pass_edit.echoMode() == QtWidgets.QLineEdit.Password
    dlg.show_pass_btn.click()
    assert dlg.pass_edit.echoMode() == QtWidgets.QLineEdit.Normal
    dlg.show_pass_btn.click()
    assert dlg.pass_edit.echoMode() == QtWidgets.QLineEdit.Password

    dlg.port_spin.setValue(port)
    dlg.toggle_server()
    assert srv.enabled
    dlg.note_edit.setText("UI mark")
    dlg.mark_now()
    assert dlg.inc_table.rowCount() == 1
    dlg.toggle_server()
    assert not srv.enabled
    srv.stop(wait=True)
