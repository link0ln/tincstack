"""Tests for two-stage autonomous self-healing and alert deduplication in tools/vpn-diag."""
from __future__ import annotations

import importlib.machinery
import importlib.util
from pathlib import Path


def _load_vpn_diag():
    script = Path(__file__).resolve().parents[3] / "tools" / "vpn-diag"
    loader = importlib.machinery.SourceFileLoader("vpn_diag_mod", str(script))
    spec = importlib.util.spec_from_loader("vpn_diag_mod", loader)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


vd = _load_vpn_diag()


def _topo():
    return {
        "nodes": [
            {
                "name": "router",
                "ssh": "root@router.invalid",
                "cli": "tinc",
                "container": "tincstack",
                "route_checks": [
                    {"table": "240", "min_count": 1, "restore_cmd": "ip route replace default dev tincstack table 240"}
                ],
            }
        ],
        "sni_urls": [],
        "alerts": {
            "telegram_bot_token": "TEST_TOKEN",
            "telegram_chat_id": "12345",
        },
    }


def _healthy_node(name: str = "router"):
    return {
        "name": name,
        "ssh_ok": True,
        "doctor": {"status": "HEALTHY", "issues": []},
        "routes": [{"table": "240", "count": 1, "ok": True}],
        "sockets": {},
        "ports": [],
        "pings": [],
        "logs_anomalies": [],
        "issues": [],
    }


def test_stage1_immediate_soft_fix_clears_route_and_alerts_once(tmp_path):
    topo = _topo()
    nodes = topo["nodes"]
    state = vd.load_watch_state(tmp_path / "state.json")
    events_path = tmp_path / "events.jsonl"

    missing_rt = _healthy_node()
    missing_rt["issues"] = [{
        "severity": "CRIT",
        "component": "route_table_240",
        "node": "router",
        "message": "Policy table 240 missing",
        "fix_id": "restore_route:router:240",
        "fix_cmd": "ip route replace default dev tincstack table 240",
    }]

    calls = {"gather": 0}
    cmds = []
    alerts = []

    def gather_fn(_nodes, _sni, _agent, _probe):
        calls["gather"] += 1
        nr = missing_rt if calls["gather"] == 1 else _healthy_node()
        return [nr], [], vd.aggregate_issues([nr], [])

    def run_fn(_ncfg, cmd, _agent, timeout=30.0):
        cmds.append(cmd)
        return 0, "ok", ""

    def alert_fn(_topo, subject, body):
        alerts.append((subject, body))
        return [{"channel": "telegram", "ok": True, "info": "HTTP 200"}]

    rec = vd.run_watch_iteration(
        topo, nodes, None, True, state,
        now_ts=1000.0, gather_fn=gather_fn, run_node_fn=run_fn, alert_fn=alert_fn,
        events_path=events_path,
    )
    assert cmds == ["ip route replace default dev tincstack table 240"]
    assert rec["status"] == "HEALTHY"
    assert len(rec["soft_fixes"]) == 1
    assert rec["hard_restarts"] == []
    assert len(alerts) == 1
    assert "AUTO-FIXED -> HEALTHY" in alerts[0][0]
    assert events_path.is_file()


def test_stage2_restart_requires_3_strikes_and_15m_cooldown_and_dedups_alerts(tmp_path):
    topo = _topo()
    nodes = topo["nodes"]
    state = vd.load_watch_state(tmp_path / "state.json")

    crit_nr = {
        "name": "router",
        "ssh_ok": True,
        "doctor": None,
        "routes": [],
        "sockets": {},
        "ports": [],
        "pings": [],
        "logs_anomalies": [],
        "issues": [{"severity": "CRIT", "component": "doctor", "node": "router", "message": "tincd down"}],
    }

    restarted_once = {"done": False}
    cmds = []
    alerts = []

    def gather_fn(_nodes, _sni, _agent, _probe):
        nr = _healthy_node() if restarted_once["done"] else crit_nr
        return [nr], [], vd.aggregate_issues([nr], [])

    def run_fn(_ncfg, cmd, _agent, timeout=30.0):
        cmds.append(cmd)
        if "docker restart" in cmd:
            restarted_once["done"] = True
        return 0, "", ""

    def alert_fn(_topo, subject, body):
        alerts.append(subject)
        return [{"channel": "telegram", "ok": True, "info": "HTTP 200"}]

    # Strike 1 & Strike 2: NO docker restart, and alert sent ONLY on Strike 1 (deduplicated on Strike 2)
    r1 = vd.run_watch_iteration(topo, nodes, None, True, state, now_ts=100.0, gather_fn=gather_fn, run_node_fn=run_fn, alert_fn=alert_fn)
    r2 = vd.run_watch_iteration(topo, nodes, None, True, state, now_ts=190.0, gather_fn=gather_fn, run_node_fn=run_fn, alert_fn=alert_fn)
    assert r1["hard_restarts"] == []
    assert r2["hard_restarts"] == []
    assert cmds == []
    assert len(alerts) == 1

    # Strike 3: triggers Stage 2 docker restart + post-restart route restorecmd, clears after verify
    r3 = vd.run_watch_iteration(topo, nodes, None, True, state, now_ts=280.0, gather_fn=gather_fn, run_node_fn=run_fn, alert_fn=alert_fn)
    assert len(r3["hard_restarts"]) == 1
    assert cmds == [
        "docker restart tincstack",
        "ip route replace default dev tincstack table 240",
    ]
    assert r3["status"] == "HEALTHY"
    assert len(alerts) == 2

    # Failure resumes inside 15-minute cooldown -> even after 3 more strikes at ts=400..580, cooldown blocks restart!
    restarted_once["done"] = False
    cmds.clear()
    for t in (400.0, 490.0, 580.0):
        vd.run_watch_iteration(topo, nodes, None, True, state, now_ts=t, gather_fn=gather_fn, run_node_fn=run_fn, alert_fn=alert_fn)
    assert cmds == []

    # After 15m cooldown (280 + 900 = 1180s), 4th failure at ts=1200 triggers Stage 2 again
    r_after = vd.run_watch_iteration(topo, nodes, None, True, state, now_ts=1200.0, gather_fn=gather_fn, run_node_fn=run_fn, alert_fn=alert_fn)
    assert len(r_after["hard_restarts"]) == 1
    assert "docker restart tincstack" in cmds


def test_ssh_down_never_restarts_container(tmp_path):
    topo = _topo()
    nodes = topo["nodes"]
    state = vd.load_watch_state(tmp_path / "state.json")
    ssh_down = {
        "name": "router",
        "ssh_ok": False,
        "doctor": None,
        "routes": [],
        "sockets": {},
        "ports": [],
        "pings": [],
        "logs_anomalies": [],
        "issues": [{"severity": "CRIT", "component": "ssh", "node": "router", "message": "SSH unreachable"}],
    }
    cmds = []
    for t in (100.0, 200.0, 300.0, 400.0):
        rec = vd.run_watch_iteration(
            topo, nodes, None, True, state, now_ts=t,
            gather_fn=lambda _n, _s, _a, _p: ([ssh_down], [], ssh_down["issues"]),
            run_node_fn=lambda _nc, cmd, _a, timeout=30.0: cmds.append(cmd) or (0, "", ""),
            alert_fn=lambda _t, _sub, _b: [],
        )
        assert rec["hard_restarts"] == []
    assert cmds == []
