"""tinc_control: dump parsers and the invite/join commands with a mocked runner."""
import tinc_control as tc


NODES = """\
demobook id 1a2b at MYSELF port 655 cipher 0 digest 0 maclength 0 compression 0 options c status 0 nexthop demobook via demobook distance 0 pmtu 1518 (min 0 max 1518) rx 0 0 tx 0 0
peer1 id 3c4d at 203.0.113.9 port 40000 cipher 0 digest 0 maclength 0 compression 0 options c status 0x90 nexthop peer1 via peer1 distance 1 pmtu 1400 (min 1400 max 1400) rx 10 1200 tx 12 1500 rtt 23.5
relayed id 5e6f at 198.51.100.2 port 655 cipher 0 digest 0 maclength 0 compression 0 options c status 0x10 nexthop peer1 via peer1 distance 2 pmtu 1400 (min 0 max 1518) rx 0 0 tx 0 0
"""
SUBNETS = "10.99.0.1/32 owner demobook\n10.99.0.2/32 owner peer1\n"


def make(calls):
    def runner(cmd, timeout):
        calls.append((cmd, timeout))
        sub = cmd[cmd.index("-c") + 2:]
        if sub == ["dump", "nodes"]:
            return 0, NODES, ""
        if sub == ["dump", "edges"]:
            return 0, "", ""
        if sub == ["dump", "subnets"]:
            return 0, SUBNETS, ""
        if sub[0] == "invite":
            return 0, f"203.0.113.9:655/abcDEF_{sub[1]}\n", "Warning: using local address 203.0.113.9\n"
        if sub[0] == "join":
            return (0, "Configuration stored in: /x/tinc.yaml\n", "") if "abc" in sub[1] \
                else (1, "", "Error: invalid invitation\n")
        return 1, "", "unknown"
    return tc.TincControl(tinc_exe="tinc", yaml_path="/x/tinc.yaml", runner=runner)


def test_snapshot_parsing_and_link_labels():
    calls = []
    snap = make(calls).snapshot("demo")
    assert not snap.error
    assert calls[0][0][:5] == ["tinc", "-n", "demo", "-c", "/x/tinc.yaml"]
    n = snap.nodes
    assert n["demobook"].link == "self"
    assert n["peer1"].link == "direct-udp" and n["peer1"].rtt == 23.5 and n["peer1"].rx_bytes == 1200
    assert n["relayed"].link == "relay" and n["relayed"].nexthop == "peer1"
    assert n["peer1"].subnets == ["10.99.0.2/32"]


def test_invite_returns_one_line_and_surfaces_stderr():
    calls = []
    res = make(calls).invite("demo", "laptop")
    assert res.ok and res.stdout == "203.0.113.9:655/abcDEF_laptop"
    assert "local address" in res.stderr
    assert calls[-1][0] == ["tinc", "-n", "demo", "-c", "/x/tinc.yaml", "invite", "laptop"]
    assert calls[-1][1] == 90.0


def test_join_ok_and_failure():
    calls = []
    ctl = make(calls)
    ok = ctl.join("newnet", "  203.0.113.9:655/abcDEF  ")
    assert ok.ok and calls[-1][0] == ["tinc", "-n", "newnet", "-c", "/x/tinc.yaml", "join",
                                      "203.0.113.9:655/abcDEF"]
    bad = ctl.join(None, "garbage")
    assert not bad.ok and "invalid invitation" in bad.stderr
    assert calls[-1][0] == ["tinc", "-c", "/x/tinc.yaml", "join", "garbage"]


def test_runner_failure_is_reported_not_raised():
    ctl = tc.TincControl(tinc_exe="/nonexistent/tinc", yaml_path="/x/tinc.yaml")
    snap = ctl.snapshot("demo")
    assert snap.error
