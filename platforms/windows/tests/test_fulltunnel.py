"""fulltunnel: the full-tunnel reconciler against a fake routing table. What
matters is order and upkeep -- every peer endpoint pinned to the physical
gateway before 0.0.0.0/1 + 128.0.0.0/1 go on the tunnel adapter, pins moved
when the gateway changes, the split routes off while the exit is unusable, and
everything removed again, split routes first."""
import time

import pytest

import fulltunnel as ft
import runtime as rt_mod
import yaml_config as yc
from fulltunnel import Route
from tinc_control import Edge, NetworkSnapshot, Node, Subnet

PHYS, TUN = 7, 12
OWN = "windows"


class FakeSystem(ft.System):
    def __init__(self):
        self.table = [Route("0.0.0.0/0", "192.168.1.1", PHYS, 35),
                      Route("192.168.1.0/24", "0.0.0.0", PHYS, 281)]
        self.tunnel = TUN
        self.local = ["192.168.1.0/24"]
        self.dns = {"ruvds.example": ["80.87.200.39"]}
        self.resolved = []
        self.calls = []
        self.fail = {}

    def route_table(self):
        return list(self.table)

    def ifindex(self, aliases):
        return self.tunnel

    def local_nets(self):
        return list(self.local)

    def resolve(self, host):
        self.resolved.append(host)
        if host not in self.dns:
            raise OSError("no such host")
        return self.dns[host]

    def add_route(self, prefix, ifindex, via=""):
        self.calls.append(("add", prefix, ifindex, via))
        if prefix in self.fail:
            return False, self.fail[prefix]
        self.table.append(Route(prefix, via or "0.0.0.0", ifindex, 0))
        return True, "Ok."

    def delete_route(self, prefix, ifindex, via=""):
        self.calls.append(("del", prefix, ifindex, via))
        self.table = [r for r in self.table if not (r.prefix == prefix and r.ifindex == ifindex)]
        return True, "Ok."

    def prefixes_on(self, ifindex):
        return sorted(r.prefix for r in self.table if r.ifindex == ifindex)


def node(name, address, reachable=True, distance=1):
    return Node(name=name, address=address, distance=distance,
                status={"reachable": reachable})


def snapshot(euvds_reachable=True, announces_default=True, extra_nodes=(), extra_edges=()):
    """The shape of the real network on 2026-09-27: this Windows node dials
    ruvds2, ruvds2 dials euvds (the exit), the phone is known but down."""
    nodes = {
        OWN: node(OWN, "MYSELF", distance=0),
        "ruvds2": node("ruvds2", "80.87.200.39"),
        "euvds": node("euvds", "88.218.122.166", reachable=euvds_reachable, distance=2),
        "phone": node("phone", "203.0.113.50", reachable=False, distance=-1),
    }
    for n in extra_nodes:
        nodes[n.name] = n
    edges = [
        Edge(frm=OWN, to="ruvds2", address="80.87.200.39", port="8443"),
        Edge(frm="ruvds2", to=OWN, address="79.139.184.85", port="1155"),   # our own public address
        Edge(frm="ruvds2", to="euvds", address="88.218.122.166", port="444"),
        Edge(frm="euvds", to="ruvds2", address="80.87.200.39", port="655"),
        *extra_edges,
    ]
    subnets = [Subnet("10.8.179.1", "ruvds2"), Subnet("10.8.179.3", OWN),
               Subnet("10.8.179.4", "euvds")]
    if announces_default:
        subnets.append(Subnet("0.0.0.0/0", "euvds"))
    snap = NetworkSnapshot(net="tincstack", nodes=nodes, edges=edges, subnets=subnets)
    snap.attach_subnets()
    return snap


OPTIONS = {"Name": OWN, "ConnectTo": "ruvds2", "InterfaceAddress": "10.8.179.3/24"}
HOSTS = {"ruvds2": "Address = 80.87.200.39\nSubnet = 10.8.179.1/32\n"}


def tunnel(system=None):
    return ft.FullTunnel(net="tincstack", exit_node="euvds", aliases=["tincstack"],
                         system=system or FakeSystem())


def pinned(system):
    return sorted(r.prefix for r in system.table if r.ifindex == PHYS and r.prefix.endswith("/32"))


def test_pins_every_peer_endpoint_before_the_split_routes():
    s = FakeSystem()
    t = tunnel(s)
    t.step(snapshot(), OPTIONS, HOSTS, OWN)

    assert pinned(s) == ["203.0.113.50/32", "80.87.200.39/32", "88.218.122.166/32"]
    # through the physical gateway, not the tunnel
    assert all(c[2] == PHYS and c[3] == "192.168.1.1" for c in s.calls if c[1].endswith("/32"))
    # this node's own public address (on the edge towards it) is not a peer
    assert "79.139.184.85/32" not in pinned(s)
    split = [i for i, c in enumerate(s.calls) if c[1] in ft.SPLIT]
    pins = [i for i, c in enumerate(s.calls) if c[1].endswith("/32")]
    assert len(split) == 2 and min(split) > max(pins)
    # two halves on the adapter, on-link; the physical default route stays
    assert s.prefixes_on(TUN) == ["0.0.0.0/1", "128.0.0.0/1"]
    assert ("add", "0.0.0.0/1", TUN, "") in s.calls
    assert Route("0.0.0.0/0", "192.168.1.1", PHYS, 35) in s.table
    assert t.state == "active via euvds"


def test_a_second_pass_changes_nothing():
    s = FakeSystem()
    t = tunnel(s)
    t.step(snapshot(), OPTIONS, HOSTS, OWN)
    n = len(s.calls)
    assert t.step(snapshot(), OPTIONS, HOSTS, OWN) == []
    assert len(s.calls) == n


def test_addresses_on_the_lan_or_inside_the_vpn_are_not_pinned():
    s = FakeSystem()
    lan_peer = node("nas", "192.168.1.20")
    via_vpn = Edge(frm="ruvds2", to="nas", address="10.8.179.9", port="655")
    tunnel(s).step(snapshot(extra_nodes=[lan_peer], extra_edges=[via_vpn]), OPTIONS, HOSTS, OWN)
    assert "192.168.1.20/32" not in pinned(s)
    assert "10.8.179.9/32" not in pinned(s)


def test_the_connect_to_address_is_pinned_before_any_connection_exists():
    """Right after a (re)start there are no edges yet: the peer tincd is about
    to dial must already be pinned, or its first packet goes into the tunnel."""
    s = FakeSystem()
    t = tunnel(s)
    fresh = NetworkSnapshot(net="tincstack", nodes={OWN: node(OWN, "MYSELF", distance=0)})
    hosts = {"ruvds2": "Address = ruvds.example 8443\n"}
    t.step(fresh, OPTIONS, hosts, OWN)
    assert pinned(s) == ["80.87.200.39/32"]
    # the exit is not known yet: nothing goes on the adapter
    assert s.prefixes_on(TUN) == []
    assert t.state == "paused: euvds is not in the network"
    t.step(fresh, OPTIONS, hosts, OWN)
    assert s.resolved == ["ruvds.example"]      # cached, not resolved every pass


def test_a_new_physical_gateway_moves_every_pin():
    s = FakeSystem()
    t = tunnel(s)
    t.step(snapshot(), OPTIONS, HOSTS, OWN)
    # Wi-Fi gone, LTE up: another interface, another gateway
    s.table = [r for r in s.table if r.ifindex != PHYS] + [Route("0.0.0.0/0", "10.64.0.1", 9, 50)]
    s.calls.clear()
    t.step(snapshot(), OPTIONS, HOSTS, OWN)
    adds = sorted(c[1] for c in s.calls if c[0] == "add")
    assert adds == ["203.0.113.50/32", "80.87.200.39/32", "88.218.122.166/32"]
    assert all(c[2] == 9 and c[3] == "10.64.0.1" for c in s.calls if c[0] == "add")
    assert {c[1] for c in s.calls if c[0] == "del"} == set(adds)
    assert s.prefixes_on(TUN) == ["0.0.0.0/1", "128.0.0.0/1"]


def test_an_unreachable_exit_takes_the_split_routes_off_and_back():
    s = FakeSystem()
    t = tunnel(s)
    t.step(snapshot(), OPTIONS, HOSTS, OWN)
    t.step(snapshot(euvds_reachable=False), OPTIONS, HOSTS, OWN)
    assert s.prefixes_on(TUN) == []
    assert len(pinned(s)) == 3                  # pins stay: they cost nothing
    assert t.state == "paused: euvds is unreachable"
    t.step(snapshot(), OPTIONS, HOSTS, OWN)
    assert s.prefixes_on(TUN) == ["0.0.0.0/1", "128.0.0.0/1"]
    assert t.state == "active via euvds"


def test_an_exit_that_stops_announcing_the_default_route_is_not_used():
    s = FakeSystem()
    t = tunnel(s)
    t.step(snapshot(), OPTIONS, HOSTS, OWN)
    t.step(snapshot(announces_default=False), OPTIONS, HOSTS, OWN)
    assert s.prefixes_on(TUN) == []
    assert t.state == "paused: euvds does not announce 0.0.0.0/0"


def test_a_neighbour_that_cannot_be_pinned_blocks_the_split_routes():
    """The one pin whose absence is the loop: the peer this node talks to."""
    s = FakeSystem()
    s.fail["80.87.200.39/32"] = "Access is denied."
    t = tunnel(s)
    t.step(snapshot(), OPTIONS, HOSTS, OWN)
    assert s.prefixes_on(TUN) == []
    assert t.state.startswith("not applied: could not pin 80.87.200.39")


def test_nothing_happens_until_the_adapter_exists():
    s = FakeSystem()
    s.tunnel = None
    t = tunnel(s)
    assert t.step(snapshot(), OPTIONS, HOSTS, OWN) == ["full tunnel: waiting for the tunnel adapter"]
    assert s.calls == []


def test_offline_means_no_split_routes():
    s = FakeSystem()
    t = tunnel(s)
    t.step(snapshot(), OPTIONS, HOSTS, OWN)
    s.table = [r for r in s.table if r.prefix != "0.0.0.0/0"]
    t.step(snapshot(), OPTIONS, HOSTS, OWN)
    assert s.prefixes_on(TUN) == []
    assert t.state == "no physical default route (offline?)"


def test_a_restarted_adapter_gets_the_split_routes_again():
    s = FakeSystem()
    t = tunnel(s)
    t.step(snapshot(), OPTIONS, HOSTS, OWN)
    # tincd restarted: Windows dropped the old adapter's routes, new index
    s.table = [r for r in s.table if r.ifindex != TUN]
    s.tunnel = 15
    t.step(snapshot(), OPTIONS, HOSTS, OWN)
    assert s.prefixes_on(15) == ["0.0.0.0/1", "128.0.0.0/1"]


def test_stop_removes_the_split_routes_first_then_every_pin():
    s = FakeSystem()
    t = tunnel(s)
    t.step(snapshot(), OPTIONS, HOSTS, OWN)
    s.calls.clear()
    t.stop()
    dels = [c[1] for c in s.calls if c[0] == "del"]
    assert dels[:2] == list(ft.SPLIT)
    assert sorted(dels[2:]) == ["203.0.113.50/32", "80.87.200.39/32", "88.218.122.166/32"]
    assert s.prefixes_on(TUN) == [] and pinned(s) == []
    assert t.state == "off"


def test_choose_gateway_skips_the_tunnel_and_prefers_the_lowest_metric():
    table = [Route("0.0.0.0/0", "0.0.0.0", TUN, 1),          # a tunnel default must never be chosen
             Route("0.0.0.0/0", "192.168.1.1", PHYS, 35),
             Route("0.0.0.0/0", "10.64.0.1", 9, 20),
             Route("10.0.0.0/8", "10.64.0.1", 9, 1)]
    assert ft.choose_gateway(table, TUN) == ft.Gateway(9, "10.64.0.1")
    assert ft.choose_gateway(table[:1], TUN) is None
    assert ft.Gateway(9, "0.0.0.0").via == ""                  # on-link gateway: no nexthop


def test_connect_to_hosts_reads_every_address_line():
    opts = {"ConnectTo": ["a", "b", "missing"]}
    hosts = {"a": "Address = 1.2.3.4 655\nAddress = a.example\n", "b": "address=5.6.7.8"}
    assert ft.connect_to_hosts(opts, hosts) == ["1.2.3.4", "a.example", "5.6.7.8"]
    assert ft.connect_to_hosts({}, hosts) == []


def test_maintainer_runs_passes_and_cleans_up_when_stopped():
    s = FakeSystem()
    t = tunnel(s)
    lines = []
    m = ft.Maintainer(t, snapshot, lambda: (OPTIONS, HOSTS, OWN), lines.append, interval=0.01)
    m.start()
    deadline = time.time() + 5
    while t.state != "active via euvds" and time.time() < deadline:
        time.sleep(0.01)
    assert t.state == "active via euvds"
    m.stop()
    assert not m.is_alive()
    assert s.prefixes_on(TUN) == [] and pinned(s) == []
    assert lines[0] == "full tunnel: on, exit node euvds" and lines[-1] == "full tunnel: off"


def test_maintainer_survives_a_failing_pass():
    s = FakeSystem()
    t = tunnel(s)
    lines = []
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("tinc dump timed out")
        return snapshot()

    m = ft.Maintainer(t, flaky, lambda: (OPTIONS, HOSTS, OWN), lines.append, interval=0.01)
    m.start()
    deadline = time.time() + 5
    while t.state != "active via euvds" and time.time() < deadline:
        time.sleep(0.01)
    m.stop()
    assert any("pass failed: RuntimeError" in x for x in lines)
    assert t.state == "off"


def test_maintainer_removes_split_routes_when_daemon_hangs():
    s = FakeSystem()
    t = tunnel(s)
    lines = []
    hung = {"v": False}

    def snap_fn():
        if hung["v"]:
            return NetworkSnapshot("tincstack", error="tinc timed out after 5s")
        return snapshot()

    m = ft.Maintainer(t, snap_fn, lambda: (OPTIONS, HOSTS, OWN), lines.append, interval=0.01)
    m.start()
    assert _wait(lambda: t.state == "active via euvds")
    assert s.prefixes_on(TUN) == ["0.0.0.0/1", "128.0.0.0/1"]
    hung["v"] = True
    assert _wait(lambda: s.prefixes_on(TUN) == [])
    assert t.state == "waiting for the daemon"
    assert any("removing split routes (fail-open)" in x for x in lines)
    m.stop()



# ---- Runtime wiring ------------------------------------------------------------

def _runtime(tmp_path, monkeypatch, full_tunnel="euvds"):
    monkeypatch.setenv("TINCSTACK_BIN_DIR", str(tmp_path / "nobin"))
    cfg = tmp_path / "tinc.yaml"
    cfg.write_text("networks:\n  tincstack:\n    options:\n      Name: windows\n"
                   "      ConnectTo: ruvds2\n    hosts:\n      ruvds2: |\n"
                   "        Address = 80.87.200.39\n")
    app = yc.load(str(cfg))
    app.net("tincstack").full_tunnel = full_tunnel

    class FakeControl:
        def __init__(self, *a, **k):
            pass

        def snapshot(self, net):
            return snapshot()

    monkeypatch.setattr(rt_mod, "TincControl", FakeControl)
    s = FakeSystem()
    r = rt_mod.Runtime(app, ft_system=s, ft_interval=0.01)
    monkeypatch.setattr(r, "_daemon_alive", lambda net: True)
    return r, s, app


def _wait(cond, timeout=5.0):
    deadline = time.time() + timeout
    while not cond() and time.time() < deadline:
        time.sleep(0.01)
    return cond()


def test_runtime_sync_starts_and_stops_the_maintainer(tmp_path, monkeypatch):
    r, s, app = _runtime(tmp_path, monkeypatch)
    assert r.full_tunnel_sync("tincstack") == "full tunnel via euvds: starting"
    assert _wait(lambda: r.full_tunnel_state("tincstack") == "active via euvds")
    assert s.prefixes_on(TUN) == ["0.0.0.0/1", "128.0.0.0/1"]
    # a second sync while it runs does not start another one
    assert r.full_tunnel_sync("tincstack").startswith("full tunnel via euvds: ")
    assert len(r._ft) == 1

    app.net("tincstack").full_tunnel = ""
    assert r.full_tunnel_sync("tincstack") == "full tunnel off"
    assert r.full_tunnel_state("tincstack") == ""
    assert s.prefixes_on(TUN) == [] and pinned(s) == []


def test_runtime_sync_without_a_running_daemon_only_reports(tmp_path, monkeypatch):
    r, s, _ = _runtime(tmp_path, monkeypatch)
    monkeypatch.setattr(r, "_daemon_alive", lambda net: False)
    assert "applied when 'tincstack' starts" in r.full_tunnel_sync("tincstack")
    assert r.full_tunnel_state("tincstack") == "" and s.calls == []


def test_runtime_stop_removes_the_routes_before_stopping_the_daemon(tmp_path, monkeypatch):
    r, s, _ = _runtime(tmp_path, monkeypatch)
    r.full_tunnel_sync("tincstack")
    assert _wait(lambda: r.full_tunnel_state("tincstack") == "active via euvds")
    order = []
    s_delete = s.delete_route

    def delete(prefix, ifindex, via=""):
        order.append(("route", prefix))
        return s_delete(prefix, ifindex, via)

    s.delete_route = delete
    monkeypatch.setattr(r, "_tinc", lambda net, *a, **k: order.append(("tinc",) + a) or (0, ""))
    monkeypatch.setattr(r, "is_running", lambda net: False)
    r.stop("tincstack", timeout=0.5)
    first_tinc = next(i for i, o in enumerate(order) if o[0] == "tinc")
    assert order[:2] == [("route", "0.0.0.0/1"), ("route", "128.0.0.0/1")]
    assert all(o[0] == "route" for o in order[:first_tinc])
    assert s.prefixes_on(TUN) == [] and pinned(s) == []


def test_full_tunnel_setting_round_trips_through_tinc_yaml(tmp_path):
    cfg = tmp_path / "tinc.yaml"
    cfg.write_text("networks:\n  tincstack:\n    options:\n      Name: windows\n")
    app = yc.load(str(cfg))
    app.net("tincstack").full_tunnel = "euvds"
    yc.save(app)
    text = cfg.read_text()
    assert "full_tunnel: euvds" in text
    # a network-level key of tincmgr's, never an option the daemon reads
    assert "full_tunnel" not in str(yc.load(str(cfg)).net("tincstack").options)
    assert yc.load(str(cfg)).net("tincstack").full_tunnel == "euvds"
    app.net("tincstack").full_tunnel = ""
    yc.save(app)
    assert "full_tunnel" not in cfg.read_text()


@pytest.mark.parametrize("addr, ok", [
    ("80.87.200.39", True), ("10.20.0.5", True),       # private but not on-link: still leaves physically
    ("192.168.1.20", False), ("10.8.179.4", False),    # on-link / inside the VPN
    ("127.0.0.1", False), ("169.254.1.1", False), ("224.0.0.1", False),
    ("MYSELF", False), ("unknown", False), ("2001:db8::1", False),
])
def test_pinnable(addr, ok):
    assert ft.pinnable(addr, ["192.168.1.0/24"], ["10.8.179.0/24"]) is ok


def test_win32_add_route_falls_back_to_set_when_route_exists(monkeypatch):
    import routes
    calls = []

    def fake_netsh(args, timeout=15.0):
        calls.append(args)
        if "add" in args:
            return False, "Этот объект уже существует."
        return True, "OK."

    monkeypatch.setattr(routes, "_netsh", fake_netsh)
    w = ft.Win32.__new__(ft.Win32)
    ok, msg = w.add_route("80.87.200.39/32", 14, "192.168.1.1")
    assert ok and msg == "OK."
    assert len(calls) == 2 and "add" in calls[0] and "set" in calls[1]


def test_relay_only_peer_is_not_pinned_to_physical_gateway():
    s = FakeSystem()
    t = tunnel(s)
    snap = snapshot()
    snap.nodes["euvds"].no_direct = True
    opts = {"Name": OWN, "ConnectTo": "ruvds2, euvds", "NoDirectNodes": ["euvds"],
            "InterfaceAddress": "10.8.179.3/24"}
    hosts = {
        "ruvds2": "Address = 80.87.200.39\nSubnet = 10.8.179.1/32\n",
        "euvds": "Address = 88.218.122.166\nDirectConnect = no\nSubnet = 10.8.179.4/32\n",
    }
    t.step(snap, opts, hosts, OWN)
    # ruvds2 is pinned, but euvds (RelayOnly) must NOT be pinned to physical gateway
    assert "80.87.200.39/32" in pinned(s)
    assert "88.218.122.166/32" not in pinned(s)
    assert t.state == "active via euvds"


def test_weighted_default_route_is_accepted_by_exit_ready():
    snap = snapshot(announces_default=False)
    snap.subnets.append(Subnet("0.0.0.0/0#10", "euvds"))
    snap.attach_subnets()
    ok, reason = ft.exit_ready(snap, "euvds")
    assert ok and reason == ""


def test_remote_split_or_wide_subnets_never_suppress_endpoint_pinning():
    """WL-03: remote peers announcing 0.0.0.0/1 + 128.0.0.0/1 (or wide prefixes
    covering peer public IPs) must never block /32 physical gateway pinning."""
    s = FakeSystem()
    t = tunnel(s)
    snap = snapshot()
    snap.subnets.extend([
        Subnet("0.0.0.0/1", "euvds"),
        Subnet("128.0.0.0/1", "euvds"),
        Subnet("80.0.0.0/8", "ruvds2"),
    ])
    snap.attach_subnets()
    opts = dict(OPTIONS, InterfaceRoute="80.0.0.0/8 10.8.179.1")
    t.step(snap, opts, HOSTS, OWN)
    assert "80.87.200.39/32" in pinned(s)
    assert "88.218.122.166/32" in pinned(s)
    assert "203.0.113.50/32" in pinned(s)
    assert t.state == "active via euvds"


def test_second_split_route_failure_rolls_back_first_half():
    """WL-09: if adding 128.0.0.0/1 fails after 0.0.0.0/1 succeeded, 0.0.0.0/1
    must be deleted immediately so traffic is never half-routed."""
    s = FakeSystem()
    s.fail["128.0.0.0/1"] = "Access is denied."
    t = tunnel(s)
    t.step(snapshot(), OPTIONS, HOSTS, OWN)
    assert t.split_if is None
    assert s.prefixes_on(TUN) == []
    assert t.state.startswith("not applied: adding 128.0.0.0/1")


def test_ddns_refresh_on_every_maintainer_step_and_cached_fallback_on_timeout():
    """H-WIN-01: Maintainer._step() (refresh_dns=True) and RESOLVE_TTL expiry
    re-resolve ConnectTo hostnames even while split_if is active, updating /32
    pins when DDNS rotates while keeping cached IPs if DNS fails/times out."""
    s = FakeSystem()
    now = [100.0]
    t = ft.FullTunnel(
        net="tincstack", exit_node="euvds", aliases=["tincstack"],
        system=s, clock=lambda: now[0], resolve_timeout=0.05,
    )
    hosts = {"ruvds2": "Address = ruvds.example 8443\n"}
    snap = snapshot()
    # Suppose live edge has not flipped yet; ConnectTo DDNS rotates to a new IP
    snap.nodes["ruvds2"].address = "ruvds.example"
    snap.edges = [e for e in snap.edges if e.to != "ruvds2" and e.frm != "ruvds2"]
    snap.edges.extend([
        Edge(frm=OWN, to="ruvds2", address="ruvds.example", port="8443"),
        Edge(frm="ruvds2", to="euvds", address="88.218.122.166", port="444"),
    ])

    t.step(snap, OPTIONS, hosts, OWN, refresh_dns=True)
    assert t.split_if == TUN
    assert s.resolved == ["ruvds.example"]
    assert "80.87.200.39/32" in pinned(s)

    # DDNS rotates while split_if is active -> refresh_dns=True updates /32 pin!
    s.dns["ruvds.example"] = ["198.51.100.77"]
    t.step(snap, OPTIONS, hosts, OWN, refresh_dns=True)
    assert len(s.resolved) == 2
    assert "198.51.100.77/32" in pinned(s)
    assert "80.87.200.39/32" not in pinned(s)

    # Transient DNS failure while split_if is active -> keeps cached 198.51.100.77/32 pin!
    del s.dns["ruvds.example"]
    t.step(snap, OPTIONS, hosts, OWN, refresh_dns=True)
    assert "198.51.100.77/32" in pinned(s)
    assert t.split_if == TUN

    # Verify _resolve_with_timeout aborts a hung resolver promptly
    with pytest.raises(OSError, match="timed out"):
        ft._resolve_with_timeout(lambda _h: time.sleep(1.0) or ["1.2.3.4"], "hung.example", 0.05)


def test_ipv6_endpoint_pinned_before_split_v6_and_unpinnable_v6_skips_split_v6():
    """H-WIN-01: IPv6 /128 peer endpoints are pinned via physical IPv6 gateway
    BEFORE ::/1 and 8000::/1 are installed on Wintun, and if an active IPv6-only
    carrier cannot be pinned on the physical interface, SPLIT_V6 is NOT installed."""
    class DualStackSystem(FakeSystem):
        def __init__(self, with_v6_gw: bool = True):
            super().__init__()
            self.table_v6 = (
                [Route("::/0", "fe80::1", PHYS, 25)] if with_v6_gw else []
            )
            self.local_v6 = ["2001:db8:1::/64"]

        def supports_ipv6(self):
            return True

        def route_table_v6(self):
            return list(self.table_v6)

        def local_nets_v6(self):
            return list(self.local_v6)

        def add_route(self, prefix, ifindex, via=""):
            self.calls.append(("add", prefix, ifindex, via))
            if ":" in prefix:
                self.table_v6.append(Route(prefix, via or "::", ifindex, 0))
                return True, "Ok."
            return super().add_route(prefix, ifindex, via)

        def delete_route(self, prefix, ifindex, via=""):
            self.calls.append(("del", prefix, ifindex, via))
            if ":" in prefix:
                self.table_v6 = [r for r in self.table_v6 if not (r.prefix == prefix and r.ifindex == ifindex)]
                return True, "Ok."
            return super().delete_route(prefix, ifindex, via)

        def prefixes_on_all(self, ifindex):
            return sorted(
                [r.prefix for r in self.table if r.ifindex == ifindex]
                + [r.prefix for r in self.table_v6 if r.ifindex == ifindex]
            )

    # Case 1: Dual-stack physical gateway exists -> /128 pin added BEFORE ::/1 and 8000::/1
    s1 = DualStackSystem(with_v6_gw=True)
    snap_v6 = snapshot()
    snap_v6.nodes["ruvds2"].address = "2001:db8:99::42"
    snap_v6.edges[0] = Edge(frm=OWN, to="ruvds2", address="2001:db8:99::42", port="8443")
    hosts_v6 = {"ruvds2": "Address = 2001:db8:99::42\nSubnet = 10.8.179.1/32\n"}
    t1 = tunnel(s1)
    t1.step(snap_v6, OPTIONS, hosts_v6, OWN)
    pin_idx = next(i for i, c in enumerate(s1.calls) if c[1] == "2001:db8:99::42/128")
    split_v6_idxs = [i for i, c in enumerate(s1.calls) if c[1] in ft.SPLIT_V6]
    assert split_v6_idxs and pin_idx < min(split_v6_idxs)
    assert s1.calls[pin_idx] == ("add", "2001:db8:99::42/128", PHYS, "fe80::1")
    assert set(ft.SPLIT_V6) <= set(s1.prefixes_on_all(TUN))
    t1.stop()
    assert s1.prefixes_on_all(TUN) == []
    assert not [r for r in s1.table_v6 if r.prefix == "2001:db8:99::42/128"]

    # Case 2: Active carrier is IPv6-only, but physical IPv6 gateway is missing ->
    # SPLIT_V6 must NOT be installed (otherwise Wintun hijacks the outer IPv6 carrier!)
    s2 = DualStackSystem(with_v6_gw=False)
    t2 = tunnel(s2)
    t2.step(snap_v6, OPTIONS, hosts_v6, OWN)
    assert s2.prefixes_on_all(TUN) == ["0.0.0.0/1", "128.0.0.0/1"]


def test_journal_persisted_before_mutating_routes_and_guid_dns_rollback(tmp_path):
    """H-WIN-01: rollback journal is persisted BEFORE adding split routes/DNS,
    and DNS crash recovery uses adapter GUID + alias rather than stale ifindex."""
    import json
    jpath = tmp_path / "ft-journal.json"
    observed_journal_before_split = []
    cleared_dns_ids = []
    cleared_ifindexes = []

    class TrackingSystem(FakeSystem):
        def adapter_guid(self, ifindex):
            if self.tunnel is not None and int(ifindex) == self.tunnel:
                return "{11111111-2222-3333-4444-555555555555}"
            # Recycled foreign adapter now occupying the old ephemeral ifindex!
            return "{99999999-8888-7777-6666-555555555555}"

        def set_tunnel_dns(self, ifindex, dns_servers):
            # Journal must already record DNS rollback metadata BEFORE set_tunnel_dns runs!
            data = json.loads(jpath.read_text(encoding="utf-8"))
            assert data["dns_if"] == TUN
            assert data["dns_guid"] == "{11111111-2222-3333-4444-555555555555}"
            assert data["dns_alias"] == "tincstack"
            return True, "dns set"

        def clear_tunnel_dns(self, ifindex):
            cleared_ifindexes.append(int(ifindex))
            return True, ""

        def clear_tunnel_dns_by_id(self, alias="", guid=""):
            cleared_dns_ids.append((alias, guid))
            return True, ""

        def add_route(self, prefix, ifindex, via=""):
            if prefix in ft.SPLIT:
                observed_journal_before_split.append(jpath.is_file())
            return super().add_route(prefix, ifindex, via)

    s = TrackingSystem()
    t = ft.FullTunnel(net="tincstack", exit_node="euvds", aliases=["tincstack"],
                      system=s, journal_path=str(jpath))
    t.step(snapshot(), OPTIONS, HOSTS, OWN)
    assert observed_journal_before_split == [True, True]

    # Simulate reboot where ephemeral ifindex TUN was recycled to a foreign adapter:
    # cleanup_journal MUST NOT wipe DNS on recycled TUN, and instead clears by alias + GUID!
    s.tunnel = None
    assert ft.cleanup_journal(str(jpath), s, ["tincstack"])
    assert cleared_ifindexes == []
    assert cleared_dns_ids == [("tincstack", "{11111111-2222-3333-4444-555555555555}")]


def test_single_network_full_tunnel_exclusivity(tmp_path, monkeypatch):
    """M-WIN-02: Runtime refuses enabling active full_tunnel on a second network
    while another network already owns full_tunnel."""
    cfg = tmp_path / "tinc.yaml"
    cfg.write_text("networks:\n  net1:\n    full_tunnel: gw1\n    options:\n      Name: a\n  net2:\n    full_tunnel: gw2\n    options:\n      Name: b\n")
    app = yc.load(str(cfg))
    rt = rt_mod.Runtime(app, ft_system=FakeSystem(), ft_interval=60.0)
    monkeypatch.setattr(rt, "is_running", lambda net: True)
    try:
        m1 = rt.full_tunnel_sync("net1")
        assert "starting" in m1 or "full tunnel via gw1" in m1
        assert rt.active_full_tunnel_net() == "net1"
        m2 = rt.full_tunnel_sync("net2")
        assert "refused" in m2 and "net1" in m2
        assert "net2" not in rt._ft
    finally:
        rt.stop_all()


def test_ipv6_leak_guard_installed_when_system_supports_ipv6():
    """WL-08: when System.supports_ipv6() is True and no IPv6 default route is
    configured, ::/1 and 8000::/1 are installed on the tunnel adapter and cleaned on stop."""
    class V6System(FakeSystem):
        def supports_ipv6(self):
            return True

    s = V6System()
    t = tunnel(s)
    t.step(snapshot(), OPTIONS, HOSTS, OWN)
    assert s.prefixes_on(TUN) == ["0.0.0.0/1", "128.0.0.0/1", "8000::/1", "::/1"]
    t.stop()
    assert s.prefixes_on(TUN) == []


def test_same_ifindex_nexthop_change_and_crash_journal_cleanup(tmp_path):
    """WL-14: changing gateway nexthop on the same interface updates /32 pins,
    and cleanup_journal removes orphaned split routes + pins after an unclean exit."""
    jpath = str(tmp_path / "tincstack-ft-journal.json")
    s = FakeSystem()
    t = ft.FullTunnel(net="tincstack", exit_node="euvds", aliases=["tincstack"],
                      system=s, journal_path=jpath)
    t.step(snapshot(), OPTIONS, HOSTS, OWN)
    assert any(r.prefix == "80.87.200.39/32" and r.nexthop == "192.168.1.1" for r in s.table)

    # Same ifindex PHYS (7), new router IP 192.168.1.254
    s.table = [
        Route("0.0.0.0/0", "192.168.1.254", PHYS, 35) if r.prefix == "0.0.0.0/0" else r
        for r in s.table
    ]
    t.step(snapshot(), OPTIONS, HOSTS, OWN)
    pin_routes = [r for r in s.table if r.prefix == "80.87.200.39/32" and r.ifindex == PHYS]
    assert len(pin_routes) == 1 and pin_routes[0].nexthop == "192.168.1.254"

    # Simulate crash recovery from journal on a new session
    cleaned = ft.cleanup_journal(jpath, s, ["tincstack"])
    assert cleaned
    assert s.prefixes_on(TUN) == []
    assert pinned(s) == []



