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
