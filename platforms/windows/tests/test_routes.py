"""Routes to the subnets peers announce: which ones are worth offering, how the
InterfaceRoute option is read and written, and the local-conflict warning."""
import pytest

import routes


@pytest.mark.parametrize("subnet, ok", [
    ("192.168.1.0/24", True),
    ("10.0.0.0/8", True),
    ("fd00::/64", True),
    ("10.200.240.7", False),        # the peer's own address (tinc prints /32 bare)
    ("10.200.240.7/32", False),
    ("0.0.0.0/0", False),           # a full tunnel is not a checkbox
    ("::/0", False),
    ("not a subnet", False),
    ("", False),
])
def test_routable(subnet, ok):
    assert routes.routable(subnet) is ok


def test_why_not_routable_explains_each_refusal():
    assert "own address" in routes.why_not_routable("10.200.240.7")
    assert "full tunnel" in routes.why_not_routable("0.0.0.0/0").lower()
    assert "not a subnet" in routes.why_not_routable("wat")
    assert routes.why_not_routable("192.168.1.0/24") == ""


def test_entry_and_destination_round_trip():
    # the documented spelling is "<prefix> <gateway>" -- what `tinc join` writes
    assert routes.entry("192.168.1.0/24", "10.200.240.7") == "192.168.1.0/24 10.200.240.7"
    assert routes.entry("192.168.1.0/24") == "192.168.1.0/24"
    # a host part that is set is normalised away, so two spellings are one route
    assert routes.entry("192.168.1.5/24") == "192.168.1.0/24"
    assert routes.destination("192.168.1.0/24 10.200.240.7") == "192.168.1.0/24"
    # ...and the `ip route` spelling the daemon also accepts reads back the same
    assert routes.destination("192.168.1.0/24 via 10.200.240.7") == "192.168.1.0/24"
    assert routes.destination("192.168.1.0/24") == "192.168.1.0/24"


def test_values_reads_both_shapes():
    assert routes.values({}) == []
    assert routes.values({"InterfaceRoute": "10.0.0.0/8"}) == ["10.0.0.0/8"]
    assert routes.values({"InterfaceRoute": ["10.0.0.0/8", "172.16.0.0/12"]}) == \
        ["10.0.0.0/8", "172.16.0.0/12"]


def test_add_and_remove_keep_the_schema_shape():
    o = {}
    routes.add(o, "192.168.1.0/24", "10.200.240.7")
    assert o == {"InterfaceRoute": "192.168.1.0/24 10.200.240.7"}   # one -> scalar
    routes.add(o, "172.16.0.0/12")
    assert o["InterfaceRoute"] == ["192.168.1.0/24 10.200.240.7", "172.16.0.0/12"]
    routes.remove(o, "172.16.0.0/12")
    assert o == {"InterfaceRoute": "192.168.1.0/24 10.200.240.7"}
    routes.remove(o, "192.168.1.0/24")
    assert o == {}                                                      # none -> absent


def test_adding_the_same_subnet_twice_replaces_rather_than_duplicates():
    """The same subnet announced by two nodes must not become two routes: the
    last choice wins, and it is the one whose nexthop is recorded."""
    o = {}
    routes.add(o, "192.168.1.0/24", "10.200.240.7")
    routes.add(o, "192.168.1.0/24", "10.200.240.9")
    assert routes.values(o) == ["192.168.1.0/24 10.200.240.9"]
    assert routes.has(o, "192.168.1.0/24")


def test_has_ignores_the_nexthop():
    o = {"InterfaceRoute": "192.168.1.0/24 via 10.200.240.7"}   # either spelling
    assert routes.has(o, "192.168.1.0/24")
    assert not routes.has(o, "192.168.2.0/24")


def test_conflicts_finds_an_overlapping_local_network():
    local = ["192.168.1.0/24", "10.200.240.0/24"]
    assert routes.conflicts("192.168.1.0/24", local) == ["192.168.1.0/24"]
    assert routes.conflicts("192.168.1.128/25", local) == ["192.168.1.0/24"]
    assert routes.conflicts("172.16.0.0/12", local) == []
    assert routes.conflicts("fd00::/64", local) == []          # different family


def test_adapter_aliases_prefers_the_configured_name():
    assert routes.adapter_aliases({"WintunInterface": "gnet-tun"}, "gnet") == ["gnet-tun", "gnet"]
    assert routes.adapter_aliases({}, "gnet") == ["gnet"]
    assert routes.adapter_aliases({"Interface": "gnet"}, "gnet") == ["gnet"]


def test_live_calls_refuse_to_pretend_off_windows():
    ok, msg = routes.apply_now("gnet", "192.168.1.0/24")
    assert not ok and "Windows" in msg
    ok, msg = routes.remove_now("gnet", "192.168.1.0/24")
    assert not ok and "Windows" in msg
    assert routes.local_ipv4_subnets() == []
