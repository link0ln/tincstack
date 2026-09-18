"""yaml_config: schema round-trip, malformed-file guard, atomic save and the
concurrent-writer merge (the daemon appends to the file while the GUI holds a
copy in memory)."""
import os
import textwrap

import pytest
import yaml

import yaml_config as yc


def build_sample(path: str) -> yc.AppConfig:
    app = yc.AppConfig(path=path, workdir="tincmgr-data")
    app.networks["demo"] = yc.NetworkCfg(
        name="demo",
        autostart=True,
        options={
            "Name": "demobook",
            "Mode": "router",
            "Port": 0,
            "AddressFamily": "ipv4",
            "AutoConnect": True,          # -> yes
            "LocalDiscovery": True,       # -> yes
            "DeviceType": "wintun",
            "WintunAddress": "10.99.0.1/24",
            "ConnectTo": ["hubA", "hubB"],  # -> two lines
            "PreferredTransports": ["quic", "plain"],
        },
        keys={"ed25519_priv": "-----BEGIN ED25519 PRIVATE KEY-----\nFAKE\n-----END ED25519 PRIVATE KEY-----"},
        hosts={
            "demobook": "Ed25519PublicKey = AAAA\nSubnet = 10.99.0.1/32",
            "hubA": "Address = 1.2.3.4\nPort = 655\nEd25519PublicKey = BBBB\nSubnet = 10.99.0.2/32",
        },
    )
    return app


def test_round_trip(tmp_path):
    cfg = str(tmp_path / "tinc.yaml")
    app = build_sample(cfg)
    yc.save(app)
    app2 = yc.load(cfg)
    assert app2.workdir == "tincmgr-data"
    nc = app2.net("demo")
    assert nc and nc.autostart and nc.node_name == "demobook"
    assert nc.device_type == "wintun" and nc.wintun_address == "10.99.0.1/24"
    assert nc.options["ConnectTo"] == ["hubA", "hubB"]
    assert nc.options["PreferredTransports"] == ["quic", "plain"]
    assert nc.hosts["hubA"].startswith("Address = 1.2.3.4")
    # multi-line strings are emitted as literal blocks (readable, daemon-compatible)
    text = open(cfg, encoding="utf-8").read()
    assert "ed25519_priv: |" in text and "hubA: |" in text


def test_options_conf_rendering():
    nc = build_sample("x").net("demo")
    conf = yc.options_to_conf(nc.options)
    assert "AutoConnect = yes" in conf
    assert "ConnectTo = hubA" in conf and "ConnectTo = hubB" in conf
    assert "Port = 0" in conf
    back = yc.conf_to_options(conf)
    assert back["ConnectTo"] == ["hubA", "hubB"]
    assert back["AutoConnect"] is True and back["Port"] == 0


def test_unknown_keys_are_carried(tmp_path):
    cfg = tmp_path / "tinc.yaml"
    cfg.write_text("future_top: 1\nnetworks:\n  n:\n    options: {Name: a}\n    future_net: [1, 2]\n")
    app = yc.load(str(cfg))
    app.net("n").options["Port"] = 655
    yc.save(app)
    doc = yaml.safe_load(cfg.read_text())
    assert doc["future_top"] == 1
    assert doc["networks"]["n"]["future_net"] == [1, 2]
    assert doc["networks"]["n"]["options"]["Port"] == 655


@pytest.mark.parametrize("text,needle", [
    ("networks:\n  a: [\n", "malformed YAML"),
    ("- just\n- a list\n", "top level must be a mapping"),
    ("networks: [a, b]\n", "'networks' must be a mapping"),
    ("networks:\n  a:\n    options: nope\n", "options must be a mapping"),
])
def test_malformed_raises_config_error(tmp_path, text, needle):
    cfg = tmp_path / "tinc.yaml"
    cfg.write_text(text)
    with pytest.raises(yc.ConfigError) as ei:
        yc.load(str(cfg))
    assert needle in str(ei.value)
    assert str(cfg) in str(ei.value)


def test_missing_file_loads_empty(tmp_path):
    app = yc.load(str(tmp_path / "absent.yaml"))
    assert app.networks == {}


def test_atomic_save_never_truncates(tmp_path, monkeypatch):
    """A failure between temp-write and rename must leave the original intact."""
    cfg = str(tmp_path / "tinc.yaml")
    app = build_sample(cfg)
    yc.save(app)
    before = open(cfg, "rb").read()
    app.net("demo").options["Port"] = 1

    def boom(src, dst):
        raise OSError("simulated crash before rename")
    monkeypatch.setattr(yc.os, "replace", boom)
    with pytest.raises(OSError):
        yc.save(app)
    assert open(cfg, "rb").read() == before, "original file was modified in place"
    assert not [p for p in os.listdir(tmp_path) if p.endswith(".tmp")], "temp file leaked"
    monkeypatch.undo()
    yc.save(app)
    assert yc.load(cfg).net("demo").options["Port"] == 1


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_atomic_save_keeps_mode(tmp_path):
    cfg = str(tmp_path / "tinc.yaml")
    app = build_sample(cfg)
    yc.save(app)
    os.chmod(cfg, 0o600)
    app.net("demo").options["Port"] = 2
    yc.save(app)
    assert oct(os.stat(cfg).st_mode & 0o777) == "0o600"


def test_concurrent_writer_merge(tmp_path):
    """The daemon appends a learned peer key (and re-emits the file) while the
    GUI holds an older in-memory copy; the GUI's save must keep the daemon's
    additions and write only the keys the user changed."""
    cfg = tmp_path / "tinc.yaml"
    cfg.write_text(textwrap.dedent("""\
        networks:
          demo:
            autostart: true
            options:
              Name: demobook
              Mode: router
              Port: 655
            hosts:
              demobook: |
                Ed25519PublicKey = AAAA
                Subnet = 10.99.0.1/32
        """))
    app = yc.load(str(cfg))           # GUI snapshot (baseline)

    # daemon writes meanwhile: learned peer + persisted Address on own record
    cfg.write_text(textwrap.dedent("""\
        networks:
          demo:
            autostart: true
            options:
              Name: demobook
              Mode: router
              Port: 655
              AddressPool: 10.99.0.0/24
            hosts:
              demobook: |
                Ed25519PublicKey = AAAA
                Subnet = 10.99.0.1/32
                Address = 203.0.113.9
              peer1: |
                Ed25519PublicKey = PPPP
                Subnet = 10.99.0.2/32
        """))

    # user ticks QUIC in the editor
    app.net("demo").options["PreferredTransports"] = ["quic", "plain"]
    yc.save(app)

    expected = textwrap.dedent("""\
        networks:
          demo:
            autostart: true
            options:
              Name: demobook
              Mode: router
              Port: 655
              AddressPool: 10.99.0.0/24
              PreferredTransports:
                - quic
                - plain
            hosts:
              demobook: |
                Ed25519PublicKey = AAAA
                Subnet = 10.99.0.1/32
                Address = 203.0.113.9
              peer1: |
                Ed25519PublicKey = PPPP
                Subnet = 10.99.0.2/32
        """)
    assert cfg.read_text() == expected

    # the model absorbed the daemon's additions (same NetworkCfg object)
    nc = app.net("demo")
    assert "peer1" in nc.hosts and nc.options["AddressPool"] == "10.99.0.0/24"

    # second save with nothing changed: no rewrite, nothing deleted
    mtime = cfg.stat().st_mtime_ns
    yc.save(app)
    assert cfg.stat().st_mtime_ns == mtime
    assert cfg.read_text() == expected


def test_save_refuses_to_overwrite_unparsable_file(tmp_path):
    cfg = tmp_path / "tinc.yaml"
    app = build_sample(str(cfg))
    yc.save(app)
    cfg.write_text("networks: [broken\n")
    app.net("demo").options["Port"] = 3
    with pytest.raises(yc.ConfigError):
        yc.save(app)
    assert cfg.read_text() == "networks: [broken\n"


def test_delete_propagates(tmp_path):
    cfg = str(tmp_path / "tinc.yaml")
    app = build_sample(cfg)
    yc.save(app)
    del app.net("demo").hosts["hubA"]
    del app.net("demo").options["ConnectTo"]
    yc.save(app)
    app2 = yc.load(cfg)
    assert "hubA" not in app2.net("demo").hosts
    assert "ConnectTo" not in app2.net("demo").options
    assert "demobook" in app2.net("demo").hosts


def test_diff_documents_is_minimal():
    old = {"networks": {"a": {"options": {"Name": "x", "Port": 1}, "hosts": {"h": "1"}}}}
    new = {"networks": {"a": {"options": {"Name": "x", "Port": 2}, "hosts": {"h": "1", "g": "2"}}}}
    patch = yc.diff_documents(old, new)
    assert patch == {("networks", "a", "options", "Port"): 2,
                     ("networks", "a", "hosts", "g"): "2"}


def test_save_text_validates(tmp_path):
    cfg = tmp_path / "tinc.yaml"
    with pytest.raises(yc.ConfigError):
        yc.save_text(str(cfg), "networks: [\n")
    assert not cfg.exists()
    yc.save_text(str(cfg), "networks: {}")
    assert cfg.read_text() == "networks: {}\n"
