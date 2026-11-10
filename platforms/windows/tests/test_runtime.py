"""runtime: size-based log rotation while the daemon runs, start/stop against
fake tincd/tinc scripts (no admin, no real daemon), key-merge helper, and
binary discovery."""
import os
import stat
import sys
import textwrap
import time

import pytest

import paths
import runtime as rt_mod
import yaml_config as yc


def test_merge_pubkeys_keeps_subnet():
    existing = "Ed25519PublicKey = OLD\nSubnet = 10.0.0.1/32\nAddress = 1.2.3.4"
    fresh = "Ed25519PublicKey = NEW\n"
    out = rt_mod.merge_pubkeys(existing, fresh)
    assert "NEW" in out and "OLD" not in out
    assert "Subnet = 10.0.0.1/32" in out and "Address = 1.2.3.4" in out


def test_logsink_rotates_while_writing(tmp_path):
    log = str(tmp_path / "demo-tincd.log")
    r, w = os.pipe()
    sink = rt_mod.LogSink(log, os.fdopen(r, "rb"), max_bytes=10_000, backups=2)
    sink.start()
    line = b"x" * 99 + b"\n"
    with os.fdopen(w, "wb", buffering=0) as wf:
        for _ in range(350):          # 35 KB through a 10 KB limit
            wf.write(line)
    sink.join(timeout=5)
    assert not sink.is_alive()
    assert sink.rotations >= 3
    sizes = {p: os.path.getsize(os.path.join(tmp_path, p)) for p in sorted(os.listdir(tmp_path))}
    assert set(sizes) == {"demo-tincd.log", "demo-tincd.log.1", "demo-tincd.log.2"}
    assert all(s <= 10_000 for s in sizes.values()), sizes
    # nothing lost inside the retained window: every kept file holds whole lines
    for p in sizes:
        data = open(os.path.join(tmp_path, p), "rb").read()
        assert data.endswith(b"\n") and set(data.replace(b"\n", b"")) <= {ord("x")}


@pytest.mark.skipif(sys.platform == "win32", reason="fake binaries are POSIX shell scripts")
def test_start_stop_with_fake_core(tmp_path, monkeypatch):
    """Runtime.start spawns tincd -n NET -c tinc.yaml -D with a pipe into the
    rotating sink; is_running/stop go through `tinc`. The fake daemon logs
    ~30 KB so rotation is exercised on the real start path."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    state = tmp_path / "state"
    fake_tincd = bindir / "tincd"
    fake_tincd.write_text(textwrap.dedent(f"""\
        #!/bin/sh
        # args: -n NET -c YAML -D
        echo "fake tincd started $*"
        touch "{state}"
        i=0
        while [ $i -lt 300 ]; do
          echo "log line $i ......................................................................"
          i=$((i+1))
        done
        trap 'rm -f "{state}"; exit 0' TERM INT
        while [ -f "{state}" ]; do sleep 0.1; done
        """))
    fake_tinc = bindir / "tinc"
    fake_tinc.write_text(textwrap.dedent(f"""\
        #!/bin/sh
        # args: -n NET -c YAML CMD...
        shift 4
        case "$1" in
          dump) [ -f "{state}" ] && exit 0 || exit 1 ;;
          stop) rm -f "{state}"; exit 0 ;;
        esac
        exit 1
        """))
    for p in (fake_tincd, fake_tinc):
        p.chmod(p.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv(paths.BIN_DIR_ENV, str(bindir))

    cfg = str(tmp_path / "tinc.yaml")
    app = yc.AppConfig(path=cfg)
    app.networks["demo"] = yc.NetworkCfg(name="demo", options={"Name": "demobook"})
    yc.save(app)

    rt = rt_mod.Runtime(app, log_max_bytes=8_000, log_backups=3)
    assert rt.tincd == str(fake_tincd)
    assert not rt.is_running("demo")
    ok, msg = rt.start("demo")
    assert ok, msg
    assert rt.is_running("demo")
    time.sleep(0.5)
    log = rt.log_path("demo")
    assert os.path.exists(log) and os.path.exists(log + ".1"), "rotation did not happen while running"
    assert os.path.getsize(log) <= 8_000 and os.path.getsize(log + ".1") <= 8_000
    kept = "".join(open(log + suffix).read() for suffix in (".3", ".2", ".1", ""))
    assert "fake tincd started -n demo -c" in kept and "log line 299" in kept
    ok, msg = rt.stop("demo")
    assert ok and msg == "stopped"
    assert not rt.is_running("demo")
    assert "demo" not in rt._procs and "demo" not in rt._sinks


def test_start_reports_missing_binary(tmp_path, monkeypatch):
    monkeypatch.setenv(paths.BIN_DIR_ENV, str(tmp_path / "nope"))
    monkeypatch.setattr(paths.shutil, "which", lambda name: None)
    app = yc.AppConfig(path=str(tmp_path / "tinc.yaml"))
    app.networks["demo"] = yc.NetworkCfg(name="demo")
    rt = rt_mod.Runtime(app)
    ok, msg = rt.start("demo")
    assert not ok and "tincd not found" in msg


@pytest.mark.parametrize("device_type", ["wintun", ""])
@pytest.mark.parametrize("ok, expect, refuse", [
    (True, "wintun MTU: MTU=1400 set on 'demo'", "FAILED"),
    (False, "wintun MTU clamp to 1400 FAILED: adapter ['demo'] not found", "MTU: adapter"),
])
def test_wintun_mtu_log_tells_a_failed_clamp_from_a_good_one(tmp_path, monkeypatch, device_type, ok, expect, refuse):
    """The clamp's success flag used to be dropped: a failure was logged
    exactly like a success. Also verify default (empty) DeviceType is clamped."""
    import types
    msg = "MTU=1400 set on 'demo'" if ok else "adapter ['demo'] not found"
    monkeypatch.setitem(sys.modules, "netmtu",
                        types.SimpleNamespace(set_interface_mtu=lambda aliases, mtu: (ok, msg)))
    app = yc.AppConfig(path=str(tmp_path / "tinc.yaml"))
    opts = {"DeviceType": device_type} if device_type else {}
    app.networks["demo"] = yc.NetworkCfg(name="demo", options=opts)
    rt = rt_mod.Runtime(app)
    rt._apply_wintun_mtu("demo")
    text = (tmp_path / "demo-tincmgr.log").read_text()
    assert expect in text and refuse not in text


def test_paths_resolution(tmp_path, monkeypatch):
    monkeypatch.setenv(paths.BIN_DIR_ENV, str(tmp_path))
    exe = ".exe" if sys.platform == "win32" else ""
    (tmp_path / ("tincd" + exe)).write_text("")
    (tmp_path / ("tinc" + exe)).write_text("")
    assert paths.tincd_exe() == str(tmp_path / ("tincd" + exe))
    ok, msg = paths.binaries_present()
    assert ok and str(tmp_path) in msg
    monkeypatch.delenv(paths.BIN_DIR_ENV)
    assert os.path.basename(paths.resource_dir()) == "resources"
    assert os.path.dirname(paths.resource_dir()) == os.path.dirname(os.path.dirname(paths.__file__))


def test_orphan_cleanup_skips_when_load_error_and_never_kills_by_image(tmp_path, monkeypatch):
    """WL-10: _kill_orphan_daemons must do nothing when load_error is set, and
    must only target stale PID-file processes whose control socket is dead."""
    app = yc.AppConfig(path=str(tmp_path / "tinc.yaml"))
    app.networks["demo"] = yc.NetworkCfg(name="demo", options={"Name": "demobook"})
    rdir = tmp_path / "demo"
    rdir.mkdir()
    (rdir / "pid").write_text("99999\n")

    terminated: list[int] = []
    monkeypatch.setattr(rt_mod.Runtime, "_terminate_tincd_pid", classmethod(lambda cls, pid: terminated.append(pid) or True))

    # 1. With load_error set: never touch any daemon
    rt_err = rt_mod.Runtime(app, load_error="malformed YAML")
    rt_err._kill_orphan_daemons()
    assert terminated == []
    assert (rdir / "pid").exists()

    # 2. Without load_error, if control socket responds (is_running=True): keep daemon alive
    rt_ok = rt_mod.Runtime(app)
    monkeypatch.setattr(rt_ok, "is_running", lambda net: True)
    rt_ok._kill_orphan_daemons("demo")
    assert terminated == []
    assert (rdir / "pid").exists()

    # 3. Without load_error, if control socket is dead: terminate recorded PID only
    monkeypatch.setattr(rt_ok, "is_running", lambda net: False)
    rt_ok._kill_orphan_daemons("demo")
    assert terminated == [99999]
    assert not (rdir / "pid").exists()


def test_sync_diag_port_prefers_live_diag_port_fn(tmp_path, monkeypatch):
    """WL-12: Runtime._sync_diag_port uses the live diag_port_fn rather than a
    stale diag_settings.json file."""
    import threading
    import diagnostics
    diagnostics.save_diag_settings(str(tmp_path), enabled=True, port=9999)
    app = yc.AppConfig(path=str(tmp_path / "tinc.yaml"))
    app.networks["demo"] = yc.NetworkCfg(name="demo", options={"Name": "demobook"})
    rt = rt_mod.Runtime(app, diag_port_fn=lambda: 8777)
    seen: list[tuple[str, int]] = []
    done = threading.Event()

    def fake_diag_port(self, net, port=None, timeout=3.0):
        seen.append((net, port))
        done.set()
        return True, port

    monkeypatch.setattr(rt_mod.TincControl, "diag_port", fake_diag_port)
    rt._sync_diag_port("demo")
    assert done.wait(2.0)
    assert seen == [("demo", 8777)]


def test_generate_keys_uses_private_dir_under_config_base(tmp_path, monkeypatch):
    """WL-18: generate_keys stages temporary key files inside self.base (with
    paths.mkdir_private), never under world-shared %TEMP%."""
    cfg = str(tmp_path / "tinc.yaml")
    app = yc.AppConfig(path=cfg)
    app.networks["demo"] = yc.NetworkCfg(
        name="demo",
        options={"Name": "demobook"},
        hosts={"demobook": "Subnet = 10.99.0.1/32\n"},
    )
    rt = rt_mod.Runtime(app)
    seen_dirs: list[str] = []

    def fake_run(args, **kwargs):
        cdir = args[args.index("-c") + 1]
        seen_dirs.append(cdir)
        assert os.path.dirname(os.path.abspath(cdir)) == os.path.abspath(str(tmp_path))
        if sys.platform != "win32":
            assert stat.S_IMODE(os.stat(cdir).st_mode) == 0o700
        open(os.path.join(cdir, "ed25519_key.priv"), "w", encoding="utf-8").write("PRIVKEY\n")
        open(os.path.join(cdir, "hosts", "demobook"), "w", encoding="utf-8").write("Ed25519PublicKey = PUBKEY\n")
        return type("P", (), {"returncode": 0, "stdout": "ok", "stderr": ""})()

    monkeypatch.setattr(rt_mod.subprocess, "run", fake_run)
    ok, msg = rt.generate_keys("demo")
    assert ok and msg == "keys generated"
    assert len(seen_dirs) == 1 and not os.path.exists(seen_dirs[0])
    assert app.net("demo").keys["ed25519_priv"] == "PRIVKEY"
    assert "Ed25519PublicKey = PUBKEY" in app.net("demo").hosts["demobook"]
    assert "Subnet = 10.99.0.1/32" in app.net("demo").hosts["demobook"]

