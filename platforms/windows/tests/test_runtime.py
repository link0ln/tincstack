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
