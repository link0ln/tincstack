"""Unit tests for Windows security hardening, CLI elevation/detachment, orphan PID
verification, stop_all idempotency, and disk-to-YAML migration."""
from __future__ import annotations

import os
import stat
import sys
import textwrap

import pytest

import cli
import management
import paths
import runtime as rt_mod
import yaml_config as yc

TOOLS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools")
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)
import import_from_disk  # noqa: E402


def test_c_win_01_untrusted_env_ignores_bin_dir_and_refuses_mei_fallback(tmp_path, monkeypatch):
    """C-WIN-01: when frozen or elevated on Windows, TINCSTACK_BIN_DIR is ignored,
    stage_binaries never falls back to %TEMP%\\_MEI* on failure, and matching
    SHA-256 skips overwriting a running binary without raising PermissionError."""
    evil_bin = tmp_path / "evil_bin"
    evil_bin.mkdir()
    (evil_bin / "tincd.exe").write_bytes(b"EVIL")
    monkeypatch.setenv(paths.BIN_DIR_ENV, str(evil_bin))

    res = tmp_path / "_MEI9999"
    res.mkdir()
    good_bytes = b"AUTHENTIC-TINCD"
    for n in ("tincd.exe", "tinc.exe", "wintun.dll"):
        (res / n).write_bytes(good_bytes)

    prot = tmp_path / "PF" / "tincmgr"
    staged_dir = prot / "bin"
    staged_dir.mkdir(parents=True)
    for n in ("tincd.exe", "tinc.exe", "wintun.dll"):
        (staged_dir / n).write_bytes(good_bytes)

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(paths, "is_frozen", lambda: True)
    monkeypatch.setattr(paths, "is_elevated", lambda: True)
    monkeypatch.setattr(management, "is_admin", lambda: True)
    monkeypatch.setattr(paths, "resource_dir", lambda: str(res))
    monkeypatch.setattr(paths, "protected_dir", lambda: str(prot))

    # 1. TINCSTACK_BIN_DIR is completely ignored when untrusted_env() is True!
    assert paths.untrusted_env() is True
    assert paths.tincd_exe() != str(evil_bin / "tincd.exe")

    # 2. If the staged binary is locked/running (os.replace raises PermissionError),
    #    matching SHA-256 skips overwriting cleanly without raising PermissionError!
    monkeypatch.setattr(
        os,
        "replace",
        lambda *a, **k: (_ for _ in ()).throw(PermissionError("binary is running")),
    )
    assert paths.stage_file(str(res / "tincd.exe"), str(staged_dir / "tincd.exe")) is False
    monkeypatch.undo()

    # 3. If staging into %ProgramFiles%\tincmgr\bin fails and no staged copy exists yet,
    #    Runtime NEVER falls back to executing from %TEMP%\_MEI9999!
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(paths, "is_frozen", lambda: True)
    monkeypatch.setattr(paths, "is_elevated", lambda: True)
    monkeypatch.setattr(management, "is_admin", lambda: True)
    monkeypatch.setattr(paths, "resource_dir", lambda: str(res))
    empty_prot = tmp_path / "PF_empty" / "tincmgr"
    monkeypatch.setattr(paths, "protected_dir", lambda: str(empty_prot))
    monkeypatch.setattr(paths, "lock_down_acl", lambda *a, **k: None)
    monkeypatch.setattr(paths, "mkdir_private", lambda p: (os.makedirs(p, exist_ok=True), p)[1])
    monkeypatch.setattr(
        paths,
        "stage_file",
        lambda *a, **k: (_ for _ in ()).throw(PermissionError("Access denied")),
    )
    cfg = tmp_path / "tinc.yaml"
    cfg.write_text("networks: {}\n", encoding="utf-8")
    rt = rt_mod.Runtime(yc.load(str(cfg)))
    assert "_MEI9999" not in rt.tincd
    assert rt.tincd == str(empty_prot / "bin" / "tincd.exe")
    assert "Access denied" in rt.stage_note


def test_c_win_03_safe_rollback_exe_and_reparse_point_guards(tmp_path, monkeypatch):
    """C-WIN-03: safe_rollback_exe only returns an existing non-symlink installed_exe
    inside %ProgramFiles%\\tincmgr, and reject_reparse_point blocks symlinks."""
    prot = tmp_path / "PF" / "tincmgr"
    monkeypatch.setattr(paths, "protected_dir", lambda: str(prot))

    # Not installed yet -> None
    assert management.safe_rollback_exe() is None

    app_dir = prot / "app"
    app_dir.mkdir(parents=True)
    exe = app_dir / "tincmgr.exe"
    exe.write_bytes(b"MZ-installed")
    assert management.safe_rollback_exe() == str(exe)

    # Replace installed exe with a symlink to an untrusted binary -> must return None!
    untrusted = tmp_path / "evil.exe"
    untrusted.write_bytes(b"MZ-evil")
    exe.unlink()
    exe.symlink_to(untrusted)
    assert management.safe_rollback_exe() is None
    with pytest.raises(OSError, match="symlink|reparse"):
        paths.reject_reparse_point(str(exe))


def test_h_win_05_cli_elevated_config_and_detached_daemon_spawn(tmp_path, monkeypatch):
    """H-WIN-05: when elevated without -c, cli.py resolves elevated_config_path()
    (ignoring untrusted CWD tinc.yaml), and `cli up` spawns tincd detached writing
    logs directly to a file rather than an ephemeral parent pipe."""
    cwd_dir = tmp_path / "untrusted_cwd"
    cwd_dir.mkdir()
    (cwd_dir / "tinc.yaml").write_text(
        "networks:\n  evil:\n    options:\n      ScriptsInterpreter: calc.exe\n",
        encoding="utf-8",
    )
    prot_cfg = tmp_path / "PF" / "tincmgr" / "tinc.yaml"
    prot_cfg.parent.mkdir(parents=True)
    prot_cfg.write_text("networks:\n  corp:\n    options:\n      Name: node1\n", encoding="utf-8")

    monkeypatch.chdir(cwd_dir)
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(paths, "is_elevated", lambda: True)
    monkeypatch.setattr(paths, "elevated_config_path", lambda: str(prot_cfg))
    assert cli._resolve_config_path(None) == str(prot_cfg)

    # Verify detached Runtime.start writes directly to log file with no LogSink pipe
    monkeypatch.undo()
    if sys.platform != "win32":
        bindir = tmp_path / "bin"
        bindir.mkdir()
        state = tmp_path / "det_state"
        fake_tincd = bindir / "tincd"
        fake_tincd.write_text(
            textwrap.dedent(f"""\
                #!/bin/sh
                echo "detached daemon output $*"
                touch "{state}"
                trap 'rm -f "{state}"; exit 0' TERM INT
                while [ -f "{state}" ]; do sleep 0.05; done
            """),
            encoding="utf-8",
        )
        fake_tinc = bindir / "tinc"
        fake_tinc.write_text(
            textwrap.dedent(f"""\
                #!/bin/sh
                shift 4
                case "$1" in
                  dump) [ -f "{state}" ] && exit 0 || exit 1 ;;
                  stop) rm -f "{state}"; exit 0 ;;
                esac
                exit 1
            """),
            encoding="utf-8",
        )
        for p in (fake_tincd, fake_tinc):
            p.chmod(p.stat().st_mode | stat.S_IXUSR)
        monkeypatch.setenv(paths.BIN_DIR_ENV, str(bindir))

        app = yc.load(str(prot_cfg))
        rt = rt_mod.Runtime(app)
        ok, msg = rt.start("corp", detached=True)
        assert ok, msg
        assert "corp" not in rt._sinks
        assert rt.is_running("corp")
        assert "detached daemon output" in open(rt.log_path("corp"), encoding="utf-8").read()
        rt.stop_all()
        # M-WIN-04: stop_all() is idempotent
        rt.stop_all()


def test_m_win_03_orphan_pid_verifies_network_cmdline_before_killing(tmp_path, monkeypatch):
    """M-WIN-03: _kill_orphan_daemons refuses to kill a recycled/other-network PID
    whose command line does not carry `-n <net>`."""
    cfg = tmp_path / "tinc.yaml"
    cfg.write_text("networks:\n  demo:\n    options:\n      Name: n1\n", encoding="utf-8")
    app = yc.load(str(cfg))
    rdir = tmp_path / "demo"
    rdir.mkdir()
    (rdir / "pid").write_text("42424\n", encoding="utf-8")

    killed: list[int] = []
    monkeypatch.setattr(rt_mod.Runtime, "_terminate_tincd_pid", classmethod(lambda cls, pid: killed.append(pid) or True))

    rt = rt_mod.Runtime(app)
    monkeypatch.setattr(rt, "is_running", lambda net: False)

    # Case 1: PID belongs to another network (`-n othernet`) -> NOT killed, stale PID file cleaned!
    monkeypatch.setattr(rt_mod.Runtime, "_pid_cmdline", classmethod(lambda cls, pid: ["tincd", "-n", "othernet", "-D"]))
    rt._kill_orphan_daemons("demo")
    assert killed == []
    assert not (rdir / "pid").exists()

    # Case 2: PID matches `tincd -n demo` -> killed!
    (rdir / "pid").write_text("42424\n", encoding="utf-8")
    monkeypatch.setattr(rt_mod.Runtime, "_pid_cmdline", classmethod(lambda cls, pid: ["/usr/sbin/tincd", "-n", "demo", "-D"]))
    rt._kill_orphan_daemons("demo")
    assert killed == [42424]


def test_m_win_05_import_from_disk_handles_bat_cmd_and_tls_keys(tmp_path):
    """M-WIN-05: import_from_disk imports .bat/.cmd scripts, tls_cert/tls_key/acme_account,
    and preserves string-typed options like ObfsPassword = 123456."""
    src = tmp_path / "legacy_net"
    (src / "hosts").mkdir(parents=True)
    (src / "tinc.conf").write_text(
        "Name = winbox\nPort = 655\nObfsPassword = 001234\nScriptsExtension = .cmd\n",
        encoding="utf-8",
    )
    (src / "tinc-up.bat").write_text("@echo up\n", encoding="utf-8")
    (src / "host-up.cmd").write_text("@echo host-up\n", encoding="utf-8")
    (src / "ed25519_key.priv").write_text("ED_PRIV\n", encoding="utf-8")
    (src / "tls_cert.pem").write_text("TLS_CERT_PEM\n", encoding="utf-8")
    (src / "tls_key.pem").write_text("TLS_KEY_PEM\n", encoding="utf-8")
    (src / "acme_account.key").write_text("ACME_KEY_PEM\n", encoding="utf-8")
    (src / "hosts" / "winbox").write_text("Subnet = 10.0.0.1/32\n", encoding="utf-8")

    nc = import_from_disk.import_net(str(tmp_path), "legacy_net", autostart_running=False)
    assert nc.options["ObfsPassword"] == "001234" and isinstance(nc.options["ObfsPassword"], str)
    assert nc.scripts["tinc-up.bat"] == "@echo up"
    assert nc.scripts["host-up.cmd"] == "@echo host-up"
    assert nc.keys["ed25519_priv"] == "ED_PRIV"
    assert nc.keys["tls_cert"] == "TLS_CERT_PEM"
    assert nc.keys["tls_key"] == "TLS_KEY_PEM"
    assert nc.keys["acme_account"] == "ACME_KEY_PEM"
