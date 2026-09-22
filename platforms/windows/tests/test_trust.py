"""The elevated app executes and obeys only what administrators can change
(review 2026-09-22, local privilege escalation): staged core binaries compared
by content, the autostart task pointed at an admin-only copy of the exe, the
config adopted into the admin-only folder once. Program Files and schtasks are
stand-ins here (tmp_path, a fake subprocess.run); the ACL itself is Windows'."""
import os
import subprocess
import sys

import pytest

import management
import paths
import runtime as rt_mod
import yaml_config as yc


# -- stage_file: by content, not by size ----------------------------------------

def test_stage_file_replaces_a_same_size_different_binary(tmp_path):
    """The measured case: two tincd.exe builds of 1816078 bytes each with
    different hashes. A size check staged nothing and kept the old daemon."""
    src, dst = tmp_path / "new.exe", tmp_path / "bin" / "tincd.exe"
    dst.parent.mkdir()
    src.write_bytes(b"A" * 4096)
    dst.write_bytes(b"B" * 4096)
    assert os.path.getsize(src) == os.path.getsize(dst)
    assert paths.stage_file(str(src), str(dst)) is True
    assert dst.read_bytes() == src.read_bytes()
    assert not (tmp_path / "bin" / "tincd.exe.new").exists()


def test_stage_file_leaves_an_identical_file_alone(tmp_path):
    src, dst = tmp_path / "a", tmp_path / "b"
    src.write_bytes(b"same")
    dst.write_bytes(b"same")
    before = os.stat(dst).st_mtime_ns
    assert paths.stage_file(str(src), str(dst)) is False
    assert os.stat(dst).st_mtime_ns == before


def test_stage_file_creates_the_target_dir(tmp_path):
    src = tmp_path / "a"
    src.write_bytes(b"x")
    assert paths.stage_file(str(src), str(tmp_path / "new" / "dir" / "a")) is True


# -- where binaries are staged ----------------------------------------------------

def test_bin_stage_dir_elevated_is_the_protected_folder(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "protected_dir", lambda: str(tmp_path / "PF" / "tincmgr"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "user"))
    assert paths.bin_stage_dir(True) == str(tmp_path / "PF" / "tincmgr" / "bin")
    # unelevated: nothing it runs can raise privileges, keep the per-user dir
    assert paths.bin_stage_dir(False) == str(tmp_path / "user" / "tincmgr" / "bin")


def test_bin_stage_dir_without_a_protected_folder_falls_back(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "protected_dir", lambda: None)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "user"))
    assert paths.bin_stage_dir(True) == str(tmp_path / "user" / "tincmgr" / "bin")


def test_protected_dir_is_none_off_windows(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    assert paths.protected_dir() is None


@pytest.mark.skipif(sys.platform != "win32", reason="asks the Windows shell")
def test_protected_dir_ignores_the_environment(monkeypatch):
    """An elevated process inherits its environment from whoever launched it."""
    real = paths.protected_dir()
    monkeypatch.setenv("ProgramFiles", r"C:\Users\Public\evil")
    assert paths.protected_dir() == real
    assert "evil" not in real


def test_runtime_stages_elevated_binaries_by_hash(tmp_path, monkeypatch):
    res, prot = tmp_path / "meipass", tmp_path / "PF" / "tincmgr"
    res.mkdir()
    for n in ("tincd.exe", "tinc.exe", "wintun.dll"):
        (res / n).write_bytes(n.encode() * 100)
    stale = prot / "bin" / "tincd.exe"
    stale.parent.mkdir(parents=True)
    stale.write_bytes(b"x" * len(b"tincd.exe" * 100))          # same size, older build
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(paths, "resource_dir", lambda: str(res))
    monkeypatch.setattr(paths, "protected_dir", lambda: str(prot))
    monkeypatch.setattr(management, "is_admin", lambda: True)
    cfg = tmp_path / "tinc.yaml"
    cfg.write_text("networks: {}\n")
    r = rt_mod.Runtime(yc.load(str(cfg)))
    assert r.tincd == str(prot / "bin" / "tincd.exe")
    assert r.bindir == str(prot / "bin")
    assert stale.read_bytes() == (res / "tincd.exe").read_bytes()
    assert (prot / "bin" / "wintun.dll").read_bytes() == (res / "wintun.dll").read_bytes()
    assert r.stage_note == ""


# -- the config ---------------------------------------------------------------------

def test_adopt_config_imports_once_then_ignores_the_old_file(tmp_path):
    legacy = tmp_path / "Downloads" / "tinc.yaml"
    legacy.parent.mkdir()
    legacy.write_text("networks:\n  home: {}\n")
    prot = tmp_path / "PF" / "tincmgr" / "tinc.yaml"

    path, note = paths.adopt_config(str(prot), str(legacy))
    assert path == str(prot) and "imported" in note
    assert prot.read_text() == legacy.read_text()

    # an unelevated process rewrites the old file: the elevated app must not care
    legacy.write_text("networks:\n  home:\n    options:\n      ScriptsInterpreter: calc.exe\n")
    path, note = paths.adopt_config(str(prot), str(legacy))
    assert path == str(prot)
    assert "ScriptsInterpreter" not in prot.read_text()
    assert "is not read" in note and str(legacy) in note


def test_adopt_config_creates_an_empty_one(tmp_path):
    prot = tmp_path / "PF" / "tincmgr" / "tinc.yaml"
    path, note = paths.adopt_config(str(prot), None)
    assert path == str(prot) and "created" in note
    assert prot.read_text() == "networks: {}\n"


def test_adopt_config_is_quiet_when_the_legacy_hit_is_the_protected_file(tmp_path):
    """The installed exe lives in the protected folder, so the old search
    (next to the exe first) finds the protected config itself."""
    prot = tmp_path / "tinc.yaml"
    prot.write_text("networks: {}\n")
    assert paths.adopt_config(str(prot), str(prot)) == (str(prot), "")


# -- autostart ---------------------------------------------------------------------

class FakeSchtasks:
    def __init__(self, command=None):
        self.command = command
        self.calls = []

    def __call__(self, args, **kw):
        self.calls.append(list(args))
        out = ""
        rc = 0
        if args[:2] == ["schtasks", "/query"]:
            if self.command is None:
                rc = 1
            else:
                out = f"<Task><Actions><Exec><Command>\"{self.command}\"</Command></Exec></Actions></Task>"
        elif args[:2] == ["schtasks", "/create"]:
            self.command = args[args.index("/tr") + 1].strip('"')
        elif args[:2] == ["schtasks", "/delete"]:
            self.command = None
        return subprocess.CompletedProcess(args, rc, out, "")


@pytest.fixture
def fake_windows(tmp_path, monkeypatch):
    prot = tmp_path / "PF" / "tincmgr"
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(paths, "protected_dir", lambda: str(prot))
    monkeypatch.setattr(management, "_clear_task_battery_limits", lambda name: None)
    return prot


def test_startup_task_runs_the_admin_only_copy(tmp_path, monkeypatch, fake_windows):
    exe = tmp_path / "Downloads" / "tincmgr.exe"
    exe.parent.mkdir()
    exe.write_bytes(b"MZ v1")
    fake = FakeSchtasks()
    monkeypatch.setattr(subprocess, "run", fake)

    ok, _ = management.set_startup_task(True, str(exe))
    assert ok
    assert fake.command == str(fake_windows / "tincmgr.exe")
    assert (fake_windows / "tincmgr.exe").read_bytes() == b"MZ v1"
    create = next(c for c in fake.calls if c[:2] == ["schtasks", "/create"])
    assert str(exe) not in " ".join(create)


def test_refresh_moves_an_old_task_off_the_user_folder(tmp_path, monkeypatch, fake_windows):
    exe = tmp_path / "Downloads" / "tincmgr.exe"
    exe.parent.mkdir()
    exe.write_bytes(b"MZ v2")
    fake = FakeSchtasks(command=str(exe))          # what tincmgr <= 0.4.1 registered
    monkeypatch.setattr(subprocess, "run", fake)

    note = management.refresh_startup_task(str(exe))
    assert fake.command == str(fake_windows / "tincmgr.exe")
    assert "now runs" in note


def test_refresh_brings_the_installed_copy_up_to_date(tmp_path, monkeypatch, fake_windows):
    installed = fake_windows / "tincmgr.exe"
    installed.parent.mkdir(parents=True)
    installed.write_bytes(b"MZ v1")
    exe = tmp_path / "tincmgr.exe"
    exe.write_bytes(b"MZ v2")                     # same size, newer build
    fake = FakeSchtasks(command=str(installed))
    monkeypatch.setattr(subprocess, "run", fake)

    assert management.refresh_startup_task(str(exe)) == ""
    assert installed.read_bytes() == b"MZ v2"
    assert not any(c[:2] == ["schtasks", "/create"] for c in fake.calls)


def test_refresh_does_nothing_without_a_task(tmp_path, monkeypatch, fake_windows):
    fake = FakeSchtasks(command=None)
    monkeypatch.setattr(subprocess, "run", fake)
    assert management.refresh_startup_task(str(tmp_path / "tincmgr.exe")) == ""
    assert not (fake_windows / "tincmgr.exe").exists()
