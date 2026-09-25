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


def test_runtime_refuses_a_tampered_bundled_tincd(tmp_path, monkeypatch):
    """The onefile's unpack dir is user-writable and tincd.exe there is not
    open: with a manifest, a replaced tincd.exe is neither staged nor run --
    the old fallback to "the bundled core" would have run exactly that file."""
    import hashlib
    res, prot = tmp_path / "meipass", tmp_path / "PF" / "tincmgr"
    res.mkdir()
    good = {n: n.encode() * 100 for n in ("tincd.exe", "tinc.exe", "wintun.dll")}
    for n, data in good.items():
        (res / n).write_bytes(data)
    b = paths.Bundle("v0.5.0", {"_internal/" + n: (hashlib.sha256(d).hexdigest(), n)
                                for n, d in good.items()}, str(res))
    staged = prot / "bin" / "tincd.exe"
    staged.parent.mkdir(parents=True)
    staged.write_bytes(b"previously staged, verified")
    (res / "tincd.exe").write_bytes(b"planted")
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(paths, "bundle", lambda: b)
    monkeypatch.setattr(paths, "resource_dir", lambda: str(res))
    monkeypatch.setattr(paths, "protected_dir", lambda: str(prot))
    monkeypatch.setattr(management, "is_admin", lambda: True)
    cfg = tmp_path / "tinc.yaml"
    cfg.write_text("networks: {}\n")
    r = rt_mod.Runtime(yc.load(str(cfg)))
    assert r.tincd == str(staged)
    assert staged.read_bytes() == b"previously staged, verified"
    assert "refused" in r.stage_note and "manifest" in r.stage_note


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


# -- the config is created private -------------------------------------------------

def test_private_sddl_elevated_excludes_the_user_and_is_owned_by_administrators():
    s = paths.private_sddl(True, "S-1-5-21-1-2-3-1001")
    assert s == "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
    assert "S-1-5-21" not in s               # the user's unelevated processes get nothing


def test_private_sddl_unelevated_adds_the_user_and_nobody_else():
    s = paths.private_sddl(False, "S-1-5-21-1-2-3-1001")
    assert s == "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-21-1-2-3-1001)"
    for who in ("WD", "BU", "AU", "IU"):     # Everyone, Users, Authenticated, Interactive
        assert f";;;{who})" not in s
    with pytest.raises(OSError):
        paths.private_sddl(False, None)
    with pytest.raises(OSError):
        paths.private_sddl(False, "S-1-5-21)(A;;FA;;;WD")


def _sddl(path):
    """The file's SDDL, read as icacls would (Windows / Wine only)."""
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
    try:
        import file_sddl
    finally:
        sys.path.pop(0)
    return file_sddl.sddl(str(path))


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")
def test_write_private_is_0600_on_posix(tmp_path):
    p = tmp_path / "tinc.yaml"
    paths.write_private(str(p), b"tls_key: x\n")
    assert p.read_bytes() == b"tls_key: x\n"
    assert os.stat(p).st_mode & 0o777 == 0o600


@pytest.mark.skipif(sys.platform != "win32", reason="Windows security descriptors")
def test_write_private_gives_everyone_nothing_on_windows(tmp_path):
    """Wine keeps no DACL of its own: it maps it onto the unix mode, so what
    can be seen here is that Everyone got no ACE, where an ordinary file
    written the same way has one. Protection and ownership: real Windows."""
    plain = tmp_path / "plain.yaml"
    plain.write_bytes(b"x")
    assert ";;;WD)" in _sddl(plain)            # the control: an inherited/default ACL
    p = tmp_path / "tinc.yaml"
    paths.write_private(str(p), b"tls_key: x\n")
    s = _sddl(p)
    assert ";;;WD)" not in s and ";;;BU)" not in s, s
    yc.atomic_write_text(str(p), "tls_key: y\n")
    s = _sddl(p)
    assert ";;;WD)" not in s and ";;;BU)" not in s, s
    assert p.read_text() == "tls_key: y\n"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows security descriptors")
def test_private_sddl_strings_parse_on_windows():
    import ctypes
    from ctypes import wintypes
    conv = ctypes.windll.advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    conv.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    for s in (paths.private_sddl(True, None), paths.private_sddl(False, "S-1-5-21-1-2-3-1001")):
        sd = ctypes.c_void_p()
        assert conv(s, 1, ctypes.byref(sd), None), s
        ctypes.windll.kernel32.LocalFree(sd)


def test_adopt_config_writes_it_private(tmp_path):
    prot = tmp_path / "PF" / "tincmgr" / "tinc.yaml"
    paths.adopt_config(str(prot), None)
    if sys.platform != "win32":
        assert os.stat(prot).st_mode & 0o777 == 0o600
    else:
        assert ";;;WD)" not in _sddl(prot)
    assert not (prot.parent / "tinc.yaml.new").exists()


# -- versions ------------------------------------------------------------------------

def test_version_key():
    assert paths.version_key("v0.4.1") == (0, 4, 1)
    assert paths.version_key("0.10.0") == (0, 10, 0)
    assert paths.version_key(" v0.4.1\n") == (0, 4, 1)
    for v in ("dev", "", None, "v0.4", "v0.4.1-rc1", "0.4.1.2"):
        assert paths.version_key(v) is None


@pytest.mark.parametrize("ours, installed, ok", [
    ("v0.5.0", None, True),            # nothing, or the unversioned pre-onedir layout
    ("v0.5.0", "v0.4.1", True),        # upgrade
    ("v0.5.0", "v0.5.0", True),        # same release (a rebuild)
    ("v0.4.1", "v0.5.0", False),       # the "last run wins" downgrade
    ("v0.4.9", "v0.10.0", False),      # numeric, not string, order
    ("dev", "v0.5.0", False),          # a dev build cannot prove it is newer
    ("v0.5.0", "dev", True),           # a release replaces a dev install
    ("dev", "dev", True),
])
def test_check_downgrade(ours, installed, ok):
    if ok:
        management.check_downgrade(ours, installed)
    else:
        with pytest.raises(management.DowngradeRefused):
            management.check_downgrade(ours, installed)


# -- autostart: the onedir tree under Program Files ------------------------------------

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


def make_bundle(root, version, tag=b"v1"):
    """A onefile's unpack dir as tincmgr.spec lays it out: the onedir exe
    under _app/, every _internal/ file at the top."""
    import hashlib
    root.mkdir(parents=True, exist_ok=True)
    content = {"_app/tincmgr.exe": b"MZ onedir " + tag,
               "python312.dll": b"python " + tag,
               "PySide6/Qt6Core.dll": b"qt " + tag,
               "tincd.exe": b"tincd " + tag}
    for rel, data in content.items():
        p = root.joinpath(*rel.split("/"))
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    files = {}
    for rel, data in content.items():
        dest = "tincmgr.exe" if rel == "_app/tincmgr.exe" else "_internal/" + rel
        files[dest] = (hashlib.sha256(data).hexdigest(), rel)
    return paths.Bundle(version, files, str(root))


@pytest.fixture
def fake_windows(tmp_path, monkeypatch):
    prot = tmp_path / "PF" / "tincmgr"
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(paths, "protected_dir", lambda: str(prot))
    monkeypatch.setattr(management, "_clear_task_battery_limits", lambda name: None)
    return prot


def use_bundle(monkeypatch, b):
    monkeypatch.setattr(paths, "bundle", lambda: b)


def test_startup_task_runs_the_installed_onedir_copy(tmp_path, monkeypatch, fake_windows):
    exe = tmp_path / "Downloads" / "tincmgr.exe"
    exe.parent.mkdir()
    exe.write_bytes(b"MZ onefile")
    use_bundle(monkeypatch, make_bundle(tmp_path / "Temp" / "_MEI1234", "v0.5.0"))
    fake = FakeSchtasks()
    monkeypatch.setattr(subprocess, "run", fake)

    ok, _ = management.set_startup_task(True, str(exe))
    assert ok
    app = fake_windows / "app"
    assert fake.command == str(app / "tincmgr.exe")
    assert (app / "tincmgr.exe").read_bytes() == b"MZ onedir v1"
    assert (app / "_internal" / "python312.dll").read_bytes() == b"python v1"
    assert (app / "_internal" / "PySide6" / "Qt6Core.dll").read_bytes() == b"qt v1"
    assert management.installed_version() == "v0.5.0"
    create = next(c for c in fake.calls if c[:2] == ["schtasks", "/create"])
    assert str(exe) not in " ".join(create) and "_MEI" not in " ".join(create)
    assert not (fake_windows / "app.new").exists() and not (fake_windows / "app.old").exists()


def test_install_refuses_a_file_swapped_in_the_unpack_dir(tmp_path, monkeypatch, fake_windows):
    """The onefile's %TEMP%\\_MEIxxxx is writable by the user's unelevated
    processes for as long as the app runs. A DLL replaced there must not
    reach Program Files."""
    old = make_bundle(tmp_path / "old", "v0.4.0", b"v0")
    use_bundle(monkeypatch, old)
    monkeypatch.setattr(subprocess, "run", FakeSchtasks())
    management.install_self(str(tmp_path / "x.exe"))
    before = (fake_windows / "app" / "_internal" / "python312.dll").read_bytes()

    b = make_bundle(tmp_path / "Temp" / "_MEI9", "v0.5.0")
    (tmp_path / "Temp" / "_MEI9" / "python312.dll").write_bytes(b"planted by a medium-IL process")
    use_bundle(monkeypatch, b)
    with pytest.raises(OSError, match="does not match"):
        management.install_self(str(tmp_path / "x.exe"))
    assert (fake_windows / "app" / "_internal" / "python312.dll").read_bytes() == before
    assert management.installed_version() == "v0.4.0"
    assert not (fake_windows / "app.new").exists()


def test_install_keeps_the_old_tree_when_it_cannot_be_replaced(tmp_path, monkeypatch, fake_windows):
    """A running installed copy has its DLLs mapped: Windows refuses to move
    its directory. The old tree must survive whole."""
    use_bundle(monkeypatch, make_bundle(tmp_path / "a", "v0.4.0", b"v0"))
    management.install_self(str(tmp_path / "x.exe"))
    use_bundle(monkeypatch, make_bundle(tmp_path / "b", "v0.5.0"))
    real_rename = os.rename

    def busy(src, dst):
        if str(src) == str(fake_windows / "app"):
            raise PermissionError(32, "in use")
        return real_rename(src, dst)
    monkeypatch.setattr(os, "rename", busy)
    with pytest.raises(OSError, match="running"):
        management.install_self(str(tmp_path / "x.exe"))
    assert management.installed_version() == "v0.4.0"
    assert (fake_windows / "app" / "tincmgr.exe").read_bytes() == b"MZ onedir v0"
    assert not (fake_windows / "app.new").exists()


def test_the_installed_copy_does_not_reinstall_itself(tmp_path, monkeypatch, fake_windows):
    use_bundle(monkeypatch, None)            # the onedir carries no manifest
    target = management.installed_exe()
    assert management.install_self(target) == target
    with pytest.raises(OSError, match="single-file"):
        management.install_self(str(tmp_path / "elsewhere.exe"))


def test_refresh_moves_an_old_task_off_the_user_folder(tmp_path, monkeypatch, fake_windows):
    exe = tmp_path / "Downloads" / "tincmgr.exe"
    exe.parent.mkdir()
    exe.write_bytes(b"MZ onefile")
    use_bundle(monkeypatch, make_bundle(tmp_path / "Temp" / "_MEI1", "v0.5.0"))
    fake = FakeSchtasks(command=str(exe))          # what tincmgr <= 0.4.1 registered
    monkeypatch.setattr(subprocess, "run", fake)

    note = management.refresh_startup_task(str(exe))
    assert fake.command == str(fake_windows / "app" / "tincmgr.exe")
    assert "now runs" in note


def test_refresh_moves_the_program_files_onefile_task_to_the_onedir(tmp_path, monkeypatch, fake_windows):
    """The layout before this change: the onefile itself under Program Files,
    which unpacked into the user's %TEMP% at every logon."""
    legacy = fake_windows / "tincmgr.exe"
    legacy.parent.mkdir(parents=True)
    legacy.write_bytes(b"MZ onefile 0.4.1")
    use_bundle(monkeypatch, make_bundle(tmp_path / "Temp" / "_MEI1", "v0.5.0"))
    fake = FakeSchtasks(command=str(legacy))
    monkeypatch.setattr(subprocess, "run", fake)

    note = management.refresh_startup_task(str(tmp_path / "tincmgr.exe"))
    assert fake.command == str(fake_windows / "app" / "tincmgr.exe")
    assert "now runs" in note
    assert not legacy.exists()


def test_refresh_brings_the_installed_copy_up_to_date(tmp_path, monkeypatch, fake_windows):
    use_bundle(monkeypatch, make_bundle(tmp_path / "old", "v0.4.1", b"v0"))
    fake = FakeSchtasks()
    monkeypatch.setattr(subprocess, "run", fake)
    assert management.set_startup_task(True, str(tmp_path / "x.exe"))[0]
    creates = len([c for c in fake.calls if c[:2] == ["schtasks", "/create"]])

    use_bundle(monkeypatch, make_bundle(tmp_path / "new", "v0.5.0", b"v1"))
    assert management.refresh_startup_task(str(tmp_path / "x.exe")) == ""
    assert (fake_windows / "app" / "_internal" / "python312.dll").read_bytes() == b"python v1"
    assert management.installed_version() == "v0.5.0"
    assert len([c for c in fake.calls if c[:2] == ["schtasks", "/create"]]) == creates


def test_refresh_never_downgrades_but_the_toggle_may(tmp_path, monkeypatch, fake_windows):
    """Last run must not win: an older tincmgr.exe run elevated leaves a newer
    install alone. Turning run-at-startup on is an explicit choice and may."""
    use_bundle(monkeypatch, make_bundle(tmp_path / "new", "v0.5.0", b"v1"))
    fake = FakeSchtasks()
    monkeypatch.setattr(subprocess, "run", fake)
    assert management.set_startup_task(True, str(tmp_path / "x.exe"))[0]

    use_bundle(monkeypatch, make_bundle(tmp_path / "old", "v0.4.1", b"v0"))
    note = management.refresh_startup_task(str(tmp_path / "x.exe"))
    assert "left the installed copy" in note and "v0.5.0" in note
    assert (fake_windows / "app" / "_internal" / "python312.dll").read_bytes() == b"python v1"
    assert management.installed_version() == "v0.5.0"

    assert management.set_startup_task(True, str(tmp_path / "x.exe"))[0]
    assert management.installed_version() == "v0.4.1"


def test_refresh_does_nothing_without_a_task(tmp_path, monkeypatch, fake_windows):
    use_bundle(monkeypatch, make_bundle(tmp_path / "b", "v0.5.0"))
    fake = FakeSchtasks(command=None)
    monkeypatch.setattr(subprocess, "run", fake)
    assert management.refresh_startup_task(str(tmp_path / "tincmgr.exe")) == ""
    assert not (fake_windows / "app").exists()


