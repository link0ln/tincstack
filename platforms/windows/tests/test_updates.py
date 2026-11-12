"""updates.py: version comparison and asset discovery, without the network."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for p in (ROOT, os.path.join(ROOT, "backend")):
    if p not in sys.path:
        sys.path.insert(0, p)

import updates


def release(tag, with_windows=True):
    assets = []
    if with_windows:
        assets = [
            {"name": f"tincstack-{tag}-windows-x86_64.zip", "browser_download_url": f"https://x/{tag}.zip"},
            {"name": "SHA256SUMS", "browser_download_url": "https://x/SHA256SUMS"},
            {"name": f"tincstack-{tag}.apk", "browser_download_url": f"https://x/{tag}.apk"},
        ]
    return {"tag_name": tag, "draft": False, "prerelease": False, "body": "notes", "assets": assets}


def test_parse_version():
    assert updates.parse_version("v0.5.6") == (0, 5, 6)
    assert updates.parse_version("0.10.2") == (0, 10, 2)
    assert updates.parse_version("dev") is None
    assert updates.parse_version("") is None


def test_find_assets_picks_the_windows_zip_and_sums():
    rel = updates.find_assets(release("v0.5.6"))
    assert rel is not None
    assert rel.version == "v0.5.6"
    assert rel.zip_url.endswith(".zip")
    assert rel.sums_url.endswith("SHA256SUMS")


def test_find_assets_skips_a_release_without_windows_files():
    assert updates.find_assets(release("v0.1.0", with_windows=False)) is None


def test_check_compares_against_the_installed_version():
    rel = updates.find_assets(release("v0.5.6"))
    ours = "v0.5.5"
    o, t = updates.parse_version(ours), updates.parse_version(rel.version)
    assert t > o
    assert not (updates.parse_version("v0.5.6") > t)


def test_three_hour_cap_holds_across_restarts(tmp_path, monkeypatch):
    from datetime import datetime
    marker = tmp_path / "update_last_check"
    marker.write_text("2026-10-09T07:00:00+00:00\n")
    now = datetime.fromisoformat("2026-10-09T08:00:00+00:00").timestamp()
    last = updates.read_last_check(str(tmp_path))
    assert last is not None
    monkeypatch.setattr(updates, "_get", lambda *a, **k: (_ for _ in ()).throw(AssertionError("touched network")))
    # not due: check() must return None without touching the network
    assert updates.check("v0.5.5", now, last) is None


def test_marker_roundtrip(tmp_path):
    updates.write_last_check(str(tmp_path), "2026-10-09T08:00:00+00:00")
    assert updates.read_last_check(str(tmp_path)) == "2026-10-09T08:00:00+00:00"
    assert updates.read_last_check(os.path.join(str(tmp_path), "nope")) is None


def test_force_check_bypasses_three_hour_cap(monkeypatch):
    import json
    import time
    monkeypatch.setattr(updates, "_get", lambda url, timeout=30: json.dumps(release("v0.5.6")).encode("utf-8"))
    now = time.time()
    recent = "2099-01-01T00:00:00+00:00"
    assert updates.check("v0.5.5", now, recent, force=False) is None
    rel = updates.check("v0.5.5", now, recent, force=True)
    assert rel is not None and rel.version == "v0.5.6"


def test_check_detailed_reports_update_and_up_to_date(monkeypatch):
    import json
    monkeypatch.setattr(updates, "_get", lambda url, timeout=30: json.dumps(release("v0.5.6")).encode("utf-8"))
    status, rel, detail = updates.check_detailed("v0.5.5")
    assert status == "update" and rel is not None and detail == "v0.5.6"
    status2, rel2, detail2 = updates.check_detailed("v0.5.6")
    assert status2 == "up_to_date" and rel2 is None and detail2 == "v0.5.6"


def test_find_assets_accepts_release_with_asset_digest_without_sums_file():
    rel_data = {
        "tag_name": "v0.5.13",
        "draft": False,
        "prerelease": False,
        "body": "notes",
        "assets": [
            {
                "name": "tincstack-v0.5.13-windows-x86_64.zip",
                "browser_download_url": "https://x/v0.5.13.zip",
                "digest": "sha256:" + ("a" * 64),
            }
        ],
    }
    rel = updates.find_assets(rel_data)
    assert rel is not None
    assert rel.version == "v0.5.13"
    assert rel.sums_url == ""
    assert rel.zip_digest == "sha256:" + ("a" * 64)


def test_fetch_streams_with_progress_and_verifies_checksums(tmp_path, monkeypatch):
    import hashlib
    import io
    import zipfile

    exe_payload = b"MZ-fake-tincmgr-exe-" * 4096
    exe_sha = hashlib.sha256(exe_payload).hexdigest()
    inner_sums = f"{exe_sha}  ./tincmgr.exe\n".encode("utf-8")

    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("tincmgr.exe", exe_payload)
        zf.writestr("SHA256SUMS", inner_sums)
    zip_bytes = zbuf.getvalue()
    zip_sha = hashlib.sha256(zip_bytes).hexdigest()

    zip_name = "tincstack-v0.5.40-windows-x86_64.zip"
    sums_bytes = f"{zip_sha}  {zip_name}\n".encode("utf-8")
    sums_sha = hashlib.sha256(sums_bytes).hexdigest()
    notes = f"## Checksums\n\nSHA256SUMS: {sums_sha}\n"

    rel = updates.Release(
        "v0.5.40",
        "v0.5.40",
        f"https://example.invalid/{zip_name}",
        "https://example.invalid/SHA256SUMS",
        notes,
        zip_name=zip_name,
    )

    class FakeResp:
        def __init__(self, data: bytes, status: int = 200, total_len: int | None = None):
            self._bio = io.BytesIO(data)
            self.status = status
            self.headers = {"Content-Length": str(len(data) if total_len is None else total_len)}

        def getcode(self):
            return self.status

        def read(self, n: int = -1) -> bytes:
            return self._bio.read(n)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    calls = []

    def fake_urlopen(req, timeout=25):
        url = req.full_url
        rng = req.get_header("Range")
        calls.append((url, rng))
        if url.endswith("SHA256SUMS"):
            return FakeResp(sums_bytes)
        # First attempt returns only the first half to simulate a dropped connection,
        # second attempt resumes with HTTP 206 Partial Content!
        half = len(zip_bytes) // 2
        if rng is None:
            return FakeResp(zip_bytes[:half], status=200, total_len=len(zip_bytes))
        assert rng == f"bytes={half}-"
        return FakeResp(zip_bytes[half:], status=206, total_len=len(zip_bytes) - half)

    monkeypatch.setattr(updates.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(updates.time, "sleep", lambda _s: None)

    events = []
    exe_path, zpath = updates.fetch(rel, str(tmp_path), progress_cb=lambda r, t, s: events.append((r, t, s)))
    assert os.path.isfile(exe_path)
    assert open(exe_path, "rb").read() == exe_payload
    assert any("Downloading v0.5.40" in s for _, _, s in events)
    assert any(r == len(zip_bytes) and t == len(zip_bytes) for r, t, _ in events)
    # Verify that resume with Range header was used on the retry
    assert (f"https://example.invalid/{zip_name}", f"bytes={len(zip_bytes) // 2}-") in calls


def test_fetch_fails_fast_on_404_with_clear_message(tmp_path, monkeypatch):
    import email.message
    import urllib.error
    import pytest

    rel = updates.Release(
        "v0.5.40",
        "v0.5.40",
        "https://example.invalid/tincstack-v0.5.40-windows-x86_64.zip",
        "https://example.invalid/SHA256SUMS",
        "notes",
    )
    attempts = []

    def fake_urlopen(req, timeout=25):
        attempts.append(req.full_url)
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", email.message.Message(), None)

    monkeypatch.setattr(updates.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(OSError, match="HTTP 404"):
        updates.fetch(rel, str(tmp_path))
    # 404 must not retry 3 times
    assert len(attempts) == 1


def test_clean_pyinstaller_env_resets_meipass2(monkeypatch):
    import management
    monkeypatch.setenv("_MEIPASS2", r"C:\Users\u\AppData\Local\Temp\_MEI12345")
    env = management._clean_pyinstaller_env()
    assert "_MEIPASS2" not in env
    assert env.get("PYINSTALLER_RESET_ENVIRONMENT") == "1"


def test_create_staging_dir_and_verify_staged_exe_rejects_tampering(tmp_path):
    """WL-02: update staging uses a private staging directory outside %TEMP%,
    and verify_staged_exe detects any post-extraction modification or symlink."""
    import hashlib
    import stat

    staging = updates.create_staging_dir(str(tmp_path), elevated=False)
    assert os.path.isdir(staging)
    assert os.path.abspath(staging).startswith(os.path.abspath(str(tmp_path)))
    if sys.platform != "win32":
        assert stat.S_IMODE(os.stat(staging).st_mode) == 0o700

    exe = os.path.join(staging, "tincmgr.exe")
    payload = b"MZ-authentic-binary"
    digest = hashlib.sha256(payload).hexdigest()
    with open(exe, "wb") as f:
        f.write(payload)

    assert updates.verify_staged_exe(exe, digest) is True
    # Tamper with staged binary -> verification must fail
    with open(exe, "wb") as f:
        f.write(b"MZ-tampered-binary")
    assert updates.verify_staged_exe(exe, digest) is False


def test_fetch_verifies_both_sums_url_and_zip_digest(tmp_path, monkeypatch):
    """M-WIN-01: when BOTH sums_url and rel.zip_digest are present, fetch() must
    verify BOTH and refuse a mismatch in either one."""
    import hashlib
    import io
    import zipfile
    import pytest

    exe_payload = b"MZ-real-exe"
    exe_sha = hashlib.sha256(exe_payload).hexdigest()
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("tincmgr.exe", exe_payload)
        zf.writestr("SHA256SUMS", f"{exe_sha}  tincmgr.exe\n".encode("utf-8"))
    zip_bytes = zbuf.getvalue()
    zip_sha = hashlib.sha256(zip_bytes).hexdigest()
    zip_name = "tincstack-v0.6.0-windows-x86_64.zip"
    sums_bytes = f"{zip_sha}  {zip_name}\n".encode("utf-8")

    class FakeResp:
        def __init__(self, data: bytes):
            self._bio = io.BytesIO(data)
            self.status = 200
            self.headers = {"Content-Length": str(len(data))}

        def getcode(self):
            return 200

        def read(self, n: int = -1) -> bytes:
            return self._bio.read(n)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    monkeypatch.setattr(
        updates.urllib.request,
        "urlopen",
        lambda req, timeout=25: FakeResp(sums_bytes if req.full_url.endswith("SHA256SUMS") else zip_bytes),
    )

    # Matching sums_url, but tampered/mismatched zip_digest -> must fail!
    bad_dir = tmp_path / "bad"
    bad_dir.mkdir()
    bad_rel = updates.Release(
        "v0.6.0", "v0.6.0", f"https://x/{zip_name}", "https://x/SHA256SUMS", "",
        zip_name=zip_name, zip_digest="sha256:" + ("f" * 64),
    )
    with pytest.raises((OSError, ValueError), match="digest"):
        updates.fetch(bad_rel, str(bad_dir))

    # Both sums_url and zip_digest match -> succeeds!
    good_dir = tmp_path / "good"
    good_dir.mkdir()
    good_rel = updates.Release(
        "v0.6.0", "v0.6.0", f"https://x/{zip_name}", "https://x/SHA256SUMS", "",
        zip_name=zip_name, zip_digest="sha256:" + zip_sha,
    )
    exe_out, _ = updates.fetch(good_rel, str(good_dir))
    assert os.path.isfile(exe_out)



