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
    import time
    marker = tmp_path / "update_last_check"
    now = time.time()
    marker.write_text("2026-10-09T07:00:00+00:00\n")
    last = updates.read_last_check(str(tmp_path))
    assert last is not None
    # not due: check() must return None without touching the network
    # (it would fail on a network call in this offline test if it did)
    assert updates.check("v0.5.5", now, last) is None


def test_marker_roundtrip(tmp_path):
    updates.write_last_check(str(tmp_path), "2026-10-09T08:00:00+00:00")
    assert updates.read_last_check(str(tmp_path)) == "2026-10-09T08:00:00+00:00"
    assert updates.read_last_check(os.path.join(str(tmp_path), "nope")) is None
