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

