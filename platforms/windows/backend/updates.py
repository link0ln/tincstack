"""updates.py — check GitHub Releases for a newer tincmgr build.

Policy (owner, 2026-10-09): check at most once every three hours, in the
background; when a newer release exists, surface it in the UI (a banner in
the main window and a tray notification); "Update" downloads the release's
Windows zip, verifies its SHA256SUMS against the release body (the release
job publishes SHA256SUMS as an asset and its sha256 in the body), extracts
tincmgr.exe (the single-file installer), runs it elevated, and it
self-installs via management.install_self() — the exact path the app already
uses to install its own build at startup.

Trust is unchanged: the zip must pass its SHA256SUMS (transport integrity),
and install_self verifies every staged file against the manifest compiled
into the running exe. A release that fails verification is deleted, never
run.

Only stdlib: urllib for HTTPS (GitHub Releases API + asset download), zipfile
for the archive, hashlib for the sums.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import urllib.request
import zipfile

API = "https://api.github.com/repos/link0ln/tincstack/releases/latest"
CHECK_MIN_SECS = 3 * 60 * 60          # the owner's cap: never poll more often
LAST_CHECK = "update_last_check"      # marker file name (in the app's state dir)
USER_AGENT = "tincmgr-update-check"


class Release:
    def __init__(self, tag: str, version: str, zip_url: str, sums_url: str, notes: str,
                 zip_name: str = "", zip_digest: str = "") -> None:
        self.tag = tag
        self.version = version
        self.zip_url = zip_url
        self.sums_url = sums_url
        self.notes = notes
        self.zip_name = zip_name or f"tincstack-{tag}-windows-x86_64.zip"
        self.zip_digest = zip_digest


def _get(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def parse_version(v: str) -> tuple[int, int, int] | None:
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", (v or "").strip())
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def find_assets(release: dict) -> Release | None:
    """The Windows zip + SHA256SUMS of a release, or None when this release
    ships none (e.g. the source-only tags of early 2026)."""
    raw_assets = release.get("assets", []) or []
    assets = {a["name"]: a["browser_download_url"] for a in raw_assets if a.get("name") and a.get("browser_download_url")}
    digests = {a["name"]: str(a.get("digest") or "") for a in raw_assets if a.get("name")}
    zips = sorted(n for n in assets if re.fullmatch(r"tincstack-v[\d.]+-windows-x86_64\.zip", n))
    sums = next((n for n in assets if n == "SHA256SUMS"), None)
    if not zips:
        return None
    zname = zips[0]
    return Release(release.get("tag_name", ""), release.get("tag_name", ""),
                   assets[zname], assets[sums] if sums else "", release.get("body", ""),
                   zip_name=zname, zip_digest=digests.get(zname, ""))


def check_detailed(installed_version: str | None) -> tuple[str, Release | None, str]:
    """Unconditional check against GitHub Releases (used by manual 'Check updates').
    Returns (status, release, detail) where status is 'update', 'up_to_date', or 'error'."""
    try:
        data = json.loads(_get(API))
    except Exception as e:
        return "error", None, str(e)
    if data.get("draft") or data.get("prerelease"):
        return "error", None, "latest release is a draft or prerelease"
    rel = find_assets(data)
    if rel is None:
        return "error", None, f"release {data.get('tag_name', '?')} has no Windows build"
    ours, theirs = parse_version(installed_version or ""), parse_version(rel.version)
    if not theirs:
        return "error", None, f"unrecognized release tag: {rel.version!r}"
    if not ours or theirs > ours:
        return "update", rel, rel.version
    return "up_to_date", None, rel.version


def check(installed_version: str | None, now: float, last_marker: str | None,
          force: bool = False) -> Release | None:
    """A newer Release, or None (up to date / not due / no Windows assets).

    `last_marker` is the ISO timestamp of the previous check from the marker
    file; unless `force=True`, a check runs only when it is older than
    CHECK_MIN_SECS, so the three-hour cap holds across restarts, not just
    within one session.
    Raises nothing: any network failure becomes a None (checked again at the
    next due moment)."""
    if not force and last_marker:
        try:
            from datetime import datetime
            last = datetime.fromisoformat(last_marker).timestamp()
            if now - last < CHECK_MIN_SECS:
                return None
        except ValueError:
            pass
    status, rel, _detail = check_detailed(installed_version)
    return rel if status == "update" else None


def _parse_sums_lines(text: str) -> dict[str, str]:
    sums: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
            sums[os.path.basename(parts[1].lstrip("*"))] = parts[0].lower()
    return sums


def fetch(rel: Release, workdir: str) -> tuple[str, str]:
    """Download the zip (and its SHA256SUMS when present) into workdir; verify;
    return the path of the verified tincmgr.exe (extracted, not yet run). Raises
    on any mismatch — a bad download is never installed."""
    zip_filename = os.path.basename(getattr(rel, "zip_name", "") or f"tincstack-{rel.tag}-windows-x86_64.zip")
    zpath = os.path.join(workdir, zip_filename)
    spath = zpath + ".sums"
    with open(zpath, "wb") as f:
        f.write(_get(rel.zip_url, timeout=600))

    def sha(p: str) -> str:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    if rel.sums_url:
        with open(spath, "wb") as f:
            f.write(_get(rel.sums_url, timeout=120))
        # If the release body pins the SHA256 of SHA256SUMS itself, verify it first.
        notes = getattr(rel, "notes", "") or ""
        m_sums = re.search(r"([0-9a-fA-F]{64})\s+\*?SHA256SUMS\b|SHA256SUMS[^0-9a-fA-F\n]*([0-9a-fA-F]{64})", notes)
        if m_sums:
            expected_sums_sha = (m_sums.group(1) or m_sums.group(2)).lower()
            if sha(spath) != expected_sums_sha:
                os.unlink(zpath)
                os.unlink(spath)
                raise ValueError("SHA256SUMS does not match the digest in release notes")

        with open(spath, encoding="utf-8", errors="replace") as sf:
            sums = _parse_sums_lines(sf.read())

        expected_zip_sha = sums.get(zip_filename) or sums.get(f"{rel.tag}-windows.zip")
        if not expected_zip_sha:
            os.unlink(zpath)
            raise ValueError("SHA256SUMS does not list the zip")
        if sha(zpath) != expected_zip_sha:
            os.unlink(zpath)
            raise ValueError("the downloaded zip does not match its SHA256SUMS")
    elif getattr(rel, "zip_digest", "").lower().startswith("sha256:"):
        expected_zip_sha = rel.zip_digest.split(":", 1)[1].strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", expected_zip_sha) and sha(zpath) != expected_zip_sha:
            os.unlink(zpath)
            raise ValueError("the downloaded zip does not match the release asset SHA-256 digest")

    exe = os.path.join(workdir, "tincmgr.exe")
    inner_exe_sha: str | None = None
    with zipfile.ZipFile(zpath) as z:
        names = [
            n for n in z.namelist()
            if (n == "tincmgr.exe" or n.endswith("/tincmgr.exe"))
            and ".." not in n.replace("\\", "/").split("/")
        ]
        if not names:
            raise ValueError("the zip has no tincmgr.exe")
        sums_names = [
            n for n in z.namelist()
            if (n == "SHA256SUMS" or n.endswith("/SHA256SUMS"))
            and ".." not in n.replace("\\", "/").split("/")
        ]
        if sums_names:
            with z.open(sums_names[0]) as sf:
                inner_sums = _parse_sums_lines(sf.read().decode("utf-8", "replace"))
                inner_exe_sha = inner_sums.get("tincmgr.exe")
        with z.open(names[0]) as src, open(exe, "wb") as dst:
            while True:
                chunk = src.read(1 << 20)
                if not chunk:
                    break
                dst.write(chunk)
    if not os.path.isfile(exe):
        raise ValueError("tincmgr.exe did not extract")
    if inner_exe_sha and sha(exe) != inner_exe_sha:
        os.unlink(exe)
        raise ValueError("extracted tincmgr.exe does not match inner SHA256SUMS")
    if not rel.sums_url and not getattr(rel, "zip_digest", "").lower().startswith("sha256:") and not inner_exe_sha:
        os.unlink(exe)
        raise ValueError("release provides neither SHA256SUMS nor asset digest")
    return exe, zpath


def cleanup_old_workdirs(max_age_secs: float = 120.0) -> None:
    """Remove leftover tincmgr-update-* temp directories from earlier updates."""
    import shutil
    import time
    tmp = tempfile.gettempdir()
    now = time.time()
    try:
        entries = os.listdir(tmp)
    except OSError:
        return
    for name in entries:
        if not name.startswith("tincmgr-update-"):
            continue
        p = os.path.join(tmp, name)
        try:
            if os.path.isdir(p) and (now - os.path.getmtime(p)) >= max_age_secs:
                shutil.rmtree(p, ignore_errors=True)
        except OSError:
            pass


def marker_path(state_dir: str) -> str:
    return os.path.join(state_dir, LAST_CHECK)


def read_last_check(state_dir: str) -> str | None:
    try:
        with open(marker_path(state_dir), encoding="utf-8") as f:
            v = f.read().strip()
            return v or None
    except OSError:
        return None


def write_last_check(state_dir: str, iso: str) -> None:
    try:
        os.makedirs(state_dir, exist_ok=True)
        with open(marker_path(state_dir), "w", encoding="utf-8") as f:
            f.write(iso + "\n")
    except OSError:
        pass  # a missed marker only means one extra check after the next start
