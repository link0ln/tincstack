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
    def __init__(self, tag: str, version: str, zip_url: str, sums_url: str, notes: str) -> None:
        self.tag = tag
        self.version = version
        self.zip_url = zip_url
        self.sums_url = sums_url
        self.notes = notes


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
    assets = {a["name"]: a["browser_download_url"] for a in release.get("assets", [])}
    zips = sorted(n for n in assets if re.fullmatch(r"tincstack-v[\d.]+-windows-x86_64\.zip", n))
    sums = next((n for n in assets if n == "SHA256SUMS"), None)
    if not zips or not sums:
        return None
    return Release(release.get("tag_name", ""), release.get("tag_name", ""),
                   assets[zips[0]], assets[sums], release.get("body", ""))


def check(installed_version: str | None, now: float, last_marker: str | None) -> Release | None:
    """A newer Release, or None (up to date / not due / no Windows assets).

    `last_marker` is the ISO timestamp of the previous check from the marker
    file; a check runs only when it is older than CHECK_MIN_SECS, so the
    three-hour cap holds across restarts, not just within one session.
    Raises nothing: any network failure becomes a None (checked again at the
    next due moment)."""
    if last_marker:
        try:
            from datetime import datetime
            last = datetime.fromisoformat(last_marker).timestamp()
            if now - last < CHECK_MIN_SECS:
                return None
        except ValueError:
            pass
    try:
        data = json.loads(_get(API))
    except Exception:
        return None
    if data.get("draft") or data.get("prerelease"):
        return None
    rel = find_assets(data)
    if rel is None:
        return None
    ours, theirs = parse_version(installed_version or ""), parse_version(rel.version)
    if theirs and (not ours or theirs > ours):
        return rel
    return None


def fetch(rel: Release, workdir: str) -> tuple[str, str]:
    """Download the zip and its SHA256SUMS into workdir; verify; return the
    path of the verified tincmgr.exe (extracted, not yet run). Raises on any
    mismatch — a bad download is never installed."""
    zpath = os.path.join(workdir, rel.tag + "-windows.zip")
    spath = zpath + ".sums"
    with open(zpath, "wb") as f:
        f.write(_get(rel.zip_url, timeout=600))
    with open(spath, "wb") as f:
        f.write(_get(rel.sums_url, timeout=120))

    # SHA256SUMS lines: "<hex>  <name>"
    sums = {}
    for line in open(spath, encoding="utf-8", errors="replace").read().splitlines():
        parts = line.split()
        if len(parts) == 2 and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
            sums[os.path.basename(parts[1])] = parts[0].lower()

    def sha(p: str) -> str:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    if os.path.basename(zpath) not in sums:
        raise ValueError("SHA256SUMS does not list the zip")
    if sha(zpath) != sums[os.path.basename(zpath)]:
        os.unlink(zpath)
        raise ValueError("the downloaded zip does not match its SHA256SUMS")

    with zipfile.ZipFile(zpath) as z:
        names = [n for n in z.namelist() if n == "tincmgr.exe" or n.endswith("/tincmgr.exe")]
        if not names:
            raise ValueError("the zip has no tincmgr.exe")
        z.extract(names[0], workdir)
    exe = os.path.join(workdir, names[0])
    if not os.path.isfile(exe):
        raise ValueError("tincmgr.exe did not extract")
    return exe, zpath


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
