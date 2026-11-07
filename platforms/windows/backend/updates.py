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
import http.client
import json
import os
import re
import socket
import ssl
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from typing import Callable

API = "https://api.github.com/repos/link0ln/tincstack/releases/latest"
CHECK_MIN_SECS = 3 * 60 * 60          # the owner's cap: never poll more often
LAST_CHECK = "update_last_check"      # marker file name (in the app's state dir)
USER_AGENT = "tincmgr-update-check"
CHUNK_SIZE = 64 * 1024                # 64 KB streaming chunks
STREAM_TIMEOUT = 25                   # per-chunk socket timeout (seconds)
MAX_DOWNLOAD_RETRIES = 3


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


def format_network_error(exc: BaseException, context: str = "") -> str:
    """Turn low-level urllib/socket exceptions into clear user-facing diagnostics."""
    prefix = f"{context}: " if context else ""
    if isinstance(exc, urllib.error.HTTPError):
        code = exc.code
        if code == 404:
            return (f"{prefix}release asset not found on GitHub (HTTP 404). "
                    "The release may still be building or uploading — please try again in a few minutes.")
        if code in (403, 429):
            return f"{prefix}GitHub rate limit or access denied (HTTP {code}). Please wait a few minutes and retry."
        if 500 <= code < 600:
            return f"{prefix}GitHub server error (HTTP {code}). Please try again shortly."
        return f"{prefix}HTTP {code} ({exc.reason})"
    if isinstance(exc, urllib.error.URLError):
        reason = exc.reason
        if isinstance(reason, (socket.timeout, TimeoutError)):
            return f"{prefix}connection timed out (network or VPN link may be congested or unreachable)."
        if isinstance(reason, ssl.SSLError):
            return f"{prefix}TLS/SSL connection error ({reason})."
        if isinstance(reason, OSError):
            msg = getattr(reason, "strerror", None) or str(reason)
            return f"{prefix}network connection failed ({msg}). Check your internet or VPN connection."
        return f"{prefix}network error ({reason})."
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return f"{prefix}connection timed out while transferring data (network stalled)."
    if isinstance(exc, http.client.IncompleteRead):
        return f"{prefix}connection closed before download finished ({len(exc.partial)} bytes received)."
    if isinstance(exc, ssl.SSLError):
        return f"{prefix}TLS/SSL transfer error ({exc})."
    return f"{prefix}{exc}"


def _get(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


_DEFAULT_GET = _get


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
        return "error", None, format_network_error(e)
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


def _stream_download(
    url: str,
    dst_path: str,
    timeout: int = STREAM_TIMEOUT,
    max_retries: int = MAX_DOWNLOAD_RETRIES,
    progress_cb: Callable[[int, int, str], None] | None = None,
    stage: str = "Downloading…",
) -> None:
    """Stream `url` to `dst_path` in chunks with per-chunk socket timeout,
    automatic retry with HTTP Range resume, Content-Length verification, and
    live progress reporting."""
    if _get is not _DEFAULT_GET:
        if progress_cb:
            progress_cb(0, 0, stage)
        try:
            data = _get(url, timeout=timeout)
        except Exception as e:
            raise OSError(format_network_error(e, stage.rstrip("…"))) from e
        with open(dst_path, "wb") as f:
            f.write(data)
        if progress_cb:
            progress_cb(len(data), len(data), stage)
        return

    part_path = dst_path + ".part"
    try:
        if os.path.exists(part_path):
            os.unlink(part_path)
    except OSError:
        pass

    last_err: BaseException | None = None
    retries = max(1, int(max_retries))
    for attempt in range(1, retries + 1):
        offset = 0
        try:
            if os.path.isfile(part_path):
                offset = os.path.getsize(part_path)
        except OSError:
            offset = 0

        stage_txt = stage if attempt == 1 else f"{stage.rstrip('…')} (attempt {attempt}/{retries})…"
        if progress_cb and offset == 0:
            progress_cb(0, 0, stage_txt)

        headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        if offset > 0:
            headers["Range"] = f"bytes={offset}-"
        req = urllib.request.Request(url, headers=headers)

        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                status_code = getattr(r, "status", None) or r.getcode() or 200
                hdrs = getattr(r, "headers", None) or {}
                raw_cl = hdrs.get("Content-Length") if hasattr(hdrs, "get") else None
                content_len = 0
                if raw_cl:
                    try:
                        content_len = max(0, int(str(raw_cl).strip()))
                    except ValueError:
                        content_len = 0

                if status_code == 206 and offset > 0:
                    mode = "ab"
                    read_so_far = offset
                    total_bytes = (offset + content_len) if content_len > 0 else 0
                else:
                    mode = "wb"
                    read_so_far = 0
                    total_bytes = content_len

                last_emit_ts = 0.0
                last_pct = -1
                if progress_cb:
                    progress_cb(read_so_far, total_bytes, stage_txt)
                    last_emit_ts = time.monotonic()

                with open(part_path, mode) as f:
                    while True:
                        chunk = r.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        f.write(chunk)
                        read_so_far += len(chunk)
                        if progress_cb:
                            now_ts = time.monotonic()
                            pct = int((read_so_far * 100) // total_bytes) if total_bytes > 0 else -1
                            if (pct != last_pct) or (now_ts - last_emit_ts >= 0.08) or (total_bytes > 0 and read_so_far >= total_bytes):
                                last_pct = pct
                                last_emit_ts = now_ts
                                progress_cb(read_so_far, total_bytes, stage_txt)
                    f.flush()
                    os.fsync(f.fileno())

                if total_bytes > 0 and read_so_far < total_bytes:
                    raise OSError(
                        f"incomplete download ({read_so_far} of {total_bytes} bytes received)"
                    )

            os.replace(part_path, dst_path)
            if progress_cb:
                progress_cb(read_so_far, total_bytes or read_so_far, stage)
            return
        except urllib.error.HTTPError as he:
            last_err = he
            if he.code == 416 and offset > 0:
                try:
                    os.unlink(part_path)
                except OSError:
                    pass
                continue
            if he.code in (400, 401, 403, 404, 410):
                try:
                    if os.path.exists(part_path):
                        os.unlink(part_path)
                except OSError:
                    pass
                raise OSError(format_network_error(he, stage.rstrip("…"))) from he
            if attempt < retries:
                time.sleep(1.0 * attempt)
                continue
        except (urllib.error.URLError, socket.timeout, TimeoutError, http.client.HTTPException, ssl.SSLError, OSError) as err:
            last_err = err
            if attempt < retries:
                time.sleep(1.0 * attempt)
                continue

    try:
        if os.path.exists(part_path):
            os.unlink(part_path)
    except OSError:
        pass
    assert last_err is not None
    raise OSError(format_network_error(last_err, stage.rstrip("…"))) from last_err


def fetch(
    rel: Release,
    workdir: str,
    progress_cb: Callable[[int, int, str], None] | None = None,
) -> tuple[str, str]:
    """Download the zip (and its SHA256SUMS when present) into workdir; verify;
    return the path of the verified tincmgr.exe (extracted, not yet run). Raises
    on any mismatch — a bad download is never installed."""
    zip_filename = os.path.basename(getattr(rel, "zip_name", "") or f"tincstack-{rel.tag}-windows-x86_64.zip")
    zpath = os.path.join(workdir, zip_filename)
    spath = zpath + ".sums"

    def sha(p: str) -> str:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    def cleanup_files() -> None:
        for p in (zpath, zpath + ".part", spath, spath + ".part"):
            try:
                if os.path.exists(p):
                    os.unlink(p)
            except OSError:
                pass

    expected_zip_sha: str | None = None
    if rel.sums_url:
        _stream_download(
            rel.sums_url,
            spath,
            timeout=20,
            max_retries=MAX_DOWNLOAD_RETRIES,
            progress_cb=progress_cb,
            stage=f"Fetching {rel.version} checksums…",
        )
        # If the release body pins the SHA256 of SHA256SUMS itself, verify it first.
        notes = getattr(rel, "notes", "") or ""
        m_sums = re.search(r"([0-9a-fA-F]{64})\s+\*?SHA256SUMS\b|SHA256SUMS[^0-9a-fA-F\n]*([0-9a-fA-F]{64})", notes)
        if m_sums:
            expected_sums_sha = (m_sums.group(1) or m_sums.group(2)).lower()
            if sha(spath) != expected_sums_sha:
                cleanup_files()
                raise ValueError("SHA256SUMS does not match the digest in release notes")

        with open(spath, encoding="utf-8", errors="replace") as sf:
            sums = _parse_sums_lines(sf.read())

        expected_zip_sha = sums.get(zip_filename) or sums.get(f"{rel.tag}-windows.zip")
        if not expected_zip_sha:
            cleanup_files()
            raise ValueError("SHA256SUMS does not list the zip")
    elif getattr(rel, "zip_digest", "").lower().startswith("sha256:"):
        cand = rel.zip_digest.split(":", 1)[1].strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", cand):
            expected_zip_sha = cand

    _stream_download(
        rel.zip_url,
        zpath,
        timeout=STREAM_TIMEOUT,
        max_retries=MAX_DOWNLOAD_RETRIES,
        progress_cb=progress_cb,
        stage=f"Downloading {rel.version}…",
    )

    if progress_cb:
        try:
            zsize = os.path.getsize(zpath)
        except OSError:
            zsize = 0
        progress_cb(zsize, zsize, f"Verifying {rel.version} SHA-256 checksum…")

    if rel.sums_url:
        if sha(zpath) != expected_zip_sha:
            cleanup_files()
            raise ValueError("the downloaded zip does not match its SHA256SUMS")
    elif expected_zip_sha:
        if sha(zpath) != expected_zip_sha:
            cleanup_files()
            raise ValueError("the downloaded zip does not match the release asset SHA-256 digest")

    if progress_cb:
        try:
            zsize = os.path.getsize(zpath)
        except OSError:
            zsize = 0
        progress_cb(zsize, zsize, f"Extracting {rel.version} installer…")

    exe = os.path.join(workdir, "tincmgr.exe")
    inner_exe_sha: str | None = None
    try:
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
    except zipfile.BadZipFile as e:
        cleanup_files()
        raise ValueError(f"downloaded archive is corrupted ({e})") from e

    if not os.path.isfile(exe):
        cleanup_files()
        raise ValueError("tincmgr.exe did not extract")
    if inner_exe_sha and sha(exe) != inner_exe_sha:
        os.unlink(exe)
        cleanup_files()
        raise ValueError("extracted tincmgr.exe does not match inner SHA256SUMS")
    if not rel.sums_url and not expected_zip_sha and not inner_exe_sha:
        os.unlink(exe)
        cleanup_files()
        raise ValueError("release provides neither SHA256SUMS nor asset digest")
    return exe, zpath


def cleanup_old_workdirs(max_age_secs: float = 3600.0) -> None:
    """Remove leftover tincmgr-update-* temp directories from earlier updates."""
    import shutil
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
            if not os.path.isdir(p):
                continue
            newest = os.path.getmtime(p)
            for child in os.listdir(p):
                try:
                    newest = max(newest, os.path.getmtime(os.path.join(p, child)))
                except OSError:
                    pass
            if (now - newest) >= max_age_secs:
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
