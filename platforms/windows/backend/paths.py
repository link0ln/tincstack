"""
paths.py — locate the tincstack core binaries and resolve config / work dirs.

The whole point of this app is "drop two files (the .exe and a .yaml) anywhere,
run, and the VPNs come up". So binary resolution works in these modes:

  * override — $TINCSTACK_BIN_DIR names a directory holding tincd/tinc
               (used by tests and by the Linux CLI against a core build).
  * frozen   — PyInstaller: tincd.exe / tinc.exe / wintun.dll are in
               sys._MEIPASS -- the onefile's unpack dir in %TEMP%, or the
               onedir's own _internal\\ -- and the .exe is sys.executable.
  * source   — running main.py from a checkout: binaries live in
               platforms/windows/resources/, populated by
               `platforms/windows/build-core-win.sh` from the core cross-build
               (core/Dockerfile.build-win). That directory is gitignored.
  * PATH     — on non-Windows hosts, fall back to `tincd`/`tinc` on $PATH
               (the Linux path of cli.py used to be broken because only the
               Windows binaries were looked for).

Trust (review 2026-09-22, local privilege escalation): the app runs elevated,
and everything it used to read from -- next to the exe, the working directory,
%LOCALAPPDATA% -- an unelevated process of the same user can rewrite. So an
elevated app on Windows keeps what it executes and what it obeys under
protected_dir() (%ProgramFiles%\\tincmgr), which only Administrators and SYSTEM
may write: the staged core binaries (bin\\), the autostart copy of the exe, and
the config. A config found in the old places is imported once (adopt_config).

The elevated app itself is never the onefile the user downloaded: that one
unpacks python3*.dll and Qt into %TEMP%\\_MEIxxxx, which the user's unelevated
processes can write to, and the logon task would start it with no prompt at
every logon. What the task runs is a PyInstaller onedir tree installed under
%ProgramFiles%\\tincmgr\\app (bundle(), management.install_self()), which loads
everything from where it lies and unpacks nothing.

Apart from stage_file(), stage_verified(), write_private(), mkdir_private() and
adopt_config(), nothing here writes anything; callers create the runtime dirs (runtime.py).
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import sys

APP_NAME = "tincmgr"
CONFIG_BASENAMES = ("tinc.yaml", "tinc.yml", "tincmgr.yaml")
BIN_DIR_ENV = "TINCSTACK_BIN_DIR"

_EXE = ".exe" if sys.platform == "win32" else ""


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def is_elevated() -> bool:
    """True when running with an elevated Administrator token on Windows."""
    if sys.platform != "win32":
        return False
    try:
        return _token_identity()[0]
    except Exception:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False


def untrusted_env() -> bool:
    """True when environment variables may have been inherited across UAC from an
    unprivileged caller (frozen Windows build or elevated Windows token)."""
    return is_frozen() or (sys.platform == "win32" and is_elevated())


def resource_dir() -> str:
    """Directory that holds tincd / tinc / wintun.dll (see module docstring)."""
    if not untrusted_env():
        override = os.environ.get(BIN_DIR_ENV)
        if override:
            return override
    if is_frozen():
        # onefile: extracted to _MEIPASS; onedir: next to the exe
        return getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "resources")


def app_dir() -> str:
    """Directory the executable (or main.py) lives in — where we look for the
    YAML and, by default, place the runtime data folder."""
    if is_frozen():
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _binary(name: str) -> str:
    """Resolve one core binary: resource dir first, then (non-Windows) $PATH.
    Always returns a path; `os.path.isfile()` tells the caller if it exists."""
    cand = os.path.join(resource_dir(), name + _EXE)
    if os.path.isfile(cand):
        return cand
    if sys.platform != "win32":
        found = shutil.which(name)
        if found:
            return found
    return cand


def tincd_exe() -> str:
    return _binary("tincd")


def tinc_exe() -> str:
    return _binary("tinc")


def wintun_dll() -> str:
    return os.path.join(resource_dir(), "wintun.dll")


def binaries_present() -> tuple[bool, str]:
    """(ok, human message) — whether both core binaries resolve."""
    missing = [p for p in (tincd_exe(), tinc_exe()) if not os.path.isfile(p)]
    if not missing:
        return True, f"core binaries: {os.path.dirname(tincd_exe())}"
    return False, ("core binaries missing: " + ", ".join(missing)
                   + f" — run platforms/windows/build-core-win.sh or set ${BIN_DIR_ENV}")


def _writable(d: str) -> bool:
    try:
        os.makedirs(d, exist_ok=True)
        probe = os.path.join(d, ".w")
        with open(probe, "w") as f:
            f.write("")
        os.remove(probe)
        return True
    except OSError:
        return False


def local_appdata_dir() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, APP_NAME)


def find_config(explicit: str | None = None) -> str | None:
    """Locate the YAML config. Order: explicit arg → next to the exe → cwd →
    %LOCALAPPDATA%\\tincmgr. Returns a path that exists, else None."""
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    for base in (app_dir(), os.getcwd(), local_appdata_dir()):
        for name in CONFIG_BASENAMES:
            p = os.path.join(base, name)
            if os.path.isfile(p):
                return p
    return None


def default_config_path() -> str:
    """Where to create a config if none exists (next to the exe if writable,
    else %LOCALAPPDATA%)."""
    if _writable(app_dir()):
        return os.path.join(app_dir(), CONFIG_BASENAMES[0])
    return os.path.join(local_appdata_dir(), CONFIG_BASENAMES[0])


# -- the admin-only folder (Windows, elevated) ---------------------------------

_CSIDL_PROGRAM_FILES = 0x0026


def _program_files() -> str:
    """%ProgramFiles% from the shell, not from the environment: an elevated
    process inherits its environment from whoever launched it, so the variable
    is exactly as trustworthy as the folders this is meant to avoid."""
    import ctypes
    buf = ctypes.create_unicode_buffer(260)
    rc = ctypes.windll.shell32.SHGetFolderPathW(None, _CSIDL_PROGRAM_FILES, None, 0, buf)  # type: ignore[attr-defined]
    if rc != 0 or not buf.value:
        raise OSError(f"SHGetFolderPathW(CSIDL_PROGRAM_FILES) failed: {rc:#x}")
    return buf.value


def protected_dir() -> str | None:
    """Windows: %ProgramFiles%\\tincmgr. Program Files lets only Administrators
    and SYSTEM create or change anything, so an unelevated process cannot plant
    a file there before or after us -- which %ProgramData% (users may create
    files there) and %LOCALAPPDATA% cannot promise. None elsewhere, or if the
    folder cannot be resolved."""
    if sys.platform != "win32":
        return None
    try:
        return os.path.join(_program_files(), APP_NAME)
    except (OSError, AttributeError):
        return None


def elevated_config_path() -> str | None:
    """Config path inside %ProgramFiles%\\tincmgr for elevated Windows processes."""
    prot = protected_dir()
    return os.path.join(prot, CONFIG_BASENAMES[0]) if prot else None


def _under_protected_dir(path: str) -> bool:
    """True when `path` is equal to or nested inside `protected_dir()`."""
    prot = protected_dir()
    if not prot or not path:
        return False
    p = os.path.normcase(os.path.abspath(path))
    d = os.path.normcase(os.path.abspath(prot)).rstrip("\\/")
    return p == d or p.startswith(d + os.sep)


def is_reparse_point(path: str) -> bool:
    """True when `path` is a symlink, junction, or Win32 reparse point."""
    if not path:
        return False
    try:
        if os.path.islink(path):
            return True
    except OSError:
        pass
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
            k32.GetFileAttributesW.restype = wintypes.DWORD
            attrs = k32.GetFileAttributesW(path)
            if attrs != 0xFFFFFFFF and (attrs & 0x400):  # FILE_ATTRIBUTE_REPARSE_POINT
                return True
        except Exception:
            pass
    return False


def reject_reparse_point(path: str) -> None:
    """Raise OSError if `path` (or on Windows any existing parent directory above
    the drive root) is a symlink / junction / reparse point."""
    if not path:
        return
    if is_reparse_point(path):
        raise OSError(f"refusing symlink or reparse point: {path}")
    if sys.platform == "win32":
        cur = os.path.abspath(path)
        while True:
            parent = os.path.dirname(cur)
            if not parent or parent == cur:
                break
            _drive, tail = os.path.splitdrive(parent)
            if tail in ("\\", "/", ""):
                break
            if os.path.exists(parent) and is_reparse_point(parent):
                raise OSError(f"refusing reparse-point ancestor {parent} for {path}")
            cur = parent


def bin_stage_dir(elevated: bool) -> str:
    """Where the core binaries are staged and run from: the protected folder
    when elevated (an elevated tincd must not be replaceable by the user), else
    %LOCALAPPDATA%\\tincmgr\\bin as before (nothing elevated runs it)."""
    prot = protected_dir() if elevated else None
    return os.path.join(prot or local_appdata_dir(), "bin")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def stage_file(src: str, dst: str) -> bool:
    """Make dst a copy of src; True if it had to be written. Compared by
    SHA-256, not size: PE files are section-aligned, and two different builds
    of tincd.exe measured 1816078 bytes each, so a size check staged nothing on
    an upgrade and kept running the old daemon. src is read once and the bytes
    that were hashed are the bytes written, so swapping src between the check
    and the copy changes nothing. Written to dst.new and renamed into place:
    a failed copy never leaves a truncated binary behind."""
    reject_reparse_point(src)
    reject_reparse_point(dst)
    with open(src, "rb") as f:
        data = f.read()
    src_sha = hashlib.sha256(data).hexdigest()
    if os.path.isfile(dst):
        try:
            if sha256_file(dst) == src_sha:
                return False
        except OSError:
            pass
    os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
    tmp = dst + ".new"
    reject_reparse_point(tmp)
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, dst)
    return True


class IntegrityError(OSError):
    """A file does not match the manifest compiled into this build."""


def stage_verified(src: str, dst: str, sha256: str) -> bool:
    """stage_file() for a file whose content is known in advance: src is read
    once, and unless those bytes hash to `sha256` nothing is written and
    OSError is raised. For copying out of a directory an unelevated process
    can write to (a onefile's %TEMP%\\_MEIxxxx) into one it cannot: what is
    checked is exactly what is written, so swapping src at any moment either
    fails the check or changes nothing. True if dst had to be written."""
    reject_reparse_point(dst)
    with open(src, "rb") as f:
        data = f.read()
    if hashlib.sha256(data).hexdigest() != sha256:
        raise IntegrityError(f"{src} does not match this build's manifest; not copied")
    if os.path.isfile(dst):
        try:
            if sha256_file(dst) == sha256:
                return False
        except OSError:
            pass
    os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
    tmp = dst + ".new"
    reject_reparse_point(tmp)
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, dst)
    return True


# -- the installable build ------------------------------------------------------

class Bundle:
    """What this build can install: a PyInstaller onedir tree (Program Files
    runs it, and a onedir never unpacks anything), listed by the manifest the
    spec generated at build time. `files` maps each path of the onedir tree
    ("tincmgr.exe", "_internal/python312.dll", ...) to (sha256, path relative
    to `root` where this build carries it)."""

    def __init__(self, version: str, files: dict[str, tuple[str, str]], root: str) -> None:
        self.version = version
        self.files = files
        self.root = root

    def manifest_text(self) -> str:
        """The record written next to the installed copy; equal text means the
        installed tree is this build's."""
        lines = [f"version {self.version}"]
        lines += [f"{sha} {rel}" for rel, (sha, _src) in sorted(self.files.items())]
        return "\n".join(lines) + "\n"


def bundle() -> Bundle | None:
    """The installable build, or None (running from source, from the onedir
    itself, or a build without a manifest). The manifest is a Python module
    compiled into the onefile's PYZ -- read from the exe, not unpacked to
    %TEMP% like the files it describes -- and main imports it at start, before
    anything else could have swapped the exe."""
    if not is_frozen():
        return None
    try:
        import tincmgr_bundle  # type: ignore[import-not-found]  # generated by tincmgr.spec
    except ImportError:
        return None
    root = getattr(sys, "_MEIPASS", None)
    if not root:
        return None
    return Bundle(tincmgr_bundle.VERSION, dict(tincmgr_bundle.FILES), root)


def version_key(v: str | None) -> tuple[int, int, int] | None:
    """'v0.4.1' / '0.4.1' -> (0, 4, 1); None for anything else (a dev build,
    an install made before versions were recorded)."""
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", (v or "").strip())
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


# -- private files (the config holds private keys and API tokens) -------------------

def private_sddl(elevated: bool, user_sid: str | None) -> str:
    """The security descriptor a config is created with on Windows -- the same
    one the core writes it with (yamlconf.c private_sd()). Protected (P), so
    nothing is inherited: Program Files would hand Users read access to the
    tls_key, acme_account and CloudflareToken in it. SYSTEM and Administrators,
    plus the user only when not elevated: an elevated admin's token carries the
    same user SID as that user's unelevated processes, so an ACE for it (or
    ownership by it, which implies WRITE_DAC) would give every one of those
    processes the keys and the config the elevated app obeys."""
    base = "(A;;FA;;;SY)(A;;FA;;;BA)"
    if elevated:
        return "O:BAD:P" + base
    if not user_sid or not re.fullmatch(r"S-1(-\d+)+", user_sid):
        raise OSError(f"no usable user SID ({user_sid!r}) for a private file")
    return f"D:P{base}(A;;FA;;;{user_sid})"


def private_dir_sddl(elevated: bool, user_sid: str | None) -> str:
    """Protected directory SDDL with OICI inheritance so files created inside by
    child processes (such as tincd's `pid` file containing `controlcookie`, or
    rotated logs) inherit only SYSTEM + Administrators access when elevated."""
    base = "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    if elevated:
        return "O:BAD:P" + base
    if not user_sid or not re.fullmatch(r"S-1(-\d+)+", user_sid):
        raise OSError(f"no usable user SID ({user_sid!r}) for a private directory")
    return f"D:P{base}(A;OICI;FA;;;{user_sid})"


def _token_identity() -> tuple[bool, str | None]:
    """(elevated, user SID string) of this process's token."""
    import ctypes
    from ctypes import wintypes
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                             wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    token_query, token_user, token_elevation = 0x0008, 1, 20

    tok = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), token_query, ctypes.byref(tok)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        elev, n = wintypes.DWORD(0), wintypes.DWORD(0)
        elevated = bool(advapi32.GetTokenInformation(tok, token_elevation, ctypes.byref(elev),
                                                     ctypes.sizeof(elev), ctypes.byref(n))) and bool(elev.value)
        advapi32.GetTokenInformation(tok, token_user, None, 0, ctypes.byref(n))
        buf = ctypes.create_string_buffer(max(n.value, 1))
        if not advapi32.GetTokenInformation(tok, token_user, buf, n, ctypes.byref(n)):
            return elevated, None
        psid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]   # TOKEN_USER.User.Sid
        s = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(psid, ctypes.byref(s)):
            return elevated, None
        try:
            return elevated, s.value
        finally:
            kernel32.LocalFree(s)
    finally:
        kernel32.CloseHandle(tok)


def open_private_new(path: str) -> int:
    """Create `path` (it must not exist) for writing, readable by nobody the
    config's readers do not already include, and return an fd. Windows: the
    file is born with private_sddl() -- never an inherited ACL, and never
    fixed up afterwards, when the bytes may already have been read. POSIX:
    O_EXCL, mode 0600."""
    reject_reparse_point(path)
    if sys.platform != "win32":
        return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                    ("bInheritHandle", wintypes.BOOL)]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                     wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    elevated, sid = _token_identity()
    sd = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            private_sddl(elevated, sid), 1, ctypes.byref(sd), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        sa = SecurityAttributes(ctypes.sizeof(SecurityAttributes), sd, False)
        generic_write, create_new, file_attribute_normal = 0x40000000, 1, 0x80
        h = kernel32.CreateFileW(path, generic_write, 0, ctypes.byref(sa), create_new,
                                 file_attribute_normal, None)
        if h is None or h == wintypes.HANDLE(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel32.LocalFree(sd)
    try:
        return msvcrt.open_osfhandle(h, os.O_WRONLY | getattr(os, "O_BINARY", 0))
    except OSError:
        kernel32.CloseHandle(h)
        raise


def lock_down_acl(path: str, elevated: bool | None = None) -> None:
    """Apply a protected private DACL (POSIX 0700/0600; Windows SYSTEM +
    Administrators when elevated, plus user SID when unelevated) to an existing
    file or directory, refusing symlinks/reparse points."""
    path = os.path.abspath(path)
    reject_reparse_point(path)
    if not os.path.exists(path):
        return
    is_dir = os.path.isdir(path)
    if sys.platform != "win32":
        os.chmod(path, 0o700 if is_dir else 0o600)
        return
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    advapi32.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    advapi32.SetFileSecurityW.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]

    tok_elev, sid = _token_identity()
    use_elev = tok_elev if elevated is None else bool(elevated)
    sddl = private_dir_sddl(use_elev, sid) if is_dir else private_sddl(use_elev, sid)
    sd = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(sd), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        # `sd` built from `D:P...` already carries `SE_DACL_PROTECTED`; using
        # `SetFileSecurityW(DACL_SECURITY_INFORMATION)` applies the exact
        # security descriptor via `NtSetSecurityObject` on both native Windows
        # and Wine (where `SetNamedSecurityInfoW` synthesizes a fallback `WD` ACE).
        dacl_info = 0x00000004
        if not advapi32.SetFileSecurityW(path, dacl_info, sd):
            raise ctypes.WinError(ctypes.get_last_error())
        if use_elev:
            # Best-effort transfer ownership to Builtin Administrators (`O:BA`)
            # when `SeRestorePrivilege` is available on native Windows.
            advapi32.SetFileSecurityW(path, 0x00000001, sd)
    finally:
        kernel32.LocalFree(sd)


def open_private_append(path: str, binary: bool = False):
    """Open or create `path` for appending with private ACLs (0600 on POSIX;
    private_sddl() on Windows), refusing symlinks/reparse points, and return a
    writable file object."""
    path = os.path.abspath(path)
    reject_reparse_point(path)
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    if sys.platform != "win32":
        fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass
    else:
        import ctypes
        import msvcrt
        from ctypes import wintypes

        class SecurityAttributes(ctypes.Structure):
            _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                        ("bInheritHandle", wintypes.BOOL)]

        existed = os.path.exists(path)
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
        kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                         wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

        elevated, sid = _token_identity()
        sd = ctypes.c_void_p()
        if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                private_sddl(elevated, sid), 1, ctypes.byref(sd), None):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            sa = SecurityAttributes(ctypes.sizeof(SecurityAttributes), sd, False)
            file_append_data = 0x00000004
            share_rw = 0x00000001 | 0x00000002
            open_always, attr_normal = 4, 0x80
            h = kernel32.CreateFileW(path, file_append_data, share_rw, ctypes.byref(sa),
                                     open_always, attr_normal, None)
            if h is None or h == wintypes.HANDLE(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            kernel32.LocalFree(sd)
        try:
            fd = msvcrt.open_osfhandle(h, os.O_WRONLY | os.O_APPEND | getattr(os, "O_BINARY", 0))
        except OSError:
            kernel32.CloseHandle(h)
            raise
        if existed:
            try:
                lock_down_acl(path, elevated=elevated)
            except OSError:
                pass
    try:
        if binary:
            return os.fdopen(fd, "ab", buffering=0)
        return os.fdopen(fd, "a", encoding="utf-8", newline="\n")
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def mkdir_private(path: str) -> str:
    """Create directory `path` restricted to the current security context
    (Windows: private_dir_sddl() protected DACL, refusing reparse points; POSIX:
    mode 0700, refusing symlinks). Returns `path`."""
    path = os.path.abspath(path)
    reject_reparse_point(path)
    if sys.platform != "win32":
        os.makedirs(path, mode=0o700, exist_ok=True)
        reject_reparse_point(path)
        os.chmod(path, 0o700)
        return path

    import ctypes
    from ctypes import wintypes

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                    ("bInheritHandle", wintypes.BOOL)]

    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    advapi32.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    advapi32.SetFileSecurityW.restype = wintypes.BOOL
    kernel32.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p]
    kernel32.CreateDirectoryW.restype = wintypes.BOOL
    kernel32.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetFileAttributesW.restype = wintypes.DWORD
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]

    elevated, sid = _token_identity()
    sd = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            private_dir_sddl(elevated, sid), 1, ctypes.byref(sd), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        sa = SecurityAttributes(ctypes.sizeof(SecurityAttributes), sd, False)
        if not kernel32.CreateDirectoryW(path, ctypes.byref(sa)):
            err = ctypes.get_last_error()
            error_already_exists = 183
            if err != error_already_exists:
                raise ctypes.WinError(err)
            attrs = kernel32.GetFileAttributesW(path)
            invalid_attrs, attr_dir, attr_reparse = 0xFFFFFFFF, 0x10, 0x400
            if attrs == invalid_attrs or not (attrs & attr_dir) or (attrs & attr_reparse):
                raise OSError(f"refusing unsafe existing directory: {path}")
            if not advapi32.SetFileSecurityW(path, 0x00000004, sd):
                raise ctypes.WinError(ctypes.get_last_error())
            if elevated:
                advapi32.SetFileSecurityW(path, 0x00000001, sd)
    finally:
        kernel32.LocalFree(sd)
    return path


def write_private(path: str, data: bytes) -> None:
    """Replace `path` atomically with `data`, created by open_private_new()."""
    reject_reparse_point(path)
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = path + ".new"
    reject_reparse_point(tmp)
    try:
        os.remove(tmp)            # a leftover would keep its own ACL
    except FileNotFoundError:
        pass
    fd = open_private_new(tmp)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def adopt_config(protected: str, legacy: str | None) -> tuple[str, str]:
    """The elevated app's config is `protected`. The first time, a config found
    in the old places (`legacy`) is copied in -- once: that is the user choosing
    the file they run with; re-reading it on every start is what let any
    unelevated process decide what the elevated one executes (ScriptsInterpreter,
    scripts in the runtime folder). Returns (path, note for the status bar)."""
    reject_reparse_point(protected)
    if os.path.isfile(protected):
        try:
            lock_down_acl(protected)
        except OSError:
            pass
        if legacy and os.path.normcase(os.path.abspath(legacy)) != os.path.normcase(os.path.abspath(protected)):
            return protected, (f"config: {protected} -- {legacy} is not read: the elevated app "
                               "only uses a config in a folder only administrators can change")
        return protected, ""
    os.makedirs(os.path.dirname(protected), exist_ok=True)
    if legacy:
        reject_reparse_point(legacy)
        with open(legacy, "rb") as f:
            data = f.read()
    else:
        data = b"networks: {}\n"
    write_private(protected, data)
    if legacy:
        return protected, f"config: imported {legacy} into {protected}; that copy is the one used from now on"
    return protected, f"config: created {protected}"
