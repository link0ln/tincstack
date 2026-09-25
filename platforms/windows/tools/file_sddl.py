"""Print a file's security descriptor as SDDL (owner, group, DACL).

Runs under a *Windows* CPython (the win-exe image's, under Wine): Wine's
icacls/cacls are stubs that print nothing, so windows-wine-test.sh reads the
descriptor itself, the way icacls would, through the same Win32 calls.

    wine C:\\Python312\\python.exe file_sddl.py <path> [<path> ...]
"""

import ctypes
import sys
from ctypes import wintypes

OWNER = 0x1
GROUP = 0x2
DACL = 0x4

advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

GetFileSecurityW = advapi32.GetFileSecurityW
GetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p,
                             wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
GetFileSecurityW.restype = wintypes.BOOL

ToSddl = advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW
ToSddl.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                   ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(wintypes.ULONG)]
ToSddl.restype = wintypes.BOOL

kernel32.LocalFree.argtypes = [ctypes.c_void_p]


def sddl(path: str) -> str:
    info = OWNER | GROUP | DACL
    need = wintypes.DWORD(0)
    GetFileSecurityW(path, info, None, 0, ctypes.byref(need))
    if not need.value:
        raise OSError(ctypes.get_last_error(), f"GetFileSecurityW({path})")
    buf = ctypes.create_string_buffer(need.value)
    if not GetFileSecurityW(path, info, buf, need, ctypes.byref(need)):
        raise OSError(ctypes.get_last_error(), f"GetFileSecurityW({path})")
    out = wintypes.LPWSTR()
    if not ToSddl(buf, 1, info, ctypes.byref(out), None):
        raise OSError(ctypes.get_last_error(), "ConvertSecurityDescriptorToStringSecurityDescriptorW")
    try:
        return out.value or ""
    finally:
        kernel32.LocalFree(out)


if __name__ == "__main__":
    rc = 0
    for p in sys.argv[1:]:
        try:
            print(f"{p}\t{sddl(p)}")
        except OSError as e:
            print(f"{p}\tERROR {e}")
            rc = 1
    sys.exit(rc)
