"""netmtu.py — set a network interface's IPv4 MTU the proper way, via the Win32
IP Helper API (GetIpInterfaceEntry / SetIpInterfaceEntry), instead of shelling
out to netsh. Windows-only; used to clamp the Wintun adapter's MTU (which the
driver defaults to 65535) down to the tunnel's real payload size.

Reference: MIB_IPINTERFACE_ROW / SetIpInterfaceEntry (iphlpapi.dll, netioapi.h).
"""
from __future__ import annotations

import ctypes
import time
from ctypes import wintypes

AF_INET = 2
NO_ERROR = 0
_SCOPE_LEVEL_COUNT = 16


class _NET_LUID(ctypes.Structure):
    _fields_ = [("Value", ctypes.c_uint64)]


class MIB_IPINTERFACE_ROW(ctypes.Structure):
    # Layout must match netioapi.h exactly — GetIpInterfaceEntry writes the whole
    # struct, so a short/misaligned definition would corrupt the stack.
    _fields_ = [
        ("Family", ctypes.c_ushort),
        ("InterfaceLuid", ctypes.c_uint64),
        ("InterfaceIndex", ctypes.c_uint32),
        ("MaxReassemblySize", ctypes.c_uint32),
        ("InterfaceIdentifier", ctypes.c_uint64),
        ("MinRouterAdvertisementInterval", ctypes.c_uint32),
        ("MaxRouterAdvertisementInterval", ctypes.c_uint32),
        ("AdvertisingEnabled", ctypes.c_ubyte),
        ("ForwardingEnabled", ctypes.c_ubyte),
        ("WeakHostSend", ctypes.c_ubyte),
        ("WeakHostReceive", ctypes.c_ubyte),
        ("UseAutomaticMetric", ctypes.c_ubyte),
        ("UseNeighborUnreachabilityDetection", ctypes.c_ubyte),
        ("ManagedAddressConfigurationSupported", ctypes.c_ubyte),
        ("OtherStatefulConfigurationSupported", ctypes.c_ubyte),
        ("AdvertiseDefaultRoute", ctypes.c_ubyte),
        ("RouterDiscoveryBehavior", ctypes.c_int),
        ("DadTransmits", ctypes.c_uint32),
        ("BaseReachableTime", ctypes.c_uint32),
        ("RetransmitTime", ctypes.c_uint32),
        ("PathMtuDiscoveryTimeout", ctypes.c_uint32),
        ("LinkLocalAddressBehavior", ctypes.c_int),
        ("LinkLocalAddressTimeout", ctypes.c_uint32),
        ("ZoneIndices", ctypes.c_uint32 * _SCOPE_LEVEL_COUNT),
        ("SitePrefixLength", ctypes.c_uint32),
        ("Metric", ctypes.c_uint32),
        ("NlMtu", ctypes.c_uint32),
        ("Connected", ctypes.c_ubyte),
        ("SupportsWakeUpPatterns", ctypes.c_ubyte),
        ("SupportsNeighborDiscovery", ctypes.c_ubyte),
        ("SupportsRouterDiscovery", ctypes.c_ubyte),
        ("ReachableTime", ctypes.c_uint32),
        ("TransmitOffload", ctypes.c_ubyte),
        ("ReceiveOffload", ctypes.c_ubyte),
        ("DisableDefaultRoutes", ctypes.c_ubyte),
    ]


def _iphlpapi():
    lib = ctypes.WinDLL("iphlpapi.dll")
    lib.ConvertInterfaceAliasToLuid.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(_NET_LUID)]
    lib.ConvertInterfaceAliasToLuid.restype = ctypes.c_long
    lib.InitializeIpInterfaceEntry.argtypes = [ctypes.POINTER(MIB_IPINTERFACE_ROW)]
    lib.InitializeIpInterfaceEntry.restype = None
    lib.GetIpInterfaceEntry.argtypes = [ctypes.POINTER(MIB_IPINTERFACE_ROW)]
    lib.GetIpInterfaceEntry.restype = ctypes.c_long
    lib.SetIpInterfaceEntry.argtypes = [ctypes.POINTER(MIB_IPINTERFACE_ROW)]
    lib.SetIpInterfaceEntry.restype = ctypes.c_long
    return lib


def _luid(lib, alias):
    luid = _NET_LUID()
    if lib.ConvertInterfaceAliasToLuid(alias, ctypes.byref(luid)) == NO_ERROR and luid.Value:
        return luid
    return None


def get_interface_mtu(alias, family=AF_INET):
    """Return (True, mtu:int) for `alias`, or (False, error:str)."""
    lib = _iphlpapi()
    luid = _luid(lib, alias)
    if not luid:
        return False, f"interface '{alias}' not found"
    row = MIB_IPINTERFACE_ROW()
    lib.InitializeIpInterfaceEntry(ctypes.byref(row))
    row.Family = family
    row.InterfaceLuid = luid.Value
    st = lib.GetIpInterfaceEntry(ctypes.byref(row))
    if st != NO_ERROR:
        return False, f"GetIpInterfaceEntry failed ({st})"
    return True, int(row.NlMtu)


def set_interface_mtu(aliases, mtu, family=AF_INET, timeout=15.0, poll=0.5):
    """Force the IPv4 MTU on the first of `aliases` that resolves, waiting up to
    `timeout`s for the adapter to appear (tincd creates the Wintun adapter a
    moment after start). Returns (ok:bool, message:str). Requires admin."""
    if isinstance(aliases, str):
        aliases = [aliases]
    lib = _iphlpapi()
    deadline = time.monotonic() + timeout
    luid = used = None
    while True:
        for a in aliases:
            luid = _luid(lib, a)
            if luid:
                used = a
                break
        if luid or time.monotonic() >= deadline:
            break
        time.sleep(poll)
    if not luid:
        return False, f"adapter {aliases} not found within {timeout:.0f}s"
    row = MIB_IPINTERFACE_ROW()
    lib.InitializeIpInterfaceEntry(ctypes.byref(row))
    row.Family = family
    row.InterfaceLuid = luid.Value
    st = lib.GetIpInterfaceEntry(ctypes.byref(row))
    if st != NO_ERROR:
        return False, f"GetIpInterfaceEntry('{used}') failed ({st})"
    if family == AF_INET:
        # documented gotcha: Get returns SitePrefixLength as 0xFF, Set then rejects it
        row.SitePrefixLength = 0
    row.NlMtu = int(mtu)
    st = lib.SetIpInterfaceEntry(ctypes.byref(row))
    if st != NO_ERROR:
        return False, f"SetIpInterfaceEntry('{used}',{mtu}) failed ({st})"
    return True, f"MTU={mtu} set on '{used}'"
