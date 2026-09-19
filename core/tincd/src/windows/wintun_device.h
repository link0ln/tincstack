#ifndef TINC_WINDOWS_WINTUN_DEVICE_H
#define TINC_WINDOWS_WINTUN_DEVICE_H

/*
    wintun_device.h -- what the device dispatcher needs from the Wintun backend.

    This program is free software; see the GPL v2+ (same as the rest of tinc).
*/

#include "../system.h"

/* True if wintun.dll is present and usable. A quiet probe: it loads the DLL
   and checks its entry points, and touches no adapter, so device_dispatch.c
   can ask before choosing a backend. */
bool wintun_available(void);

#endif
