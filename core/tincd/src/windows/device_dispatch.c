/*
    device_dispatch.c -- pick the Windows device backend at runtime

    tinc on Windows can now use either the classic TAP-Win32 backend (layer 2,
    device.c -> tap_devops) or the Wintun backend (layer 3, wintun_device.c ->
    wintun_devops). This file provides the single `os_devops` the rest of tinc
    links against and forwards every call to the backend:

        DeviceType = wintun   -> Wintun (WireGuard tunnel adapter, L3)
        DeviceType = anything -> TAP-Win32 (L2)
        DeviceType unset      -> Wintun if wintun.dll is usable, else TAP-Win32

    The default used to be TAP-Win32, which meant a node that joined by
    invitation looked for a driver this distribution does not ship (we ship
    wintun.dll) and died with "No Windows tap device found!". Wintun needs no
    pre-installed adapter — it creates one on connect — so it is the right
    default; a host that really has a TAP adapter and no wintun.dll still
    lands on TAP, and `DeviceType` still decides outright when it is set.

    Keeping the choice at runtime means one tincd.exe supports both.

    GPL-2.0-or-later.
*/

#include "../system.h"

#include <string.h>

#include "../conf.h"
#include "../device.h"
#include "../logger.h"
#include "../xalloc.h"

extern const devops_t tap_devops;
extern const devops_t wintun_devops;
extern bool wintun_available(void);

static const devops_t *active = NULL;

static const devops_t *select_backend(const char **why) {
	char *type = NULL;

	if(get_config_string(lookup_config(&config_tree, "DeviceType"), &type)) {
		bool wintun = type && !strcasecmp(type, "wintun");
		free(type);
		*why = "DeviceType";
		return wintun ? &wintun_devops : &tap_devops;
	}

	if(wintun_available()) {
		*why = "no DeviceType set, wintun.dll is usable";
		return &wintun_devops;
	}

	*why = "no DeviceType set and no usable wintun.dll";
	return &tap_devops;
}

static bool d_setup(void) {
	const char *why = "";
	active = select_backend(&why);
	logger(DEBUG_ALWAYS, LOG_INFO, "Using %s device backend (%s)",
	       active == &wintun_devops ? "Wintun (L3)" : "TAP-Win32 (L2)", why);
	return active->setup();
}

static void d_close(void) {
	if(active && active->close) {
		active->close();
	}

	active = NULL;
}

static bool d_read(vpn_packet_t *packet) {
	return (active && active->read) ? active->read(packet) : false;
}

static bool d_write(vpn_packet_t *packet) {
	return (active && active->write) ? active->write(packet) : false;
}

static void d_enable(void) {
	if(active && active->enable) {
		active->enable();
	}
}

static void d_disable(void) {
	if(active && active->disable) {
		active->disable();
	}
}

const devops_t os_devops = {
	.setup = d_setup,
	.close = d_close,
	.read = d_read,
	.write = d_write,
	.enable = d_enable,
	.disable = d_disable,
};
