/*
    device_dispatch.c -- pick the Windows device backend at runtime

    tinc on Windows can now use either the classic TAP-Win32 backend (layer 2,
    device.c -> tap_devops) or the Wintun backend (layer 3, wintun_device.c ->
    wintun_devops). This file provides the single `os_devops` the rest of tinc
    links against and forwards every call to the backend selected by the
    `DeviceType` option:

        DeviceType = wintun   -> Wintun (WireGuard tunnel adapter, L3)
        (anything else)       -> TAP-Win32 (default, L2)

    Keeping the choice at runtime means one tincd.exe supports both, so
    existing TAP setups keep working while new ones can opt into Wintun.

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

static const devops_t *active = NULL;

static const devops_t *select_backend(void) {
	char *type = NULL;
	const devops_t *sel = &tap_devops;

	if(get_config_string(lookup_config(&config_tree, "DeviceType"), &type)) {
		if(type && !strcasecmp(type, "wintun")) {
			sel = &wintun_devops;
		}

		free(type);
	}

	return sel;
}

static bool d_setup(void) {
	active = select_backend();
	logger(DEBUG_ALWAYS, LOG_INFO, "Using %s device backend",
	       active == &wintun_devops ? "Wintun (L3)" : "TAP-Win32 (L2)");
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
