/*
    autoif.c -- built-in interface addressing for YAML-mode nodes.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
*/

#include "system.h"

#include "autoif.h"
#include "conf.h"
#include "device.h"
#include "logger.h"
#include "net.h"
#include "node.h"
#include "zeroconf.h"
#include "subnet.h"
#include "xalloc.h"

/* The address to configure: InterfaceAddress if set, else our first IPv4
   /32 Subnet with the AddressPool's prefix. Caller frees; NULL if unknown.
   Not static: the Wintun backend assigns the adapter address from the same
   two sources, so both platforms answer "what is my address" identically. */
char *autoif_own_address(void) {
	char *addr = NULL;

	if(get_config_string(lookup_config(&config_tree, "InterfaceAddress"), &addr)) {
		return addr;
	}

	uint32_t pool_net;
	int prefix;

	if(!address_pool || !zeroconf_pool_parse(address_pool, &pool_net, &prefix)) {
		return NULL;
	}

	for splay_each(subnet_t, s, &myself->subnet_tree) {
		if(s->type != SUBNET_IPV4 || s->net.ipv4.prefixlength != 32) {
			continue;
		}

		const uint8_t *x = s->net.ipv4.address.x;
		xasprintf(&addr, "%u.%u.%u.%u/%d", x[0], x[1], x[2], x[3], prefix);
		return addr;
	}

	return NULL;
}

/* Only characters that can appear in an address, prefix or interface name
   are allowed into the shell command line, and a value may not start with
   '-' (it would be read by `ip' as an option, not an address). The values
   come from the YAML and, on a joined node, from the inviter's Ifconfig/
   Route lines, so they are treated as untrusted here. */
static bool shell_safe(const char *s) {
	if(!*s || *s == '-') {
		return false;
	}

	for(; *s; s++) {
		if(!isalnum((uint8_t) *s) && !strchr("./:-_", *s)) {
			return false;
		}
	}

	return *s == 0;
}

/* Format into cmd, refusing a command line that did not fit. */
static bool build(char *cmd, size_t cmdlen, const char *fmt, ...) ATTR_FORMAT(printf, 3, 4);
static bool build(char *cmd, size_t cmdlen, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(cmd, cmdlen, fmt, ap);
	va_end(ap);

	if(n < 0 || (size_t)n >= cmdlen) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Built-in tinc-up: command line too long, not run");
		return false;
	}

	return true;
}

#ifdef HAVE_LINUX
/* Only the Linux path runs commands (WIFEXITED is POSIX; on Windows the
   declaration was implicit and the function dead code until gcc 14 made
   that an error). */
static bool run(const char *cmd) {
	logger(DEBUG_STATUS, LOG_INFO, "Built-in tinc-up: %s", cmd);
	int status = system(cmd);

	if(status == -1 || !WIFEXITED(status) || WEXITSTATUS(status)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Built-in tinc-up command failed: %s", cmd);
		return false;
	}

	return true;
}
#endif

bool autoif_up(void) {
#ifdef HAVE_LINUX

	if(!iface || !shell_safe(iface)) {
		return false;
	}

	char *addr = autoif_own_address();

	if(!addr) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "No tinc-up script and no address to configure on %s (set InterfaceAddress or AddressPool + Subnet)", iface);
		return false;
	}

	if(!shell_safe(addr)) {
		free(addr);
		return false;
	}

	char cmd[512];
	bool ok = true;

	ok &= build(cmd, sizeof(cmd), "ip addr replace %s dev %s", addr, iface) && run(cmd);
	ok &= build(cmd, sizeof(cmd), "ip link set %s up", iface) && run(cmd);

	for(config_t *cfg = lookup_config(&config_tree, "InterfaceRoute"); cfg; cfg = lookup_config_next(&config_tree, cfg)) {
		char *route = xstrdup(cfg->value);
		char *via = strchr(route, ' ');

		if(via) {
			*via++ = 0;
			via += strspn(via, " ");

			/* Two spellings reach this option and both have to work:
			   "<prefix> <gateway>", which is what `tinc join' writes from an
			   invitation's Route line, and "<prefix> via <gateway>", which is
			   what anyone who knows `ip route' types. The second one used to
			   be dropped with "not a route" -- the gateway kept the keyword,
			   which then failed shell_safe() on the space. */
			if(!strncmp(via, "via ", 4)) {
				via += 4;
				via += strspn(via, " ");
			}
		}

		if(shell_safe(route) && (!via || !*via || shell_safe(via))) {
			bool built;

			if(via && *via) {
				built = build(cmd, sizeof(cmd), "ip route replace %s via %s dev %s", route, via, iface);
			} else {
				built = build(cmd, sizeof(cmd), "ip route replace %s dev %s", route, iface);
			}

			ok &= built && run(cmd);
		} else {
			logger(DEBUG_ALWAYS, LOG_WARNING, "Ignoring InterfaceRoute `%s': not a route", cfg->value);
		}

		free(route);
	}

	if(ok) {
		logger(DEBUG_ALWAYS, LOG_INFO, "Interface %s configured with %s (built-in tinc-up)", iface, addr);
	}

	free(addr);
	return ok;
#else
	logger(DEBUG_ALWAYS, LOG_WARNING, "No tinc-up script found; configure the interface address by other means on this platform");
	return false;
#endif
}
