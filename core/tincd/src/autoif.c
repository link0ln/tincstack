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
	uint32_t pool_net;
	int prefix = 24;
	bool have_pool = address_pool && zeroconf_pool_parse(address_pool, &pool_net, &prefix);

	if(get_config_string(lookup_config(&config_tree, "InterfaceAddress"), &addr)) {
		if(addr && !strchr(addr, '/') && !strchr(addr, ':')) {
			char *with_prefix = NULL;
			xasprintf(&with_prefix, "%s/%d", addr, prefix);
			free(addr);
			return with_prefix;
		}
		return addr;
	}

	if(!have_pool) {
		return NULL;
	}

	const uint8_t *fallback_x = NULL;

	for splay_each(subnet_t, s, &myself->subnet_tree) {
		if(s->type != SUBNET_IPV4 || s->net.ipv4.prefixlength != 32) {
			continue;
		}

		const uint8_t *x = s->net.ipv4.address.x;
		uint32_t host_ip = ((uint32_t)x[0] << 24) | ((uint32_t)x[1] << 16) | ((uint32_t)x[2] << 8) | (uint32_t)x[3];
		uint32_t mask = prefix == 0 ? 0 : (~0u << (32 - prefix));

		if((host_ip & mask) == (pool_net & mask)) {
			xasprintf(&addr, "%u.%u.%u.%u/%d", x[0], x[1], x[2], x[3], prefix);
			return addr;
		}

		if(!fallback_x) {
			fallback_x = x;
		}
	}

	if(fallback_x) {
		xasprintf(&addr, "%u.%u.%u.%u/%d", fallback_x[0], fallback_x[1], fallback_x[2], fallback_x[3], prefix);
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

static bool digits_only(const char *s) {
	if(!s || !*s) {
		return false;
	}

	for(; *s; s++) {
		if(!isdigit((uint8_t)*s)) {
			return false;
		}
	}

	return true;
}

static bool token_next(const char **cursor, char *out, size_t outlen) {
	const char *p = *cursor;

	while(*p == ' ' || *p == '\t') {
		p++;
	}

	if(!*p) {
		*cursor = p;
		return false;
	}

	const char *end = p;

	while(*end && *end != ' ' && *end != '\t') {
		end++;
	}

	size_t len = (size_t)(end - p);

	if(len == 0 || len >= outlen) {
		return false;
	}

	memcpy(out, p, len);
	out[len] = '\0';
	*cursor = end;
	return true;
}

bool autoif_build_route_cmd(const char *spec, const char *ifname, char *buf, size_t buflen) {
	if(!spec || !*spec || !ifname || !*ifname || !shell_safe(ifname) || !buf || buflen == 0) {
		return false;
	}

	const char *cur = spec;
	char first[128];

	if(!token_next(&cur, first, sizeof(first)) || !shell_safe(first)) {
		return false;
	}

	char rtype[16] = "";
	char prefix[128];

	if(!strcasecmp(first, "unreachable")) {
		snprintf(rtype, sizeof(rtype), "unreachable");
	} else if(!strcasecmp(first, "blackhole")) {
		snprintf(rtype, sizeof(rtype), "blackhole");
	} else if(!strcasecmp(first, "prohibit")) {
		snprintf(rtype, sizeof(rtype), "prohibit");
	}

	if(rtype[0]) {
		if(!token_next(&cur, prefix, sizeof(prefix)) || !shell_safe(prefix)) {
			return false;
		}
	} else {
		snprintf(prefix, sizeof(prefix), "%s", first);
	}

	/* First/prefix token must be "default" or an IPv4/IPv6 CIDR/address literal. */
	if(strcmp(prefix, "default") != 0 && !strchr(prefix, '.') && !strchr(prefix, ':')) {
		return false;
	}

	char via[128] = "";
	char table[64] = "";
	char metric[32] = "";
	char mtu[32] = "";
	char advmss[32] = "";
	char src[128] = "";
	char scope[32] = "";

	char tok[128];
	bool first_extra = true;

	while(token_next(&cur, tok, sizeof(tok))) {
		/* Fail-closed route types accept only table and metric (no dev/via). */
		if(rtype[0] && strcasecmp(tok, "table") != 0 && strcasecmp(tok, "metric") != 0) {
			return false;
		}

		/* Truncate gracefully check: if next char after token isn't ws or NUL, token_next failed. */
		if(!strcasecmp(tok, "via")) {
			if(!token_next(&cur, via, sizeof(via)) || !shell_safe(via) || (!strchr(via, '.') && !strchr(via, ':'))) {
				return false;
			}
		} else if(!strcasecmp(tok, "table")) {
			if(!token_next(&cur, table, sizeof(table)) || !shell_safe(table)) {
				return false;
			}
		} else if(!strcasecmp(tok, "metric")) {
			if(!token_next(&cur, metric, sizeof(metric)) || !digits_only(metric)) {
				return false;
			}
		} else if(!strcasecmp(tok, "mtu")) {
			if(!token_next(&cur, mtu, sizeof(mtu)) || !digits_only(mtu)) {
				return false;
			}

			long m = strtol(mtu, NULL, 10);

			if(m < 576 || m > 9000) {
				return false;
			}
		} else if(!strcasecmp(tok, "advmss")) {
			if(!token_next(&cur, advmss, sizeof(advmss)) || !digits_only(advmss)) {
				return false;
			}

			long mss = strtol(advmss, NULL, 10);

			if(mss < 500 || mss > 8960) {
				return false;
			}
		} else if(!strcasecmp(tok, "src")) {
			if(!token_next(&cur, src, sizeof(src)) || !shell_safe(src) || (!strchr(src, '.') && !strchr(src, ':'))) {
				return false;
			}
		} else if(!strcasecmp(tok, "scope")) {
			if(!token_next(&cur, scope, sizeof(scope)) ||
			                (strcasecmp(scope, "global") && strcasecmp(scope, "link") && strcasecmp(scope, "host"))) {
				return false;
			}
		} else if(!strcasecmp(tok, "dev")) {
			char devtok[128];

			if(!token_next(&cur, devtok, sizeof(devtok)) || strcmp(devtok, ifname) != 0) {
				return false;
			}
		} else if(first_extra && shell_safe(tok) && (strchr(tok, '.') || strchr(tok, ':'))) {
			/* Legacy 2-token syntax: "<prefix> <gateway>" */
			snprintf(via, sizeof(via), "%s", tok);
		} else {
			return false;
		}

		first_extra = false;
	}

	/* Guard against overly long single tokens skipped cleanly above */
	while(*cur == ' ' || *cur == '\t') {
		cur++;
	}

	if(*cur != '\0') {
		return false;
	}

	size_t off = 0;
	int w = rtype[0]
	        ? snprintf(buf + off, buflen - off, "ip route replace %s %s", rtype, prefix)
	        : snprintf(buf + off, buflen - off, "ip route replace %s", prefix);

	if(w < 0 || (size_t)w >= buflen - off) {
		return false;
	}

	off += (size_t)w;

	if(via[0]) {
		w = snprintf(buf + off, buflen - off, " via %s", via);

		if(w < 0 || (size_t)w >= buflen - off) {
			return false;
		}

		off += (size_t)w;
	}

	if(!rtype[0]) {
		w = snprintf(buf + off, buflen - off, " dev %s", ifname);

		if(w < 0 || (size_t)w >= buflen - off) {
			return false;
		}

		off += (size_t)w;
	}

	const struct {
		const char *key;
		const char *val;
	} extras[] = {
		{ "table", table },
		{ "metric", metric },
		{ "mtu", mtu },
		{ "advmss", advmss },
		{ "src", src },
		{ "scope", scope },
	};

	for(size_t i = 0; i < sizeof(extras) / sizeof(extras[0]); i++) {
		if(extras[i].val[0]) {
			w = snprintf(buf + off, buflen - off, " %s %s", extras[i].key, extras[i].val);

			if(w < 0 || (size_t)w >= buflen - off) {
				return false;
			}

			off += (size_t)w;
		}
	}

	return true;
}

bool autoif_ensure_routes(void) {
#ifdef HAVE_LINUX
	config_t *first_cfg = lookup_config(&config_tree, "InterfaceRoute");

	if(!first_cfg) {
		return true;
	}

	if(!iface || !shell_safe(iface) || geteuid() != 0) {
		return false;
	}

	char cmd[512];
	bool ok = true;

	for(config_t *cfg = first_cfg; cfg; cfg = lookup_config_next(&config_tree, cfg)) {
		if(autoif_build_route_cmd(cfg->value, iface, cmd, sizeof(cmd))) {
			ok &= run(cmd);
		} else {
			logger(DEBUG_ALWAYS, LOG_WARNING, "Ignoring InterfaceRoute `%s': not a route", cfg->value);
		}
	}

	return ok;
#else
	return true;
#endif
}

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
	ok &= build(cmd, sizeof(cmd), "ip link set %s txqueuelen 4000 up", iface) && run(cmd);

	if(build(cmd, sizeof(cmd), "tc qdisc replace dev %s root fq flow_limit 2000 >/dev/null 2>&1", iface)) {
		if(system(cmd) < 0) {
			/* Best-effort: kernels without sch_fq keep their default qdisc. */
		}
	}

	ok &= autoif_ensure_routes();

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
