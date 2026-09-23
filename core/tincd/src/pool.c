/*
    pool.c -- assign invitee addresses from AddressPool.

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

#include "conf.h"
#include "control_common.h"
#include "names.h"
#include "pool.h"
#include "subnet.h"
#include "tincctl.h"
#include "utils.h"
#include "xalloc.h"
#include "yamlconf.h"
#include "zeroconf.h"

typedef enum {
	USED_HOST,      /* Subnet line in a host record */
	USED_PENDING,   /* Subnet promised by an outstanding invitation */
	USED_LIVE,      /* Subnet announced by a node the daemon can see */
} used_source_t;

typedef struct {
	uint32_t address;   /* host order */
	int prefix;
	char *owner;
	used_source_t source;
} used_t;

typedef struct {
	used_t *items;
	size_t n, cap;
} used_list_t;

static void used_add(used_list_t *list, const subnet_t *s, const char *owner, used_source_t source) {
	if(s->type != SUBNET_IPV4) {
		return;
	}

	if(list->n == list->cap) {
		list->cap = list->cap ? list->cap * 2 : 32;
		list->items = xrealloc(list->items, list->cap * sizeof(*list->items));
	}

	const uint8_t *x = s->net.ipv4.address.x;
	used_t *u = &list->items[list->n++];
	u->address = ((uint32_t)x[0] << 24) | ((uint32_t)x[1] << 16) | ((uint32_t)x[2] << 8) | x[3];
	u->prefix = s->net.ipv4.prefixlength;
	u->owner = xstrdup(owner ? owner : "?");
	u->source = source;
}

static void used_free(used_list_t *list) {
	for(size_t i = 0; i < list->n; i++) {
		free(list->items[i].owner);
	}

	free(list->items);
	list->items = NULL;
	list->n = list->cap = 0;
}

/* Add every "Subnet = ..." line of a host-file-style stream. */
static void scan_subnets(FILE *f, used_list_t *list, const char *owner, used_source_t source) {
	char buf[1024];

	while(fgets(buf, sizeof(buf), f)) {
		char *p = buf + strspn(buf, " \t");
		size_t len = strcspn(p, " \t=");

		if(len != 6 || strncasecmp(p, "Subnet", 6)) {
			continue;
		}

		char *value = p + len;
		value += strspn(value, " \t");

		if(*value == '=') {
			value++;
			value += strspn(value, " \t");
		}

		rstrip(value);

		subnet_t s = {0};

		if(str2net(&s, value)) {
			used_add(list, &s, owner, source);
		}
	}
}

static void collect_host(used_list_t *list, const char *name) {
	char fname[PATH_MAX];
	snprintf(fname, sizeof(fname), "%s" SLASH "hosts" SLASH "%s", confbase, name);
	FILE *f = config_fopen(fname, "r");

	if(!f) {
		return;
	}

	scan_subnets(f, list, name, USED_HOST);
	fclose(f);
}

static void collect_hosts(used_list_t *list) {
	if(yamlconf_global && netname) {
		const char **names = yamlconf_host_names(yamlconf_global, netname);

		if(names) {
			for(size_t i = 0; names[i]; i++) {
				collect_host(list, names[i]);
			}

			free(names);
		}

		return;
	}

	char dname[PATH_MAX];
	snprintf(dname, sizeof(dname), "%s" SLASH "hosts", confbase);
	DIR *dir = opendir(dname);

	if(!dir) {
		return;
	}

	struct dirent *ent;

	while((ent = readdir(dir))) {
		if(check_id(ent->d_name)) {
			collect_host(list, ent->d_name);
		}
	}

	closedir(dir);
}

static void collect_pending(used_list_t *list) {
	char dname[PATH_MAX];
	snprintf(dname, sizeof(dname), "%s" SLASH "invitations", confbase);
	DIR *dir = opendir(dname);

	if(!dir) {
		return;
	}

	struct dirent *ent;

	while((ent = readdir(dir))) {
		/* Invitation files are named by an 18-byte urlsafe-base64 hash;
		   "<hash>.used" is one whose join is in flight. */
		size_t namelen = strlen(ent->d_name);

		if(namelen != 24 && !(namelen == 29 && !strcmp(ent->d_name + 24, ".used"))) {
			continue;
		}

		char fname[PATH_MAX];

		if((size_t)snprintf(fname, sizeof(fname), "%s" SLASH "%s", dname, ent->d_name) >= sizeof(fname)) {
			continue;
		}

		FILE *f = fopen(fname, "r");

		if(!f) {
			continue;
		}

		/* The invitee's name is the first line: "Name = <invitee>". */
		char owner[256] = "pending";
		char first[1024];

		if(fgets(first, sizeof(first), f)) {
			char *v = first + strcspn(first, " \t=");
			v += strspn(v, " \t=");
			rstrip(v);

			if(*v) {
				snprintf(owner, sizeof(owner), "%s", v);
			}
		}

		rewind(f);
		scan_subnets(f, list, owner, USED_PENDING);
		fclose(f);
	}

	closedir(dir);
}

static void collect_live(used_list_t *list) {
	if(!connect_tincd(false)) {
		return;
	}

	sendline(fd, "%d %d", CONTROL, REQ_DUMP_SUBNETS);

	while(recvline(fd, line, sizeof(line))) {
		char netstr[4096], owner[4096];
		int code, req;
		int n = sscanf(line, "%d %d %4095s %4095s", &code, &req, netstr, owner);

		if(n < 2 || code != CONTROL) {
			break;
		}

		if(req != REQ_DUMP_SUBNETS) {
			continue;  /* a reply to an earlier request (e.g. reload) */
		}

		if(n == 2) {
			break;  /* end of dump */
		}

		if(n != 4 || owner[0] == '(') {
			continue;  /* "(broadcast)" subnets are not addresses */
		}

		subnet_t s = {0};

		if(str2net(&s, netstr)) {
			used_add(list, &s, owner, USED_LIVE);
		}
	}
}

bool pool_parse(const char *pool, uint32_t *network, int *prefix) {
	return zeroconf_pool_parse(pool, network, prefix);
}

/* A Subnet reserves pool addresses only if it lies inside the pool. A
   subnet wider than the pool (an exit node's 0.0.0.0/0, a site's /16) is a
   route, not an address claim: counting it would let one host record --
   or one authenticated peer announcing such a subnet -- mark the whole
   pool as used and stop every further invitation. */
static bool inside_pool(const used_t *u, uint32_t network, int pool_prefix) {
	if(u->prefix < pool_prefix) {
		return false;
	}

	uint32_t pool_mask = 0xffffffffu << (32 - pool_prefix);
	return (u->address & pool_mask) == network;
}

static const used_t *find_used(const used_list_t *list, uint32_t candidate, uint32_t network, int pool_prefix) {
	for(size_t i = 0; i < list->n; i++) {
		const used_t *u = &list->items[i];

		if(!inside_pool(u, network, pool_prefix)) {
			continue;
		}

		uint32_t mask = 0xffffffffu << (32 - u->prefix);

		if((candidate & mask) == (u->address & mask)) {
			return u;
		}
	}

	return NULL;
}

char *pool_allocate(const char *pool) {
	uint32_t network;
	int prefix;

	if(!pool_parse(pool, &network, &prefix)) {
		fprintf(stderr, "Invalid AddressPool `%s' (expected IPv4 a.b.c.d/8..30)\n", pool ? pool : "");
		return NULL;
	}

	used_list_t used = {0};
	collect_hosts(&used);
	collect_pending(&used);
	collect_live(&used);

	uint32_t broadcast = network | (0xffffffffu >> prefix);
	char *result = NULL;

	for(uint32_t candidate = network + 1; candidate < broadcast; candidate++) {
		const used_t *u = find_used(&used, candidate, network, prefix);

		if(!u) {
			xasprintf(&result, "%u.%u.%u.%u",
			          (candidate >> 24) & 255, (candidate >> 16) & 255, (candidate >> 8) & 255, candidate & 255);
			break;
		}

		/* An address the daemon sees in use but the host database does not
		   know about (e.g. the invitee's own record was edited away) must
		   never be re-issued: say so, and move on. */
		if(u->source == USED_LIVE) {
			fprintf(stderr, "Address %u.%u.%u.%u is held by live node %s, skipping.\n",
			        (candidate >> 24) & 255, (candidate >> 16) & 255, (candidate >> 8) & 255, candidate & 255, u->owner);
		}
	}

	if(!result) {
		fprintf(stderr, "No free address left in AddressPool %s (%lu in use).\n", pool, (unsigned long)used.n);
	}

	used_free(&used);
	return result;
}
