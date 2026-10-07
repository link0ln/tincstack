/*
    address_cache.c -- Manage cache of recently seen addresses
    Copyright (C) 2018 Guus Sliepen <guus@tinc-vpn.org>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "system.h"

#include "address_cache.h"
#include "conf.h"
#include "dnsrefresh.h"
#include "names.h"
#include "netutl.h"
#include "xalloc.h"

static const unsigned int NOT_CACHED = UINT_MAX;

// Find edges pointing to this node, and use them to build a list of unique, known addresses.
static struct addrinfo *get_known_addresses(node_t *n) {
	struct addrinfo *ai = NULL;
	struct addrinfo *oai = NULL;

	for splay_each(edge_t, e, &n->edge_tree) {
		if(!e->reverse) {
			continue;
		}

		bool found = false;

		for(struct addrinfo *aip = ai; aip; aip = aip->ai_next) {
			if(!sockaddrcmp(&e->reverse->address, (sockaddr_t *)aip->ai_addr)) {
				found = true;
				break;
			}
		}

		if(found) {
			continue;
		}

		oai = ai;
		ai = xzalloc(sizeof(*ai));
		ai->ai_family = e->reverse->address.sa.sa_family;
		ai->ai_socktype = SOCK_STREAM;
		ai->ai_protocol = IPPROTO_TCP;
		ai->ai_addrlen = SALEN(e->reverse->address.sa);
		ai->ai_addr = xmalloc(ai->ai_addrlen);
		memcpy(ai->ai_addr, &e->reverse->address, ai->ai_addrlen);
		ai->ai_next = oai;
	}

	return ai;
}

static void free_known_addresses(struct addrinfo *ai) {
	for(struct addrinfo *aip = ai, *next; aip; aip = next) {
		next = aip->ai_next;
		free(aip->ai_addr);
		free(aip);
	}
}

static unsigned int find_cached(address_cache_t *cache, const sockaddr_t *sa) {
	for(unsigned int i = 0; i < cache->data.used; i++)
		if(!sockaddrcmp(&cache->data.address[i], sa)) {
			return i;
		}

	return NOT_CACHED;
}

void add_recent_address(address_cache_t *cache, const sockaddr_t *sa) {
	// Check if it's already cached
	unsigned int pos = find_cached(cache, sa);

	// It's in the first spot, so nothing to do
	if(pos == 0) {
		return;
	}

	logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Caching recent address for %s", cache->node->name);

	// Shift everything, move/add the address to the first slot
	if(pos == NOT_CACHED) {
		if(cache->data.used < MAX_CACHED_ADDRESSES) {
			cache->data.used++;
		}

		pos = cache->data.used - 1;
	}

	memmove(&cache->data.address[1], &cache->data.address[0], pos * sizeof(cache->data.address[0]));

	cache->data.address[0] = *sa;

	// Write the cache
	char fname[PATH_MAX];
	snprintf(fname, sizeof(fname), "%s" SLASH "cache" SLASH "%s", confbase, cache->node->name);
	FILE *fp = fopen(fname, "wb");

	if(fp) {
		fwrite(&cache->data, sizeof(cache->data), 1, fp);
		fclose(fp);
	}
}

const sockaddr_t *get_recent_address(address_cache_t *cache) {
	// Check if there is an address in our cache of recently seen addresses
	if(cache->tried < cache->data.used) {
		return &cache->data.address[cache->tried++];
	}

	// Next, check any recently seen addresses not in our cache
	while(cache->tried == cache->data.used) {
		if(!cache->ai) {
			cache->aip = cache->ai = get_known_addresses(cache->node);
		}

		if(cache->ai) {
			if(cache->aip) {
				sockaddr_t *sa = (sockaddr_t *)cache->aip->ai_addr;
				cache->aip = cache->aip->ai_next;

				if(find_cached(cache, sa) != NOT_CACHED) {
					continue;
				}

				return sa;
			} else {
				free_known_addresses(cache->ai);
				cache->ai = NULL;
			}
		}

		cache->tried++;
	}

	// Before re-reading the Address statements (a resolver round trip that
	// fails outright when the resolver is down), offer the DNS watcher's
	// persisted last-good endpoint for each watched name: it was a live DNS
	// answer once, and it is only ever replaced by a newer one. Ranked below
	// the graph's known addresses, above the fresh resolution.
	if(!cache->config_tree) {
		cache->config_tree = create_configuration();
		read_host_config(cache->config_tree, cache->node->name, false);
	}

	if(!cache->lg_tried) {
		cache->lg_tried = true;

		for(config_t *cfg = lookup_config(cache->config_tree, "Address"); cfg; cfg = lookup_config_next(cache->config_tree, cfg)) {
			char *address = NULL;
			get_config_string(cfg, &address);

			if(address && *address) {
				char *space = strchr(address, ' ');

				if(space) {
					*space = 0;
				}

				const sockaddr_t *lg = dnsrefresh_last_good(cache->node->name, address);

				if(lg && find_cached(cache, lg) == NOT_CACHED) {
					free(address);
					return lg;
				}
			}

			free(address);
		}
	}

	cache->cfg = lookup_config(cache->config_tree, "Address");

	while(cache->cfg && !cache->aip) {
		char *address, *port;

		get_config_string(cache->cfg, &address);

		char *space = strchr(address, ' ');

		if(space) {
			port = xstrdup(space + 1);
			*space = 0;
		} else {
			if(!get_config_string(lookup_config(cache->config_tree, "Port"), &port)) {
				port = xstrdup("655");
			}
		}

		if(cache->ai) {
			free_known_addresses(cache->ai);
		}

		cache->aip = cache->ai = str2addrinfo(address, port, SOCK_STREAM);

		if(cache->ai) {
			struct addrinfo *ai = NULL;

			for(; cache->aip; cache->aip = cache->aip->ai_next) {
				struct addrinfo *oai = ai;

				ai = xzalloc(sizeof(*ai));
				ai->ai_family = cache->aip->ai_family;
				ai->ai_socktype = cache->aip->ai_socktype;
				ai->ai_protocol = cache->aip->ai_protocol;
				ai->ai_addrlen = cache->aip->ai_addrlen;
				ai->ai_addr = xmalloc(ai->ai_addrlen);
				memcpy(ai->ai_addr, cache->aip->ai_addr, ai->ai_addrlen);
				ai->ai_next = oai;
			}

			freeaddrinfo(cache->ai);
			cache->aip = cache->ai = ai;
		}

		free(address);
		free(port);

		cache->cfg = lookup_config_next(cache->config_tree, cache->cfg);
	}

	if(cache->ai) {
		if(cache->aip) {
			sockaddr_t *sa = (sockaddr_t *)cache->aip->ai_addr;

			cache->aip = cache->aip->ai_next;
			return sa;
		} else {
			free_known_addresses(cache->ai);
			cache->ai = NULL;
		}
	}

	// We're all out of addresses.
	exit_configuration(cache->config_tree);
	cache->config_tree = NULL;

	return NULL;
}

address_cache_t *open_address_cache(node_t *node) {
	address_cache_t *cache = xmalloc(sizeof(*cache));
	cache->node = node;

	// Try to open an existing address cache
	char fname[PATH_MAX];
	snprintf(fname, sizeof(fname), "%s" SLASH "cache" SLASH "%s", confbase, node->name);
	FILE *fp = fopen(fname, "rb");

	if(!fp || fread(&cache->data, sizeof(cache->data), 1, fp) != 1 || cache->data.version != ADDRESS_CACHE_VERSION) {
		memset(&cache->data, 0, sizeof(cache->data));
	}

	if(fp) {
		fclose(fp);
	}

	// Ensure we have a valid state
	cache->config_tree = NULL;
	cache->cfg = NULL;
	cache->ai = NULL;
	cache->aip = NULL;
	cache->tried = 0;
	cache->lg_tried = false;
	cache->data.version = ADDRESS_CACHE_VERSION;

	if(cache->data.used > MAX_CACHED_ADDRESSES) {
		cache->data.used = 0;
	}

	return cache;
}

void reset_address_cache(address_cache_t *cache) {
	if(cache->config_tree) {
		exit_configuration(cache->config_tree);
		cache->config_tree = NULL;
	}

	if(cache->ai) {
		free_known_addresses(cache->ai);
	}

	cache->config_tree = NULL;
	cache->cfg = NULL;
	cache->ai = NULL;
	cache->aip = NULL;
	cache->tried = 0;
	cache->lg_tried = false;
}

/* Remove one address from the persisted recent list and rewind the walk, so
   the next dial does not try it again this cycle. A DNS watcher that saw a
   peer's address leave its record calls this for the old address before
   re-dialling: reset alone would re-offer the stale entry first. */
void drop_address(address_cache_t *cache, const sockaddr_t *sa) {
	unsigned int pos = find_cached(cache, sa);

	if(pos == NOT_CACHED) {
		return;
	}

	memmove(&cache->data.address[pos], &cache->data.address[pos + 1],
	        (cache->data.used - pos - 1) * sizeof(cache->data.address[0]));
	cache->data.used--;

	if(cache->tried > pos) {
		cache->tried--;
	}

	// Persist the shrunk list.
	char fname[PATH_MAX];
	snprintf(fname, sizeof(fname), "%s" SLASH "cache" SLASH "%s", confbase, cache->node->name);
	FILE *fp = fopen(fname, "wb");

	if(fp) {
		fwrite(&cache->data, sizeof(cache->data), 1, fp);
		fclose(fp);
	}
}

static bool same_ip(const sockaddr_t *a, const sockaddr_t *b) {
	if(a->sa.sa_family != b->sa.sa_family) {
		return false;
	}

	if(a->sa.sa_family == AF_INET) {
		return a->in.sin_addr.s_addr == b->in.sin_addr.s_addr;
	}

	if(a->sa.sa_family == AF_INET6) {
		return !memcmp(&a->in6.sin6_addr, &b->in6.sin6_addr, sizeof(struct in6_addr));
	}

	return false;
}

/* drop_address, but by IP alone: a peer's cached entries carry the ephemeral
   source ports of accepted connections, and a DNS watcher that saw the IP
   leave must purge every one of them, not just the service-port spelling. */
void drop_address_ip(address_cache_t *cache, const sockaddr_t *sa) {
	bool changed = false;

	for(unsigned int i = 0; i < cache->data.used;) {
		if(same_ip(&cache->data.address[i], sa)) {
			memmove(&cache->data.address[i], &cache->data.address[i + 1],
			        (cache->data.used - i - 1) * sizeof(cache->data.address[0]));
			cache->data.used--;

			if(cache->tried > i) {
				cache->tried--;
			}

			changed = true;
		} else {
			i++;
		}
	}

	if(!changed) {
		return;
	}

	char fname[PATH_MAX];
	snprintf(fname, sizeof(fname), "%s" SLASH "cache" SLASH "%s", confbase, cache->node->name);
	FILE *fp = fopen(fname, "wb");

	if(fp) {
		fwrite(&cache->data, sizeof(cache->data), 1, fp);
		fclose(fp);
	}
}

void close_address_cache(address_cache_t *cache) {
	if(cache->config_tree) {
		exit_configuration(cache->config_tree);
		cache->config_tree = NULL;
	}

	if(cache->ai) {
		free_known_addresses(cache->ai);
	}

	free(cache);
}
