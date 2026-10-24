/*
    node.c -- node tree management
    Copyright (C) 2001-2013 Guus Sliepen <guus@tinc-vpn.org>,
                  2001-2005 Ivo Timmermans

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
#include "control_common.h"
#include "edge.h"
#include "logger.h"
#include "names.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "protocol.h"
#include "splay_tree.h"
#include "utils.h"
#include "xalloc.h"

#define TINC_TRANSPORT_DAEMON
#include "transport.h"

#include "ed25519/sha512.h"

node_t *myself;

static int node_compare(const node_t *a, const node_t *b) {
	return strcmp(a->name, b->name);
}

static int node_id_compare(const node_t *a, const node_t *b) {
	return memcmp(&a->id, &b->id, sizeof(node_id_t));
}

static int node_udp_compare(const node_t *a, const node_t *b) {
	int result = sockaddrcmp(&a->address, &b->address);

	if(result) {
		return result;
	}

	return (a->name && b->name) ? strcmp(a->name, b->name) : 0;
}

splay_tree_t node_tree = {
	.compare = (splay_compare_t) node_compare,
	.delete = (splay_action_t) free_node,
};

static splay_tree_t node_id_tree = {
	.compare = (splay_compare_t) node_id_compare,
};

static splay_tree_t node_udp_tree = {
	.compare = (splay_compare_t) node_udp_compare,
};

static splay_tree_t blocked_node_tree = {
	.compare = (splay_compare_t) strcmp,
	.delete = (splay_action_t) free,
};

void exit_nodes(void) {
	splay_empty_tree(&blocked_node_tree);
	splay_empty_tree(&node_udp_tree);
	splay_empty_tree(&node_id_tree);
	splay_empty_tree(&node_tree);
}

bool node_is_blocked(const char *name) {
	if(!name || !*name) {
		return false;
	}

	if(myself && myself->name && !strcmp(name, myself->name)) {
		return false;
	}

	return splay_search(&blocked_node_tree, name) != NULL;
}

void setup_blocked_nodes(void) {
	splay_empty_tree(&blocked_node_tree);

	for(config_t *cfg = lookup_config(&config_tree, "BlockedNodes"); cfg; cfg = lookup_config_next(&config_tree, cfg)) {
		if(!cfg->value) {
			continue;
		}

		char *copy = xstrdup(cfg->value);
		char *saveptr = NULL;

		for(char *tok = strtok_r(copy, " \t,;", &saveptr); tok; tok = strtok_r(NULL, " \t,;", &saveptr)) {
			if(check_id(tok) && (!myself || !myself->name || strcmp(tok, myself->name))) {
				if(!splay_search(&blocked_node_tree, tok)) {
					splay_insert(&blocked_node_tree, xstrdup(tok));
				}
			}
		}

		free(copy);
	}

	for list_each(connection_t, c, &connection_list) {
		if(c->status.control || !c->name) {
			continue;
		}

		if(node_is_blocked(c->name)) {
			if(c->outgoing) {
				list_delete(&outgoing_list, c->outgoing);
				c->outgoing = NULL;
			}

			terminate_connection(c, c->edge);
		}
	}

	for list_each(outgoing_t, outgoing, &outgoing_list) {
		if(outgoing->node && node_is_blocked(outgoing->node->name)) {
			list_delete_node(&outgoing_list, node);
		}
	}

	for splay_each(node_t, n, &node_tree) {
		if(n == myself || !node_is_blocked(n->name)) {
			continue;
		}

		logger(DEBUG_ALWAYS, LOG_INFO, "Purging blocked node %s from node tree", n->name);

		if(confbase) {
			char cpath[PATH_MAX];
			snprintf(cpath, sizeof(cpath), "%s" SLASH "cache" SLASH "%s", confbase, n->name);
			unlink(cpath);
		}

		for splay_each(subnet_t, s, &n->subnet_tree) {
			if(!tunnelserver) {
				send_del_subnet(everyone, s);
			}

			if(n->status.reachable) {
				subnet_update(n, s, false);
			}

			subnet_del(n, s);
		}

		for splay_each(edge_t, e, &edge_weight_tree) {
			if(e->from == n || e->to == n) {
				if(!tunnelserver) {
					send_del_edge(everyone, e);
				}

				edge_del(e);
			}
		}

		node_del(n);
	}
}

node_t *new_node(const char *name) {
	node_t *n = xzalloc(sizeof(*n));

	if(replaywin) {
		n->late = xzalloc(replaywin);
	}

	init_subnet_tree(&n->subnet_tree);
	init_edge_tree(&n->edge_tree);

	n->mtu = MTU;
	n->maxmtu = MTU;
	n->udp_ping_rtt = -1;
	n->name = xstrdup(name);

	return n;
}

void free_node(node_t *n) {
	if(!n) {
		return;
	}

	splay_empty_tree(&n->subnet_tree);
	splay_empty_tree(&n->edge_tree);

	sockaddrfree(&n->address);

#ifndef DISABLE_LEGACY
	cipher_free(n->incipher);
	digest_free(n->indigest);
	cipher_free(n->outcipher);
	digest_free(n->outdigest);
#endif

	ecdsa_free(n->ecdsa);
	sptps_stop(&n->sptps);

	timeout_del(&n->udp_ping_timeout);
	timeout_del(&n->punch_timer);

	free(n->hostname);
	free(n->name);
	free(n->late);
	free(n->tls_fingerprint);

	if(n->address_cache) {
		close_address_cache(n->address_cache);
	}

	free(n);
}

void node_add(node_t *n) {
	unsigned char buf[64];
	sha512(n->name, strlen(n->name), buf);
	memcpy(&n->id, buf, sizeof(n->id));

	splay_insert(&node_tree, n);
	splay_insert(&node_id_tree, n);
}

void node_del(node_t *n) {
	splay_delete(&node_udp_tree, n);

	for splay_each(subnet_t, s, &n->subnet_tree) {
		subnet_del(n, s);
	}

	for splay_each(edge_t, e, &n->edge_tree) {
		edge_del(e);
	}

	splay_delete(&node_id_tree, n);
	splay_delete(&node_tree, n);
}

node_t *lookup_node(char *name) {
	node_t n = {0};

	n.name = name;

	return splay_search(&node_tree, &n);
}

node_t *lookup_node_id(const node_id_t *id) {
	node_t n = {.id = *id};
	return splay_search(&node_id_tree, &n);
}

node_t *lookup_node_udp(const sockaddr_t *sa) {
	node_t tmp = {.address = *sa};
	return splay_search(&node_udp_tree, &tmp);
}

void update_node_udp(node_t *n, const sockaddr_t *sa) {
	if(n == myself) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Trying to update UDP address of myself!");
		return;
	}

	if(sa && address_routes_via_vpn(sa)) {
		if(n->address.sa.sa_family != AF_UNSPEC && n->address.sa.sa_family != AF_UNKNOWN && !address_routes_via_vpn(&n->address)) {
			return;
		}

		sa = NULL;
	}

	/* The address we already use, and the node is indexed under it: nothing
	   to learn, and nothing to invalidate -- invalidating it would throw away
	   a confirmed path and its PMTU for news that is not news. */
	if(sa && !sockaddrcmp(sa, &n->address) && splay_search(&node_udp_tree, n) == n) {
		return;
	}

	splay_delete(&node_udp_tree, n);

	if(sa) {
		n->address = *sa;
		n->sock = 0;

		for(int i = 0; i < listen_sockets; i++) {
			if(listen_socket[i].sa.sa.sa_family == sa->sa.sa_family) {
				n->sock = i;
				break;
			}
		}

		splay_insert(&node_udp_tree, n);
		free(n->hostname);
		n->hostname = sockaddr2hostname(&n->address);
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "UDP address of %s set to %s", n->name, n->hostname);
	}

	/* invalidate UDP information - note that this is a security feature as well to make sure
	   we can't be tricked into flooding any random address with UDP packets.
	   For a datagram carrier (quic), data packets ride the carrier flow rather
	   than n->address, so learning the peer's raw UDP data-socket address
	   (send_carrier_beacon) must not wipe out the carrier's confirmed PMTU. */
	n->status.udp_addr_confirmed = false;

	if(!sa || !n->connection || !n->connection->transport || !n->connection->transport->send_datagram) {
		n->status.udp_confirmed = false;
		n->maxrecentlen = 0;
		n->mtuprobes = 0;
		n->minmtu = 0;
		n->maxmtu = MTU;
	}
}

bool dump_nodes(connection_t *c) {
	for splay_each(node_t, n, &node_tree) {
		char id[2 * sizeof(n->id) + 1];

		for(size_t c = 0; c < sizeof(n->id); ++c) {
			snprintf(id + 2 * c, 3, "%02x", n->id.x[c]);
		}

		id[sizeof(id) - 1] = 0;
		char transports[TRANSPORT_LIST_MAX];
		transport_mask_to_string(transport_node_mask(n), transports);
		/* Trailing tls fingerprint token ("-" if unknown), like transports: an
		   older CLI's sscanf stops before it and ignores it. */
		send_request(c, "%d %d %s %s %s %d %d %lu %d %x %x %s %s %d %d %d %d %ld %d %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %s %s", CONTROL, REQ_DUMP_NODES,
		             n->name, id, n->hostname ? n->hostname : "unknown port unknown",
#ifdef DISABLE_LEGACY
		             0, 0, 0UL,
#else
		             cipher_get_nid(n->outcipher), digest_get_nid(n->outdigest), (unsigned long)digest_length(n->outdigest),
#endif
		             n->outcompression, n->options, n->status.value,
		             n->nexthop ? n->nexthop->name : "-", n->via && n->via->name ? n->via->name : "-", n->distance,
		             n->mtu, n->minmtu, n->maxmtu, (long)n->last_state_change, n->udp_ping_rtt,
		             n->in_packets, n->in_bytes, n->out_packets, n->out_bytes, transports,
		             n->tls_fingerprint ? n->tls_fingerprint : "-");
	}

	return send_request(c, "%d %d", CONTROL, REQ_DUMP_NODES);
}

bool dump_traffic(connection_t *c) {
	for splay_each(node_t, n, &node_tree)
		send_request(c, "%d %d %s %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64, CONTROL, REQ_DUMP_TRAFFIC,
		             n->name, n->in_packets, n->in_bytes, n->out_packets, n->out_bytes);

	return send_request(c, "%d %d", CONTROL, REQ_DUMP_TRAFFIC);
}
