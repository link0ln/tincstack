/*
    autoconnect.c -- automatic connection establishment
    Copyright (C) 2017-2022 Guus Sliepen <guus@tinc-vpn.org>

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

#include "autoconnect.h"
#include "connection.h"
#include "crypto.h"
#include "edge.h"
#include "logger.h"
#include "node.h"
#include "xalloc.h"

/* It set IndirectData itself: only the nodes it dials or that it lets dial it
   may talk to it, everyone else goes through them (OPTION_DECLARED_INDIRECT).
   An AutoConnect dial is a direct contact, and a firewalled node sees it
   anyway on the wire, so it is never made. */
static bool declared_indirect(node_t *n) {
	for splay_each(edge_t, e, &n->edge_tree) {
		if(e->options & OPTION_DECLARED_INDIRECT) {
			return true;
		}
	}

	return false;
}

static void make_new_connection(void) {
	/* Select a random node we haven't connected to yet. */
	uint32_t count = 0;

	for splay_each(node_t, n, &node_tree) {
		if(n == myself || n->connection || !(n->status.has_address || n->status.reachable) || declared_indirect(n) || node_is_blocked(n->name)) {
			continue;
		}

		count++;
	}

	if(!count) {
		return;
	}

	uint32_t r = prng(count);

	for splay_each(node_t, n, &node_tree) {
		if(n == myself || n->connection || !(n->status.has_address || n->status.reachable) || declared_indirect(n) || node_is_blocked(n->name)) {
			continue;
		}

		if(r) {
			--r;
			continue;
		}

		bool found = false;

		for list_each(outgoing_t, outgoing, &outgoing_list) {
			if(outgoing->node == n) {
				found = true;
				break;
			}
		}

		if(!found) {
			logger(DEBUG_CONNECTIONS, LOG_INFO, "Autoconnecting to %s", n->name);
			outgoing_t *outgoing = xzalloc(sizeof(*outgoing));
			outgoing->node = n;
			list_insert_tail(&outgoing_list, outgoing);
			setup_outgoing_connection(outgoing, false);
		}

		break;
	}
}

static void connect_to_unreachable(void) {
	/* Select a random known node. The rationale is that if there are many
	 * reachable nodes, and only a few unreachable nodes, we don't want all
	 * reachable nodes to try to connect to the unreachable ones at the
	 * same time. This way, we back off automatically. Conversely, if there
	 * are only a few reachable nodes, and many unreachable ones, we're
	 * going to try harder to connect to them. */

	uint32_t r = prng(node_tree.count);

	for splay_each(node_t, n, &node_tree) {
		if(r--) {
			continue;
		}

		/* Is it unreachable and do we know an address for it? If not, return. */
		if(n == myself || n->connection || n->status.reachable || !n->status.has_address || declared_indirect(n) || node_is_blocked(n->name)) {
			return;
		}

		/* Are we already trying to make an outgoing connection to it? If so, return. */
		for list_each(outgoing_t, outgoing, &outgoing_list) {
			if(outgoing->node == n) {
				return;
			}
		}

		logger(DEBUG_CONNECTIONS, LOG_INFO, "Autoconnecting to %s", n->name);
		outgoing_t *outgoing = xzalloc(sizeof(*outgoing));
		outgoing->node = n;
		list_insert_tail(&outgoing_list, outgoing);
		setup_outgoing_connection(outgoing, false);

		return;
	}
}

static void drop_superfluous_outgoing_connection(void) {
	/* Choose a random outgoing connection to a node that has at least one other connection. */
	uint32_t count = 0;

	for list_each(connection_t, c, &connection_list) {
		if(!c->edge || !c->outgoing || c->outgoing->from_config || !c->node || c->node->edge_tree.count < 2) {
			continue;
		}

		count++;
	}

	if(!count) {
		return;
	}

	uint32_t r = prng(count);

	for list_each(connection_t, c, &connection_list) {
		if(!c->edge || !c->outgoing || c->outgoing->from_config || !c->node || c->node->edge_tree.count < 2) {
			continue;
		}

		if(r--) {
			continue;
		}

		logger(DEBUG_CONNECTIONS, LOG_INFO, "Autodisconnecting from %s", c->name);
		list_delete(&outgoing_list, c->outgoing);
		c->outgoing = NULL;
		terminate_connection(c, c->edge);
		break;
	}
}

static void drop_superfluous_pending_connections(void) {
	for list_each(outgoing_t, o, &outgoing_list) {
		if(o->from_config) {
			continue;
		}

		/* Only look for connections that are waiting to be retried later. */
		bool found = false;

		for list_each(connection_t, c, &connection_list) {
			if(c->outgoing == o) {
				found = true;
				break;
			}
		}

		if(found) {
			continue;
		}

		logger(DEBUG_CONNECTIONS, LOG_INFO, "Cancelled outgoing connection to %s", o->node->name);
		list_delete_node(&outgoing_list, node);
	}
}

void do_autoconnect(void) {
	/* Count number of active connections. */
	uint32_t nc = 0;

	for list_each(connection_t, c, &connection_list) {
		if(c->edge) {
			nc++;
		}
	}

	/* Less than 3 connections? Eagerly try to make a new one. */
	if(nc < 3) {
		make_new_connection();
		return;
	}

	/* More than 3 connections? See if we can get rid of a superfluous one. */
	if(nc > 3) {
		drop_superfluous_outgoing_connection();
	}

	/* Drop pending outgoing connections from the outgoing list. */
	drop_superfluous_pending_connections();

	/* Check if there are unreachable nodes that we should try to connect to. */
	connect_to_unreachable();
}

/* Emergency mesh entry failover when AutoConnect = no:
   If this node has at least one configured ConnectTo peer (so it is not a
   passive server-only node), but currently has zero active meta connections
   (nc == 0) and every configured ConnectTo peer has failed at least one full
   carrier walk (failures >= 1), try connecting to one known mesh peer whose
   address we have (from config or cache/<peer>). Once a primary ConnectTo
   connection recovers, drop the temporary fallback connection. */
void do_fallback_autoconnect(void) {
	uint32_t nc = 0;
	bool configured_active = false;
	bool has_configured = false;
	bool all_configured_failed = true;

	for list_each(connection_t, c, &connection_list) {
		if(c->edge) {
			nc++;

			if(c->outgoing && c->outgoing->from_config) {
				configured_active = true;
			}
		}
	}

	for list_each(outgoing_t, o, &outgoing_list) {
		if(o->from_config) {
			has_configured = true;

			if(o->failures == 0 && o->transport_idx == 0 && o->last_ok_failures == 0) {
				all_configured_failed = false;
			}
		}
	}

	if(!has_configured) {
		return;
	}

	if(configured_active) {
		drop_superfluous_pending_connections();

		if(nc > 1) {
			drop_superfluous_outgoing_connection();
		}

		return;
	}

	if(nc > 0 || !all_configured_failed) {
		return;
	}

	/* Check if a fallback outgoing attempt is already running or failed. */
	for list_each(outgoing_t, o, &outgoing_list) {
		if(o->from_config) {
			continue;
		}

		bool active_dial = false;

		for list_each(connection_t, c, &connection_list) {
			if(c->outgoing == o) {
				active_dial = true;
				break;
			}
		}

		if(active_dial || o->failures == 0) {
			return;
		}

		logger(DEBUG_CONNECTIONS, LOG_INFO, "Fallback peer %s also unreachable; rotating candidate", o->node->name);
		list_delete_node(&outgoing_list, node);
	}

	uint32_t count = 0;

	for splay_each(node_t, n, &node_tree) {
		if(n == myself || n->connection || !n->status.has_address || node_is_blocked(n->name)) {
			continue;
		}

		bool in_outgoing = false;

		for list_each(outgoing_t, o, &outgoing_list) {
			if(o->node == n) {
				in_outgoing = true;
				break;
			}
		}

		if(!in_outgoing) {
			count++;
		}
	}

	if(!count) {
		return;
	}

	uint32_t r = prng(count);

	for splay_each(node_t, n, &node_tree) {
		if(n == myself || n->connection || !n->status.has_address || node_is_blocked(n->name)) {
			continue;
		}

		bool in_outgoing = false;

		for list_each(outgoing_t, o, &outgoing_list) {
			if(o->node == n) {
				in_outgoing = true;
				break;
			}
		}

		if(in_outgoing) {
			continue;
		}

		if(r) {
			--r;
			continue;
		}

		logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Primary ConnectTo unreachable; trying fallback mesh peer %s", n->name);
		outgoing_t *outgoing = xzalloc(sizeof(*outgoing));
		outgoing->node = n;
		list_insert_tail(&outgoing_list, outgoing);
		setup_outgoing_connection(outgoing, false);
		break;
	}
}
