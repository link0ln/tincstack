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
#include "event.h"
#include "logger.h"
#include "node.h"
#include "tier_gate.h"
#include "xalloc.h"

/* It set IndirectData itself: only the nodes it dials or that it lets dial it
   may talk to it, everyone else goes through them (OPTION_DECLARED_INDIRECT).
   An AutoConnect dial is a direct contact, and a firewalled node sees it
   anyway on the wire, so it is never made. */
static bool declared_indirect(node_t *n) {
	if(n->options & OPTION_DECLARED_INDIRECT) {
		return true;
	}

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
		if(n == myself || n->connection || !(n->status.has_address || n->status.reachable) || declared_indirect(n) || node_is_blocked(n->name) || n->status.no_direct || n->remote_no_direct || node_is_no_direct(n->name)) {
			continue;
		}

		count++;
	}

	if(!count) {
		return;
	}

	uint32_t r = prng(count);

	for splay_each(node_t, n, &node_tree) {
		if(n == myself || n->connection || !(n->status.has_address || n->status.reachable) || declared_indirect(n) || node_is_blocked(n->name) || n->status.no_direct || n->remote_no_direct || node_is_no_direct(n->name)) {
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
		if(n == myself || n->connection || n->status.reachable || !n->status.has_address || declared_indirect(n) || node_is_blocked(n->name) || n->status.no_direct || n->remote_no_direct || node_is_no_direct(n->name)) {
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

static timeout_t fallback_sched_timer;
static bool fallback_sched_armed = false;
static time_t fallback_unreachable_since = 0;

static void fallback_sched_cb(void *data) {
	(void)data;
	fallback_sched_armed = false;

	if(!autoconnect || low_power_mode) {
		do_fallback_autoconnect();
	}
}

void fallback_schedule_in(int delay_ms) {
	if(delay_ms < 0) {
		delay_ms = 0;
	}

	struct timeval tv = {
		.tv_sec = delay_ms / 1000,
		.tv_usec = (delay_ms % 1000) * 1000,
	};

	if(fallback_sched_armed) {
		timeout_set(&fallback_sched_timer, &tv);
	} else {
		fallback_sched_armed = true;
		timeout_add(&fallback_sched_timer, fallback_sched_cb, NULL, &tv);
	}
}

void fallback_schedule_immediate(void) {
	fallback_schedule_in(0);
}

void fallback_on_reachability_change(void) {
	fallback_schedule_in(50);
}

void fallback_exit(void) {
	if(fallback_sched_armed) {
		timeout_del(&fallback_sched_timer);
		fallback_sched_armed = false;
	}

	fallback_unreachable_since = 0;
}

static bool peer_is_primary_connectto(const node_t *n) {
	if(!n) {
		return false;
	}

	for list_each(outgoing_t, o, &outgoing_list) {
		if(o->from_config && o->node == n) {
			return true;
		}
	}

	return false;
}

static bool fallback_target_reachable(void) {
	for(size_t i = 0; ; i++) {
		const char *name = tier_gate_fallback_name_at(i);

		if(!name) {
			break;
		}

		char *tmp = xstrdup(name);
		node_t *fn = lookup_node(tmp);
		free(tmp);

		if(fn && (fn->status.reachable || fn->connection)) {
			return true;
		}
	}

	return false;
}

static void drop_unmanaged_fallback_connections(time_t oldest_primary_active_at) {
	int hold_sec = tier_gate_hold_base();
	time_t now_s = now.tv_sec;
	time_t elapsed = (oldest_primary_active_at > 0 && now_s >= oldest_primary_active_at)
	                 ? (now_s - oldest_primary_active_at) : 0;

	if(elapsed < hold_sec) {
		bool has_unmanaged = false;

		for list_each(connection_t, c, &connection_list) {
			if(c->edge && c->outgoing && (c->outgoing->is_fallback || !c->outgoing->from_config) &&
			                !c->status.tier_managed_by_peer) {
				has_unmanaged = true;
				break;
			}
		}

		if(has_unmanaged) {
			fallback_schedule_in((int)(hold_sec - elapsed) * 1000 + 100);
		}

		return;
	}

	for(;;) {
		connection_t *victim = NULL;

		for list_each(connection_t, c, &connection_list) {
			if(!c->edge || !c->outgoing || c->outgoing->from_config || !c->node) {
				continue;
			}

			if(c->status.tier_managed_by_peer) {
				continue;
			}

			if(c->node->edge_tree.count < 2) {
				continue;
			}

			victim = c;
			break;
		}

		if(!victim) {
			break;
		}

		node_t *vnode = victim->node;
		outgoing_t *vout = victim->outgoing;
		logger(DEBUG_CONNECTIONS, LOG_INFO, "Primary ConnectTo stabilized; disconnecting fallback peer %s", victim->name);

		/* Clear outgoing pointers across any sibling connections to vnode before deleting vout. */
		for list_each(connection_t, sib, &connection_list) {
			if(sib->outgoing == vout) {
				sib->outgoing = NULL;
			}
		}

		list_delete(&outgoing_list, vout);

		/* Collect and terminate all sibling connections to the fallback peer cleanly. */
		for(;;) {
			connection_t *sib_conn = NULL;

			for list_each(connection_t, sc, &connection_list) {
				if(sc == victim || (vnode && sc->node == vnode)) {
					sib_conn = sc;
					break;
				}
			}

			if(!sib_conn) {
				break;
			}

			terminate_connection(sib_conn, sib_conn->edge);
		}
	}
}

/* Emergency mesh entry failover when AutoConnect = no (or low_power_mode):
   If this node has at least one configured ConnectTo peer, switch to an
   eligible fallback peer (preferring FallbackConnectTo, then exit/higher-tier
   peers) when all configured ConnectTo peers fail or lose reachability to
   FallbackConnectTo for >= 8s. Once primary ConnectTo recovers, hold until
   peer-managed redirect (TERMREQ tier_gate) or hold_base stabilizes + alternate
   edge exists. */
void do_fallback_autoconnect(void) {
	if(tier_gate_is_enabled() && !tier_gate_has_fallback_connect_to()) {
		return;
	}

	uint32_t nc = 0;
	bool configured_active = false;
	bool has_configured = false;
	bool all_configured_failed = true;
	time_t oldest_primary_active_at = 0;

	for list_each(connection_t, c, &connection_list) {
		if(c->edge) {
			nc++;

			if((c->outgoing && c->outgoing->from_config) ||
			                (!c->status.multipath_sub && peer_is_primary_connectto(c->node))) {
				configured_active = true;

				if(c->activated_at > 0 && (!oldest_primary_active_at || c->activated_at < oldest_primary_active_at)) {
					oldest_primary_active_at = c->activated_at;
				}
			}
		}
	}

	for list_each(outgoing_t, o, &outgoing_list) {
		if(o->from_config) {
			has_configured = true;

			if(o->failures == 0 && o->transport_idx == 0 && o->last_ok_failures == 0 &&
			                !o->dropped_since_ok && o->dial_attempts_failed == 0) {
				all_configured_failed = false;
			}
		}
	}

	if(!has_configured) {
		fallback_unreachable_since = 0;
		return;
	}

	bool blind_primary_fallback = false;

	if(configured_active) {
		drop_superfluous_pending_connections();

		if(tier_gate_has_fallback_connect_to()) {
			if(fallback_target_reachable()) {
				fallback_unreachable_since = 0;
			} else {
				if(fallback_unreachable_since <= 0) {
					fallback_unreachable_since = now.tv_sec > 0 ? now.tv_sec : 1;
				}

				time_t unreach_elapsed = now.tv_sec >= fallback_unreachable_since
				                         ? (now.tv_sec - fallback_unreachable_since) : 0;

				if(unreach_elapsed >= 8) {
					blind_primary_fallback = true;
				} else {
					fallback_schedule_in((int)(8 - unreach_elapsed) * 1000 + 100);
				}
			}
		} else {
			fallback_unreachable_since = 0;
		}

		if(!blind_primary_fallback) {
			if(nc > 1) {
				drop_unmanaged_fallback_connections(oldest_primary_active_at);
			}

			return;
		}
	} else {
		fallback_unreachable_since = 0;

		if(nc > 0 || !all_configured_failed) {
			return;
		}
	}

	/* Check if a fallback outgoing attempt is already running or failed/rejected. */
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

		if(active_dial && !tier_gate_peer_in_cooldown(o->node)) {
			return;
		}

		if(!active_dial && o->failures == 0 && o->dial_attempts_failed == 0 && !o->dropped_since_ok &&
		                !tier_gate_peer_in_cooldown(o->node)) {
			return;
		}

		if(!tier_gate_peer_in_cooldown(o->node) && o->ev.cb) {
			bool has_alt = false;

			for splay_each(node_t, alt, &node_tree) {
				if(alt != myself && alt != o->node && !alt->connection && alt->status.has_address &&
				                !node_is_blocked(alt->name) && !alt->status.no_direct &&
				                !alt->remote_no_direct && !node_is_no_direct(alt->name) &&
				                !tier_gate_peer_in_cooldown(alt)) {
					has_alt = true;
					break;
				}
			}

			if(!has_alt) {
				return;
			}
		}

		logger(DEBUG_CONNECTIONS, LOG_INFO, "Fallback peer %s also unavailable; rotating candidate", o->node->name);
		list_delete_node(&outgoing_list, node);
	}

	node_t *best = NULL;
	int best_cat = -1;
	int best_sub = INT_MAX;
	uint32_t ties = 0;

	for splay_each(node_t, n, &node_tree) {
		if(n == myself || n->connection || !n->status.has_address ||
		                node_is_blocked(n->name) || n->status.no_direct ||
		                n->remote_no_direct || node_is_no_direct(n->name) ||
		                tier_gate_peer_in_cooldown(n)) {
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

		int f_rank = tier_gate_fallback_rank(n->name);

		if(blind_primary_fallback && f_rank <= 0) {
			continue;
		}

		int cat = 0;
		int sub = 0;

		if(f_rank > 0) {
			cat = 2;
			sub = f_rank;
		} else if(n->was_exit_node || n->peer_tier > 1) {
			cat = 1;
			sub = -n->peer_tier;
		}

		if(cat > best_cat || (cat == best_cat && sub < best_sub)) {
			best = n;
			best_cat = cat;
			best_sub = sub;
			ties = 1;
		} else if(cat == best_cat && sub == best_sub) {
			ties++;

			if(prng(ties) == 0) {
				best = n;
			}
		}
	}

	if(!best) {
		return;
	}

	logger(DEBUG_ALWAYS, LOG_NOTICE,
	       "%s; trying fallback mesh peer %s (cat=%d, exit=%d, tier=%d)",
	       blind_primary_fallback ? "FallbackConnectTo unreachable via primary for >=8s" : "Primary ConnectTo unreachable",
	       best->name, best_cat, best->was_exit_node ? 1 : 0, best->peer_tier);
	outgoing_t *outgoing = xzalloc(sizeof(*outgoing));
	outgoing->node = best;
	outgoing->is_fallback = true;
	list_insert_tail(&outgoing_list, outgoing);
	setup_outgoing_connection(outgoing, false);
}
