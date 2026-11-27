/*
    tier_gate.c -- Authoritative tiered admission & BGP-style flap dampening
*/

#include "system.h"

#include "tier_gate.h"
#include "address_cache.h"
#include "autoconnect.h"
#include "conf.h"
#include "conf_net.h"
#include "connection.h"
#include "edge.h"
#include "event.h"
#include "graph.h"
#include "logger.h"
#include "net.h"
#include "node.h"
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"

#define TINC_TRANSPORT_DAEMON
#include "transport.h"

#define TINC_TIER_GATE_MAX_FALLBACK 32

static bool tier_gate_enabled = false;
static int tier_hold_base_val = TIER_HOLD_BASE_DEFAULT;
static int tier_active_tier_val = 1;
static int tier_max_tier_val = 1;
static tier_state_t tier_state_val = TIER_STATE_DISABLED;

static unsigned int tier_transitions_total = 0;
static unsigned int tier_rejects_total = 0;
static unsigned int tier_redirects_total = 0;

static char *fallback_targets[TINC_TIER_GATE_MAX_FALLBACK];
static size_t fallback_target_count = 0;

static timeout_t tier_gate_timer;
static bool tier_gate_timer_armed = false;

static const char *state_to_str(tier_state_t st) {
	switch(st) {
	case TIER_STATE_DISABLED:
		return "disabled";

	case TIER_STATE_NORMAL:
		return "normal";

	case TIER_STATE_FALLBACK:
		return "fallback";

	case TIER_STATE_PROBATION:
		return "probation";
	}

	return "disabled";
}

int tier_gate_required_hold_sec(int flap_count, int base_sec) {
	if(flap_count <= 0) {
		return 0;
	}

	int eff_base = CLAMP(base_sec, 5, 600);
	int hold = eff_base;

	if(flap_count == 1) {
		hold = eff_base;
	} else if(flap_count == 2) {
		hold = eff_base * 2;
	} else if(flap_count == 3) {
		hold = eff_base * 4;
	} else {
		hold = eff_base * 7;
	}

	return MIN(hold, TIER_HOLD_MAX);
}

int tier_gate_drop_penalty_delta(int new_flap_count) {
	int idx = MAX(0, new_flap_count - 1);

	if(idx > 4) {
		idx = 4;
	}

	return TIER_DROP_PENALTY_BASE + TIER_DROP_PENALTY_STEP * idx;
}

int tier_gate_decay_penalty(int penalty, time_t elapsed_sec, bool online) {
	if(penalty <= 0 || elapsed_sec <= 0) {
		return MAX(0, penalty);
	}

	int rate = online ? TIER_DECAY_ONLINE_PER_SEC : TIER_DECAY_OFFLINE_PER_SEC;
	int64_t drop = (int64_t)elapsed_sec * (int64_t)rate;

	if(drop >= penalty) {
		return 0;
	}

	return penalty - (int)drop;
}

bool tier_gate_is_rtt_anomaly(int baseline_rtt_ms, int rtt_ms) {
	if(rtt_ms < 0) {
		return false;
	}

	if(rtt_ms > 1500) {
		return true;
	}

	if(baseline_rtt_ms > 0) {
		int thresh = MAX(300, baseline_rtt_ms * 4);

		if(rtt_ms > thresh) {
			return true;
		}
	}

	return false;
}

bool tier_gate_can_clear_quarantine(int penalty, int stable_sec, int flap_count, int base_sec) {
	if(penalty > TIER_REUSE_THRESHOLD) {
		return false;
	}

	return stable_sec >= tier_gate_required_hold_sec(flap_count, base_sec);
}

int tier_gate_read_host_tier(const char *name) {
	if(!name || !check_id(name)) {
		return 1;
	}

	splay_tree_t hcfg;
	init_configuration(&hcfg);
	int tier = 1;

	if(read_host_config(&hcfg, name, false)) {
		int v = 1;

		if(get_config_int(lookup_config(&hcfg, "PeerTier"), &v)) {
			tier = CLAMP(v, 0, 100);
		}
	}

	splay_empty_tree(&hcfg);
	return tier;
}

static void free_fallback_targets(void) {
	for(size_t i = 0; i < fallback_target_count; i++) {
		free(fallback_targets[i]);
		fallback_targets[i] = NULL;
	}

	fallback_target_count = 0;
}

static void add_fallback_target(const char *name) {
	if(!name || !*name || !check_id(name)) {
		return;
	}

	if(myself && myself->name && !strcmp(name, myself->name)) {
		return;
	}

	for(size_t i = 0; i < fallback_target_count; i++) {
		if(!strcmp(fallback_targets[i], name)) {
			return;
		}
	}

	if(fallback_target_count < TINC_TIER_GATE_MAX_FALLBACK) {
		fallback_targets[fallback_target_count++] = xstrdup(name);
	}
}

int tier_gate_fallback_rank(const char *name) {
	if(!name || !*name) {
		return 0;
	}

	for(size_t i = 0; i < fallback_target_count; i++) {
		if(!strcmp(fallback_targets[i], name)) {
			return (int)(i + 1);
		}
	}

	return 0;
}

bool tier_gate_has_fallback_connect_to(void) {
	return fallback_target_count > 0;
}

const char *tier_gate_fallback_name_at(size_t index) {
	if(index >= fallback_target_count) {
		return NULL;
	}

	return fallback_targets[index];
}

bool tier_gate_is_enabled(void) {
	return tier_gate_enabled;
}

int tier_gate_active_tier(void) {
	return tier_active_tier_val;
}

int tier_gate_max_tier(void) {
	return tier_max_tier_val;
}

int tier_gate_hold_base(void) {
	return tier_hold_base_val;
}

const char *tier_gate_state_name(void) {
	return state_to_str(tier_state_val);
}

unsigned int tier_gate_transitions_count(void) {
	return tier_transitions_total;
}

unsigned int tier_gate_rejects_count(void) {
	return tier_rejects_total;
}

unsigned int tier_gate_redirects_count(void) {
	return tier_redirects_total;
}

bool tier_gate_peer_is_healthy(const node_t *n) {
	if(!n || n == myself || node_is_blocked(n->name)) {
		return false;
	}

	if(n->peer_tier < 1 || n->tier_quarantined) {
		return false;
	}

	if(!n->connection || !n->connection->edge || !n->connection->status.active) {
		return false;
	}

	return true;
}

/* Make-before-break reachability check: verify that `target` (a lower-tier
   direct peer) already has an active bidirectional transit path in the mesh
   graph starting exclusively from healthy peers with peer_tier >= min_tier.
   Does not touch n->status.visited, so it never disturbs sssp_bfs(). */
static bool peer_reachable_via_higher_tier(const node_t *target, int min_tier) {
	if(!myself || !target || target == myself || node_tree.count == 0) {
		return false;
	}

	size_t cap = (size_t)node_tree.count;
	node_t **queue = xzalloc(cap * sizeof(*queue));
	size_t qhead = 0;
	size_t qtail = 0;

	for splay_each(node_t, rel, &node_tree) {
		if(rel == myself || rel == target || node_is_blocked(rel->name)) {
			continue;
		}

		if(rel->peer_tier < min_tier || rel->tier_quarantined) {
			continue;
		}

		if(!rel->connection || !rel->connection->edge || !rel->connection->status.active) {
			continue;
		}

		if(!lookup_edge(myself, rel) || !lookup_edge(rel, myself)) {
			continue;
		}

		if(qtail < cap) {
			queue[qtail++] = rel;
		}
	}

	while(qhead < qtail) {
		node_t *cur = queue[qhead++];

		for splay_each(edge_t, e, &cur->edge_tree) {
			if(!e->reverse || !e->to || e->to == myself) {
				continue;
			}

			if(e->to == target) {
				free(queue);
				return true;
			}

			if(node_is_blocked(e->to->name)) {
				continue;
			}

			bool already = false;

			for(size_t i = 0; i < qtail; i++) {
				if(queue[i] == e->to) {
					already = true;
					break;
				}
			}

			if(!already && qtail < cap) {
				queue[qtail++] = e->to;
			}
		}
	}

	free(queue);
	return false;
}

void tier_gate_reset_direct_path_state(node_t *n) {
	if(!n || n == myself) {
		return;
	}

	timeout_del(&n->udp_ping_timeout);
	timeout_del(&n->punch_timer);

	n->status.udp_confirmed = false;
	n->status.udp_addr_confirmed = false;
	n->udp_ping_rtt = -1;
	n->udp_ping_unanswered = 0;
	n->mtu = MTU;
	n->maxmtu = MTU;
	n->minmtu = 0;
	n->mtuprobes = 0;
	n->maxrecentlen = 0;
}

static void redirect_peer_now(node_t *n) {
	if(!n || !n->connection) {
		return;
	}

	connection_t *primary = n->connection;
	tier_redirects_total++;

	logger(DEBUG_ALWAYS, LOG_NOTICE,
	       "[TIER-GATE] Redirecting %s (tier=%d < active_tier=%d) back through higher-tier transit",
	       n->name, n->peer_tier, tier_active_tier_val);

	send_request(primary, "%d tier_gate %d %d", TERMREQ, tier_active_tier_val, n->peer_tier);

	/* Collect secondary multipath siblings first so multipath_promote_survivor()
	   cannot promote another direct socket while tearing down primary. */
	size_t max_sibs = connection_list.count > 0 ? (size_t)connection_list.count : 1;
	connection_t **sibs = xzalloc(max_sibs * sizeof(*sibs));
	size_t nsibs = 0;

	for list_each(connection_t, sib, &connection_list) {
		if(sib != primary && sib->status.multipath_sub &&
		                (sib->node == n || (!sib->node && sib->name && !strcmp(sib->name, n->name)))) {
			if(nsibs < max_sibs) {
				sibs[nsibs++] = sib;
			}
		}
	}

	for(size_t i = 0; i < nsibs; i++) {
		if(connection_is_live(sibs[i])) {
			sibs[i]->status.multipath_sub = false;
			sibs[i]->status.no_tarpit = true;
			sibs[i]->status.tier_rejected = true;
			sibs[i]->edge = NULL;
			sibs[i]->outgoing = NULL;
			terminate_connection(sibs[i], false);
		}
	}

	free(sibs);

	if(connection_is_live(primary)) {
		primary->status.no_tarpit = true;
		primary->status.tier_rejected = true;
		bool had_edge = (primary->edge != NULL);
		terminate_connection(primary, had_edge);
	}

	n->tier_redirect_grace_until = 0;
	tier_gate_reset_direct_path_state(n);
}

static void process_redirects(void) {
	if(!tier_gate_enabled || node_tree.count == 0) {
		return;
	}

	size_t cap = (size_t)node_tree.count;
	node_t **victims = xzalloc(cap * sizeof(*victims));
	size_t nvictims = 0;

	for splay_each(node_t, n, &node_tree) {
		if(n == myself || !n->connection || !n->connection->status.active || !n->connection->edge) {
			if(n != myself) {
				n->tier_redirect_grace_until = 0;
			}

			continue;
		}

		if(n->peer_tier >= tier_active_tier_val) {
			n->tier_redirect_grace_until = 0;
			continue;
		}

		if(peer_reachable_via_higher_tier(n, tier_active_tier_val)) {
			if(nvictims < cap) {
				victims[nvictims++] = n;
			}
		} else if(n->tier_redirect_grace_until == 0) {
			n->tier_redirect_grace_until = now.tv_sec + TIER_REDIRECT_GRACE_SEC;
			logger(DEBUG_ALWAYS, LOG_NOTICE,
			       "[TIER-GATE] Waking %s (tier=%d < active_tier=%d) to reconnect primary hub (%ds make-before-break grace)",
			       n->name, n->peer_tier, tier_active_tier_val, TIER_REDIRECT_GRACE_SEC);
			send_request(n->connection, "%d tier_retry_primary", PING);
		} else if(now.tv_sec >= n->tier_redirect_grace_until) {
			logger(DEBUG_ALWAYS, LOG_WARNING,
			       "[TIER-GATE] Redirect grace expired for %s (tier=%d < active_tier=%d); closing direct link",
			       n->name, n->peer_tier, tier_active_tier_val);

			if(nvictims < cap) {
				victims[nvictims++] = n;
			}
		}
	}

	for(size_t i = 0; i < nvictims; i++) {
		redirect_peer_now(victims[i]);
	}

	free(victims);
}

void tier_gate_recompute(bool allow_redirects) {
	int max_t = 1;

	for splay_each(node_t, n, &node_tree) {
		if(n == myself || node_is_blocked(n->name)) {
			continue;
		}

		if(n->peer_tier > max_t) {
			max_t = n->peer_tier;
		}
	}

	tier_max_tier_val = max_t;

	if(!tier_gate_enabled) {
		tier_active_tier_val = 1;
		tier_state_val = TIER_STATE_DISABLED;

		for splay_each(node_t, n, &node_tree) {
			n->tier_redirect_grace_until = 0;
		}

		return;
	}

	int best_healthy = 0;
	bool has_probation = false;

	for splay_each(node_t, n, &node_tree) {
		if(n == myself || node_is_blocked(n->name)) {
			continue;
		}

		if(n->peer_tier > 1 && n->tier_quarantined && n->connection && n->connection->edge && n->connection->status.active) {
			has_probation = true;
		}

		if(tier_gate_peer_is_healthy(n) && n->peer_tier > best_healthy) {
			best_healthy = n->peer_tier;
		}
	}

	int old_active = tier_active_tier_val;
	tier_state_t old_state = tier_state_val;

	int new_active = best_healthy > 0 ? best_healthy : 1;
	tier_state_t new_state;

	if(new_active >= tier_max_tier_val) {
		new_state = TIER_STATE_NORMAL;
	} else if(has_probation) {
		new_state = TIER_STATE_PROBATION;
	} else {
		new_state = TIER_STATE_FALLBACK;
	}

	tier_active_tier_val = new_active;
	tier_state_val = new_state;

	if(old_active != new_active && old_state != TIER_STATE_DISABLED) {
		tier_transitions_total++;
		logger(DEBUG_ALWAYS, LOG_NOTICE,
		       "[TIER-GATE] Active tier transition: %d -> %d (state=%s -> %s, max_tier=%d)",
		       old_active, new_active, state_to_str(old_state), state_to_str(new_state), tier_max_tier_val);
	} else if(old_state != new_state) {
		logger(DEBUG_ALWAYS, LOG_NOTICE,
		       "[TIER-GATE] State transition: %s -> %s (active_tier=%d, max_tier=%d)",
		       state_to_str(old_state), state_to_str(new_state), new_active, tier_max_tier_val);
	}

	if(allow_redirects) {
		process_redirects();
	}
}

void tier_gate_step_second(void) {
	if(!tier_gate_enabled) {
		return;
	}

	time_t now_s = now.tv_sec;
	bool promoted_any = false;
	bool need_redirect_check = false;

	for splay_each(node_t, n, &node_tree) {
		if(n == myself || node_is_blocked(n->name)) {
			continue;
		}

		bool connected = (n->connection && n->connection->edge && n->connection->status.active);

		if(connected && n->peer_tier > 1) {
			if(n->tier_connected_since <= 0) {
				n->tier_connected_since = now_s;
			}

			/* Check inflight probation probe timeout first */
			if(n->tier_quarantined && n->tier_probe_inflight &&
			                now_s - n->tier_probe_tx_tv.tv_sec >= TIER_PROBE_TIMEOUT_SEC) {
				n->tier_probe_inflight = false;
				n->tier_penalty = MIN(TIER_PENALTY_MAX, n->tier_penalty + TIER_ANOMALY_PENALTY);
				n->tier_stable_sec = 0;
				logger(DEBUG_ALWAYS, LOG_WARNING,
				       "[TIER-GATE] Probation probe timeout for %s: penalty=%d (+%d), reset stable=0s",
				       n->name, n->tier_penalty, TIER_ANOMALY_PENALTY);
			}

			/* Decay penalty while cleanly connected */
			if(n->tier_last_decay > 0 && now_s > n->tier_last_decay) {
				n->tier_penalty = tier_gate_decay_penalty(n->tier_penalty, now_s - n->tier_last_decay, true);
			}

			n->tier_last_decay = now_s;

			if(n->tier_quarantined) {
				if(!n->tier_probe_inflight && n->tier_stable_sec < INT_MAX) {
					n->tier_stable_sec++;
				}

				if(!n->tier_probe_inflight && now_s - n->tier_last_probe_sent >= TIER_PROBE_INTERVAL_SEC) {
					n->tier_last_probe_sent = now_s;
					n->tier_probe_inflight = true;
					gettimeofday(&n->tier_probe_tx_tv, NULL);
					send_request(n->connection, "%d tier_probe", PING);
				}

				int req_hold = tier_gate_required_hold_sec(n->tier_flap_count, tier_hold_base_val);

				if(tier_gate_can_clear_quarantine(n->tier_penalty, n->tier_stable_sec,
				                                  n->tier_flap_count, tier_hold_base_val)) {
					n->tier_quarantined = false;
					n->tier_probe_inflight = false;
					n->tier_last_probation_log = 0;
					promoted_any = true;
					logger(DEBUG_ALWAYS, LOG_NOTICE,
					       "[TIER-GATE] Probation cleared for %s (tier=%d): stable=%ds >= %ds, penalty=%d <= %d",
					       n->name, n->peer_tier, n->tier_stable_sec, req_hold,
					       n->tier_penalty, TIER_REUSE_THRESHOLD);
				} else if(now_s - n->tier_last_probation_log >= 15) {
					n->tier_last_probation_log = now_s;
					logger(DEBUG_ALWAYS, LOG_INFO,
					       "[TIER-GATE] Probation progress %s: flaps=%d penalty=%d/%d stable=%ds/%ds rtt=%dms",
					       n->name, n->tier_flap_count, n->tier_penalty, TIER_REUSE_THRESHOLD,
					       n->tier_stable_sec, req_hold, n->tier_last_rtt_ms);
				}
			} else if(n->tier_flap_count > 0 && n->tier_penalty == 0 &&
			                n->tier_connected_since > 0 && now_s - n->tier_connected_since >= TIER_CLEAN_RESET_SEC) {
				logger(DEBUG_ALWAYS, LOG_INFO,
				       "[TIER-GATE] Clearing flap history for %s after %ds clean uptime (flaps %d -> 0)",
				       n->name, TIER_CLEAN_RESET_SEC, n->tier_flap_count);
				n->tier_flap_count = 0;
			}
		} else if(!connected && n->tier_quarantined) {
			if(n->tier_last_decay > 0 && now_s > n->tier_last_decay) {
				n->tier_penalty = tier_gate_decay_penalty(n->tier_penalty, now_s - n->tier_last_decay, false);
			}

			n->tier_last_decay = now_s;
		}

		if(connected && n->peer_tier < tier_active_tier_val) {
			need_redirect_check = true;
		}
	}

	if(promoted_any) {
		tier_gate_recompute(true);
	} else if(need_redirect_check) {
		process_redirects();
	}
}

static void tier_gate_timer_cb(void *data) {
	(void)data;
	tier_gate_step_second();
	timeout_set(&tier_gate_timer, &(struct timeval) {1, 0});
}

void tier_gate_init(void) {
	if(tier_gate_timer_armed) {
		return;
	}

	tier_gate_timer_armed = true;
	timeout_add(&tier_gate_timer, tier_gate_timer_cb, NULL, &(struct timeval) {1, 0});
}

void tier_gate_exit(void) {
	if(tier_gate_timer_armed) {
		timeout_del(&tier_gate_timer);
		tier_gate_timer_armed = false;
	}

	free_fallback_targets();
	tier_gate_enabled = false;
	tier_hold_base_val = TIER_HOLD_BASE_DEFAULT;
	tier_active_tier_val = 1;
	tier_max_tier_val = 1;
	tier_state_val = TIER_STATE_DISABLED;
}

void tier_gate_reload(void) {
	bool enabled = false;
	get_config_bool(lookup_config(&config_tree, "TierGate"), &enabled);

	int hold_base = TIER_HOLD_BASE_DEFAULT;

	if(get_config_int(lookup_config(&config_tree, "TierHoldBase"), &hold_base)) {
		hold_base = CLAMP(hold_base, 5, 600);
	} else {
		hold_base = TIER_HOLD_BASE_DEFAULT;
	}

	free_fallback_targets();

	for(config_t *cfg = lookup_config(&config_tree, "FallbackConnectTo"); cfg; cfg = lookup_config_next(&config_tree, cfg)) {
		if(!cfg->value) {
			continue;
		}

		char *copy = xstrdup(cfg->value);
		char *saveptr = NULL;

		for(char *tok = strtok_r(copy, " \t,;", &saveptr); tok; tok = strtok_r(NULL, " \t,;", &saveptr)) {
			add_fallback_target(tok);
		}

		free(copy);
	}

	tier_gate_enabled = enabled;
	tier_hold_base_val = hold_base;

	if(enabled) {
		for splay_each(node_t, n, &node_tree) {
			if(n != myself && n->connection && n->connection->status.active &&
			                n->connection->edge && n->tier_connected_since <= 0) {
				n->tier_connected_since = n->connection->activated_at > 0 ? n->connection->activated_at : now.tv_sec;
			}
		}
	} else {
		for splay_each(node_t, n, &node_tree) {
			n->tier_quarantined = false;
			n->tier_probe_inflight = false;
			n->tier_redirect_grace_until = 0;
		}
	}

	tier_gate_recompute(true);

	logger(DEBUG_ALWAYS, LOG_INFO,
	       "[TIER-GATE] Config loaded: enabled=%s hold_base=%ds active_tier=%d max_tier=%d state=%s fallback_targets=%zu",
	       tier_gate_enabled ? "yes" : "no", tier_hold_base_val,
	       tier_active_tier_val, tier_max_tier_val, state_to_str(tier_state_val),
	       fallback_target_count);
}

void tier_gate_note_peer_rejected(node_t *n) {
	if(!n || n == myself) {
		return;
	}

	if(n->tier_reject_streak < 6) {
		n->tier_reject_streak++;
	}

	static const int backoff_sec[] = { 1, 2, 5, 10, 15, 15 };
	int idx = CLAMP(n->tier_reject_streak - 1, 0, (int)(sizeof(backoff_sec) / sizeof(backoff_sec[0])) - 1);
	int delay = backoff_sec[idx];

	n->tier_rejected_until = now.tv_sec + delay;
	fallback_schedule_in(delay * 1000 + 50);
}

time_t tier_gate_peer_retry_after(const node_t *n) {
	if(!n) {
		return 0;
	}

	return n->tier_rejected_until;
}

bool tier_gate_peer_in_cooldown(const node_t *n) {
	if(!n || n->tier_rejected_until <= 0) {
		return false;
	}

	return now.tv_sec < n->tier_rejected_until;
}

void tier_gate_clear_peer_cooldown(node_t *n) {
	if(!n) {
		return;
	}

	n->tier_rejected_until = 0;
	n->tier_reject_streak = 0;
}

void tier_gate_clear_all_cooldowns(void) {
	for splay_each(node_t, n, &node_tree) {
		n->tier_rejected_until = 0;
		n->tier_reject_streak = 0;
	}
}

void tier_gate_retry_primary_connectto(void) {
	for list_each(outgoing_t, outgoing, &outgoing_list) {
		if(!outgoing->from_config || !outgoing->node || outgoing->node->connection) {
			continue;
		}

		outgoing->timeout = 0;

		if(outgoing->node->address_cache) {
			reset_address_cache(outgoing->node->address_cache);
		}

		if(outgoing->ev.cb) {
			timeout_set(&outgoing->ev, &(struct timeval) {0, 0});
		}
	}
}

bool tier_gate_check_admission(connection_t *c, node_t *n, bool we_dialled) {
	if(!tier_gate_enabled || !c) {
		return true;
	}

	int pt = n ? n->peer_tier : tier_gate_read_host_tier(c->name);

	if(pt > 0 && pt >= tier_active_tier_val) {
		return true;
	}

	tier_rejects_total++;

	if(we_dialled && c->outgoing) {
		transport_candidate_activated(c->outgoing, c);
	}

	c->status.no_tarpit = true;
	c->status.tier_rejected = true;
	send_request(c, "%d tier_gate %d %d", TERMREQ, tier_active_tier_val, pt);

	logger(DEBUG_ALWAYS, LOG_NOTICE,
	       "[TIER-GATE] Refused direct connection with %s (%s): peer_tier=%d < active_tier=%d (state=%s)",
	       c->name ? c->name : "?", c->hostname ? c->hostname : "?",
	       pt, tier_active_tier_val, state_to_str(tier_state_val));

	/* Reactively ping any healthy higher-tier peer whose link has been silent
	   for >= 2s so dead-peer detection starts right away if a client already
	   detected a higher-tier hub outage slightly earlier than our own timer. */
	for splay_each(node_t, rel, &node_tree) {
		if(rel == myself || rel->peer_tier < tier_active_tier_val || rel->tier_quarantined) {
			continue;
		}

		connection_t *rc = rel->connection;

		if(rc && rc->status.active && !rc->status.pinged && rc->last_ping_time + 2 <= now.tv_sec) {
			send_ping(rc);
		}
	}

	return false;
}

void tier_gate_on_connection_activated(connection_t *c, node_t *n) {
	if(!c || !n || n == myself) {
		return;
	}

	tier_gate_clear_peer_cooldown(n);

	if(c->status.multipath_sub || c != n->connection) {
		return;
	}

	time_t now_s = now.tv_sec;

	if(n->tier_quarantined && n->tier_last_decay > 0 && now_s > n->tier_last_decay) {
		n->tier_penalty = tier_gate_decay_penalty(n->tier_penalty, now_s - n->tier_last_decay, false);
	}

	n->tier_connected_since = now_s;
	n->tier_last_decay = now_s;
	n->tier_last_probe_sent = 0;
	n->tier_probe_inflight = false;
	n->tier_redirect_grace_until = 0;

	if(n->tier_quarantined && tier_gate_enabled) {
		n->tier_stable_sec = 0;
		logger(DEBUG_ALWAYS, LOG_NOTICE,
		       "[TIER-GATE] Higher-tier peer %s reconnected under probation (tier=%d, flaps=%d, penalty=%d, req_hold=%ds)",
		       n->name, n->peer_tier, n->tier_flap_count, n->tier_penalty,
		       tier_gate_required_hold_sec(n->tier_flap_count, tier_hold_base_val));
	}

	tier_gate_recompute(true);

	if(tier_gate_enabled && tier_active_tier_val < tier_max_tier_val && n->peer_tier <= tier_active_tier_val) {
		send_request(c, "%d tier_hold %d %d", PING, tier_active_tier_val, tier_max_tier_val);
		logger(DEBUG_ALWAYS, LOG_NOTICE,
		       "[TIER-GATE] Admitted fallback client %s (tier=%d) while active_tier=%d < max_tier=%d",
		       n->name, n->peer_tier, tier_active_tier_val, tier_max_tier_val);
	}
}

void tier_gate_on_peer_disconnected(node_t *n) {
	if(!n || n == myself) {
		return;
	}

	n->tier_probe_inflight = false;
	n->tier_redirect_grace_until = 0;

	if(n->peer_tier > 1 && n->tier_connected_since > 0) {
		time_t now_s = now.tv_sec;

		if(n->tier_last_decay > 0 && now_s > n->tier_last_decay) {
			n->tier_penalty = tier_gate_decay_penalty(n->tier_penalty, now_s - n->tier_last_decay, true);
		}

		if(n->tier_flap_count < 100) {
			n->tier_flap_count++;
		}

		int delta = tier_gate_drop_penalty_delta(n->tier_flap_count);
		n->tier_penalty = MIN(TIER_PENALTY_MAX, n->tier_penalty + delta);
		n->tier_quarantined = true;
		n->tier_connected_since = 0;
		n->tier_last_drop = now_s;
		n->tier_last_decay = now_s;
		n->tier_stable_sec = 0;
		n->tier_last_probation_log = 0;

		if(tier_gate_enabled) {
			logger(DEBUG_ALWAYS, LOG_NOTICE,
			       "[TIER-GATE] Peer %s (tier=%d) disconnected: flaps=%d penalty=%d (+%d) hold_req=%ds; quarantined",
			       n->name, n->peer_tier, n->tier_flap_count, n->tier_penalty, delta,
			       tier_gate_required_hold_sec(n->tier_flap_count, tier_hold_base_val));
		}
	} else {
		n->tier_connected_since = 0;
	}

	if(tier_gate_enabled) {
		tier_gate_recompute(false);
	}
}

void tier_gate_on_pong(connection_t *c) {
	if(!c || !c->node || !c->node->tier_probe_inflight) {
		return;
	}

	node_t *n = c->node;
	n->tier_probe_inflight = false;

	struct timeval diff;
	timersub(&now, &n->tier_probe_tx_tv, &diff);
	int rtt_ms = (int)(diff.tv_sec * 1000 + diff.tv_usec / 1000);

	if(rtt_ms < 0) {
		rtt_ms = 0;
	}

	n->tier_last_rtt_ms = rtt_ms;

	if(tier_gate_is_rtt_anomaly(n->tier_baseline_rtt_ms, rtt_ms)) {
		n->tier_penalty = MIN(TIER_PENALTY_MAX, n->tier_penalty + TIER_ANOMALY_PENALTY);
		n->tier_stable_sec = 0;
		logger(DEBUG_ALWAYS, LOG_WARNING,
		       "[TIER-GATE] Probation RTT anomaly for %s: rtt=%dms baseline=%dms, penalty=%d (+%d), reset stable=0s",
		       n->name, rtt_ms, n->tier_baseline_rtt_ms, n->tier_penalty, TIER_ANOMALY_PENALTY);
		return;
	}

	if(n->tier_baseline_rtt_ms < 0) {
		n->tier_baseline_rtt_ms = rtt_ms;
	} else {
		n->tier_baseline_rtt_ms = (n->tier_baseline_rtt_ms * 7 + rtt_ms) / 8;
	}
}
