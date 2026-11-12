/*
    protocol_key.c -- handle the meta-protocol, key exchange
    Copyright (C) 1999-2005 Ivo Timmermans,
                  2000-2017 Guus Sliepen <guus@tinc-vpn.org>

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

#include "cipher.h"
#include "conf.h"
#include "connection.h"
#include "crypto.h"
#include "edge.h"
#include "ed25519/sha512.h"
#include "logger.h"
#include "names.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "obfs.h"
#include "protocol.h"
#include "route.h"
#include "sptps.h"
#include "utils.h"
#include "compression.h"
#include "random.h"
#include "xalloc.h"
#include "yamlconf.h"

#define TINC_TRANSPORT_DAEMON
#include "transport.h"

void send_key_changed(void) {
#ifndef DISABLE_LEGACY
	send_request(everyone, "%d %x %s", KEY_CHANGED, prng(UINT32_MAX), myself->name);

	/* Immediately send new keys to directly connected nodes to keep UDP mappings alive */

	for list_each(connection_t, c, &connection_list) {
		if(c->edge && c->node && c->node->status.reachable && !c->node->status.sptps) {
			send_ans_key(c->node);
		}
	}

#endif

	/* Force key exchange for connections using SPTPS */

	if(experimental) {
		for splay_each(node_t, n, &node_tree) {
			if(n->status.reachable && n->status.validkey && n->status.sptps) {
				n->last_req_key = now.tv_sec;
				sptps_force_kex(&n->sptps);
			}
		}
	}
}

bool key_changed_h(connection_t *c, const char *request) {
	char name[MAX_STRING_SIZE];
	node_t *n;

	if(sscanf(request, "%*d %*x " MAX_STRING, name) != 1) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "KEY_CHANGED",
		       c->name, c->hostname);
		return false;
	}

	if(seen_request(request)) {
		return true;
	}

	n = lookup_node(name);

	if(!n) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got %s from %s (%s) origin %s which does not exist",
		       "KEY_CHANGED", c->name, c->hostname, name);
		return true;
	}

	if(!n->status.sptps) {
		n->status.validkey = false;
		n->last_req_key = 0;
	} else {
		n->last_req_key = now.tv_sec;
	}

	/* Tell the others */

	if(!tunnelserver) {
		forward_request(c, request);
	}

	return true;
}

static bool send_sptps_data_myself(void *handle, uint8_t type, const void *data, size_t len) {
	return send_sptps_data(handle, myself, type, data, len);
}

static bool send_initial_sptps_data(void *handle, uint8_t type, const void *data, size_t len) {
	(void)type;
	node_t *to = handle;
	to->sptps.send_data = send_sptps_data_myself;

	char *buf = alloca(B64_SIZE(len));
	b64encode_tinc(data, buf, len);

	return send_request(to->nexthop->connection, "%d %s %s %d %s", REQ_KEY, myself->name, to->name, REQ_KEY, buf);
}

/* Ask a node we only know from the meta graph for its Ed25519 public key,
   without starting an SPTPS session (that is what send_req_key() does, and it
   is the *data* path). Defect C: two nodes invited by the same third node have
   no host record for each other, so neither can finish the ID exchange of a
   direct meta connection until one of them has learned the other's key. The
   key exchange used to be triggered only by traffic, i.e. only after the meta
   connection had already failed and the pair had settled on the relay.

   Rate limited to one request per node per REQ_PUBKEY_INTERVAL: id_h() calls
   this for an unauthenticated peer that claims a name we know, so without the
   limit a stranger opening connections in a loop could make us flood the relay
   with requests. */
#define REQ_PUBKEY_INTERVAL 5

/* How long an SPTPS session we started counts as "simultaneous" with a REQ_KEY
   arriving from the peer (see the glare tie-break in req_key_ext_h). Real glare
   is decided in milliseconds; this is generous enough to cover a relayed round
   trip on a slow path and far short of the 24-36 s restart cooldown it exists
   to avoid waiting for. */
#define SPTPS_GLARE_WINDOW 5

/* Mesh quorum verification for automatic Ed25519 public key rotation.
   When a node advertises an Ed25519PublicKey that differs from our cached
   record, we query reachable mesh peers (KEY_QUORUM_REQ) before replacing the
   key. Each peer replies (KEY_QUORUM_ANS) with the key it holds for the target
   and whether it has an active authenticated direct edge or SPTPS session. */
#define KEY_QUORUM_REQ          100
#define KEY_QUORUM_ANS          101
#define KEY_QUORUM_INTERVAL     10
#define KEY_QUORUM_COLLECT_SEC  5
#define KEY_QUORUM_WINDOW       30

#define KEY_QUORUM_FLAG_HAS_KEY     0x01
#define KEY_QUORUM_FLAG_DIRECT_EDGE 0x02
#define KEY_QUORUM_FLAG_VALID_SPTPS 0x04

#define MAX_TRANSITIVE_FWD_ENTRIES  4096U
#define TRANSITIVE_FWD_BURST        12U
#define TRANSITIVE_FWD_REFILL_PER_S 4U
#define MAX_SHADOW_SPTPS_ENTRIES    128U

typedef struct transitive_fwd_entry_t {
	char *from_name;
	char *to_name;
	int kind;
	uint32_t tokens;
	time_t last_refill;
	time_t last_dup_sec;
	uint8_t last_hash[16];
	list_node_t *fifo_node;
} transitive_fwd_entry_t;

static list_t transitive_fwd_fifo = {
	.head = NULL, .tail = NULL, .count = 0, .delete = NULL,
};

static int transitive_fwd_compare(const transitive_fwd_entry_t *a, const transitive_fwd_entry_t *b) {
	int c = strcmp(a->from_name, b->from_name);

	if(c) {
		return c;
	}

	c = strcmp(a->to_name, b->to_name);

	if(c) {
		return c;
	}

	return (a->kind > b->kind) - (a->kind < b->kind);
}

static void free_transitive_fwd_entry(transitive_fwd_entry_t *e) {
	if(!e) {
		return;
	}

	if(e->fifo_node) {
		list_node_t *fn = e->fifo_node;
		e->fifo_node = NULL;
		list_unlink_node(&transitive_fwd_fifo, fn);
		free(fn);
	}

	free(e->from_name);
	free(e->to_name);
	free(e);
}

static splay_tree_t transitive_fwd_tree = {
	.compare = (splay_compare_t)transitive_fwd_compare,
	.delete = (splay_action_t)free_transitive_fwd_entry,
};

bool allow_transitive_forward(const char *from_name, const char *to_name, int kind, const char *payload) {
	if(!from_name || !to_name || !*from_name || !*to_name) {
		return false;
	}

	uint8_t digest[64];
	memset(digest, 0, sizeof(digest));

	if(payload) {
		sha512(payload, strlen(payload), digest);
	}

	transitive_fwd_entry_t probe = {
		.from_name = (char *)from_name,
		.to_name = (char *)to_name,
		.kind = kind,
	};

	transitive_fwd_entry_t *e = splay_search(&transitive_fwd_tree, &probe);

	if(!e) {
		while(transitive_fwd_tree.count >= MAX_TRANSITIVE_FWD_ENTRIES && transitive_fwd_fifo.head) {
			transitive_fwd_entry_t *oldest = transitive_fwd_fifo.head->data;
			splay_delete(&transitive_fwd_tree, oldest);
		}

		e = xzalloc(sizeof(*e));
		e->from_name = xstrdup(from_name);
		e->to_name = xstrdup(to_name);
		e->kind = kind;
		e->tokens = TRANSITIVE_FWD_BURST;
		e->last_refill = now.tv_sec;
		e->fifo_node = list_insert_tail(&transitive_fwd_fifo, e);
		splay_insert(&transitive_fwd_tree, e);
	} else {
		if(now.tv_sec > e->last_refill) {
			time_t dt = now.tv_sec - e->last_refill;
			uint64_t add = (uint64_t)dt * TRANSITIVE_FWD_REFILL_PER_S;

			if(e->tokens + add > TRANSITIVE_FWD_BURST) {
				e->tokens = TRANSITIVE_FWD_BURST;
			} else {
				e->tokens += (uint32_t)add;
			}

			e->last_refill = now.tv_sec;
		} else if(now.tv_sec < e->last_refill) {
			e->last_refill = now.tv_sec;
		}

		if(payload && e->last_dup_sec == now.tv_sec && !memcmp(e->last_hash, digest, sizeof(e->last_hash))) {
			return false;
		}
	}

	if(e->tokens == 0) {
		return false;
	}

	e->tokens--;

	if(payload) {
		e->last_dup_sec = now.tv_sec;
		memcpy(e->last_hash, digest, sizeof(e->last_hash));
	}

	return true;
}

typedef struct shadow_sptps_t {
	char *peer_name;
	sptps_t sptps;
	time_t created_at;
	time_t last_force_kex;
	bool authenticated;
	list_node_t *fifo_node;
} shadow_sptps_t;

static list_t shadow_sptps_fifo = {
	.head = NULL, .tail = NULL, .count = 0, .delete = NULL,
};

static int shadow_sptps_compare(const shadow_sptps_t *a, const shadow_sptps_t *b) {
	return strcmp(a->peer_name, b->peer_name);
}

static void free_shadow_sptps(shadow_sptps_t *sh) {
	if(!sh) {
		return;
	}

	if(sh->fifo_node) {
		list_node_t *fn = sh->fifo_node;
		sh->fifo_node = NULL;
		list_unlink_node(&shadow_sptps_fifo, fn);
		free(fn);
	}

	sptps_stop(&sh->sptps);
	free(sh->peer_name);
	free(sh);
}

static splay_tree_t shadow_sptps_tree = {
	.compare = (splay_compare_t)shadow_sptps_compare,
	.delete = (splay_action_t)free_shadow_sptps,
};

static bool send_shadow_sptps_data(void *handle, uint8_t type, const void *data, size_t len) {
	shadow_sptps_t *sh = handle;

	if(!sh || !sh->peer_name || !myself) {
		return false;
	}

	node_t *peer = lookup_node(sh->peer_name);

	if(!peer) {
		return false;
	}

	return send_sptps_data(peer, myself, type, data, len);
}

static bool shadow_receive_record(void *handle, uint8_t type, const void *data, uint16_t len) {
	shadow_sptps_t *sh = handle;

	if(!sh) {
		return false;
	}

	if(type == SPTPS_HANDSHAKE) {
		sh->authenticated = true;
		return true;
	}

	node_t *peer = lookup_node(sh->peer_name);

	if(peer && sh->authenticated) {
		return receive_sptps_record(peer, type, data, len);
	}

	return true;
}

static bool shadow_sptps_try_receive(node_t *from, const void *buf, size_t len) {
	if(!from || !from->name || !buf || !len) {
		return false;
	}

	shadow_sptps_t probe = { .peer_name = from->name };
	shadow_sptps_t *sh = splay_search(&shadow_sptps_tree, &probe);

	if(!sh) {
		return false;
	}

	if(now.tv_sec - sh->created_at > 30) {
		splay_delete(&shadow_sptps_tree, sh);
		return false;
	}

	size_t consumed = sptps_receive_data(&sh->sptps, buf, len);

	if(!consumed) {
		splay_delete(&shadow_sptps_tree, sh);
		return false;
	}

	if(sh->authenticated) {
		sptps_stop(&from->sptps);
		from->sptps = sh->sptps;
		from->sptps.handle = from;
		from->sptps.send_data = send_sptps_data_myself;
		from->sptps.receive_record = receive_sptps_record;
		memset(&sh->sptps, 0, sizeof(sh->sptps));
		splay_delete(&shadow_sptps_tree, sh);
		receive_sptps_record(from, SPTPS_HANDSHAKE, NULL, 0);
	}

	return true;
}

static int str_compare_key(const char *a, const char *b) {
	return strcmp(a, b);
}

static void free_str_key(char *s) {
	free(s);
}

static splay_tree_t tofu_unpinned_tree = {
	.compare = (splay_compare_t)str_compare_key,
	.delete = (splay_action_t)free_str_key,
};

static void mark_node_tofu_unpinned(const char *name) {
	if(!name || !*name) {
		return;
	}

	if(!splay_search(&tofu_unpinned_tree, name)) {
		splay_insert(&tofu_unpinned_tree, xstrdup(name));
	}
}

static bool node_has_pinned_ecdsa_key(node_t *peer) {
	if(!peer || peer == myself || !peer->name || !*peer->name) {
		return false;
	}

	if(splay_search(&tofu_unpinned_tree, peer->name)) {
		return false;
	}

	if(!node_read_ecdsa_public_key(peer) || !ecdsa_active(peer->ecdsa)) {
		return false;
	}

	splay_tree_t cfg;
	init_configuration(&cfg);

	if(!read_host_config(&cfg, peer->name, false)) {
		splay_empty_tree(&cfg);
		return false;
	}

	ecdsa_t *pinned = NULL;
	char *cfg_pk = NULL;
	char *pubfile = NULL;

	if(get_config_string(lookup_config(&cfg, "Ed25519PublicKey"), &cfg_pk)) {
		pinned = ecdsa_set_base64_public_key(cfg_pk);
		free(cfg_pk);
	} else if(!yamlconf_path) {
		if(!get_config_string(lookup_config(&cfg, "Ed25519PublicKeyFile"), &pubfile) && confbase) {
			xasprintf(&pubfile, "%s" SLASH "hosts" SLASH "%s", confbase, peer->name);
		}

		if(pubfile) {
			FILE *fp = fopen(pubfile, "r");

			if(fp) {
				pinned = ecdsa_read_pem_public_key(fp);
				fclose(fp);
			}

			free(pubfile);
		}
	}

	splay_empty_tree(&cfg);

	if(!ecdsa_active(pinned)) {
		ecdsa_free(pinned);
		return false;
	}

	char *b64_pinned = ecdsa_get_base64_public_key(pinned);
	char *b64_mem = ecdsa_get_base64_public_key(peer->ecdsa);
	bool match = (b64_pinned && b64_mem && !strcmp(b64_pinned, b64_mem));

	free(b64_pinned);
	free(b64_mem);
	ecdsa_free(pinned);

	return match;
}

typedef struct quorum_round_t {
	char *target_name;
	char nonce[33];
	uint32_t responses_received;
	uint32_t verified_new;
	bool window_elapsed;
	timeout_t collect_timer;
	list_t asked_names;
} quorum_round_t;

static void evaluate_key_quorum(node_t *target);
static void free_quorum_voter(const void *p);

static int quorum_round_compare(const quorum_round_t *a, const quorum_round_t *b) {
	return strcmp(a->target_name, b->target_name);
}

static void free_quorum_round(quorum_round_t *r) {
	if(!r) {
		return;
	}

	timeout_del(&r->collect_timer);
	r->asked_names.delete = free_quorum_voter;
	list_empty_list(&r->asked_names);
	free(r->target_name);
	free(r);
}

static splay_tree_t quorum_round_tree = {
	.compare = (splay_compare_t)quorum_round_compare,
	.delete = (splay_action_t)free_quorum_round,
};

static quorum_round_t *lookup_quorum_round(const char *target_name) {
	if(!target_name) {
		return NULL;
	}

	quorum_round_t probe = { .target_name = (char *)target_name };
	return splay_search(&quorum_round_tree, &probe);
}

static bool quorum_was_asked(const quorum_round_t *r, const char *voter_name) {
	if(!r || !voter_name) {
		return false;
	}

	for list_each(const char, asked, &r->asked_names) {
		if(!strcmp(asked, voter_name)) {
			return true;
		}
	}

	return false;
}

static void quorum_collect_timeout_cb(void *data) {
	quorum_round_t *r = data;

	if(!r || !r->target_name) {
		return;
	}

	r->window_elapsed = true;
	node_t *target = lookup_node(r->target_name);

	if(!target || !target->pending_pubkey) {
		splay_delete(&quorum_round_tree, r);
		return;
	}

	evaluate_key_quorum(target);
}

void exit_key_quorum(void) {
	splay_empty_tree(&quorum_round_tree);
	splay_empty_tree(&shadow_sptps_tree);
	splay_empty_tree(&transitive_fwd_tree);
	list_empty_list(&shadow_sptps_fifo);
	list_empty_list(&transitive_fwd_fifo);
	splay_empty_tree(&tofu_unpinned_tree);
}

static bool is_valid_quorum_nonce(const char *nonce) {
	if(!nonce) {
		return false;
	}

	size_t len = strlen(nonce);

	if(len < 16 || len > 64) {
		return false;
	}

	for(size_t i = 0; i < len; i++) {
		if(!isxdigit((unsigned char)nonce[i])) {
			return false;
		}
	}

	return true;
}

static ecdsa_t *get_my_quorum_ecdsa(void) {
	if(myself && myself->connection && ecdsa_active(myself->connection->ecdsa)) {
		return myself->connection->ecdsa;
	}

	if(myself && ecdsa_active(myself->ecdsa)) {
		return myself->ecdsa;
	}

	return NULL;
}

static bool ecdsa_sign_base64(ecdsa_t *ecdsa, const void *msg, size_t len, char **sig_b64_out) {
	if(!ecdsa_active(ecdsa) || !sig_b64_out) {
		return false;
	}

	size_t siglen = ecdsa_size(ecdsa);

	if(siglen == 0 || siglen > 128) {
		return false;
	}

	uint8_t raw_sig[128];

	if(!ecdsa_sign(ecdsa, msg, len, raw_sig)) {
		return false;
	}

	char *b64 = xmalloc(B64_SIZE(siglen));
	b64encode_tinc(raw_sig, b64, siglen);
	*sig_b64_out = b64;
	return true;
}

static bool ecdsa_verify_base64(ecdsa_t *ecdsa, const void *msg, size_t len, const char *sig_b64) {
	if(!ecdsa_active(ecdsa) || !sig_b64) {
		return false;
	}

	size_t siglen = ecdsa_size(ecdsa);

	if(siglen == 0 || siglen > 128) {
		return false;
	}

	size_t b64len = strlen(sig_b64);

	if(b64len != (siglen * 4 + 2) / 3) {
		return false;
	}

	uint8_t raw_sig[128];

	if(b64decode_tinc(sig_b64, raw_sig, b64len) != siglen) {
		return false;
	}

	return ecdsa_verify(ecdsa, msg, len, raw_sig);
}

bool send_req_pubkey_refresh(node_t *to) {
	if(!to || !to->status.reachable || !to->nexthop || !to->nexthop->connection || to == myself) {
		return false;
	}

	if(to->last_req_pubkey && now.tv_sec - to->last_req_pubkey < REQ_PUBKEY_INTERVAL) {
		return false;
	}

	to->last_req_pubkey = now.tv_sec;
	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Refreshing Ed25519 key for %s (%s) over the meta graph", to->name, to->hostname);
	return send_request(to->nexthop->connection, "%d %s %s %d", REQ_KEY, myself->name, to->name, REQ_PUBKEY);
}

static void free_quorum_voter(const void *p) {
	free((void *)p);
}

static void clear_key_quorum(node_t *target) {
	if(!target) {
		return;
	}

	if(target->name) {
		quorum_round_t *r = lookup_quorum_round(target->name);

		if(r) {
			splay_delete(&quorum_round_tree, r);
		}
	}

	free(target->pending_pubkey);
	target->pending_pubkey = NULL;
	target->quorum_nonce[0] = '\0';
	target->quorum_asked_peers = 0;
	target->quorum_votes_new = 0;
	target->quorum_votes_old = 0;
	target->quorum_direct_new = 0;
	target->quorum_verified_old = 0;
	target->quorum_voters.delete = free_quorum_voter;
	list_empty_list(&target->quorum_voters);
}

static bool quorum_has_voted(const node_t *target, const char *voter_name) {
	if(!target || !voter_name) {
		return false;
	}

	for list_each(const char, v, &target->quorum_voters) {
		if(!strcmp(v, voter_name)) {
			return true;
		}
	}

	return false;
}

static void start_key_quorum(node_t *target, const char *candidate_pubkey) {
	if(!target || target == myself || !candidate_pubkey || !*candidate_pubkey) {
		return;
	}

	if((target->connection && target->connection->status.active) || target->status.validkey) {
		logger(DEBUG_ALWAYS, LOG_WARNING,
		       "Refusing Ed25519 key replacement for %s: local node holds an active authenticated session under the existing key",
		       target->name);
		clear_key_quorum(target);
		return;
	}

	if(target->pending_pubkey && !strcmp(target->pending_pubkey, candidate_pubkey) &&
	                now.tv_sec - target->pending_pubkey_time < KEY_QUORUM_INTERVAL) {
		return;
	}

	/* Count eligible locally-pinned reachable mesh peers first. Transient nodes
	   learned solely via ADD_EDGE / TOFU are excluded to prevent Sybil votes,
	   and auto-repin is refused whenever fewer than 2 pinned voters exist. */
	uint32_t eligible = 0;

	for splay_each(node_t, v, &node_tree) {
		if(v == myself || v == target || !v->status.reachable || !v->nexthop || !v->nexthop->connection) {
			continue;
		}

		if(!node_has_pinned_ecdsa_key(v)) {
			continue;
		}

		eligible++;
	}

	if(eligible < 2) {
		logger(DEBUG_ALWAYS, LOG_WARNING,
		       "Refusing automatic Ed25519 key update for %s: only %u locally-pinned reachable peer(s) available (< 2 required for quorum); manual administrator key update is required",
		       target->name, eligible);
		clear_key_quorum(target);
		return;
	}

	clear_key_quorum(target);

	uint8_t nonce_raw[16];
	randomize(nonce_raw, sizeof(nonce_raw));
	bin2hex(nonce_raw, target->quorum_nonce, sizeof(nonce_raw));
	target->quorum_nonce[32] = '\0';

	target->pending_pubkey = xstrdup(candidate_pubkey);
	target->pending_pubkey_time = now.tv_sec;

	quorum_round_t *round = xzalloc(sizeof(*round));
	round->target_name = xstrdup(target->name);
	memcpy(round->nonce, target->quorum_nonce, sizeof(round->nonce));
	round->asked_names.delete = free_quorum_voter;
	splay_insert(&quorum_round_tree, round);

	for splay_each(node_t, v, &node_tree) {
		if(v == myself || v == target || !v->status.reachable || !v->nexthop || !v->nexthop->connection) {
			continue;
		}

		if(!node_has_pinned_ecdsa_key(v)) {
			continue;
		}

		if(v->quorum_voted_for == target) {
			v->quorum_voted_for = NULL;
			v->quorum_voted_at = 0;
		}

		list_insert_tail(&round->asked_names, xstrdup(v->name));
		send_request(v->nexthop->connection, "%d %s %s %d %s %s",
		             REQ_KEY, myself->name, v->name, KEY_QUORUM_REQ, target->name, target->quorum_nonce);
		target->quorum_asked_peers++;
	}

	timeout_add(&round->collect_timer, quorum_collect_timeout_cb, round, &(struct timeval) {
		KEY_QUORUM_COLLECT_SEC, 0
	});

	logger(DEBUG_ALWAYS, LOG_INFO,
	       "Node %s (%s) advertised a new Ed25519 public key; querying %u locally-pinned reachable peer(s) for quorum verification",
	       target->name, target->hostname, target->quorum_asked_peers);
}

static void evaluate_key_quorum(node_t *target) {
	if(!target || !target->pending_pubkey) {
		return;
	}

	/* Local veto: if we ourselves hold an active authenticated meta connection
	   or verified SPTPS session with `target' under the existing key, never
	   replace our cached key. */
	if((target->connection && target->connection->status.active) || target->status.validkey) {
		logger(DEBUG_ALWAYS, LOG_WARNING,
		       "Quorum rejected Ed25519 key update for %s: local node holds an active authenticated session under the existing key",
		       target->name);
		clear_key_quorum(target);
		return;
	}

	/* Safety veto: if any peer in the mesh holds an active, cryptographically
	   verified session (direct meta edge or verified SPTPS session) with
	   `target' under a DIFFERENT key, immediately veto and do not replace. */
	if(target->quorum_verified_old > 0) {
		logger(DEBUG_ALWAYS, LOG_WARNING,
		       "Quorum rejected Ed25519 key update for %s: %u peer(s) still hold an active verified session under the existing key",
		       target->name, target->quorum_verified_old);
		clear_key_quorum(target);
		return;
	}

	quorum_round_t *round = lookup_quorum_round(target->name);

	if(!round || strcmp(round->nonce, target->quorum_nonce) != 0) {
		clear_key_quorum(target);
		return;
	}

	bool all_responded = (target->quorum_asked_peers >= 2 &&
	                      round->responses_received >= target->quorum_asked_peers);

	/* Prevent early-approval race before a slow honest peer can deliver a hard
	   veto (quorum_verified_old > 0): wait until either 100% of asked pinned
	   peers have responded or the collection timeout window has elapsed. */
	if(!all_responded && !round->window_elapsed) {
		return;
	}

	bool approved = false;

	if(target->quorum_asked_peers >= 2 &&
	                target->quorum_votes_new >= 2 &&
	                target->quorum_votes_new > target->quorum_votes_old &&
	                target->quorum_verified_old == 0) {
		if(all_responded) {
			approved = true;
		} else if(round->window_elapsed &&
		                (target->quorum_votes_new * 2 > target->quorum_asked_peers ||
		                 target->quorum_direct_new >= 1 ||
		                 round->verified_new >= 2)) {
			approved = true;
		}
	}

	if(!approved) {
		logger(DEBUG_ALWAYS, LOG_WARNING,
		       "Quorum rejected Ed25519 key update for %s (new_votes=%u, old_votes=%u, asked=%u, responses=%u); manual administrator key update is required if the key legitimately rotated",
		       target->name, target->quorum_votes_new, target->quorum_votes_old,
		       target->quorum_asked_peers, round->responses_received);
		clear_key_quorum(target);
		return;
	}

	ecdsa_t *new_key = ecdsa_set_base64_public_key(target->pending_pubkey);

	if(!new_key) {
		clear_key_quorum(target);
		return;
	}

	logger(DEBUG_ALWAYS, LOG_NOTICE,
	       "Quorum confirmed updated Ed25519 public key for %s (new_votes=%u, old_votes=%u, direct_neighbors=%u); updating cached key",
	       target->name, target->quorum_votes_new, target->quorum_votes_old, target->quorum_direct_new);

	ecdsa_free(target->ecdsa);
	target->ecdsa = new_key;
	replace_config_file(target->name, "Ed25519PublicKey", target->pending_pubkey);
	target->in_config = true;

	clear_key_quorum(target);

	obfs_link_rekey_node(target);
	sptps_stop(&target->sptps);
	target->status.validkey = false;
	target->status.waitingforkey = false;
	target->last_req_key = 0;

	if(target->status.reachable && !(target->connection && node_tcponly(target))) {
		send_req_key(target);
	}
}

bool send_req_pubkey(node_t *to) {
	if(node_read_ecdsa_public_key(to)) {
		return true;
	}

	return send_req_pubkey_refresh(to);
}

/* Defect E, point 3. Stream AC made a node's accept list travel as an extra
   token on ANS_PUBKEY -- but ANS_PUBKEY only ever answers a node that does not
   have the key yet, and a key is cached for ever. Two nodes that have met
   before therefore never learn each other's carriers and each keeps assuming
   the other is upstream tinc, i.e. plain-only. That is measured: the field
   pair behind one NAT still shows `transports plain' for each other after
   hours.

   The refresh asks the same question again over the graph. Deliberately the
   SAME request as before rather than a new one: an upstream tinc answers
   REQ_PUBKEY whether or not it has our key, and answers with a plain
   ANS_PUBKEY that we already parse. Nothing new goes on the wire that an
   upstream peer could choke on -- which a new request type would.

   Rate limited per node, and only ever sent while the list is still unknown
   (ANS_PUBKEY sets it, and an answer without the extra token sets it to
   `plain', so a peer that does not speak the extension is asked once, not
   once a minute for ever). */
#define REQ_TRANSPORTS_INTERVAL 60

/* The same question also carries the direct-seal capability (obfs.h), which
   a sealing node needs before it sends a peer a single direct datagram; it is
   asked while that is unknown too, every REQ_DSEAL_INTERVAL when the answer
   holds up the direct path (send_req_dseal). */
#define REQ_DSEAL_INTERVAL 10

static bool send_req_carriers(node_t *to, int interval) {
	if(!to || to == myself || (to->transports && (to->dseal & DSEAL_KNOWN))) {
		return false;
	}

	if(!to->status.reachable || !to->nexthop || !to->nexthop->connection) {
		return false;
	}

	if(to->last_req_transports && now.tv_sec - to->last_req_transports < interval) {
		return false;
	}

	to->last_req_transports = now.tv_sec;
	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Asking %s (%s) for its carrier list over the meta graph", to->name, to->hostname);
	return send_request(to->nexthop->connection, "%d %s %s %d", REQ_KEY, myself->name, to->name, REQ_PUBKEY);
}

bool send_req_transports(node_t *to) {
	return send_req_carriers(to, REQ_TRANSPORTS_INTERVAL);
}

bool send_req_dseal(node_t *to) {
	return send_req_carriers(to, REQ_DSEAL_INTERVAL);
}

bool send_req_key(node_t *to) {
	if(to->status.sptps) {
		if(!node_read_ecdsa_public_key(to)) {
			logger(DEBUG_PROTOCOL, LOG_DEBUG, "No Ed25519 key known for %s (%s)", to->name, to->hostname);
			to->last_req_pubkey = now.tv_sec;
			send_request(to->nexthop->connection, "%d %s %s %d", REQ_KEY, myself->name, to->name, REQ_PUBKEY);
			return true;
		}

		const size_t labellen = 25 + strlen(myself->name) + strlen(to->name);
		char *label = alloca(labellen);
		snprintf(label, labellen, "tinc UDP key expansion %s %s", myself->name, to->name);

		sptps_stop(&to->sptps);
		to->status.validkey = false;
		to->status.waitingforkey = true;
		to->status.sptps_route_stale = false;   /* this one goes out over the route we have now */
		to->last_req_key = now.tv_sec;
		to->sptps_cooldown = 24 + (uint8_t)prng(13);
		to->incompression = myself->incompression;
		/* DirectSeal: learn whether it reads sealed datagrams while the
		   handshake runs, so the first probe after it need not wait for the
		   answer (a no-op once known). */
		send_req_dseal(to);
		maybe_send_carrier_beacon(to);

		if((to->status.no_direct || node_is_no_direct(to->name)) && to->last_no_direct_sent != now.tv_sec) {
			to->last_no_direct_sent = now.tv_sec;
			send_no_direct_signal(to, true);
		}

		return sptps_start(&to->sptps, to, true, true, myself->connection->ecdsa, to->ecdsa, label, labellen, send_initial_sptps_data, receive_sptps_record);
	}

	return send_request(to->nexthop->connection, "%d %s %s", REQ_KEY, myself->name, to->name);
}

/* REQ_KEY is overloaded to allow arbitrary requests to be routed between two nodes. */

static bool req_key_ext_h(connection_t *c, const char *request, node_t *from, node_t *to, int reqno) {
	/* If this is a SPTPS packet, see if sending UDP info helps.
	   Note that we only do this if we're the destination or the static relay;
	   otherwise every hop would initiate its own UDP info message, resulting in elevated chatter. */
	if((reqno == REQ_KEY || reqno == SPTPS_PACKET) && (to == myself || (to->via == myself && to->nexthop == to))) {
		send_udp_info(myself, from);
	}

	if(reqno == SPTPS_PACKET) {
		/* This is a SPTPS data packet. */

		char buf[MAX_STRING_SIZE];
		size_t len = 0;

		if(sscanf(request, "%*d %*s %*s %*d " MAX_STRING, buf) == 1) {
			len = b64decode_tinc(buf, buf, strlen(buf));
		}

		if(!len) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s) to %s (%s): %s", "SPTPS_PACKET", from->name, from->hostname, to->name, to->hostname, "invalid SPTPS data");
			return true;
		}

		if(to != myself) {
			/* We don't just forward the request, because we want to use UDP if it's available. */
			if(forwarding_mode == FMODE_INTERNAL) {
				size_t origlen = len > SPTPS_DATAGRAM_OVERHEAD ? len - SPTPS_DATAGRAM_OVERHEAD : 0;
				node_t *relay = (to->via != myself && origlen <= to->via->minmtu) ? to->via : to->nexthop;

				if(!relay || relay == myself || relay == c->node || relay == from) {
					logger(DEBUG_TRAFFIC, LOG_ERR, "Routing loop relaying SPTPS_PACKET from %s to %s via %s!", from->name, to->name, relay ? relay->name : "(null)");
					return true;
				}

				send_sptps_data(to, from, 0, buf, len);
				try_tx(to, true);
			}
		} else {
			/* The packet is for us */
			if(!sptps_receive_data(&from->sptps, buf, len) && !shadow_sptps_try_receive(from, buf, len)) {
				/* Uh-oh. It might be that the tunnel is stuck in some corrupted state,
				   so let's restart SPTPS in case that helps. But don't do that too often
				   to prevent storms. See matching reasoning in net_packet.c
				   receive_udppacket: the cooldown is 30s to give in-progress
				   handshakes time to finish on the TCP relay path. */
				if(from->sptps.state == SPTPS_SECONDARY_KEX && from->last_req_key < now.tv_sec - 30 &&
				                (!from->status.validkey || now.tv_sec - from->last_udp_rx > 5)) {
					logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to decode TCP packet from %s (%s), restarting SPTPS", from->name, from->hostname);
					send_req_key(from);
				}

				return true;
			}

			send_mtu_info(myself, from, MTU);
		}

		return true;
	}

	/* The coordinated hole punch: a relay between the two ends answers it
	   instead of forwarding it (punch_h). */
	if(reqno == PUNCH_REQ) {
		return punch_h(from, to, request);
	}

	/* Requests that are not SPTPS data packets are forwarded as-is, subject to
	   loop prevention and per-(from, to) transitive rate-limiting. */

	if(to != myself) {
		if(!to->nexthop || to->nexthop == myself || to->nexthop == from || to->nexthop->connection == c) {
			logger(DEBUG_PROTOCOL, LOG_WARNING, "Dropping looping extended REQ_KEY (%d) from %s to %s", reqno, from->name, to->name);
			return true;
		}

		if(!allow_transitive_forward(from->name, to->name, reqno, request)) {
			return true;
		}

		return send_request(to->nexthop->connection, "%s", request);
	}

	/* The request is for us */

	switch(reqno) {
	case REQ_PUBKEY: {
		if(!node_read_ecdsa_public_key(from)) {
			/* Request their key *before* we send our key back. Otherwise the first SPTPS packet from them will get dropped. */
			logger(DEBUG_PROTOCOL, LOG_DEBUG, "Preemptively requesting Ed25519 key for %s (%s)", from->name, from->hostname);
			from->last_req_pubkey = now.tv_sec;
			send_request(from->nexthop->connection, "%d %s %s %d", REQ_KEY, myself->name, from->name, REQ_PUBKEY);
		}

		char *pubkey = ecdsa_get_base64_public_key(myself->connection->ecdsa);
		/* Defect D: our accept mask rides along as one extra, space-free
		   token. Upstream's ANS_PUBKEY parser is
		   `sscanf(request, "%*d %*s %*s %*d " MAX_STRING, pubkey)', which
		   stops at the first whitespace, so an upstream (or older tincstack)
		   peer ignores it and nothing on the wire changes for it. A peer that
		   does understand it stops assuming a distance-2-or-more node is
		   plain-only.
		   The mask is advisory, never a permission: the acceptor still
		   enforces its own Transports/AllowPlainMeta, so the worst a lying
		   relay can do is cause a dial the other end refuses. */
		char acceptlist[TRANSPORT_LIST_MAX];
		/* ... and after it the direct-seal capability (obfs.h), one more
		   space-free token that older parsers never reach. */
		char dseal[32];
		send_request(from->nexthop->connection, "%d %s %s %d %s %s %s", REQ_KEY, myself->name, from->name, ANS_PUBKEY, pubkey, transport_accept_string(acceptlist), dseal_token(dseal, sizeof(dseal)));
		free(pubkey);

		if(from->status.no_direct || node_is_no_direct(from->name)) {
			send_no_direct_signal(from, true);
		}

		return true;
	}

	case ANS_PUBKEY: {
		if(!from->nexthop || from->nexthop->connection != c) {
			logger(DEBUG_PROTOCOL, LOG_WARNING, "Ignoring ANS_PUBKEY from %s (%s) via unexpected connection %s", from->name, from->hostname, c->name);
			return true;
		}

		char pubkey[MAX_STRING_SIZE];
		char histransports[MAX_STRING_SIZE] = "";
		char hisdseal[MAX_STRING_SIZE] = "";
		int fields = sscanf(request, "%*d %*s %*s %*d " MAX_STRING " " MAX_STRING " " MAX_STRING, pubkey, histransports, hisdseal);

		if(fields < 1) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s): %s", "ANS_PUBKEY", from->name, from->hostname, "missing pubkey");
			return true;
		}

		if(node_read_ecdsa_public_key(from)) {
			char *knownkey = ecdsa_get_base64_public_key(from->ecdsa);
			bool same = knownkey && fields >= 1 && !strcmp(knownkey, pubkey);
			free(knownkey);

			if(!same) {
				ecdsa_t *cand = ecdsa_set_base64_public_key(pubkey);

				if(!cand) {
					logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s): %s", "ANS_PUBKEY", from->name, from->hostname, "invalid candidate pubkey");
					return true;
				}

				ecdsa_free(cand);
				start_key_quorum(from, pubkey);
				return true;
			}

			/* Learn the peer's accept mask only after verifying the key matches
			   our cached key, so an unverified key claim cannot mutate transports
			   or dseal or rewrite disk config. */
			uint32_t prev_transports = from->transports;

			if(fields >= 2 && *histransports) {
				uint32_t mask;
				char bad[TRANSPORT_LIST_MAX];

				if(transport_parse_list(histransports, &mask, NULL, NULL, bad) && mask) {
					from->transports = mask;
				} else {
					logger(DEBUG_PROTOCOL, LOG_WARNING, "Ignoring Transports of %s in ANS_PUBKEY: unknown carrier `%s'", from->name, bad);
				}
			} else if(!from->transports) {
				from->transports = TRANSPORT_MASK_PLAIN;
			}

			dseal_learn(from, fields >= 3 ? hisdseal : NULL);

			if(from->transports != prev_transports && from->transports != TRANSPORT_MASK_PLAIN && *histransports) {
				replace_config_file(from->name, "Transports", histransports);
			}

			logger(DEBUG_PROTOCOL, LOG_DEBUG, "Got ANS_PUBKEY from %s (%s) matching our cached Ed25519 key", from->name, from->hostname);
			return true;
		}

		if(!from->last_req_pubkey && !from->last_req_transports && !from->last_req_key && !from->status.waitingforkey) {
			logger(DEBUG_PROTOCOL, LOG_WARNING, "Ignoring unsolicited ANS_PUBKEY for unpinned peer %s (%s)", from->name, from->hostname);
			return true;
		}

		from->ecdsa = ecdsa_set_base64_public_key(pubkey);

		if(!from->ecdsa) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s): %s", "ANS_PUBKEY", from->name, from->hostname, "invalid pubkey");
			return true;
		}

		mark_node_tofu_unpinned(from->name);

		if(fields >= 2 && *histransports) {
			uint32_t mask;
			char bad[TRANSPORT_LIST_MAX];

			if(transport_parse_list(histransports, &mask, NULL, NULL, bad) && mask) {
				from->transports = mask;
			} else {
				logger(DEBUG_PROTOCOL, LOG_WARNING, "Ignoring Transports of %s in ANS_PUBKEY: unknown carrier `%s'", from->name, bad);
			}
		} else if(!from->transports) {
			/* An answer with no carrier token is an upstream tinc, or a
			   tincstack older than stream AC: it is plain-only and saying so
			   is what stops send_req_transports() asking again for ever. */
			from->transports = TRANSPORT_MASK_PLAIN;
		}

		/* An answer is definitive: with the token, or without it (an older
		   build, which answers the same question every time). */
		dseal_learn(from, fields >= 3 ? hisdseal : NULL);

		logger(DEBUG_PROTOCOL, LOG_INFO, "Learned Ed25519 public key from %s (%s)", from->name, from->hostname);
		append_config_file(from->name, "Ed25519PublicKey", pubkey);
		from->in_config = true;

		if(from->transports && from->transports != TRANSPORT_MASK_PLAIN && *histransports) {
			replace_config_file(from->name, "Transports", histransports);
		}

		return true;
	}

	case REQ_KEY: {
		if(!node_read_ecdsa_public_key(from)) {
			logger(DEBUG_PROTOCOL, LOG_DEBUG, "No Ed25519 key known for %s (%s)", from->name, from->hostname);
			from->last_req_pubkey = now.tv_sec;
			send_request(from->nexthop->connection, "%d %s %s %d", REQ_KEY, myself->name, from->name, REQ_PUBKEY);
			return true;
		}

		char buf[MAX_STRING_SIZE];
		size_t len = 0;

		if(sscanf(request, "%*d %*s %*s %*d " MAX_STRING, buf) == 1) {
			len = b64decode_tinc(buf, buf, strlen(buf));
		}

		if(!len) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s): %s", "REQ_SPTPS_START", from->name, from->hostname, "invalid SPTPS data");
			return true;
		}

		maybe_send_carrier_beacon(from);

		if((from->status.no_direct || node_is_no_direct(from->name)) && from->last_no_direct_sent != now.tv_sec) {
			from->last_no_direct_sent = now.tv_sec;
			send_no_direct_signal(from, true);
		}

		/* H-DP-08: NEVER call sptps_stop(&from->sptps) on an already-established
		   live SPTPS session upon receiving an unauthenticated REQ_KEY over the
		   mesh! Keep the live session intact while answering via a rate-limited
		   shadow responder (plus non-destructive sptps_force_kex) that only swaps
		   into from->sptps if the peer's Ed25519 signature authenticates. */
		if(from->status.validkey && from->sptps.state) {
			logger(DEBUG_ALWAYS, LOG_DEBUG, "Got REQ_KEY from %s while live SPTPS session is active; preserving live session until new KEX authenticates", from->name);

			if(send_req_pubkey_refresh(from) && myself->connection && myself->connection->ecdsa) {
				char *pubkey = ecdsa_get_base64_public_key(myself->connection->ecdsa);
				char acceptlist[TRANSPORT_LIST_MAX];
				char dseal[32];
				send_request(from->nexthop->connection, "%d %s %s %d %s %s %s",
				             REQ_KEY, myself->name, from->name, ANS_PUBKEY,
				             pubkey, transport_accept_string(acceptlist), dseal_token(dseal, sizeof(dseal)));
				free(pubkey);
			}

			shadow_sptps_t probe = { .peer_name = from->name };
			shadow_sptps_t *existing = splay_search(&shadow_sptps_tree, &probe);
			time_t prev_force_kex = existing ? existing->last_force_kex : 0;

			if(existing && now.tv_sec - existing->created_at < 2) {
				return true;
			}

			if(existing) {
				splay_delete(&shadow_sptps_tree, existing);
			}

			while(shadow_sptps_tree.count >= MAX_SHADOW_SPTPS_ENTRIES && shadow_sptps_fifo.head) {
				shadow_sptps_t *oldest = shadow_sptps_fifo.head->data;
				splay_delete(&shadow_sptps_tree, oldest);
			}

			if(from->sptps.state == SPTPS_SECONDARY_KEX && now.tv_sec - prev_force_kex >= 10) {
				sptps_force_kex(&from->sptps);
				prev_force_kex = now.tv_sec;
			}

			const size_t sh_labellen = 25 + strlen(from->name) + strlen(myself->name);
			char *sh_label = alloca(sh_labellen);
			snprintf(sh_label, sh_labellen, "tinc UDP key expansion %s %s", from->name, myself->name);

			shadow_sptps_t *sh = xzalloc(sizeof(*sh));
			sh->peer_name = xstrdup(from->name);
			sh->created_at = now.tv_sec;
			sh->last_force_kex = prev_force_kex;
			sh->fifo_node = list_insert_tail(&shadow_sptps_fifo, sh);
			splay_insert(&shadow_sptps_tree, sh);

			send_req_dseal(from);

			if(!sptps_start(&sh->sptps, sh, false, true, myself->connection->ecdsa, from->ecdsa,
			                sh_label, sh_labellen, send_shadow_sptps_data, shadow_receive_record) ||
			                !sptps_receive_data(&sh->sptps, buf, len)) {
				splay_delete(&shadow_sptps_tree, sh);
				return true;
			}

			send_mtu_info(myself, from, MTU);
			return true;
		}

		if(from->status.waitingforkey && from->sptps.label && from->sptps.initiator) {
			time_t pending = now.tv_sec - from->last_req_key;
			bool stale = from->status.sptps_route_stale ||
			             (from->sptps.state == SPTPS_KEX && pending >= SPTPS_GLARE_WINDOW) ||
			             pending >= 15;

			if(!stale && (strcmp(myself->name, from->name) < 0 || from->sptps.state > SPTPS_KEX)) {
				logger(DEBUG_ALWAYS, LOG_DEBUG, "Got REQ_KEY from %s while our SPTPS session is pending; keeping ours (glare tie-break: we win)", from->name);
				return true;
			}

			if(stale) {
				logger(DEBUG_ALWAYS, LOG_DEBUG, "Got REQ_KEY from %s while our own SPTPS session (pending %ld s, route %s) cannot be answered; yielding as responder rather than defending it", from->name, (long)pending, from->status.sptps_route_stale ? "gone" : "silent");
				from->status.sptps_route_stale = false;
			} else {
				logger(DEBUG_ALWAYS, LOG_DEBUG, "Got REQ_KEY from %s while our SPTPS session is pending; yielding as responder (glare tie-break: we lose)", from->name);
			}
		} else if(from->sptps.label) {
			logger(DEBUG_ALWAYS, LOG_DEBUG, "Got REQ_KEY from %s while we already started a SPTPS session!", from->name);

			if(send_req_pubkey_refresh(from) && myself->connection && myself->connection->ecdsa) {
				char *pubkey = ecdsa_get_base64_public_key(myself->connection->ecdsa);
				char acceptlist[TRANSPORT_LIST_MAX];
				char dseal[32];
				send_request(from->nexthop->connection, "%d %s %s %d %s %s %s",
				             REQ_KEY, myself->name, from->name, ANS_PUBKEY,
				             pubkey, transport_accept_string(acceptlist), dseal_token(dseal, sizeof(dseal)));
				free(pubkey);
			}
		}

		const size_t labellen = 25 + strlen(from->name) + strlen(myself->name);
		char *label = alloca(labellen);
		snprintf(label, labellen, "tinc UDP key expansion %s %s", from->name, myself->name);
		sptps_stop(&from->sptps);
		from->status.validkey = false;
		from->status.waitingforkey = true;
		from->last_req_key = now.tv_sec;
		from->sptps_cooldown = 24 + (uint8_t)prng(13);
		send_req_dseal(from);   /* see send_req_key() */
		sptps_start(&from->sptps, from, false, true, myself->connection->ecdsa, from->ecdsa, label, labellen, send_sptps_data_myself, receive_sptps_record);
		sptps_receive_data(&from->sptps, buf, len);
		send_mtu_info(myself, from, MTU);
		return true;
	}

	case DSEAL_KEX_REQ:
		return dseal_kex_h(from, request);

	case KEY_QUORUM_REQ: {
		if(!from->nexthop || from->nexthop->connection != c) {
			logger(DEBUG_PROTOCOL, LOG_WARNING, "Ignoring KEY_QUORUM_REQ from %s (%s) via unexpected connection %s", from->name, from->hostname, c->name);
			return true;
		}

		char target_name[MAX_STRING_SIZE];
		char nonce[MAX_STRING_SIZE];

		if(sscanf(request, "%*d %*s %*s %*d " MAX_STRING " " MAX_STRING, target_name, nonce) != 2 ||
		                !check_id(target_name) || !is_valid_quorum_nonce(nonce)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "KEY_QUORUM_REQ", from->name, from->hostname);
			return true;
		}

		if(node_is_blocked(target_name)) {
			return true;
		}

		ecdsa_t *my_ecdsa = get_my_quorum_ecdsa();

		if(!ecdsa_active(my_ecdsa)) {
			return true;
		}

		node_t *target = lookup_node(target_name);

		if(!target || target == myself) {
			return true;
		}

		int flags = 0;
		char *pk = NULL;

		if(node_read_ecdsa_public_key(target)) {
			pk = ecdsa_get_base64_public_key(target->ecdsa);

			if(pk && *pk) {
				flags |= KEY_QUORUM_FLAG_HAS_KEY;
			}
		}

		if(target->connection && target->connection->edge) {
			flags |= KEY_QUORUM_FLAG_DIRECT_EDGE;
		}

		if(target->status.validkey) {
			flags |= KEY_QUORUM_FLAG_VALID_SPTPS;
		}

		if(!(flags & (KEY_QUORUM_FLAG_DIRECT_EDGE | KEY_QUORUM_FLAG_VALID_SPTPS)) && target->status.reachable) {
			send_req_pubkey_refresh(target);
		}

		const char *pk_str = (pk && *pk) ? pk : "-";
		char msg[2048];
		int mlen = snprintf(msg, sizeof(msg), "tinc-key-quorum-v1 %s %s %s %s %s %d",
		                    myself->name, from->name, target->name, nonce, pk_str, flags);

		if(mlen <= 0 || (size_t)mlen >= sizeof(msg)) {
			free(pk);
			return true;
		}

		char *sig_b64 = NULL;

		if(!ecdsa_sign_base64(my_ecdsa, msg, (size_t)mlen, &sig_b64)) {
			free(pk);
			return true;
		}

		send_request(from->nexthop->connection, "%d %s %s %d %s %s %d %s %s",
		             REQ_KEY, myself->name, from->name, KEY_QUORUM_ANS,
		             target->name, pk_str, flags, nonce, sig_b64);
		free(sig_b64);
		free(pk);
		return true;
	}

	case KEY_QUORUM_ANS: {
		if(!from->nexthop || from->nexthop->connection != c) {
			logger(DEBUG_PROTOCOL, LOG_WARNING, "Ignoring KEY_QUORUM_ANS from %s (%s) via unexpected connection %s", from->name, from->hostname, c->name);
			return true;
		}

		char target_name[MAX_STRING_SIZE];
		char voted_pubkey[MAX_STRING_SIZE];
		char nonce[MAX_STRING_SIZE];
		char sig_b64[MAX_STRING_SIZE];
		int flags = 0;

		if(sscanf(request, "%*d %*s %*s %*d " MAX_STRING " " MAX_STRING " %d " MAX_STRING " " MAX_STRING,
		                target_name, voted_pubkey, &flags, nonce, sig_b64) != 5 || !check_id(target_name)) {
			logger(DEBUG_ALWAYS, LOG_WARNING, "Rejecting unsigned or malformed %s from %s (%s)", "KEY_QUORUM_ANS", from->name, from->hostname);
			return true;
		}

		node_t *target = lookup_node(target_name);

		if(!target || target == myself || from == myself || from == target || !from->status.reachable) {
			return true;
		}

		if(!target->pending_pubkey || now.tv_sec - target->pending_pubkey_time > KEY_QUORUM_WINDOW) {
			return true;
		}

		quorum_round_t *round = lookup_quorum_round(target->name);

		if(!round || !target->quorum_nonce[0] || strcmp(nonce, target->quorum_nonce) != 0 || strcmp(round->nonce, target->quorum_nonce) != 0) {
			logger(DEBUG_PROTOCOL, LOG_WARNING, "Rejecting KEY_QUORUM_ANS from %s for %s: nonce mismatch", from->name, target->name);
			return true;
		}

		if(!quorum_was_asked(round, from->name) || !node_has_pinned_ecdsa_key(from)) {
			logger(DEBUG_ALWAYS, LOG_WARNING, "Rejecting KEY_QUORUM_ANS from unpinned or unasked peer %s for %s", from->name, target->name);
			return true;
		}

		if(quorum_has_voted(target, from->name)) {
			return true;
		}

		if(!ecdsa_active(from->ecdsa)) {
			logger(DEBUG_ALWAYS, LOG_WARNING, "Rejecting KEY_QUORUM_ANS from %s for %s: voter Ed25519 public key unknown", from->name, target->name);
			return true;
		}

		char msg[2048];
		int mlen = snprintf(msg, sizeof(msg), "tinc-key-quorum-v1 %s %s %s %s %s %d",
		                    from->name, myself->name, target->name, target->quorum_nonce, voted_pubkey, flags);

		if(mlen <= 0 || (size_t)mlen >= sizeof(msg) ||
		                !ecdsa_verify_base64(from->ecdsa, msg, (size_t)mlen, sig_b64)) {
			logger(DEBUG_ALWAYS, LOG_WARNING, "Rejecting KEY_QUORUM_ANS from %s for %s: invalid Ed25519 signature", from->name, target->name);
			return true;
		}

		target->quorum_voters.delete = free_quorum_voter;
		list_insert_tail(&target->quorum_voters, xstrdup(from->name));
		from->quorum_voted_for = target;
		from->quorum_voted_at = target->pending_pubkey_time;
		round->responses_received++;

		if((flags & KEY_QUORUM_FLAG_HAS_KEY) && strcmp(voted_pubkey, "-") != 0) {
			bool has_graph_edge = lookup_edge(from, target) != NULL || lookup_edge(target, from) != NULL;
			bool is_direct = has_graph_edge && ((flags & KEY_QUORUM_FLAG_DIRECT_EDGE) != 0);
			bool is_verified = (has_graph_edge && (flags & KEY_QUORUM_FLAG_DIRECT_EDGE)) ||
			                   ((flags & KEY_QUORUM_FLAG_VALID_SPTPS) != 0);

			if(!strcmp(voted_pubkey, target->pending_pubkey)) {
				target->quorum_votes_new++;

				if(is_direct) {
					target->quorum_direct_new++;
				}

				if(is_verified) {
					round->verified_new++;
				}
			} else {
				target->quorum_votes_old++;

				if(is_verified) {
					target->quorum_verified_old++;
				}
			}
		}

		/* Immediate hard veto on verified old session or local active session;
		   otherwise evaluate early ONLY when all asked pinned peers have replied. */
		if((target->connection && target->connection->status.active) ||
		                target->status.validkey ||
		                target->quorum_verified_old > 0 ||
		                round->responses_received >= target->quorum_asked_peers) {
			evaluate_key_quorum(target);
		}

		return true;
	}

	default:
		logger(DEBUG_ALWAYS, LOG_ERR, "Unknown extended REQ_KEY request from %s (%s): %s", from->name, from->hostname, request);
		return true;
	}
}

bool req_key_h(connection_t *c, const char *request) {
	char from_name[MAX_STRING_SIZE];
	char to_name[MAX_STRING_SIZE];
	node_t *from, *to;
	int reqno = 0;

	if(sscanf(request, "%*d " MAX_STRING " " MAX_STRING " %d", from_name, to_name, &reqno) < 2) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "REQ_KEY", c->name,
		       c->hostname);
		return false;
	}

	if(!check_id(from_name) || !check_id(to_name)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s): %s", "REQ_KEY", c->name, c->hostname, "invalid name");
		return false;
	}

	if(node_is_blocked(from_name) || node_is_blocked(to_name)) {
		return true;
	}

	from = lookup_node(from_name);

	if(!from) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got %s from %s (%s) origin %s which does not exist in our connection list",
		       "REQ_KEY", c->name, c->hostname, from_name);
		return true;
	}

	to = lookup_node(to_name);

	if(!to) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got %s from %s (%s) destination %s which does not exist in our connection list",
		       "REQ_KEY", c->name, c->hostname, to_name);
		return true;
	}

	/* Check if this key request is for us */

	if(to == myself) {                      /* Yes */
		if(!from->status.reachable) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Got %s from %s (%s) origin %s which is not reachable",
			       "REQ_KEY", c->name, c->hostname, from_name);
			return true;
		}

		/* Is this an extended REQ_KEY message? */
		if(experimental && reqno) {
			return req_key_ext_h(c, request, from, to, reqno);
		}

		/* No, just send our key back */
		send_ans_key(from);
	} else {
		if(tunnelserver) {
			return true;
		}

		if(!to->status.reachable) {
			logger(DEBUG_PROTOCOL, LOG_WARNING, "Got %s from %s (%s) destination %s which is not reachable",
			       "REQ_KEY", c->name, c->hostname, to_name);
			return true;
		}

		/* Is this an extended REQ_KEY message? */
		if(experimental && reqno) {
			return req_key_ext_h(c, request, from, to, reqno);
		}

		if(!to->nexthop || to->nexthop == myself || to->nexthop == from || to->nexthop->connection == c) {
			return true;
		}

		if(!allow_transitive_forward(from->name, to->name, REQ_KEY, request)) {
			return true;
		}

		send_request(to->nexthop->connection, "%s", request);
	}

	return true;
}

bool send_ans_key(node_t *to) {
	if(to->status.sptps) {
		abort();
	}

#ifdef DISABLE_LEGACY
	return false;
#else
	size_t keylen = myself->incipher ? cipher_keylength(myself->incipher) : 1;
	size_t keyhexlen = HEX_SIZE(keylen);
	char *key = alloca(keyhexlen);

	randomize(key, keylen);

	cipher_free(to->incipher);
	to->incipher = NULL;

	digest_free(to->indigest);
	to->indigest = NULL;

	if(myself->incipher) {
		to->incipher = cipher_alloc();

		if(!cipher_open_by_nid(to->incipher, cipher_get_nid(myself->incipher))) {
			abort();
		}

		if(!cipher_set_key(to->incipher, key, false)) {
			abort();
		}
	}

	if(myself->indigest) {
		to->indigest = digest_alloc();

		if(!digest_open_by_nid(to->indigest,
		                       digest_get_nid(myself->indigest),
		                       digest_length(myself->indigest))) {
			abort();
		}

		if(!digest_set_key(to->indigest, key, keylen)) {
			abort();
		}
	}

	to->incompression = myself->incompression;

	bin2hex(key, key, keylen);

	// Reset sequence number and late packet window
	to->received_seqno = 0;
	to->received = 0;

	if(replaywin) {
		memset(to->late, 0, replaywin);
	}

	to->status.validkey_in = true;

	bool sent = send_request(to->nexthop->connection, "%d %s %s %s %d %d %lu %d", ANS_KEY,
	                         myself->name, to->name, key,
	                         cipher_get_nid(to->incipher),
	                         digest_get_nid(to->indigest),
	                         (unsigned long)digest_length(to->indigest),
	                         to->incompression);

	memzero(key, keyhexlen);

	return sent;
#endif
}

bool ans_key_h(connection_t *c, const char *request) {
	char from_name[MAX_STRING_SIZE];
	char to_name[MAX_STRING_SIZE];
	char key[MAX_STRING_SIZE];
	char address[MAX_STRING_SIZE] = "";
	char port[MAX_STRING_SIZE] = "";
	int cipher, digest;
	unsigned long maclength;
	int compression;
	node_t *from, *to;

	if(sscanf(request, "%*d "MAX_STRING" "MAX_STRING" "MAX_STRING" %d %d %lu %d "MAX_STRING" "MAX_STRING,
	                from_name, to_name, key, &cipher, &digest, &maclength,
	                &compression, address, port) < 7) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "ANS_KEY", c->name,
		       c->hostname);
		return false;
	}

	if(!check_id(from_name) || !check_id(to_name)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s): %s", "ANS_KEY", c->name, c->hostname, "invalid name");
		return false;
	}

	if(node_is_blocked(from_name) || node_is_blocked(to_name)) {
		return true;
	}

	from = lookup_node(from_name);

	if(!from) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got %s from %s (%s) origin %s which does not exist in our connection list",
		       "ANS_KEY", c->name, c->hostname, from_name);
		return true;
	}

	to = lookup_node(to_name);

	if(!to) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got %s from %s (%s) destination %s which does not exist in our connection list",
		       "ANS_KEY", c->name, c->hostname, to_name);
		return true;
	}

	/* Forward it if necessary */

	if(to != myself) {
		if(tunnelserver) {
			return true;
		}

		if(!to->status.reachable) {
			logger(DEBUG_ALWAYS, LOG_WARNING, "Got %s from %s (%s) destination %s which is not reachable",
			       "ANS_KEY", c->name, c->hostname, to_name);
			return true;
		}

		if(!to->nexthop || to->nexthop == myself || to->nexthop == from || to->nexthop->connection == c) {
			logger(DEBUG_PROTOCOL, LOG_WARNING, "Dropping looping ANS_KEY from %s to %s", from->name, to->name);
			return true;
		}

		if(!allow_transitive_forward(from->name, to->name, ANS_KEY, request)) {
			return true;
		}

		if(!*address && (from->status.udp_confirmed || from->status.udp_addr_confirmed) && from->address.sa.sa_family != AF_UNSPEC &&
		                !from->status.no_direct && !from->remote_no_direct &&
		                !to->status.no_direct && !to->remote_no_direct && to->minmtu) {
			char *address, *port;
			logger(DEBUG_PROTOCOL, LOG_DEBUG, "Appending reflexive UDP address to ANS_KEY from %s to %s", from->name, to->name);
			sockaddr2str(&from->address, &address, &port);
			send_request(to->nexthop->connection, "%s %s %s", request, address, port);
			free(address);
			free(port);
			return true;
		}

		return send_request(to->nexthop->connection, "%s", request);
	}

#ifndef DISABLE_LEGACY
	/* Don't use key material until every check has passed. */
	cipher_free(from->outcipher);
	from->outcipher = NULL;

	digest_free(from->outdigest);
	from->outdigest = NULL;
#endif

	if(!from->status.sptps) {
		from->status.validkey = false;
	}

	switch(compression) {
	case COMPRESS_LZ4:
#ifdef HAVE_LZ4
		break;
#else
		logger(DEBUG_ALWAYS, LOG_ERR, "Node %s (%s) uses bogus compression level!", from->name, from->hostname);
		logger(DEBUG_ALWAYS, LOG_ERR, "LZ4 compression is unavailable on this node.");
		return true;
#endif

	case COMPRESS_LZO_HI:
	case COMPRESS_LZO_LO:
#ifdef HAVE_LZO
		break;
#else
		logger(DEBUG_ALWAYS, LOG_ERR, "Node %s (%s) uses bogus compression level!", from->name, from->hostname);
		logger(DEBUG_ALWAYS, LOG_ERR, "LZO compression is unavailable on this node.");
		return true;
#endif

	case COMPRESS_ZLIB_9:
	case COMPRESS_ZLIB_8:
	case COMPRESS_ZLIB_7:
	case COMPRESS_ZLIB_6:
	case COMPRESS_ZLIB_5:
	case COMPRESS_ZLIB_4:
	case COMPRESS_ZLIB_3:
	case COMPRESS_ZLIB_2:
	case COMPRESS_ZLIB_1:
#ifdef HAVE_ZLIB
		break;
#else
		logger(DEBUG_ALWAYS, LOG_ERR, "Node %s (%s) uses bogus compression level!", from->name, from->hostname);
		logger(DEBUG_ALWAYS, LOG_ERR, "ZLIB compression is unavailable on this node.");
		return true;
#endif

	case COMPRESS_NONE:
		break;

	default:
		logger(DEBUG_ALWAYS, LOG_ERR, "Node %s (%s) uses bogus compression level!", from->name, from->hostname);
		logger(DEBUG_ALWAYS, LOG_ERR, "Compression level %i is unrecognized by this node.", compression);
		return true;
	}

	from->outcompression = compression;

	/* SPTPS or old-style key exchange? */

	if(from->status.sptps) {
		const size_t buflen = strlen(key);
		uint8_t *buf = alloca(buflen);
		size_t len = b64decode_tinc(key, buf, buflen);

		if(!len || (!sptps_receive_data(&from->sptps, buf, len) && !shadow_sptps_try_receive(from, buf, len))) {
			/* If the handshake record failed verification (e.g. a rotated
			   Ed25519 key on `from'), ask `from' for its current ANS_PUBKEY
			   over the graph so quorum key verification can run. */
			send_req_pubkey_refresh(from);

			/* Uh-oh. It might be that the tunnel is stuck in some corrupted state,
			   so let's restart SPTPS in case that helps. But don't do that too often
			   to prevent storms.
			   Note that simply relying on handshake timeout is not enough, because
			   that doesn't apply to key regeneration. Cooldown raised to 30s to
			   match the other recovery paths and let in-progress handshakes finish. */
			if(!from->status.validkey && from->last_req_key < now.tv_sec - 30) {
				logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to decode handshake TCP packet from %s (%s), restarting SPTPS", from->name, from->hostname);
				send_req_key(from);
			}

			return true;
		}

		/* A relay's view of the peer is a hint for finding a path, not news
		   about one we have: every rekey of a pair whose handshake goes
		   through a relay carries it, and applying it to a confirmed direct
		   path reset that path (udp_confirmed cleared, PMTU restarted) and
		   moved the pair to the relay for seconds -- 8.6 % of packets at
		   KeyExpire 20 s in the lab (docs/nat.md §7.6). udp_info_h() has
		   always had this rule. */
		if(from->status.validkey && !from->status.no_direct && !from->remote_no_direct && *address && *port) {
			if(from->status.udp_confirmed) {
				logger(DEBUG_PROTOCOL, LOG_DEBUG, "Not using reflexive UDP address from %s (%s port %s): the direct path is confirmed", from->name, address, port);
			} else {
				logger(DEBUG_PROTOCOL, LOG_DEBUG, "Using reflexive UDP address from %s: %s port %s", from->name, address, port);
				sockaddr_t sa = str2sockaddr(address, port);
				update_node_udp(from, &sa);
				sockaddrfree(&sa);
			}
		}

		send_mtu_info(myself, from, MTU);

		return true;
	}

#ifdef DISABLE_LEGACY
	logger(DEBUG_ALWAYS, LOG_ERR, "Node %s (%s) uses legacy protocol!", from->name, from->hostname);
	return false;
#else
	/* Check and lookup cipher and digest algorithms */

	if(cipher) {
		from->outcipher = cipher_alloc();

		if(!cipher_open_by_nid(from->outcipher, cipher)) {
			cipher_free(from->outcipher);
			from->outcipher = NULL;
			logger(DEBUG_ALWAYS, LOG_ERR, "Node %s (%s) uses unknown cipher!", from->name, from->hostname);
			return false;
		}
	} else {
		from->outcipher = NULL;
	}

	if(digest) {
		from->outdigest = digest_alloc();

		if(!digest_open_by_nid(from->outdigest, digest, maclength)) {
			digest_free(from->outdigest);
			from->outdigest = NULL;
			logger(DEBUG_ALWAYS, LOG_ERR, "Node %s (%s) uses unknown digest!", from->name, from->hostname);
			return false;
		}
	} else {
		from->outdigest = NULL;
	}

	if(maclength != digest_length(from->outdigest)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Node %s (%s) uses bogus MAC length!", from->name, from->hostname);
		return false;
	}

	/* Process key */

	size_t keylen = hex2bin(key, key, sizeof(key));

	if(keylen != (from->outcipher ? cipher_keylength(from->outcipher) : 1)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Node %s (%s) uses wrong keylength!", from->name, from->hostname);
		return true;
	}

	/* Update our copy of the origin's packet key */

	if(from->outcipher && !cipher_set_key(from->outcipher, key, true)) {
		return false;
	}

	if(from->outdigest && !digest_set_key(from->outdigest, key, keylen)) {
		return false;
	}

	from->status.validkey = true;
	from->status.sptps_route_stale = false;   /* the exchange completed; see receive_sptps_record */
	from->sent_seqno = 0;

	if(*address && *port && !from->status.udp_confirmed && !from->status.no_direct && !from->remote_no_direct) {
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Using reflexive UDP address from %s: %s port %s", from->name, address, port);
		sockaddr_t sa = str2sockaddr(address, port);
		update_node_udp(from, &sa);
		sockaddrfree(&sa);
	}

	return true;
#endif
}
