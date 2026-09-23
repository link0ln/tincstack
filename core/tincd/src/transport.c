/*
    transport.c -- carrier registry, Transports/PreferredTransports
                   negotiation, outbound selection and the inbound front.

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
#include "connection.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "utils.h"
#include "xalloc.h"

#define TINC_TRANSPORT_DAEMON
#include "transport.h"
#include "obfs.h"
#include "transport_quic.h"

#include "decoy.h"

#ifdef HAVE_OPENSSL
#include "tls.h"
#endif

uint32_t transport_accept_mask;

/* Which carriers have had their `init' hook run, and whether transport_init()
   has run at all. Both are needed by transport_read_config(), which is called
   on every reload and must initialise a carrier the operator has just added
   to `Transports' -- but not before transport_init()'s own pass, which is the
   one that runs after the keys are in place. */
static uint32_t transport_init_done;
static bool transport_initialised;

transport_id_t transport_pref[TRANSPORT_MAX];
int transport_pref_count;
bool single_flow;
bool allow_plain_meta = true;
bool udp_meta_fallback = true;

#ifdef HAVE_TRANSPORT_TEST
/* The stub carrier exists to prove that fallback happens: it is selectable
   like a real carrier but every dial fails immediately, so the selector has
   to move on to the next candidate. */
static bool test_dial(connection_t *c) {
	logger(DEBUG_CONNECTIONS, LOG_INFO, "test carrier: simulated dial failure to %s (%s)", c->name, c->hostname);
	return false;
}
#endif

static const transport_t transports[TRANSPORT_MAX] = {
	[TRANSPORT_PLAIN] = {
		.id = TRANSPORT_PLAIN, .name = "plain",
		.caps = TRANSPORT_CAP_META_TCP | TRANSPORT_CAP_DATA_UDP,
		.dial = transport_plain_dial,
	},
	[TRANSPORT_SF] = {
		.id = TRANSPORT_SF, .name = "sf",
		.caps = TRANSPORT_CAP_SINGLE_FLOW | TRANSPORT_CAP_DATA_UDP,
		.exit = sf_exit,
		.dial = sf_dial,
		.send = sf_send,
		.close = sf_close,
		.local_address = sf_local_address,
		.udp_receive = sf_udp_receive,
	},
	/* obfs (M5): the single-flow engine with every frame sealed by an
	   authenticated obfs frame, plus SPTPS data datagrams sealed on the same
	   flow. See obfs.c and docs/transports.md. */
	[TRANSPORT_OBFS]  = {
		.id = TRANSPORT_OBFS, .name = "obfs",
		.caps = TRANSPORT_CAP_SINGLE_FLOW | TRANSPORT_CAP_DATA_UDP,
		.init = obfs_init,
		.exit = obfs_exit,
		.dial = obfs_dial,
		.send = sf_send,
		.close = obfs_close,
		.local_address = sf_local_address,
	},
	/* quic is filled in by M5/G3; the name is registered so option parsing
	   and peer advertisements already know it. */
#ifdef HAVE_OPENSSL
	[TRANSPORT_HTTPS] = {
		.id = TRANSPORT_HTTPS, .name = "https",
		.caps = TRANSPORT_CAP_SINGLE_FLOW | TRANSPORT_CAP_META_TCP,
		.init = https_init,
		.exit = https_exit,
		.dial = https_dial,
		.accept = https_accept,
		.send = https_send,
		.close = https_close,
	},
#else
	[TRANSPORT_HTTPS] = { .id = TRANSPORT_HTTPS, .name = "https", .caps = TRANSPORT_CAP_SINGLE_FLOW | TRANSPORT_CAP_META_TCP },
#endif
	/* quic (M5, G3): meta on one QUIC stream, SPTPS data in DATAGRAM frames,
	   over the shared UDP socket. Needs ngtcp2+GnuTLS (HAVE_QUIC) and the
	   node certificate (OpenSSL build). See transport_quic.c. */
#if defined(HAVE_QUIC) && defined(HAVE_OPENSSL)
	[TRANSPORT_QUIC]  = {
		.id = TRANSPORT_QUIC, .name = "quic",
		.caps = TRANSPORT_CAP_SINGLE_FLOW,
		.init = quic_init,
		.exit = quic_exit,
		.dial = quic_dial,
		.send = quic_send,
		.close = quic_close,
		.local_address = quic_local_address,
		.udp_receive = quic_udp_receive,
		.send_datagram = quic_send_datagram,
	},
#else
	[TRANSPORT_QUIC]  = { .id = TRANSPORT_QUIC,  .name = "quic",  .caps = TRANSPORT_CAP_SINGLE_FLOW },
#endif
#ifdef HAVE_TRANSPORT_TEST
	[TRANSPORT_TEST]  = { .id = TRANSPORT_TEST,  .name = "test",  .caps = TRANSPORT_CAP_META_TCP, .dial = test_dial },
#else
	[TRANSPORT_TEST]  = { .id = TRANSPORT_TEST,  .name = "test" },
#endif
};

const transport_t *transport_get(transport_id_t id) {
	if(id < 0 || id >= TRANSPORT_MAX) {
		return NULL;
	}

	return &transports[id];
}

/* ---- options ------------------------------------------------------------- */

/* Concatenate every value of a (possibly repeated) config variable into one
   comma-separated string, so "Transports = a, b" and the YAML list form
   (one line per item) parse identically. Caller frees. */
static char *config_join(splay_tree_t *tree, const char *variable) {
	char *joined = NULL;

	for(config_t *cfg = lookup_config(tree, variable); cfg; cfg = lookup_config_next(tree, cfg)) {
		char *value;

		if(!get_config_string(cfg, &value)) {
			continue;
		}

		if(joined) {
			char *tmp;
			xasprintf(&tmp, "%s,%s", joined, value);
			free(joined);
			free(value);
			joined = tmp;
		} else {
			joined = value;
		}
	}

	return joined;
}

bool transport_read_config(void) {
	char bad[TRANSPORT_LIST_MAX];
	char buf[TRANSPORT_LIST_MAX];
	uint32_t compiled = transport_compiled_mask();

	single_flow = false;
	get_config_bool(lookup_config(&config_tree, "SingleFlow"), &single_flow);

	/* AllowPlainMeta: may an inbound *cleartext* tinc meta connection be
	   taken on the listening port? Default yes -- that is what every tinc
	   before this option did, and what an upstream peer or `tinc join'
	   needs. `no' takes `plain' out of the accept mask, which is both
	   advertised to peers and enforced by the front (see
	   transport_front_dispatch, TCP_CLASS_TINC). */
	allow_plain_meta = true;
	get_config_bool(lookup_config(&config_tree, "AllowPlainMeta"), &allow_plain_meta);

	/* UdpMetaFallback: may a meta connection fall back onto the peer's
	   confirmed direct UDP flow when every address we know for it refused a
	   meta connection? Default yes (defect E). `no' restores the pre-fix
	   behaviour: such a pair stays relayed. */
	udp_meta_fallback = true;
	get_config_bool(lookup_config(&config_tree, "UdpMetaFallback"), &udp_meta_fallback);

	/* Transports: accept list. Default: everything compiled in. */

	char *list = config_join(&config_tree, "Transports");
	uint32_t mask = compiled;

	if(list) {
		if(!transport_parse_list(list, &mask, NULL, NULL, bad)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Invalid Transports: unknown carrier `%s'", bad);
			free(list);
			return false;
		}

		if(mask & ~compiled) {
			logger(DEBUG_ALWAYS, LOG_WARNING, "Transports lists carriers not compiled into this build (%s); ignoring them", transport_mask_to_string(mask & ~compiled, buf));
			mask &= compiled;
		}

		free(list);
	}

	/* Cleartext meta connections. Historically `plain' was forced back into
	   the accept mask whatever `Transports' said, so a node could not refuse
	   an unwrapped tinc handshake on its own port and stayed fingerprintable
	   as tinc by a single probe. Refusing is now a deliberate act
	   (`AllowPlainMeta = no'); with the default `yes' this block reproduces
	   the old behaviour, warning included. */
	if(!allow_plain_meta) {
		mask &= ~TRANSPORT_MASK_PLAIN;
		logger(DEBUG_ALWAYS, LOG_WARNING, "AllowPlainMeta = no: cleartext tinc meta connections are refused on the listening port (upstream-tinc peers, peers dialling `plain' and `tinc join' against this node will not get in)");

		if(!mask) {
			logger(DEBUG_ALWAYS, LOG_WARNING, "...and Transports lists no other carrier, so this node now answers nothing at all on its listening port");
		}
	} else if(!(mask & TRANSPORT_MASK_PLAIN)) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Transports omits `plain'; it is always accepted (upstream peers and the control connection need it)");
		mask |= TRANSPORT_MASK_PLAIN;
	}

	/* Carrier `init' hooks run once, from transport_init(), and only for the
	   carriers that were in the accept mask at startup. A reload that widens
	   `Transports' used to leave the carriers it added uninitialised, so
	   their dial and accept hooks ran against state that was never set up.
	   Initialise them here instead. At startup this block does nothing:
	   transport_read_config() runs before the keys exist, so
	   transport_initialised is still false and transport_init() does the
	   work at the proper time. A carrier that fails to initialise on a
	   reload is dropped from the accept mask rather than taking the daemon
	   down: the running node keeps the carriers it already has. */
	if(transport_initialised) {
		for(int i = 0; i < TRANSPORT_MAX; i++) {
			uint32_t bit = TRANSPORT_BIT(i);

			if(!(mask & bit) || (transport_init_done & bit) || !transports[i].init) {
				continue;
			}

			if(transports[i].init()) {
				transport_init_done |= bit;
				logger(DEBUG_ALWAYS, LOG_INFO, "Carrier `%s' initialised on reload", transports[i].name);
			} else {
				logger(DEBUG_ALWAYS, LOG_ERR, "Carrier `%s' failed to initialise on reload; leaving it out of the accept list", transports[i].name);
				mask &= ~bit;
			}
		}
	}

	transport_accept_mask = mask;

	/* PreferredTransports: dial order. Default: plain. */

	transport_id_t order[TRANSPORT_MAX];
	int count = 0;
	list = config_join(&config_tree, "PreferredTransports");

	if(list) {
		uint32_t pmask;

		if(!transport_parse_list(list, &pmask, order, &count, bad)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Invalid PreferredTransports: unknown carrier `%s'", bad);
			free(list);
			return false;
		}

		free(list);
	}

	transport_pref_count = 0;

	/* SingleFlow = yes means: dial the single-flow carrier first, whatever
	   else is listed. It is sugar for putting `sf' at the head of
	   PreferredTransports (documented in docs/transports.md). */
	if(single_flow) {
		transport_pref[transport_pref_count++] = TRANSPORT_SF;
	}

	for(int i = 0; i < count; i++) {
		if(!transports[order[i]].dial) {
			logger(DEBUG_ALWAYS, LOG_WARNING, "PreferredTransports: carrier `%s' cannot be dialled in this build; skipping", transport_name(order[i]));
			continue;
		}

		bool dup = false;

		for(int j = 0; j < transport_pref_count; j++) {
			if(transport_pref[j] == order[i]) {
				dup = true;
			}
		}

		if(!dup) {
			transport_pref[transport_pref_count++] = order[i];
		}
	}

	/* Every preference list ends at plain: it is the one carrier every tinc
	   peer accepts. */
	bool has_plain = false;

	for(int j = 0; j < transport_pref_count; j++) {
		if(transport_pref[j] == TRANSPORT_PLAIN) {
			has_plain = true;
		}
	}

	if(!has_plain) {
		transport_pref[transport_pref_count++] = TRANSPORT_PLAIN;
	}

	uint32_t pmask = 0;

	for(int j = 0; j < transport_pref_count; j++) {
		pmask |= TRANSPORT_BIT(transport_pref[j]);
	}

	char pbuf[TRANSPORT_LIST_MAX] = "";

	for(int j = 0; j < transport_pref_count; j++) {
		size_t l = strlen(pbuf);
		snprintf(pbuf + l, sizeof(pbuf) - l, "%s%s", l ? "," : "", transport_name(transport_pref[j]));
	}

	(void)pmask;

	/* obfs option surface (ObfsJunkPacket*, ObfsInit*, ...): re-read on every
	   (re)load so `tinc set Obfs... ; tinc reload' takes effect live. */
	obfs_read_config();

#if defined(HAVE_QUIC) && defined(HAVE_OPENSSL)

	/* quic: re-serve a replaced node certificate on reload. */
	if(!quic_read_config()) {
		return false;
	}

#endif

	logger(DEBUG_ALWAYS, LOG_INFO, "Transports accept=%s prefer=%s%s", transport_mask_to_string(transport_accept_mask, buf), pbuf, single_flow ? " (SingleFlow)" : "");

#ifdef HAVE_OPENSSL

	/* A node certificate replaced by `tinc cert issue' -- or by a hand-edited
	   TlsCert/TlsKey -- is served without a restart. tls_init() re-reads the
	   PEMs and rebuilds the contexts only when the fingerprint changed, so
	   this costs nothing on an ordinary reload; `tls_ready' keeps a node with
	   no TLS front from building contexts it never uses. The quic branch above
	   already did this for its own credential; the second call is the cheap
	   no-op path. */
	if(tls_ready && !tls_init()) {
		logger(DEBUG_ALWAYS, LOG_ERR,
		       "Could not reload the node certificate; keeping the one already in use");
	}

#endif

	/* Re-read the decoy config so HttpsDecoyRoot/HttpsDecoyUpstream changes take
	   effect on reload (this runs on every setup_myself_reloadable). */
	decoy_read_config();
	return true;
}

/* ---- init / exit --------------------------------------------------------- */

/* R-1: parked (unclassified, waiting for more bytes) front connections are
   re-armed from this one timer; see transport_front_dispatch(). */
static timeout_t front_poll_timer;

/* ---- front ports ------------------------------------------------------- */

#define FRONT_PORT_DEFAULT 443

/* tinc merges this node's own host record into config_tree, and that record
   is where transport_advertise_port() writes HttpsPort/QuicPort for peers.
   Read back as an option, our own advertisement would look like the
   operator's choice -- and a chosen QuicPort is also the port we dial every
   peer on. So only a line that did not come from a host record counts. */
static config_t *lookup_option_not_host(const char *option) {
	for(config_t *cfg = lookup_config(&config_tree, option); cfg; cfg = lookup_config_next(&config_tree, cfg)) {
		if(!cfg->file || !strstr(cfg->file, SLASH "hosts" SLASH)) {
			return cfg;
		}
	}

	return NULL;
}

int transport_front_port(const char *option, bool *configured) {
	int port = 0;
	*configured = get_config_int(lookup_option_not_host(option), &port);

	if(*configured) {
		return port > 0 && port < 65536 ? port : 0;
	}

	/* Only a node others dial needs a front at all. Port 0 (every node that
	   joined by invitation) means "outbound only": binding 443 there would
	   open a public port on a laptop for nothing. */
	char *p = NULL;
	bool inbound = true;

	if(get_config_string(lookup_config(&config_tree, "Port"), &p) && p) {
		inbound = !is_decimal(p) || atoi(p) != 0;
	}

	free(p);
	return inbound ? FRONT_PORT_DEFAULT : 0;
}

void transport_advertise_port(const char *key, int port) {
	splay_tree_t *tree = create_configuration();
	int current = 0;

	if(read_host_config(tree, myself->name, false)) {
		get_config_int(lookup_config(tree, key), &current);
	}

	exit_configuration(tree);

	if(current == port) {
		return;
	}

	char value[8];
	snprintf(value, sizeof(value), "%d", port);

	if(!replace_config_file(myself->name, key, port ? value : NULL)) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Could not record %s in this node's host record", key);
	}
}

bool transport_init(void) {
	/* The plain-HTTP decoy path needs the decoy config even when the https
	   carrier's init (which also reads it) is not run. Idempotent. */
	decoy_read_config();

	for(int i = 0; i < TRANSPORT_MAX; i++) {
		if(transports[i].init && (transport_accept_mask & TRANSPORT_BIT(i))) {
			if(!transports[i].init()) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Carrier `%s' failed to initialise", transports[i].name);
				return false;
			}

			transport_init_done |= TRANSPORT_BIT(i);
		}
	}

	/* A front this node no longer runs must not stay advertised, or peers
	   keep dialling a port nobody listens on. */
	if(!(transport_init_done & TRANSPORT_BIT(TRANSPORT_HTTPS))) {
		transport_advertise_port("HttpsPort", 0);
	}

	if(!(transport_init_done & TRANSPORT_BIT(TRANSPORT_QUIC))) {
		transport_advertise_port("QuicPort", 0);
	}

	/* From here on transport_read_config() (i.e. every reload) initialises a
	   carrier the operator adds to `Transports'. */
	transport_initialised = true;
	return true;
}

void transport_exit(void) {
	timeout_del(&front_poll_timer);

	for(int i = 0; i < TRANSPORT_MAX; i++) {
		if(transports[i].exit) {
			transports[i].exit();
		}
	}

	transport_init_done = 0;
	transport_initialised = false;
}

/* ---- per-node accept lists ---------------------------------------------- */

uint32_t transport_node_mask(const node_t *n) {
	return n->transports ? n->transports : TRANSPORT_MASK_PLAIN;
}

void transport_node_read_config(node_t *n, splay_tree_t *config_tree) {
	/* The peer's pinned TLS certificate fingerprint, if its host record carries
	   one (from an invitation or a first-use pin). Used by the https carrier. */
	char *fp = NULL;

	if(get_config_string(lookup_config(config_tree, "TlsFingerprint"), &fp) && fp) {
		free(n->tls_fingerprint);
		n->tls_fingerprint = fp;
	}

	char *list = config_join(config_tree, "Transports");

	if(!list) {
		return;
	}

	uint32_t mask;
	char bad[TRANSPORT_LIST_MAX];

	if(transport_parse_list(list, &mask, NULL, NULL, bad) && mask) {
		/* Taken as written, `plain' included or not: a host record saying
		   `Transports = obfs, https' is the operator stating that this peer
		   does not answer cleartext (it runs AllowPlainMeta = no), and
		   OR-ing plain back in would only produce dials it refuses. A peer
		   that does accept plain lists it, here and in its ACK. */
		n->transports = mask;
	} else {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Ignoring Transports of %s: unknown carrier `%s'", n->name, bad);
	}

	free(list);
}

const char *transport_accept_string(char *buf) {
	return transport_mask_to_string(transport_accept_mask, buf);
}

/* ---- outbound selection -------------------------------------------------- */

void transport_candidate_activated(outgoing_t *outgoing, const connection_t *c) {
	transport_id_t id = c->transport ? c->transport->id : TRANSPORT_PLAIN;

	/* Only a link we dialled ourselves proves that the candidate works: when
	   the peer dialled us first, id_h() moves the outgoing_t onto its inbound
	   connection, whose carrier is the peer's choice, not ours. */
	if(outgoing->ncandidates && outgoing->candidates[outgoing->transport_idx] == id) {
		outgoing->last_ok_mask = TRANSPORT_BIT(id);
		outgoing->last_ok_failures = 0;
	}

	outgoing->ncandidates = 0;
	outgoing->transport_idx = 0;

	/* Defect E: a link to this peer came up, whichever side dialled it and
	   over whichever carrier, so the give-up counter that quiets the "Could
	   not set up a meta connection" ERROR starts again from zero. A peer that
	   goes unreachable later is loud again, exactly once. */
	outgoing->failures = 0;
	outgoing->udp_fallback_used = false;
}

static void build_candidates(outgoing_t *outgoing) {
	uint32_t peer = transport_node_mask(outgoing->node);
	outgoing->ncandidates = 0;
	outgoing->transport_idx = 0;

	for(int i = 0; i < transport_pref_count; i++) {
		transport_id_t id = transport_pref[i];

		if((peer & TRANSPORT_BIT(id)) && transports[id].dial) {
			outgoing->candidates[outgoing->ncandidates++] = id;
		}
	}

	if(!outgoing->ncandidates) {
		outgoing->candidates[outgoing->ncandidates++] = TRANSPORT_PLAIN;
	}

	if(debug_level >= DEBUG_CONNECTIONS) {
		char buf[TRANSPORT_LIST_MAX] = "";

		for(int i = 0; i < outgoing->ncandidates; i++) {
			size_t l = strlen(buf);
			snprintf(buf + l, sizeof(buf) - l, "%s%s", l ? "," : "", transport_name(outgoing->candidates[i]));
		}

		char pbuf[TRANSPORT_LIST_MAX];
		char obuf[TRANSPORT_LIST_MAX];

		if(outgoing->last_ok_mask) {
			snprintf(obuf, sizeof(obuf), ", last activated %s", transport_mask_to_string(outgoing->last_ok_mask, pbuf));
		} else {
			*obuf = 0;
		}

		logger(DEBUG_CONNECTIONS, LOG_INFO, "Carrier candidates for %s: %s (peer accepts %s%s)", outgoing->node->name, buf, transport_mask_to_string(peer, pbuf), obuf);
	}
}

const transport_t *transport_current(outgoing_t *outgoing) {
	if(!outgoing->ncandidates) {
		build_candidates(outgoing);
	}

	return &transports[outgoing->candidates[outgoing->transport_idx]];
}

bool transport_next_candidate(outgoing_t *outgoing) {
	if(!outgoing->ncandidates) {
		build_candidates(outgoing);
	}

	transport_id_t cur = outgoing->candidates[outgoing->transport_idx];

	/* A carrier that already activated a link to this peer is not given up
	   on the first pre-activation failure (peer restarting, a single reset
	   or blocked handshake): it is retried, with the normal reconnect
	   backoff, until it has failed TRANSPORT_STICKY_FAILURES times in a row.
	   Anything less would let one reset downgrade an https/quic link to
	   plain (review L-2). */
	if(outgoing->last_ok_mask == TRANSPORT_BIT(cur)) {
		outgoing->last_ok_failures++;

		if(outgoing->last_ok_failures < TRANSPORT_STICKY_FAILURES) {
			logger(DEBUG_CONNECTIONS, LOG_INFO, "Carrier %s failed for %s before activation (%d/%d) but worked before, retrying it",
			       transport_name(cur), outgoing->node->name, outgoing->last_ok_failures, TRANSPORT_STICKY_FAILURES);
			return false;
		}

		logger(DEBUG_CONNECTIONS, LOG_INFO, "Carrier %s failed %d times in a row for %s, no longer preferred",
		       transport_name(cur), outgoing->last_ok_failures, outgoing->node->name);
		outgoing->last_ok_mask = 0;
		outgoing->last_ok_failures = 0;
	}

	if(outgoing->transport_idx + 1 < outgoing->ncandidates) {
		logger(DEBUG_CONNECTIONS, LOG_INFO, "Carrier %s failed for %s, falling back to %s",
		       transport_name(outgoing->candidates[outgoing->transport_idx]), outgoing->node->name,
		       transport_name(outgoing->candidates[outgoing->transport_idx + 1]));
		outgoing->transport_idx++;
		return true;
	}

	/* Exhausted: the next cycle restarts from the operator's first
	   preference, so a walk never settles on plain. */
	logger(DEBUG_CONNECTIONS, LOG_INFO, "Every carrier failed for %s, restarting from %s",
	       outgoing->node->name, transport_name(outgoing->candidates[0]));
	outgoing->ncandidates = 0;
	outgoing->transport_idx = 0;
	return false;
}

bool transport_udp_meta_fallback(outgoing_t *outgoing, sockaddr_t *sa) {
	if(!udp_meta_fallback || !outgoing || outgoing->udp_fallback_used) {
		return false;
	}

	if(!(transport_accept_mask & TRANSPORT_BIT(TRANSPORT_SF)) || !transports[TRANSPORT_SF].dial) {
		return false;
	}

	node_t *n = outgoing->node;

	if(!n || n == myself || !n->status.reachable || !n->status.udp_confirmed) {
		return false;
	}

	/* The UDP path must go to the peer itself. `via' is the node the data
	   actually travels through, so `via != n' means the "direct" path is a
	   relay and dialling a meta connection at that address would talk to the
	   wrong node. */
	if(n->via != n || n->address.sa.sa_family == AF_UNKNOWN || !n->address.sa.sa_family) {
		return false;
	}

	if(!(transport_node_mask(n) & TRANSPORT_BIT(TRANSPORT_SF))) {
		return false;
	}

	outgoing->udp_fallback_used = true;
	*sa = n->address;
	return true;
}

/* Global carrier ranking for the acceptor-side rule. The transport_id_t order
   (plain < sf < obfs < https < quic) doubles as "how much wrapping the carrier
   puts around SPTPS", and every build compiles the same table, so both ends
   agree on it without negotiating anything. The `test' stub carrier takes part
   in no comparison. */
static int carrier_rank(transport_id_t id) {
	return id < TRANSPORT_TEST ? (int) id : -1;
}

bool transport_outranks_connection(outgoing_t *outgoing, const connection_t *c) {
	if(!outgoing || !c || c->status.control || !c->node) {
		return false;
	}

	int have = carrier_rank(c->transport ? c->transport->id : TRANSPORT_PLAIN);

	if(have < 0) {
		return false;
	}

	int want = carrier_rank(transport_current(outgoing)->id);
	return want > have;
}

/* ---- meta-channel plumbing ----------------------------------------------- */

void transport_meta_flush(connection_t *c) {
	if(c->transport && c->transport->send) {
		c->transport->send(c);
	} else {
		io_set(&c->io, IO_READ | IO_WRITE);
	}
}

void transport_connection_close(connection_t *c) {
	if(c->transport && c->transport->close) {
		c->transport->close(c);
	}

	c->transport = NULL;
}

bool transport_local_address(connection_t *c, sockaddr_t *sa) {
	if(c->transport && c->transport->local_address) {
		return c->transport->local_address(c, sa);
	}

	socklen_t salen = sizeof(*sa);
	return getsockname(c->socket, &sa->sa, &salen) >= 0;
}

/* ---- inbound TCP front --------------------------------------------------- */

/* Security review R-1. The front peeks (MSG_PEEK) so that the bytes stay in
   the socket for the carrier that claims them (https_accept hands the socket
   to SSL_accept, which must see the ClientHello itself). When the classifier
   wants more bytes than have arrived, the pending bytes keep the socket
   readable and the level-triggered select() would call us again on every
   loop turn: one client sending a single `G', `0' or 0x16 0x03 pinned the
   daemon at 100 % CPU until pingtimeout. So an undecided connection is
   *parked*: its read interest is dropped and one global timer re-arms every
   parked connection FRONT_POLL_MS later (one peek per tick per parked client,
   never a spin). A connection that is still undecided FRONT_DEADLINE seconds
   after it was accepted is closed and tarpitted, instead of living until
   pingtimeout. A client that sends nothing at all is not parked (select never
   fires for it) and is reaped by the authentication timeout as before. */
#define FRONT_POLL_MS 200
#define FRONT_DEADLINE 2

static bool front_expired(connection_t *c) {
	return c->last_ping_time + FRONT_DEADLINE <= now.tv_sec;
}

static void front_close_undecided(connection_t *c) {
	logger(DEBUG_CONNECTIONS, LOG_INFO, "Front: %s sent no recognisable preamble within %d s; closing", c->hostname, FRONT_DEADLINE);
	c->status.tarpit = true;
	terminate_connection(c, false);
}

static void front_poll(void *data) {
	(void)data;
	bool parked = false;

	for list_each(connection_t, c, &connection_list) {
		if(!c->status.front_pending || c->io.flags) {
			continue;
		}

		if(front_expired(c)) {
			front_close_undecided(c);
			continue;
		}

		/* Re-arm: the next loop turn peeks again; if the client still has not
		   sent enough, the dispatcher parks it again until the next tick. */
		io_set(&c->io, IO_READ);
		parked = true;
	}

	if(parked) {
		timeout_set(&front_poll_timer, &(struct timeval) {
			0, FRONT_POLL_MS * 1000
		});
	}
}

static void front_park(connection_t *c) {
	io_set(&c->io, 0);

	struct timeval tv = { 0, FRONT_POLL_MS * 1000 };

	/* timeout_execute() deletes the timer (cb = NULL) after a tick that did
	   not re-arm it, so cb != NULL means a tick is already scheduled. */
	if(!front_poll_timer.cb) {
		timeout_add(&front_poll_timer, front_poll, NULL, &tv);
	}
}

bool transport_front_dispatch(connection_t *c) {
	uint8_t peek[TRANSPORT_TCP_PEEK];
	ssize_t len = recv(c->socket, peek, sizeof(peek), MSG_PEEK);

	if(len < 0) {
		if(sockwouldblock(sockerrno)) {
			return false;
		}

		logger(DEBUG_CONNECTIONS, LOG_ERR, "Front peek error for %s: %s", c->hostname, sockstrerror(sockerrno));
		terminate_connection(c, false);
		return false;
	}

	if(len == 0) {
		logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Connection closed by %s before sending anything", c->hostname);
		terminate_connection(c, false);
		return false;
	}

	transport_tcp_class_t class = transport_classify_tcp(peek, (size_t)len);

	/* The HttpsPort listener is a TLS port and nothing else: no tinc, no
	   obfs, no cleartext decoy there. What a TLS server does with bytes that
	   are not a ClientHello is the decoy's business (see decoy.c); for now
	   the connection is closed without an answer. */
	if(c->status.front_tls_only && class != TCP_CLASS_TLS && class != TCP_CLASS_NEED_MORE) {
		logger(DEBUG_CONNECTIONS, LOG_INFO, "Front: non-TLS bytes from %s on the https port; closing", c->hostname);
		terminate_connection(c, false);
		return false;
	}

	switch(class) {
	case TCP_CLASS_NEED_MORE:
		/* Wait for more bytes without spinning on the ones already there
		   (R-1): park the connection; front_poll() re-arms it or closes it
		   once FRONT_DEADLINE has passed. */
		if(front_expired(c)) {
			front_close_undecided(c);
			return false;
		}

		logger(DEBUG_META, LOG_DEBUG, "Front: %zd undecided byte(s) from %s; parking for %d ms", len, c->hostname, FRONT_POLL_MS);
		front_park(c);
		return false;

	case TCP_CLASS_TINC:

		/* Symmetric with the TLS branch below: a carrier is only taken when
		   it is in the accept mask. `plain' is in that mask unless the
		   operator set AllowPlainMeta = no.

		   Loopback is exempt on purpose. This is not a carrier decision: on
		   Windows there is no UNIX control socket, so the tinc CLI reaches
		   its own daemon by opening a TCP connection to this very port and
		   sending `0 ^<cookie> ...' -- a tinc ID line, classified TCP_CLASS_TINC.
		   Refusing that would lock the operator out of their own node while
		   buying nothing: an attacker who can already connect from 127.0.0.1
		   does not need to fingerprint the port. (POSIX control connections
		   arrive on the UNIX socket and never reach this function.) */
		if(!(transport_accept_mask & TRANSPORT_MASK_PLAIN) && !is_local_connection(&c->address)) {
			logger(DEBUG_CONNECTIONS, LOG_WARNING, "Front: refusing cleartext tinc meta connection from %s: `plain' is not in this node's Transports accept list (AllowPlainMeta = no)", c->hostname);
			c->status.tarpit = true;
			terminate_connection(c, false);
			return false;
		}

		c->status.front_pending = false;
		c->transport = &transports[TRANSPORT_PLAIN];
		logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Front: tinc connection from %s", c->hostname);
		return true;

	case TCP_CLASS_TLS:
		if((transport_accept_mask & TRANSPORT_BIT(TRANSPORT_HTTPS)) && transports[TRANSPORT_HTTPS].accept) {
			c->status.front_pending = false;
			c->transport = &transports[TRANSPORT_HTTPS];
			return transports[TRANSPORT_HTTPS].accept(c, peek, (size_t)len);
		}

		/* No https carrier / decoy in this build (M5): close without a word. */
		logger(DEBUG_CONNECTIONS, LOG_INFO, "Front: TLS ClientHello from %s but no TLS front is built; closing", c->hostname);
		c->status.tarpit = true;
		terminate_connection(c, false);
		return false;

	case TCP_CLASS_HTTP:
		/* A cleartext prober gets the same decoy content over plain HTTP. */
		c->status.front_pending = false;
		decoy_serve_plain(c);
		return false;

	case TCP_CLASS_OBFS:
		if((transport_accept_mask & TRANSPORT_BIT(TRANSPORT_OBFS)) && transports[TRANSPORT_OBFS].accept) {
			c->status.front_pending = false;
			c->transport = &transports[TRANSPORT_OBFS];
			return transports[TRANSPORT_OBFS].accept(c, peek, (size_t)len);
		}

		logger(DEBUG_CONNECTIONS, LOG_INFO, "Front: obfs preamble from %s but no obfs carrier is built; closing", c->hostname);
		c->status.tarpit = true;
		terminate_connection(c, false);
		return false;

	case TCP_CLASS_UNKNOWN:
	default:
		logger(DEBUG_CONNECTIONS, LOG_INFO, "Front: unrecognised bytes from %s; closing", c->hostname);
		c->status.tarpit = true;
		terminate_connection(c, false);
		return false;
	}
}

/* ---- inbound UDP front --------------------------------------------------- */

bool transport_udp_dispatch(listen_socket_t *ls, const uint8_t *buf, size_t len, const sockaddr_t *addr) {
	switch(transport_classify_udp(buf, len, transport_accept_mask)) {
	case UDP_CLASS_SF:
		sf_udp_receive(ls, buf, len, addr);
		return true;

	case UDP_CLASS_QUIC:
#if defined(HAVE_QUIC) && defined(HAVE_OPENSSL)

		/* A live session's packet, or a valid Initial. A long-header
		   lookalike that ngtcp2 does not accept is NOT claimed: it falls
		   through to the obfs keyed check and the SPTPS path below. */
		if(quic_udp_try(ls, buf, len, addr)) {
			return true;
		}

#else

		if(debug_level >= DEBUG_TRAFFIC) {
			char *hostname = sockaddr2hostname(addr);
			logger(DEBUG_TRAFFIC, LOG_INFO, "Dropping QUIC datagram from %s: no quic carrier in this build", hostname);
			free(hostname);
		}

		return true;
#endif

	/* fall through */
	case UDP_CLASS_OBFS:
	case UDP_CLASS_SPTPS:
	default:
		/* obfs frames look random, so the pattern classifier cannot spot
		   them; the carrier's keyed check claims them here. It re-injects the
		   inner datagram straight into the SF or SPTPS receive path (not back
		   through this dispatcher), so there is no re-entrancy and a plain
		   SPTPS datagram is never scanned when obfs is not in use. */
		if((transport_accept_mask & TRANSPORT_BIT(TRANSPORT_OBFS)) && obfs_udp_try(ls, buf, len, addr)) {
			return true;
		}

		return false;
	}
}
