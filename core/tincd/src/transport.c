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

uint32_t transport_accept_mask;
transport_id_t transport_pref[TRANSPORT_MAX];
int transport_pref_count;
bool single_flow;

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
	/* M5 fills these in; the names are registered so option parsing and
	   peer advertisements already know them. */
	[TRANSPORT_OBFS]  = { .id = TRANSPORT_OBFS,  .name = "obfs",  .caps = TRANSPORT_CAP_SINGLE_FLOW },
	[TRANSPORT_HTTPS] = { .id = TRANSPORT_HTTPS, .name = "https", .caps = TRANSPORT_CAP_SINGLE_FLOW | TRANSPORT_CAP_META_TCP },
	[TRANSPORT_QUIC]  = { .id = TRANSPORT_QUIC,  .name = "quic",  .caps = TRANSPORT_CAP_SINGLE_FLOW },
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

		if(!(mask & TRANSPORT_MASK_PLAIN)) {
			logger(DEBUG_ALWAYS, LOG_WARNING, "Transports omits `plain'; it is always accepted (upstream peers and the control connection need it)");
			mask |= TRANSPORT_MASK_PLAIN;
		}

		free(list);
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
	logger(DEBUG_ALWAYS, LOG_INFO, "Transports accept=%s prefer=%s%s", transport_mask_to_string(transport_accept_mask, buf), pbuf, single_flow ? " (SingleFlow)" : "");
	return true;
}

/* ---- init / exit --------------------------------------------------------- */

bool transport_init(void) {
	for(int i = 0; i < TRANSPORT_MAX; i++) {
		if(transports[i].init && (transport_accept_mask & TRANSPORT_BIT(i)) && !transports[i].init()) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Carrier `%s' failed to initialise", transports[i].name);
			return false;
		}
	}

	return true;
}

void transport_exit(void) {
	for(int i = 0; i < TRANSPORT_MAX; i++) {
		if(transports[i].exit) {
			transports[i].exit();
		}
	}
}

/* ---- per-node accept lists ---------------------------------------------- */

uint32_t transport_node_mask(const node_t *n) {
	return n->transports ? n->transports : TRANSPORT_MASK_PLAIN;
}

void transport_node_read_config(node_t *n, splay_tree_t *config_tree) {
	char *list = config_join(config_tree, "Transports");

	if(!list) {
		return;
	}

	uint32_t mask;
	char bad[TRANSPORT_LIST_MAX];

	if(transport_parse_list(list, &mask, NULL, NULL, bad) && mask) {
		n->transports = mask | TRANSPORT_MASK_PLAIN;
	} else {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Ignoring Transports of %s: unknown carrier `%s'", n->name, bad);
	}

	free(list);
}

const char *transport_accept_string(char *buf) {
	return transport_mask_to_string(transport_accept_mask, buf);
}

/* ---- outbound selection -------------------------------------------------- */

void transport_reset_candidates(outgoing_t *outgoing) {
	outgoing->ncandidates = 0;
	outgoing->transport_idx = 0;
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
		logger(DEBUG_CONNECTIONS, LOG_INFO, "Carrier candidates for %s: %s (peer accepts %s)", outgoing->node->name, buf, transport_mask_to_string(peer, pbuf));
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

	if(outgoing->transport_idx + 1 < outgoing->ncandidates) {
		logger(DEBUG_CONNECTIONS, LOG_INFO, "Carrier %s failed for %s, falling back to %s",
		       transport_name(outgoing->candidates[outgoing->transport_idx]), outgoing->node->name,
		       transport_name(outgoing->candidates[outgoing->transport_idx + 1]));
		outgoing->transport_idx++;
		return true;
	}

	/* Exhausted: the next cycle re-evaluates from the top. */
	outgoing->ncandidates = 0;
	outgoing->transport_idx = 0;
	return false;
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

/* M5 replaces this with the real decoy (node certificate, static content or
   upstream proxy). Until then a plaintext prober gets a minimal, valid
   response and the connection is closed. */
static void decoy_http(connection_t *c, size_t peeked) {
	static const char body[] = "<!doctype html><html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>\n";
	char header[256];
	int hlen = snprintf(header, sizeof(header),
	                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
	                    sizeof(body) - 1);

	/* Drain what has arrived so the close is a FIN, not a RST. */
	char drain[1024];
	(void)peeked;

	while(recv(c->socket, drain, sizeof(drain), 0) > 0);

	if(send(c->socket, header, hlen, 0) == hlen) {
		send(c->socket, body, sizeof(body) - 1, 0);
	}

	logger(DEBUG_CONNECTIONS, LOG_INFO, "Answered HTTP probe from %s with the decoy page", c->hostname);
	terminate_connection(c, false);
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

	switch(class) {
	case TCP_CLASS_NEED_MORE:
		/* Wait for more bytes; the authentication timeout in
		   timeout_handler() closes the connection if they never come. */
		return false;

	case TCP_CLASS_TINC:
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
		c->status.front_pending = false;
		decoy_http(c, (size_t)len);
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
		if(transports[TRANSPORT_QUIC].udp_receive) {
			transports[TRANSPORT_QUIC].udp_receive(ls, buf, len, addr);
		} else if(debug_level >= DEBUG_TRAFFIC) {
			char *hostname = sockaddr2hostname(addr);
			logger(DEBUG_TRAFFIC, LOG_INFO, "Dropping QUIC datagram from %s: no quic carrier in this build", hostname);
			free(hostname);
		}

		return true;

	case UDP_CLASS_OBFS:
		if(transports[TRANSPORT_OBFS].udp_receive) {
			transports[TRANSPORT_OBFS].udp_receive(ls, buf, len, addr);
			return true;
		}

		return false;

	case UDP_CLASS_SPTPS:
	default:
		return false;
	}
}
