/*
    obfs.c -- obfuscated-UDP carrier (M5, redesign of tinc-obfs).

    See obfs.h and docs/transports.md for the design. In one paragraph: obfs
    seals every UDP datagram of a link (single-flow meta frames and SPTPS data
    datagrams) in an authenticated frame

        nonce(8) | clen(2) | ChaCha20-Poly1305(inner) | tail-junk

    keyed from a hash of the two nodes' Ed25519 public keys. The Poly1305 tag
    is the authenticated junk/real discriminator: junk (random bytes) and
    forgeries fail it. Junk datagrams are emitted only around a handshake. On a
    relay the frame is stripped on receive and re-applied per hop, so a relayed
    SPTPS record is never double-wrapped. SPTPS is untouched.

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

#include "chacha-poly1305/chacha-poly1305.h"
#include "conf.h"
#include "ecdsa.h"
#include "ed25519/sha512.h"
#include "list.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "random.h"
#include "utils.h"
#include "xalloc.h"

#define TINC_TRANSPORT_DAEMON
#include "transport.h"
#include "obfs.h"

/* ---- configuration ------------------------------------------------------- */

int obfs_junk_count = 0;
int obfs_junk_min = 40;
int obfs_junk_max = 200;
int obfs_init_header_junk = 0;
int obfs_transport_header_junk = 0;
uint32_t obfs_init_magic = 0;
uint32_t obfs_transport_magic = 0;

/* Cold-start key scans per second: an unauthenticated datagram from an unknown
   address costs at most this many key trials, mirroring try_harder()'s bound. */
#define OBFS_SCAN_PER_SEC 25

/* ---- per-link key material ----------------------------------------------- */

struct obfs_link_t {
	node_t *node;
	chacha_poly1305_ctx_t *ctx;   /* keyed once; encrypt+decrypt use it read-only */
	bool active;                  /* an obfs flow to this node is up */
	sockaddr_t addr;              /* last known peer UDP address (fast-path match) */
	bool have_addr;
};

static list_t obfs_links = {
	.head = NULL, .tail = NULL, .count = 0,
	.delete = NULL,
};

static void obfs_link_free(obfs_link_t *l) {
	if(l->ctx) {
		chacha_poly1305_exit(l->ctx);
	}

	free(l);
}

/* Derive the 64-byte ChaCha20-Poly1305 key from a context string and the two
   nodes' Ed25519 public keys, sorted so both ends compute the same key. The
   public keys are shared material both peers already hold; an on-path censor
   without them can neither forge a real frame nor tell junk from real. */
static bool obfs_derive_key(node_t *n, uint8_t key[64]) {
	if(!myself || !myself->connection || !myself->connection->ecdsa || !n->ecdsa) {
		return false;
	}

	char *mine = ecdsa_get_base64_public_key(myself->connection->ecdsa);
	char *his = ecdsa_get_base64_public_key(n->ecdsa);

	if(!mine || !his) {
		free(mine);
		free(his);
		return false;
	}

	const char *lo = strcmp(mine, his) <= 0 ? mine : his;
	const char *hi = strcmp(mine, his) <= 0 ? his : mine;

	static const char context[] = "tincstack-obfs-v1";
	sha512_context md;
	sha512_init(&md);
	sha512_update(&md, context, sizeof(context)); /* include the NUL as a separator */
	sha512_update(&md, lo, strlen(lo));
	sha512_update(&md, "|", 1);
	sha512_update(&md, hi, strlen(hi));
	sha512_final(&md, key);

	free(mine);
	free(his);
	return true;
}

obfs_link_t *obfs_link_for_node(node_t *n) {
	for list_each(obfs_link_t, l, &obfs_links) {
		if(l->node == n) {
			return l;
		}
	}

	uint8_t key[64];

	if(!obfs_derive_key(n, key)) {
		return NULL;
	}

	obfs_link_t *l = xzalloc(sizeof(*l));
	l->node = n;
	l->ctx = chacha_poly1305_init();

	if(!l->ctx || !chacha_poly1305_set_key(l->ctx, key)) {
		obfs_link_free(l);
		return NULL;
	}

	list_insert_tail(&obfs_links, l);
	return l;
}

void obfs_link_activate(obfs_link_t *l, const sockaddr_t *addr) {
	l->active = true;

	if(addr) {
		l->addr = *addr;
		sockaddrunmap(&l->addr);
		l->have_addr = true;
	}
}

/* ---- little-endian-free 64-bit nonce helpers ----------------------------- */

static uint64_t nonce_to_u64(const uint8_t *p) {
	uint64_t v = 0;

	for(int i = 0; i < 8; i++) {
		v = (v << 8) | p[i];
	}

	return v;
}

/* ---- framing ------------------------------------------------------------- */

size_t obfs_encode(obfs_link_t *l, const void *in, size_t inlen, uint8_t *out, size_t outcap, bool init) {
	if(!l || !l->ctx) {
		return 0;
	}

	int header_junk = init ? obfs_init_header_junk : obfs_transport_header_junk;
	uint32_t magic = init ? obfs_init_magic : obfs_transport_magic;

	if(header_junk < 0) {
		header_junk = 0;
	}

	if(header_junk > OBFS_MAX_JUNK) {
		header_junk = OBFS_MAX_JUNK;
	}

	size_t clen = inlen + OBFS_TAG_LEN;

	if(clen > 0xffff || OBFS_HDR_LEN + clen + (size_t)header_junk > outcap) {
		return 0;
	}

	/* nonce: random, so frames are indistinguishable; a configured magic
	   shapes the leading bytes to mimic another protocol if desired. */
	randomize(out, OBFS_NONCE_LEN);

	if(magic) {
		out[0] = (uint8_t)(magic >> 24);
		out[1] = (uint8_t)(magic >> 16);
		out[2] = (uint8_t)(magic >> 8);
		out[3] = (uint8_t)(magic);
	}

	out[OBFS_NONCE_LEN] = (uint8_t)(clen >> 8);
	out[OBFS_NONCE_LEN + 1] = (uint8_t)(clen);

	uint64_t seqnr = nonce_to_u64(out);

	if(!chacha_poly1305_encrypt(l->ctx, seqnr, in, inlen, out + OBFS_HDR_LEN, NULL)) {
		return 0;
	}

	if(header_junk) {
		randomize(out + OBFS_HDR_LEN + clen, (size_t)header_junk);
	}

	return OBFS_HDR_LEN + clen + (size_t)header_junk;
}

/* Try to unseal one datagram with link `l'. On success writes the inner
   datagram to `out' (capacity `outcap') and returns its length; on failure
   (not our frame / junk / forgery) returns -1. */
static ssize_t obfs_open(obfs_link_t *l, const uint8_t *buf, size_t len, uint8_t *out, size_t outcap) {
	if(!l || !l->ctx || len < OBFS_MIN_FRAME) {
		return -1;
	}

	size_t clen = ((size_t)buf[OBFS_NONCE_LEN] << 8) | buf[OBFS_NONCE_LEN + 1];

	if(clen < OBFS_TAG_LEN || OBFS_HDR_LEN + clen > len) {
		return -1;
	}

	size_t innerlen = clen - OBFS_TAG_LEN;

	if(innerlen > outcap) {
		return -1;
	}

	uint64_t seqnr = nonce_to_u64(buf);
	size_t outlen = 0;

	if(!chacha_poly1305_decrypt(l->ctx, seqnr, buf + OBFS_HDR_LEN, clen, out, &outlen)) {
		return -1;
	}

	return (ssize_t)outlen;
}

/* ---- sending ------------------------------------------------------------- */

bool obfs_wrap_send(size_t sock, const sockaddr_t *sa, const void *buf, size_t len, node_t *to) {
	if(!to) {
		return false;
	}

	obfs_link_t *l = NULL;

	for list_each(obfs_link_t, cand, &obfs_links) {
		if(cand->node == to && cand->active) {
			l = cand;
			break;
		}
	}

	if(!l) {
		return false; /* not an obfs link: caller sends the datagram unchanged */
	}

	uint8_t frame[OBFS_HDR_LEN + MAXSIZE + OBFS_TAG_LEN + OBFS_MAX_JUNK];
	size_t flen = obfs_encode(l, buf, len, frame, sizeof(frame), false);

	if(!flen) {
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Could not obfs-wrap a %zu-byte datagram to %s", len, to->name);
		return true; /* it is an obfs link; dropping the datagram beats leaking it in the clear */
	}

	if(sendto(listen_socket[sock].udp.fd, (void *)frame, flen, 0, &sa->sa, SALEN(sa->sa)) < 0 && !sockwouldblock(sockerrno)) {
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Error sending obfs datagram to %s (%s): %s", to->name, to->hostname, sockstrerror(sockerrno));
	}

	return true;
}

void obfs_send_junk(size_t sock, const sockaddr_t *addr) {
	if(obfs_junk_count <= 0) {
		return;
	}

	int lo = obfs_junk_min > 0 ? obfs_junk_min : 1;
	int hi = obfs_junk_max >= lo ? obfs_junk_max : lo;

	if(hi > OBFS_MAX_JUNK) {
		hi = OBFS_MAX_JUNK;
	}

	uint8_t junk[OBFS_MAX_JUNK];

	for(int i = 0; i < obfs_junk_count; i++) {
		uint32_t r;
		randomize(&r, sizeof(r));
		int size = lo + (int)(r % (uint32_t)(hi - lo + 1));
		randomize(junk, (size_t)size);

		if(sendto(listen_socket[sock].udp.fd, (void *)junk, (size_t)size, 0, &addr->sa, SALEN(addr->sa)) < 0 && !sockwouldblock(sockerrno)) {
			break;
		}
	}

	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Sent %d obfs junk datagram(s) around a handshake", obfs_junk_count);
}

/* ---- inbound: keyed classification + decap + re-injection ---------------- */

static bool obfs_inject(listen_socket_t *ls, const uint8_t *inner, size_t innerlen, const sockaddr_t *addr, obfs_link_t *l) {
	/* A single-flow meta frame carries the SF magic; anything else is an
	   SPTPS data datagram. Re-inject it into the normal receive path; the
	   SF path is told which link this came in on so its replies are sealed
	   with the same key. The SPTPS path re-enters handle_incoming_vpn_packet
	   with obfs disabled, so the inner is never scanned as obfs again. */
	if(innerlen >= SF_MAGIC_LEN && !memcmp(inner, sf_magic, SF_MAGIC_LEN)) {
		obfs_link_activate(l, addr);
		sf_udp_receive_obfs(ls, inner, innerlen, addr, l);
		return true;
	}

	obfs_link_activate(l, addr);
	handle_incoming_vpn_packet_decap(ls, inner, innerlen, addr);
	return true;
}

bool obfs_udp_try(listen_socket_t *ls, const uint8_t *buf, size_t len, const sockaddr_t *vaddr) {
	if(len < OBFS_MIN_FRAME) {
		return false;
	}

	sockaddr_t addr = *vaddr;
	sockaddrunmap(&addr);

	uint8_t inner[MAXSIZE];

	/* Fast path: a link that is already up for this source address. One
	   Poly1305 verification, exactly as an established SPTPS peer costs one.
	   On failure fall through (do not claim it): it is junk around a handshake
	   or, during the brief window where the two ends disagree on whether the
	   link is active, a still-plain datagram that the SPTPS path must see. */
	for list_each(obfs_link_t, l, &obfs_links) {
		if(l->active && l->have_addr && !sockaddrcmp(&addr, &l->addr)) {
			ssize_t n = obfs_open(l, buf, len, inner, sizeof(inner));

			if(n >= 0) {
				return obfs_inject(ls, inner, (size_t)n, &addr, l);
			}

			return false;
		}
	}

	/* Cold start: an unknown source. Only scan when obfs is accepted and the
	   source is not an already-confirmed plain peer, and rate-limit it. */
	if(!(transport_accept_mask & TRANSPORT_BIT(TRANSPORT_OBFS))) {
		return false;
	}

	node_t *known = lookup_node_udp(&addr);

	if(known && known->status.udp_confirmed) {
		return false; /* an established plain peer: leave it to the SPTPS path */
	}

	static time_t scan_time;
	static int scan_budget;

	if(now.tv_sec != scan_time) {
		scan_time = now.tv_sec;
		scan_budget = OBFS_SCAN_PER_SEC;
	}

	for splay_each(node_t, n, &node_tree) {
		if(!n->ecdsa || n == myself) {
			continue;
		}

		if(scan_budget-- <= 0) {
			break;
		}

		obfs_link_t *l = obfs_link_for_node(n);

		if(!l) {
			continue;
		}

		ssize_t nlen = obfs_open(l, buf, len, inner, sizeof(inner));

		if(nlen >= 0) {
			logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Cold-classified an obfs datagram from %s as %s", sockaddr2hostname(&addr), n->name);
			return obfs_inject(ls, inner, (size_t)nlen, &addr, l);
		}
	}

	return false;
}

/* ---- carrier hooks ------------------------------------------------------- */

bool obfs_dial(connection_t *c) {
	node_t *n = c->outgoing ? c->outgoing->node : (c->name ? lookup_node(c->name) : NULL);

	if(!n) {
		logger(DEBUG_CONNECTIONS, LOG_ERR, "Cannot dial %s via obfs: node unknown", c->name);
		return false;
	}

	obfs_link_t *l = obfs_link_for_node(n);

	if(!l) {
		logger(DEBUG_CONNECTIONS, LOG_WARNING, "Cannot dial %s via obfs: no Ed25519 key to derive a link key from", c->name);
		return false; /* fall back to the next carrier */
	}

	/* Emit junk around the handshake before the first real frame, then bring
	   up the single-flow meta channel with obfs sealing every frame. */
	int sock = -1;

	for(int i = 0; i < listen_sockets; i++) {
		if(listen_socket[i].sa.sa.sa_family == c->address.sa.sa_family) {
			sock = i;
			break;
		}
	}

	if(sock < 0) {
		logger(DEBUG_CONNECTIONS, LOG_ERR, "No UDP socket with the address family of %s for an obfs dial", c->name);
		return false;
	}

	obfs_link_activate(l, &c->address);
	obfs_send_junk((size_t)sock, &c->address);

	return sf_dial_obfs(c, l);
}

void obfs_close(connection_t *c) {
	obfs_link_t *l = sf_connection_obfs(c);

	if(l) {
		l->active = false;
		l->have_addr = false;
	}

	sf_close(c);
}

/* ---- config / init / exit ------------------------------------------------ */

static void get_int(const char *name, int *out, int min, int max) {
	int v;

	if(get_config_int(lookup_config(&config_tree, name), &v)) {
		if(v < min) {
			v = min;
		}

		if(v > max) {
			v = max;
		}

		*out = v;
	}
}

static void get_magic(const char *name, uint32_t *out) {
	int v;

	if(get_config_int(lookup_config(&config_tree, name), &v)) {
		*out = (uint32_t)v;
	}
}

bool obfs_read_config(void) {
	obfs_links.delete = (list_action_t)obfs_link_free;
	obfs_junk_count = 0;
	obfs_junk_min = 40;
	obfs_junk_max = 200;
	obfs_init_header_junk = 0;
	obfs_transport_header_junk = 0;
	obfs_init_magic = 0;
	obfs_transport_magic = 0;

	get_int("ObfsJunkPacketCount", &obfs_junk_count, 0, 128);
	get_int("ObfsJunkPacketMinSize", &obfs_junk_min, 1, OBFS_MAX_JUNK);
	get_int("ObfsJunkPacketMaxSize", &obfs_junk_max, 1, OBFS_MAX_JUNK);
	get_int("ObfsInitHeaderJunkSize", &obfs_init_header_junk, 0, OBFS_MAX_JUNK);
	get_int("ObfsTransportHeaderJunkSize", &obfs_transport_header_junk, 0, OBFS_MAX_JUNK);
	get_magic("ObfsInitMagicHeader", &obfs_init_magic);
	get_magic("ObfsTransportMagicHeader", &obfs_transport_magic);

	if(obfs_junk_max < obfs_junk_min) {
		obfs_junk_max = obfs_junk_min;
	}

	return true;
}

bool obfs_init(void) {
	obfs_links.delete = (list_action_t)obfs_link_free;
	return obfs_read_config();
}

void obfs_exit(void) {
	list_empty_list(&obfs_links);
}
