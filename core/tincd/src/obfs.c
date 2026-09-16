/*
    obfs.c -- obfuscated-UDP carrier (M5, redesign of tinc-obfs; hardened for
    security review R findings M5-2..M5-6).

    See obfs.h and docs/transports.md for the design. In one paragraph: obfs
    seals every UDP datagram of a link (single-flow meta frames and SPTPS data
    datagrams) in an authenticated frame

        [magic] | nonce(8) | clen(2) | ChaCha20-Poly1305(inner) | tail-junk

    The nonce is a per-direction strict counter (whitened by a key-derived
    mask), so it never repeats. Keys are direction-separated. The first
    datagrams use a bootstrap key derived from the two Ed25519 public keys;
    once the connection is up the peers exchange fresh seeds over the SPTPS
    meta channel (OBFS_KEY) and switch to a per-link session key that only they
    know. A sliding replay window rejects replays, and the peer address is
    moved only after a datagram verifies and is fresh. SPTPS is untouched.

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
#include "event.h"
#include "list.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "protocol.h"
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

/* Cold-start key scans: floor per second (mirrors try_harder()'s bound); the
   real budget scales with the number of peers (see obfs_udp_try) so a large
   mesh's last node is still classified and junk floods cannot starve it. */
#define OBFS_SCAN_PER_SEC 25
#define OBFS_SCAN_MAX     512

/* Replay window width (bits) over the per-direction counter. */
#define OBFS_REPLAY_BITS 64

/* Re-derive the session key at least this often even if KeyExpire is huge. */
#define OBFS_REKEY_TICK 30

/* ---- keyed direction-separated keysets ----------------------------------- */

typedef struct obfs_replay_t {
	uint64_t max;      /* highest counter accepted so far */
	uint64_t bits;     /* bitmap of the last OBFS_REPLAY_BITS counters */
	bool started;
} obfs_replay_t;

typedef struct obfs_keyset_t {
	chacha_poly1305_ctx_t *tx;   /* our outbound direction */
	chacha_poly1305_ctx_t *rx;   /* peer's outbound direction (what we receive) */
	uint8_t mtx[OBFS_NONCE_LEN]; /* nonce whitening mask, tx */
	uint8_t mrx[OBFS_NONCE_LEN]; /* nonce whitening mask, rx */
	uint64_t ctr_tx;             /* our monotone counter for this key */
	obfs_replay_t rw;            /* replay window on the rx counter */
	bool valid;
} obfs_keyset_t;

struct obfs_link_t {
	node_t *node;
	bool i_am_lo;                /* my pubkey sorts <= peer's: fixes direction labels */
	uint8_t base[64];           /* bootstrap base secret (from the public keys) */

	obfs_keyset_t boot;         /* bootstrap keyset (public-key derived) */
	obfs_keyset_t sess;         /* current session keyset (once negotiated) */
	obfs_keyset_t next;         /* pending session keyset during (re)negotiation */
	bool sess_tx_ready;         /* the peer confirmed it can decrypt our sess frames */

	/* session-key handshake state */
	uint8_t local_seed[OBFS_SEED_LEN];
	uint8_t peer_seed[OBFS_SEED_LEN];
	bool have_local_seed;
	bool have_peer_seed;
	bool ack_sent;              /* we have sent our OBFS_KEY ack (flag 1) */
	time_t sess_time;          /* when the current session key was promoted / rekey issued */

	bool active;               /* an obfs flow to this node is up */
	sockaddr_t addr;           /* last verified peer UDP address (fast-path match) */
	bool have_addr;
};

static list_t obfs_links = {
	.head = NULL, .tail = NULL, .count = 0,
	.delete = NULL,
};

static timeout_t obfs_rekey_timer;

/* ---- key derivation ------------------------------------------------------ */

/* out = SHA-512( ctx || '\0' || label || '\0' || secret[slen] ). */
static void obfs_kdf(const char *ctx, const char *label, const uint8_t *secret, size_t slen, uint8_t out[64]) {
	sha512_context md;
	sha512_init(&md);
	sha512_update(&md, ctx, strlen(ctx) + 1);
	sha512_update(&md, label, strlen(label) + 1);
	sha512_update(&md, secret, slen);
	sha512_final(&md, out);
}

static void keyset_free(obfs_keyset_t *ks) {
	if(ks->tx) {
		chacha_poly1305_exit(ks->tx);
	}

	if(ks->rx) {
		chacha_poly1305_exit(ks->rx);
	}

	memset(ks, 0, sizeof(*ks));
}

/* Build a direction-separated keyset from a 64-byte base secret. `kctx'/`ictx'
   are the context strings for the key and the nonce mask. The tx counter starts
   at a random 48-bit value so a peer that restarts mid-link picks counters
   above the other side's replay window (no black-out) and the wire nonce never
   looks like a plaintext counter. */
static bool keyset_build(obfs_keyset_t *ks, const uint8_t base[64], const char *kctx, const char *ictx, bool i_am_lo) {
	keyset_free(ks);

	const char *txl = i_am_lo ? "l2h" : "h2l";
	const char *rxl = i_am_lo ? "h2l" : "l2h";
	uint8_t k[64];

	ks->tx = chacha_poly1305_init();
	ks->rx = chacha_poly1305_init();

	if(!ks->tx || !ks->rx) {
		keyset_free(ks);
		return false;
	}

	obfs_kdf(kctx, txl, base, 64, k);

	if(!chacha_poly1305_set_key(ks->tx, k)) {
		keyset_free(ks);
		return false;
	}

	obfs_kdf(kctx, rxl, base, 64, k);

	if(!chacha_poly1305_set_key(ks->rx, k)) {
		keyset_free(ks);
		return false;
	}

	obfs_kdf(ictx, txl, base, 64, k);
	memcpy(ks->mtx, k, OBFS_NONCE_LEN);
	obfs_kdf(ictx, rxl, base, 64, k);
	memcpy(ks->mrx, k, OBFS_NONCE_LEN);
	memset(k, 0, sizeof(k));

	randomize(&ks->ctr_tx, sizeof(ks->ctr_tx));
	ks->ctr_tx &= 0xffffffffffffULL;   /* 48-bit start, room for 2^16 rekeys' worth */
	memset(&ks->rw, 0, sizeof(ks->rw));
	ks->valid = true;
	return true;
}

/* Derive the bootstrap base secret from a context string and the two nodes'
   Ed25519 public keys, sorted so both ends compute the same key. */
static bool obfs_derive_base(node_t *n, uint8_t base[64], bool *i_am_lo) {
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

	bool lo = strcmp(mine, his) <= 0;
	const char *lop = lo ? mine : his;
	const char *hip = lo ? his : mine;

	sha512_context md;
	sha512_init(&md);
	static const char context[] = "tincstack-obfs-v2";
	sha512_update(&md, context, sizeof(context)); /* include the NUL as a separator */
	sha512_update(&md, lop, strlen(lop));
	sha512_update(&md, "|", 1);
	sha512_update(&md, hip, strlen(hip));
	sha512_final(&md, base);

	*i_am_lo = lo;
	free(mine);
	free(his);
	return true;
}

static void obfs_link_free(obfs_link_t *l) {
	keyset_free(&l->boot);
	keyset_free(&l->sess);
	keyset_free(&l->next);
	memset(l->base, 0, sizeof(l->base));
	memset(l->local_seed, 0, sizeof(l->local_seed));
	memset(l->peer_seed, 0, sizeof(l->peer_seed));
	free(l);
}

obfs_link_t *obfs_link_for_node(node_t *n) {
	for list_each(obfs_link_t, l, &obfs_links) {
		if(l->node == n) {
			return l;
		}
	}

	uint8_t base[64];
	bool i_am_lo;

	if(!obfs_derive_base(n, base, &i_am_lo)) {
		return NULL;
	}

	obfs_link_t *l = xzalloc(sizeof(*l));
	l->node = n;
	l->i_am_lo = i_am_lo;
	memcpy(l->base, base, sizeof(l->base));
	memset(base, 0, sizeof(base));

	if(!keyset_build(&l->boot, l->base, "tincstack-obfs-key", "tincstack-obfs-iv", i_am_lo)) {
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

/* ---- session key handshake ----------------------------------------------- */

static void obfs_ensure_local_seed(obfs_link_t *l) {
	if(!l->have_local_seed) {
		randomize(l->local_seed, sizeof(l->local_seed));
		l->have_local_seed = true;
	}
}

/* Derive the pending (next) session keyset from the two seeds. */
static bool obfs_build_session(obfs_link_t *l) {
	if(!l->have_local_seed || !l->have_peer_seed) {
		return false;
	}

	const uint8_t *lo_seed = l->i_am_lo ? l->local_seed : l->peer_seed;
	const uint8_t *hi_seed = l->i_am_lo ? l->peer_seed : l->local_seed;

	uint8_t base[64];
	sha512_context md;
	sha512_init(&md);
	static const char context[] = "tincstack-obfs-sess-v2";
	sha512_update(&md, context, sizeof(context));
	sha512_update(&md, lo_seed, OBFS_SEED_LEN);
	sha512_update(&md, hi_seed, OBFS_SEED_LEN);
	sha512_final(&md, base);

	bool ok = keyset_build(&l->next, base, "tincstack-obfs-skey", "tincstack-obfs-siv", l->i_am_lo);
	memset(base, 0, sizeof(base));
	return ok;
}

static void obfs_send_key(obfs_link_t *l, int flag) {
	connection_t *c = l->node ? l->node->connection : NULL;

	if(!c || c->allow_request != ALL) {
		return;   /* not activated yet: obfs_session_start will run at ack_h */
	}

	char b64[OBFS_SEED_LEN * 2];
	b64encode_tinc(l->local_seed, b64, OBFS_SEED_LEN);
	send_request(c, "%d %d %s", OBFS_KEY, flag, b64);
}

void obfs_session_start(connection_t *c) {
	if(!c->transport || c->transport->id != TRANSPORT_OBFS || !c->node) {
		return;
	}

	obfs_link_t *l = obfs_link_for_node(c->node);

	if(!l) {
		return;
	}

	/* Fresh negotiation for this connection. */
	obfs_ensure_local_seed(l);
	l->have_peer_seed = false;
	l->ack_sent = false;
	obfs_send_key(l, 0);
}

/* Re-negotiate the session key on a live link (KeyExpire alignment). TX keeps
   using the current session key until the new one is promoted, so there is no
   black-out. */
static void obfs_rekey_start(obfs_link_t *l) {
	connection_t *c = l->node ? l->node->connection : NULL;

	if(!c || c->allow_request != ALL) {
		return;
	}

	randomize(l->local_seed, sizeof(l->local_seed));
	l->have_local_seed = true;
	l->have_peer_seed = false;
	l->ack_sent = false;
	l->sess_time = now.tv_sec;   /* do not re-issue every tick while it converges */
	obfs_send_key(l, 0);
}

bool obfs_key_h(connection_t *c, const char *request) {
	int flag;
	char b64[MAX_STRING_SIZE];

	if(sscanf(request, "%*d %d " MAX_STRING, &flag, b64) != 2) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "OBFS_KEY", c->name, c->hostname);
		return false;
	}

	if(!c->node) {
		return false;
	}

	uint8_t seed[OBFS_SEED_LEN];

	/* A 32-byte seed base64-encodes to exactly 43 characters. Insist on that
	   before decoding: b64decode_tinc()'s length argument bounds the SOURCE,
	   not the destination, so a longer string would overflow `seed'. */
	if(strlen(b64) != 43 || b64decode_tinc(b64, seed, 43) != sizeof(seed)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got malformed %s seed from %s (%s)", "OBFS_KEY", c->name, c->hostname);
		return false;
	}

	obfs_link_t *l = obfs_link_for_node(c->node);

	if(!l) {
		return true;   /* no key material (no Ed25519 key): ignore gracefully */
	}

	obfs_ensure_local_seed(l);
	memcpy(l->peer_seed, seed, sizeof(seed));
	l->have_peer_seed = true;

	if(!obfs_build_session(l)) {
		logger(DEBUG_CONNECTIONS, LOG_WARNING, "Could not derive obfs session key for %s", c->name);
		return true;
	}

	/* Acknowledge once: tell the peer we have its seed and computed the key. */
	if(!l->ack_sent) {
		obfs_send_key(l, 1);
		l->ack_sent = true;
	}

	/* An ack from the peer means it has our seed and computed the same key, so
	   it can decrypt our session frames: promote the pending keyset and start
	   sending with it. */
	if(flag == 1 && l->next.valid) {
		keyset_free(&l->sess);
		l->sess = l->next;
		memset(&l->next, 0, sizeof(l->next));
		l->sess_tx_ready = true;
		l->sess_time = now.tv_sec;
		logger(DEBUG_CONNECTIONS, LOG_DEBUG, "obfs session key established with %s", c->name);
	}

	return true;
}

/* ---- framing ------------------------------------------------------------- */

size_t obfs_encode(obfs_link_t *l, const void *in, size_t inlen, uint8_t *out, size_t outcap, bool init) {
	if(!l) {
		return 0;
	}

	obfs_keyset_t *ks = (l->sess_tx_ready && l->sess.valid) ? &l->sess : &l->boot;

	if(!ks->tx) {
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

	size_t mlen = magic ? OBFS_MAGIC_LEN : 0;
	size_t clen = inlen + OBFS_TAG_LEN;

	if(clen > 0xffff || mlen + OBFS_HDR_LEN + clen + (size_t)header_junk > outcap) {
		return 0;
	}

	uint64_t counter = ks->ctr_tx++;

	/* Optional magic prefix: a plaintext header to mimic another protocol.
	   It is separate from the nonce, so it costs no nonce entropy (M5-3). */
	if(magic) {
		out[0] = (uint8_t)(magic >> 24);
		out[1] = (uint8_t)(magic >> 16);
		out[2] = (uint8_t)(magic >> 8);
		out[3] = (uint8_t)(magic);
	}

	/* Wire nonce = counter (big-endian) XOR the key-derived whitening mask. */
	uint8_t *nonce = out + mlen;

	for(int i = 0; i < OBFS_NONCE_LEN; i++) {
		nonce[i] = (uint8_t)(counter >> (8 * (7 - i))) ^ ks->mtx[i];
	}

	out[mlen + OBFS_NONCE_LEN] = (uint8_t)(clen >> 8);
	out[mlen + OBFS_NONCE_LEN + 1] = (uint8_t)(clen);

	if(!chacha_poly1305_encrypt(ks->tx, counter, in, inlen, out + mlen + OBFS_HDR_LEN, NULL)) {
		return 0;
	}

	if(header_junk) {
		randomize(out + mlen + OBFS_HDR_LEN + clen, (size_t)header_junk);
	}

	return mlen + OBFS_HDR_LEN + clen + (size_t)header_junk;
}

/* Try to unseal one datagram with keyset `ks' assuming a `mlen'-byte magic
   prefix. On success writes the inner datagram to `out' and returns its
   length, storing the recovered counter in *seq; on failure returns -1. */
static ssize_t ks_open(obfs_keyset_t *ks, size_t mlen, const uint8_t *buf, size_t len, uint8_t *out, size_t outcap, uint64_t *seq) {
	if(!ks->valid || !ks->rx || len < mlen + OBFS_MIN_FRAME) {
		return -1;
	}

	uint64_t counter = 0;

	for(int i = 0; i < OBFS_NONCE_LEN; i++) {
		counter = (counter << 8) | (uint8_t)(buf[mlen + i] ^ ks->mrx[i]);
	}

	size_t clen = ((size_t)buf[mlen + OBFS_NONCE_LEN] << 8) | buf[mlen + OBFS_NONCE_LEN + 1];

	if(clen < OBFS_TAG_LEN || mlen + OBFS_HDR_LEN + clen > len) {
		return -1;
	}

	size_t innerlen = clen - OBFS_TAG_LEN;

	if(innerlen > outcap) {
		return -1;
	}

	size_t outlen = 0;

	if(!chacha_poly1305_decrypt(ks->rx, counter, buf + mlen + OBFS_HDR_LEN, clen, out, &outlen)) {
		return -1;
	}

	*seq = counter;
	return (ssize_t)outlen;
}

/* Try every keyset (pending session, current session, bootstrap) and every
   possible magic-prefix length. On success returns the inner length and sets
   *which to the keyset that verified and *seq to the counter. */
static ssize_t obfs_open(obfs_link_t *l, const uint8_t *buf, size_t len, uint8_t *out, size_t outcap, obfs_keyset_t **which, uint64_t *seq) {
	size_t mlens[2];
	int nm = 0;
	mlens[nm++] = 0;

	if(obfs_init_magic || obfs_transport_magic) {
		mlens[nm++] = OBFS_MAGIC_LEN;
	}

	obfs_keyset_t *order[3];
	int no = 0;

	if(l->next.valid) {
		order[no++] = &l->next;
	}

	if(l->sess.valid) {
		order[no++] = &l->sess;
	}

	order[no++] = &l->boot;

	for(int o = 0; o < no; o++) {
		for(int m = 0; m < nm; m++) {
			ssize_t n = ks_open(order[o], mlens[m], buf, len, out, outcap, seq);

			if(n >= 0) {
				*which = order[o];
				return n;
			}
		}
	}

	return -1;
}

/* Sliding-window replay check on a per-direction counter. Returns true and
   records the counter when it is fresh; false for a replay or a too-old one. */
static bool obfs_replay_ok(obfs_replay_t *w, uint64_t seq) {
	if(!w->started) {
		w->started = true;
		w->max = seq;
		w->bits = 1;
		return true;
	}

	if(seq > w->max) {
		uint64_t shift = seq - w->max;
		w->bits = (shift >= OBFS_REPLAY_BITS) ? 0 : (w->bits << shift);
		w->bits |= 1;
		w->max = seq;
		return true;
	}

	uint64_t diff = w->max - seq;

	if(diff >= OBFS_REPLAY_BITS) {
		return false;   /* too old to prove non-replay */
	}

	uint64_t bit = (uint64_t)1 << diff;

	if(w->bits & bit) {
		return false;   /* already seen: replay */
	}

	w->bits |= bit;
	return true;
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

	uint8_t frame[OBFS_MAX_OVERHEAD + MAXSIZE + OBFS_MAX_JUNK];
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

	/* Connection-level event (once per handshake), logged at the connections
	   level so the sender's own junk accounting is visible at -d2; the obfs
	   test counts these lines instead of guessing junk from wire sizes (junk is
	   indistinguishable from random bytes by design). */
	logger(DEBUG_CONNECTIONS, LOG_INFO, "Sent %d obfs junk datagram(s) around a handshake", obfs_junk_count);
}

/* ---- inbound: keyed classification + replay check + re-injection --------- */

static bool obfs_inject(listen_socket_t *ls, const uint8_t *inner, size_t innerlen, const sockaddr_t *addr, obfs_link_t *l) {
	/* A single-flow meta frame carries the SF magic; anything else is an
	   SPTPS data datagram. Re-inject it into the normal receive path; the SF
	   path is told which link this came in on so its replies are sealed with
	   the same key. The SPTPS path re-enters handle_incoming_vpn_packet with
	   obfs disabled, so the inner is never scanned as obfs again. */
	if(innerlen >= SF_MAGIC_LEN && !memcmp(inner, sf_magic, SF_MAGIC_LEN)) {
		sf_udp_receive_obfs(ls, inner, innerlen, addr, l);
		return true;
	}

	handle_incoming_vpn_packet_decap(ls, inner, innerlen, addr);
	return true;
}

/* On a verified, fresh datagram: move the remembered peer address, then
   re-inject. Returns true (the datagram was claimed by obfs). */
static bool obfs_accept(listen_socket_t *ls, obfs_link_t *l, obfs_keyset_t *ks, uint64_t seq, const uint8_t *inner, size_t innerlen, const sockaddr_t *addr) {
	if(!obfs_replay_ok(&ks->rw, seq)) {
		/* Replayed or too-old datagram: drop it and, crucially, do NOT move the
		   link's remembered address (finding M5-4). It is still an obfs frame,
		   so claim it (the SPTPS path must not see the sealed bytes). */
		return true;
	}

	obfs_link_activate(l, addr);
	return obfs_inject(ls, inner, innerlen, addr, l);
}

bool obfs_udp_try(listen_socket_t *ls, const uint8_t *buf, size_t len, const sockaddr_t *vaddr) {
	if(len < OBFS_MIN_FRAME) {
		return false;
	}

	sockaddr_t addr = *vaddr;
	sockaddrunmap(&addr);

	uint8_t inner[MAXSIZE];
	obfs_keyset_t *ks = NULL;
	uint64_t seq = 0;

	/* Fast path: a link that is already up for this source address. */
	for list_each(obfs_link_t, l, &obfs_links) {
		if(l->active && l->have_addr && !sockaddrcmp(&addr, &l->addr)) {
			ssize_t n = obfs_open(l, buf, len, inner, sizeof(inner), &ks, &seq);

			if(n >= 0) {
				return obfs_accept(ls, l, ks, seq, inner, (size_t)n, &addr);
			}

			return false; /* junk around a handshake, or a still-plain datagram */
		}
	}

	/* Cold start: an unknown source. Only scan when obfs is accepted and the
	   source is not an already-confirmed plain peer. */
	if(!(transport_accept_mask & TRANSPORT_BIT(TRANSPORT_OBFS))) {
		return false;
	}

	node_t *known = lookup_node_udp(&addr);

	if(known && known->status.udp_confirmed) {
		return false; /* an established plain peer: leave it to the SPTPS path */
	}

	unsigned total = node_tree.count;

	if(total <= 1) {
		return false;
	}

	/* Budget scales with the number of peers (capped), so the last node of a
	   large mesh is still classified and a junk flood cannot starve cold
	   starts (finding M5-6). A cursor persists across ticks for fairness when
	   the budget is capped below the peer count. */
	static time_t scan_time;
	static int scan_budget;
	static unsigned scan_cursor;

	if(now.tv_sec != scan_time) {
		scan_time = now.tv_sec;
		scan_budget = total > OBFS_SCAN_PER_SEC ? (int)total : OBFS_SCAN_PER_SEC;

		if(scan_budget > OBFS_SCAN_MAX) {
			scan_budget = OBFS_SCAN_MAX;
		}
	}

	/* Round-robin from the persistent cursor, wrapping once. */
	for(int pass = 0; pass < 2; pass++) {
		unsigned idx = 0;

		for splay_each(node_t, n, &node_tree) {
			unsigned pos = idx++;

			if(pass == 0 ? (pos < scan_cursor) : (pos >= scan_cursor)) {
				continue;
			}

			if(n == myself) {
				continue;
			}

			if(scan_budget <= 0) {
				return false;
			}

			scan_budget--;
			scan_cursor = (pos + 1) % total;

			if(!node_read_ecdsa_public_key(n)) {
				continue;
			}

			obfs_link_t *l = obfs_link_for_node(n);

			if(!l) {
				continue;
			}

			ssize_t nlen = obfs_open(l, buf, len, inner, sizeof(inner), &ks, &seq);

			if(nlen >= 0) {
				if(debug_level >= DEBUG_CONNECTIONS) {
					char *hostname = sockaddr2hostname(&addr);
					logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Cold-classified an obfs datagram from %s as %s", hostname, n->name);
					free(hostname);
				}

				return obfs_accept(ls, l, ks, seq, inner, (size_t)nlen, &addr);
			}
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

	node_read_ecdsa_public_key(n); /* keys are read lazily; the dial needs it now */
	obfs_link_t *l = obfs_link_for_node(n);

	if(!l) {
		logger(DEBUG_CONNECTIONS, LOG_WARNING, "Cannot dial %s via obfs: no Ed25519 key to derive a link key from", c->name);
		return false; /* fall back to the next carrier */
	}

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

	/* The obfs_link is per-node and shared by every connection to that node.
	   When two nodes dial each other, tinc keeps one connection and closes the
	   other ("Established a second connection ... closing old connection").
	   The obfs session key belongs to whichever connection currently owns the
	   node (c->node->connection); if a superseded/stale connection is the one
	   being closed, tearing down the shared link here would wipe the live
	   session that the winning connection already negotiated and silently drop
	   the link back to the mesh-wide bootstrap key (review R M5-2). So only
	   reset the link when the closing connection is the node's current owner
	   (or the node has no owner left). */
	bool superseded = c->node && c->node->connection && c->node->connection != c;

	if(l && !superseded) {
		l->active = false;
		l->have_addr = false;
		/* Drop the session state so the next connection re-negotiates a fresh
		   session key. The bootstrap keyset (counter + replay window) is kept
		   so its counter stays monotone across reconnects. */
		keyset_free(&l->sess);
		keyset_free(&l->next);
		l->sess_tx_ready = false;
		l->ack_sent = false;
		l->have_peer_seed = false;
		l->have_local_seed = false;
	}

	sf_close(c);
}

/* ---- periodic rekey ------------------------------------------------------ */

static void obfs_periodic(void *data) {
	(void)data;

	for list_each(obfs_link_t, l, &obfs_links) {
		if(l->active && l->sess_tx_ready && l->sess.valid) {
			if(now.tv_sec - l->sess_time > keylifetime) {
				obfs_rekey_start(l);
			}

			continue;
		}

		/* Self-heal: an active link that is still carrying data on the
		   mesh-wide bootstrap key never converged on a per-link session key
		   (a handshake exchange lost to a connection replacement race, or the
		   owning connection came up after the exchange). Re-initiate the
		   exchange from the connection that currently owns the node so the
		   link cannot stay on the bootstrap key indefinitely (review R M5-2). */
		if(l->active && l->node && l->node->connection) {
			connection_t *c = l->node->connection;

			if(c->allow_request == ALL && c->transport && c->transport->id == TRANSPORT_OBFS) {
				obfs_ensure_local_seed(l);
				l->have_peer_seed = false;
				l->ack_sent = false;
				obfs_send_key(l, 0);
			}
		}
	}

	int period = keylifetime > 0 && keylifetime < OBFS_REKEY_TICK ? keylifetime : OBFS_REKEY_TICK;
	struct timeval tv = { period, 0 };
	timeout_set(&obfs_rekey_timer, &tv);
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

	int period = keylifetime > 0 && keylifetime < OBFS_REKEY_TICK ? keylifetime : OBFS_REKEY_TICK;
	struct timeval tv = { period, 0 };
	timeout_add(&obfs_rekey_timer, obfs_periodic, NULL, &tv);

	return obfs_read_config();
}

void obfs_exit(void) {
	timeout_del(&obfs_rekey_timer);
	list_empty_list(&obfs_links);
}
