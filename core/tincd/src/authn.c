/*
    authn.c -- the in-session peer authenticator shared by the `https' and
               `quic' carriers. See authn.h and docs/transports.md §8.3.

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

#include "authn.h"
#include "conf.h"
#include "connection.h"
#include "ecdsa.h"
#include "event.h"
#include "keys.h"
#include "logger.h"
#include "net.h"
#include "node.h"
#include "protocol.h"
#include "random.h"
#include "utils.h"
#include "xalloc.h"

#define AUTHN_MSG_LEN (AUTHN_FP_LEN + AUTHN_EXPORTER_LEN + AUTHN_NONCE_LEN + AUTHN_TS_LEN)

/* A tiny replay cache: (nonce -> expiry). The exporter binding already stops
   cross-session replay (a captured authenticator has the wrong exporter for a
   new TLS/QUIC session, so its signature fails); this is belt-and-suspenders
   for the same-second window, shared by every carrier. */
#define REPLAY_SLOTS 256
static struct {
	uint8_t nonce[AUTHN_NONCE_LEN];
	time_t expiry;
} replay[REPLAY_SLOTS];

static bool replay_seen(const uint8_t *nonce) {
	size_t free_slot = REPLAY_SLOTS;

	for(size_t i = 0; i < REPLAY_SLOTS; i++) {
		if(replay[i].expiry > now.tv_sec && !memcmp(replay[i].nonce, nonce, AUTHN_NONCE_LEN)) {
			return true;
		}

		if(replay[i].expiry <= now.tv_sec && free_slot == REPLAY_SLOTS) {
			free_slot = i;
		}
	}

	if(free_slot == REPLAY_SLOTS) {
		free_slot = (size_t)(now.tv_sec) % REPLAY_SLOTS; /* evict something */
	}

	memcpy(replay[free_slot].nonce, nonce, AUTHN_NONCE_LEN);
	replay[free_slot].expiry = now.tv_sec + 2 * AUTHN_TS_SKEW;
	return false;
}

/* message = server_fp(32) || exporter(32) || nonce(16) || ts_be(8) */
static void auth_message(uint8_t *msg, const uint8_t *server_fp, const uint8_t *exporter, const uint8_t *nonce, uint64_t ts) {
	memcpy(msg, server_fp, AUTHN_FP_LEN);
	memcpy(msg + AUTHN_FP_LEN, exporter, AUTHN_EXPORTER_LEN);
	memcpy(msg + AUTHN_FP_LEN + AUTHN_EXPORTER_LEN, nonce, AUTHN_NONCE_LEN);

	for(int i = 0; i < 8; i++) {
		msg[AUTHN_FP_LEN + AUTHN_EXPORTER_LEN + AUTHN_NONCE_LEN + i] = (uint8_t)(ts >> (8 * (7 - i)));
	}
}

size_t authn_build(const uint8_t *server_fp, const uint8_t *exporter, uint8_t *out, size_t outcap) {
	ecdsa_t *key = myself->connection->ecdsa;

	if(!key || ecdsa_size(key) != AUTHN_SIG_LEN) {
		return 0;
	}

	size_t namelen = strlen(myself->name);

	if(!namelen || namelen > AUTHN_MAX_NAME) {
		return 0;
	}

	size_t plen = AUTHN_HDR_LEN + namelen + AUTHN_NONCE_LEN + AUTHN_TS_LEN + AUTHN_SIG_LEN;

	if(plen > outcap) {
		return 0;
	}

	uint8_t nonce[AUTHN_NONCE_LEN];
	randomize(nonce, sizeof(nonce));
	uint64_t ts = (uint64_t) now.tv_sec;

	uint8_t msg[AUTHN_MSG_LEN];
	auth_message(msg, server_fp, exporter, nonce, ts);

	uint8_t sig[AUTHN_SIG_LEN];

	if(!ecdsa_sign(key, msg, sizeof(msg), sig)) {
		return 0;
	}

	size_t o = 0;
	out[o++] = AUTHN_VERSION;
	out[o++] = (uint8_t) namelen;
	memcpy(out + o, myself->name, namelen);
	o += namelen;
	memcpy(out + o, nonce, AUTHN_NONCE_LEN);
	o += AUTHN_NONCE_LEN;

	for(int i = 0; i < 8; i++) {
		out[o++] = (uint8_t)(ts >> (8 * (7 - i)));
	}

	memcpy(out + o, sig, AUTHN_SIG_LEN);
	o += AUTHN_SIG_LEN;
	return o;
}

size_t authn_expected_len(const uint8_t *buf, size_t len) {
	if(len < AUTHN_HDR_LEN) {
		return 0;
	}

	if(buf[0] != AUTHN_VERSION || buf[1] == 0) {
		return (size_t) -1;
	}

	return AUTHN_HDR_LEN + buf[1] + AUTHN_NONCE_LEN + AUTHN_TS_LEN + AUTHN_SIG_LEN;
}

bool authn_verify(const uint8_t *payload, size_t plen, const uint8_t *server_fp, const uint8_t *exporter,
                  const char *carrier, const char *hostname, char **name_out) {
	size_t expected = authn_expected_len(payload, plen);

	if(!expected || expected == (size_t) -1 || plen != expected) {
		return false;
	}

	size_t o = AUTHN_HDR_LEN;
	size_t namelen = payload[1];
	char name[MAX_STRING_SIZE];

	if(namelen >= sizeof(name)) {
		return false;
	}

	memcpy(name, payload + o, namelen);
	name[namelen] = 0;
	o += namelen;

	if(!check_id(name) || !strcmp(name, myself->name)) {
		return false;
	}

	const uint8_t *nonce = payload + o;
	o += AUTHN_NONCE_LEN;
	uint64_t ts = 0;

	for(int i = 0; i < 8; i++) {
		ts = (ts << 8) | payload[o++];
	}

	const uint8_t *sig = payload + o;

	/* Freshness. */
	int64_t skew = (int64_t) now.tv_sec - (int64_t) ts;

	if(skew < -AUTHN_TS_SKEW || skew > AUTHN_TS_SKEW) {
		logger(DEBUG_CONNECTIONS, LOG_DEBUG, "%s: stale authenticator from %s (skew %lld s)", carrier, hostname, (long long) skew);
		return false;
	}

	/* The peer's Ed25519 public key from our host DB. */
	splay_tree_t *tree = NULL;
	ecdsa_t *pubkey = read_ecdsa_public_key(&tree, name);

	if(!pubkey) {
		if(tree) {
			exit_configuration(tree);
		}

		logger(DEBUG_CONNECTIONS, LOG_DEBUG, "%s: authenticator from %s names unknown node %s", carrier, hostname, name);
		return false;
	}

	uint8_t msg[AUTHN_MSG_LEN];
	auth_message(msg, server_fp, exporter, nonce, ts);

	bool ok = (ecdsa_size(pubkey) == AUTHN_SIG_LEN) && ecdsa_verify(pubkey, msg, sizeof(msg), sig);
	ecdsa_free(pubkey);

	if(tree) {
		exit_configuration(tree);
	}

	if(!ok) {
		logger(DEBUG_CONNECTIONS, LOG_DEBUG, "%s: authenticator signature check failed for claimed %s", carrier, name);
		return false;
	}

	if(replay_seen(nonce)) {
		logger(DEBUG_CONNECTIONS, LOG_WARNING, "%s: replayed authenticator from %s; rejecting", carrier, hostname);
		return false;
	}

	*name_out = xstrdup(name);
	return true;
}
