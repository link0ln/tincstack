/*
    transport_quic.c -- the `quic' carrier: SPTPS meta on one QUIC stream and
                        SPTPS data records in QUIC DATAGRAM frames, over tinc's
                        own UDP listen socket (ngtcp2 + GnuTLS).

    QUIC is an outer carrier: SPTPS (Ed25519 identity, ChaCha20-Poly1305, the
    meta+data records) runs unchanged inside it (principle 1). ngtcp2 owns no
    socket, no threads and no timers -- this file feeds it datagrams read from
    the M4 front's UDP socket, drains what it wants to send, and drives one
    timeout_t from ngtcp2_conn_get_expiry(), exactly as the stream-Q spike
    proved (testing/quic-spike/). The GnuTLS-specific ~60 lines are in
    transport_quic_tls.c so another TLS backend can replace them per platform.

    Peer authentication: the dialler sends the shared authenticator (authn.c,
    the same bytes the https carrier uses) as the first bytes of stream 0; the
    acceptor verifies it before a single byte reaches receive_meta_bytes().
    Failure closes the QUIC connection with a generic transport error and the
    dialler falls back to the next carrier (M4). Design: docs/transports.md §9.

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

#ifdef HAVE_QUIC

#include <time.h>

#include <gnutls/crypto.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include "authn.h"
#include "conf.h"
#include "connection.h"
#include "event.h"
#include "list.h"
#include "logger.h"
#include "meta.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "protocol.h"
#include "tls.h"
#include "utils.h"
#include "xalloc.h"

#define TINC_TRANSPORT_DAEMON
#include "transport.h"
#include "transport_quic.h"
#include "transport_quic_tls.h"

#define QUIC_ALPN_DEFAULT "h3"
#define QUIC_MAX_DGRAM 1400
#define QUIC_DGRAM_QUEUE 64
#define QUIC_PKT_BUF 1452
#define QUIC_CID_SLOTS 16               /* issued connection ids we track per session */
#define QUIC_AUTH_CAP AUTHN_MAX_LEN     /* server-side authenticator accumulation buffer */

typedef struct quic_cid_t {
	uint8_t data[NGTCP2_MAX_CIDLEN];
	uint8_t len;
} quic_cid_t;

typedef struct quic_session_t {
	connection_t *c;
	quic_tls_t tls;
	ngtcp2_conn *conn;
	int fd;                         /* UDP socket this session's packets go out on */
	size_t sock;                    /* index into listen_socket[] of the same family
	                                   (datagram delivery, local address) */
	sockaddr_t peer;                /* current validated remote path */

	int64_t stream_id;              /* meta stream, -1 until opened/adopted */

	/* Meta TX ring: bytes stay valid until acked_stream_data_offset says so,
	   so the buffer holds [acked, appended); we hand ngtcp2 [sent, appended). */
	uint8_t *tx;
	size_t tx_cap;
	size_t tx_len;                  /* bytes currently in tx[] */
	uint64_t tx_base;               /* absolute stream offset of tx[0] (== acked) */
	uint64_t tx_sent;               /* absolute offset handed to ngtcp2 */
	bool stream_blocked;

	/* Data TX queue (DATAGRAM frames). ngtcp2 copies on accept, small ring. */
	struct {
		uint8_t data[QUIC_MAX_DGRAM];
		size_t len;
	} dgram[QUIC_DGRAM_QUEUE];
	size_t dgram_head, dgram_n;
	uint64_t dgram_id;

	/* Server-side authenticator gate. */
	bool is_server;
	bool authenticated;
	uint8_t authbuf[QUIC_AUTH_CAP];
	size_t authlen;

	quic_cid_t cids[QUIC_CID_SLOTS];
	int ncids;

	timeout_t timer;
	bool reading;                   /* inside read_pkt / handle_expiry: defer flush */
	bool dead;                      /* failed; the reaper will terminate it */
	ngtcp2_ccerr ccerr;
} quic_session_t;

static list_t quic_sessions = {
	.head = NULL, .tail = NULL, .count = 0, .delete = NULL,
};

static timeout_t quic_reaper;
static uint8_t static_secret[32];       /* stateless-reset token secret */
static bool quic_ready;

/* QuicPort: an optional extra UDP listener (e.g. 443 for HTTP/3 plausibility).
   Default = the tinc port, i.e. the shared listen socket and no extra socket.
   These entries are handed to handle_incoming_vpn_data() like the main ones
   (same classifier, same dispatch); sessions remember their own fd. */
static listen_socket_t quic_listen[MAXSOCKETS];
static int quic_listens;
static int quic_port;

static void quic_flush(quic_session_t *s);
static void quic_arm_timer(quic_session_t *s);

/* ---- time ---------------------------------------------------------------- */

static ngtcp2_tstamp quic_now(void) {
	struct timespec tp;
	clock_gettime(CLOCK_MONOTONIC, &tp);
	return (ngtcp2_tstamp)tp.tv_sec * NGTCP2_SECONDS + (ngtcp2_tstamp)tp.tv_nsec;
}

/* ---- connection id bookkeeping ------------------------------------------- */

static void cid_add(quic_session_t *s, const uint8_t *data, size_t len) {
	if(len > NGTCP2_MAX_CIDLEN) {
		return;
	}

	for(int i = 0; i < s->ncids; i++) {
		if(s->cids[i].len == len && !memcmp(s->cids[i].data, data, len)) {
			return;
		}
	}

	if(s->ncids >= QUIC_CID_SLOTS) {
		/* Drop the oldest; ngtcp2 keeps at most active_connection_id_limit
		   live at once, well under the slot count. */
		memmove(&s->cids[0], &s->cids[1], (QUIC_CID_SLOTS - 1) * sizeof(s->cids[0]));
		s->ncids = QUIC_CID_SLOTS - 1;
	}

	memcpy(s->cids[s->ncids].data, data, len);
	s->cids[s->ncids].len = (uint8_t)len;
	s->ncids++;
}

static void cid_del(quic_session_t *s, const uint8_t *data, size_t len) {
	for(int i = 0; i < s->ncids; i++) {
		if(s->cids[i].len == len && !memcmp(s->cids[i].data, data, len)) {
			memmove(&s->cids[i], &s->cids[i + 1], (s->ncids - i - 1) * sizeof(s->cids[0]));
			s->ncids--;
			return;
		}
	}
}

static quic_session_t *session_by_cid(const uint8_t *data, size_t len) {
	for list_each(quic_session_t, s, &quic_sessions) {
		for(int i = 0; i < s->ncids; i++) {
			if(s->cids[i].len == len && !memcmp(s->cids[i].data, data, len)) {
				return s;
			}
		}
	}

	return NULL;
}

/* Classifier hook (short-header 1-RTT packets): the 8-byte destination CID. */
static bool quic_cid_match(const uint8_t *dcid) {
	return session_by_cid(dcid, TRANSPORT_QUIC_CIDLEN) != NULL;
}

/* ---- teardown (deferred, never from inside a ngtcp2 callback) ------------- */

static void quic_reap(void *data) {
	(void)data;

	for list_each(quic_session_t, s, &quic_sessions) {
		if(s->dead) {
			connection_t *c = s->c;
			terminate_connection(c, c->edge);
		}
	}
}

static void schedule_reap(void) {
	struct timeval tv = {0, 0};

	if(quic_reaper.cb) {
		timeout_set(&quic_reaper, &tv);
	} else {
		timeout_add(&quic_reaper, quic_reap, NULL, &tv);
	}
}

/* Mark the session failed. If `send_cc' and the connection is still live,
   emit one CONNECTION_CLOSE first (a generic transport error: no tinc string
   on the wire). The reaper then terminates the tinc connection outside any
   ngtcp2 callback, so the ngtcp2_conn is never freed re-entrantly. */
static void quic_fail(quic_session_t *s, bool send_cc) {
	if(s->dead) {
		return;
	}

	if(send_cc && s->conn && !ngtcp2_conn_in_closing_period(s->conn) && !ngtcp2_conn_in_draining_period(s->conn)) {
		uint8_t buf[QUIC_PKT_BUF];
		ngtcp2_path_storage ps;
		ngtcp2_pkt_info pi;
		ngtcp2_path_storage_zero(&ps);

		if(!s->ccerr.error_code) {
			ngtcp2_ccerr_set_application_error(&s->ccerr, 0, NULL, 0);
		}

		ngtcp2_ssize n = ngtcp2_conn_write_connection_close(s->conn, &ps.path, &pi, buf, sizeof(buf), &s->ccerr, quic_now());

		if(n > 0) {
			sendto(s->fd, (void *)buf, (size_t)n, 0, &s->peer.sa, SALEN(s->peer.sa));
		}
	}

	s->dead = true;
	timeout_del(&s->timer);
	schedule_reap();
}

/* ---- ngtcp2 callbacks ---------------------------------------------------- */

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *ref) {
	quic_tls_t *t = (quic_tls_t *)ref->user_data;
	quic_session_t *s = (quic_session_t *)((char *)t - offsetof(quic_session_t, tls));
	return s->conn;
}

static void cb_rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *ctx) {
	(void)ctx;
	gnutls_rnd(GNUTLS_RND_RANDOM, dest, destlen);
}

static int cb_get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid, ngtcp2_stateless_reset_token *token,
                                    size_t cidlen, void *user_data) {
	(void)conn;
	quic_session_t *s = user_data;

	if(gnutls_rnd(GNUTLS_RND_RANDOM, cid->data, cidlen)) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	cid->datalen = cidlen;

	if(ngtcp2_crypto_generate_stateless_reset_token(token->data, static_secret, sizeof(static_secret), cid)) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	cid_add(s, cid->data, cidlen);
	return 0;
}

static int cb_remove_connection_id(ngtcp2_conn *conn, const ngtcp2_cid *cid, void *user_data) {
	(void)conn;
	cid_del((quic_session_t *)user_data, cid->data, cid->datalen);
	return 0;
}

/* Deliver received meta bytes to tinc; may terminate the connection, in which
   case we defer the teardown and stop. Returns false if the session died. */
static bool deliver_meta(quic_session_t *s, const uint8_t *data, size_t len) {
	if(!len) {
		return true;
	}

	if(!receive_meta_bytes(s->c, (char *)data, (ssize_t)len)) {
		quic_fail(s, false);
		return false;
	}

	return true;
}

static int cb_recv_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t offset,
                               const uint8_t *data, size_t datalen, void *user_data, void *stream_user_data) {
	(void)flags;
	(void)offset;
	(void)stream_user_data;
	quic_session_t *s = user_data;

	if(s->dead) {
		return 0;
	}

	if(s->stream_id < 0) {
		s->stream_id = stream_id;       /* server adopts the client's stream */
	} else if(stream_id != s->stream_id) {
		/* Deliberately no muxing: shut any other stream. */
		ngtcp2_conn_shutdown_stream(conn, 0, stream_id, 1);
		return 0;
	}

	const uint8_t *p = data;
	size_t remain = datalen;

	/* Server: the first bytes on stream 0 are the shared authenticator; verify
	   it before a single byte reaches the tinc protocol. */
	if(s->is_server && !s->authenticated) {
		size_t want;

		while(!s->authenticated && remain) {
			size_t expected = authn_expected_len(s->authbuf, s->authlen);

			if(expected == (size_t) -1) {
				logger(DEBUG_CONNECTIONS, LOG_INFO, "quic: malformed authenticator from %s", s->c->hostname);
				ngtcp2_ccerr_set_application_error(&s->ccerr, 1, NULL, 0);
				quic_fail(s, false);
				return 0;
			}

			want = expected ? expected - s->authlen : 1;

			if(want > QUIC_AUTH_CAP - s->authlen) {
				logger(DEBUG_CONNECTIONS, LOG_INFO, "quic: oversized authenticator from %s", s->c->hostname);
				ngtcp2_ccerr_set_application_error(&s->ccerr, 1, NULL, 0);
				quic_fail(s, false);
				return 0;
			}

			size_t take = want < remain ? want : remain;
			memcpy(s->authbuf + s->authlen, p, take);
			s->authlen += take;
			p += take;
			remain -= take;

			expected = authn_expected_len(s->authbuf, s->authlen);

			if(expected && expected != (size_t) -1 && s->authlen == expected) {
				uint8_t exporter[AUTHN_EXPORTER_LEN];
				char *name = NULL;

				if(!quic_tls_exporter(s->tls.session, exporter, sizeof(exporter)) ||
				                !authn_verify(s->authbuf, s->authlen, tls_own_fp, exporter, "quic", s->c->hostname, &name)) {
					logger(DEBUG_CONNECTIONS, LOG_INFO, "quic: authenticator from %s rejected", s->c->hostname);
					ngtcp2_ccerr_set_application_error(&s->ccerr, 1, NULL, 0);
					quic_fail(s, false);
					return 0;
				}

				free(s->c->name);
				s->c->name = name;
				s->authenticated = true;
				logger(DEBUG_CONNECTIONS, LOG_NOTICE, "quic: authenticated peer %s (%s)", s->c->name, s->c->hostname);
			}
		}
	}

	bool alive = true;

	if(remain) {
		alive = deliver_meta(s, p, remain);
	}

	/* Return the flow-control credit for everything we consumed, even if the
	   connection just died (ngtcp2 still owns the conn until the reaper runs).
	   The whole chunk was consumed (accumulated or delivered). */
	if(alive || !s->dead) {
		ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
		ngtcp2_conn_extend_max_offset(conn, datalen);
	}

	return 0;
}

static int cb_acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id, uint64_t offset, uint64_t datalen,
                                       void *user_data, void *stream_user_data) {
	(void)conn;
	(void)stream_id;
	(void)stream_user_data;
	quic_session_t *s = user_data;
	uint64_t acked = offset + datalen;

	if(acked > s->tx_base) {
		size_t drop = (size_t)(acked - s->tx_base);

		if(drop > s->tx_len) {
			drop = s->tx_len;
		}

		memmove(s->tx, s->tx + drop, s->tx_len - drop);
		s->tx_len -= drop;
		s->tx_base += drop;

		if(s->tx_sent < s->tx_base) {
			s->tx_sent = s->tx_base;
		}
	}

	return 0;
}

static int cb_stream_open(ngtcp2_conn *conn, int64_t stream_id, void *user_data) {
	(void)conn;
	quic_session_t *s = user_data;

	if(s->stream_id < 0) {
		s->stream_id = stream_id;
	}

	return 0;
}

static int cb_recv_datagram(ngtcp2_conn *conn, uint32_t flags, const uint8_t *data, size_t datalen, void *user_data) {
	(void)conn;
	(void)flags;
	quic_session_t *s = user_data;

	if(s->dead || !datalen) {
		return 0;
	}

	/* The SPTPS data record, byte-for-byte what send_sptps_data() would have
	   put on the wire; hand it straight to the SPTPS receive path with the
	   session's validated peer address, bypassing the front classifier. */
	handle_incoming_vpn_packet_decap(&listen_socket[s->sock], data, datalen, &s->peer);
	return 0;
}

static int cb_path_validation(ngtcp2_conn *conn, uint32_t flags, const ngtcp2_path *path, const ngtcp2_path *fallback,
                              ngtcp2_path_validation_result res, void *user_data) {
	(void)flags;
	(void)fallback;
	quic_session_t *s = user_data;

	if(res != NGTCP2_PATH_VALIDATION_RESULT_SUCCESS) {
		return 0;
	}

	/* A NAT rebind on the far side: adopt the new remote so datagram delivery,
	   the node's UDP address and `hostname' follow it (docs/transports.md §9.9). */
	const ngtcp2_path *cur = ngtcp2_conn_get_path(conn);

	if(cur && cur->remote.addrlen && cur->remote.addrlen <= (socklen_t)sizeof(s->peer)) {
		memcpy(&s->peer, cur->remote.addr, cur->remote.addrlen);
	} else if(path && path->remote.addrlen && path->remote.addrlen <= (socklen_t)sizeof(s->peer)) {
		memcpy(&s->peer, path->remote.addr, path->remote.addrlen);
	} else {
		return 0;
	}

	/* `dump connections' prints c->address/hostname; keep them on the live path. */
	s->c->address = s->peer;
	free(s->c->hostname);
	s->c->hostname = sockaddr2hostname(&s->peer);
	logger(DEBUG_CONNECTIONS, LOG_INFO, "quic: path validated for %s, remote now %s", s->c->name, s->c->hostname);

	return 0;
}

static int cb_extend_max_stream_data(ngtcp2_conn *conn, int64_t stream_id, uint64_t max_data, void *user_data, void *stream_user_data) {
	(void)conn;
	(void)stream_id;
	(void)max_data;
	(void)stream_user_data;
	((quic_session_t *)user_data)->stream_blocked = false;
	return 0;
}

static int cb_handshake_completed(ngtcp2_conn *conn, void *user_data) {
	(void)conn;
	quic_session_t *s = user_data;

	if(s->is_server || s->dead) {
		return 0;
	}

	/* Client: pin the server certificate (accept-on-first-use writes it back),
	   open stream 0, queue the authenticator, then drive the tinc handshake so
	   the ID line is the second thing on the stream. All appends only -- the
	   post-read flush in quic_udp_receive sends them (we are in a callback). */
	if(s->tls.have_peer_fp && !s->tls.pin[0]) {
		logger(DEBUG_ALWAYS, LOG_NOTICE, "quic: no pinned TlsFingerprint for %s; accepting %s on first use and pinning it",
		       s->c->name, s->tls.peer_fp_hex);
		append_config_file(s->c->name, "TlsFingerprint", s->tls.peer_fp_hex);
	}

	int64_t sid;

	if(ngtcp2_conn_open_bidi_stream(conn, &sid, NULL)) {
		quic_fail(s, false);
		return 0;
	}

	s->stream_id = sid;

	uint8_t exporter[AUTHN_EXPORTER_LEN];
	uint8_t auth[AUTHN_MAX_LEN];
	size_t authlen;

	if(!quic_tls_exporter(s->tls.session, exporter, sizeof(exporter)) ||
	                !(authlen = authn_build(s->tls.peer_fp, exporter, auth, sizeof(auth)))) {
		logger(DEBUG_CONNECTIONS, LOG_ERR, "quic: could not build the authenticator for %s", s->c->name);
		quic_fail(s, false);
		return 0;
	}

	/* Queue the authenticator as the first stream bytes (append to the ring). */
	if(s->tx_len + authlen > s->tx_cap) {
		s->tx_cap = s->tx_len + authlen + 4096;
		s->tx = xrealloc(s->tx, s->tx_cap);
	}

	memcpy(s->tx + s->tx_len, auth, authlen);
	s->tx_len += authlen;

	/* Sends the ID line onto the same stream (append only while reading). */
	finish_connecting(s->c);
	return 0;
}

static void quic_callbacks(ngtcp2_callbacks *cb, bool server) {
	memset(cb, 0, sizeof(*cb));

	if(server) {
		cb->recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
	} else {
		cb->client_initial = ngtcp2_crypto_client_initial_cb;
		cb->recv_retry = ngtcp2_crypto_recv_retry_cb;
	}

	cb->recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
	cb->encrypt = ngtcp2_crypto_encrypt_cb;
	cb->decrypt = ngtcp2_crypto_decrypt_cb;
	cb->hp_mask = ngtcp2_crypto_hp_mask_cb;
	cb->update_key = ngtcp2_crypto_update_key_cb;
	cb->delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
	cb->delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
	cb->version_negotiation = ngtcp2_crypto_version_negotiation_cb;
	cb->get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;
	cb->rand = cb_rand;
	cb->get_new_connection_id2 = cb_get_new_connection_id;
	cb->remove_connection_id = cb_remove_connection_id;
	cb->handshake_completed = cb_handshake_completed;
	cb->recv_stream_data = cb_recv_stream_data;
	cb->acked_stream_data_offset = cb_acked_stream_data_offset;
	cb->stream_open = cb_stream_open;
	cb->recv_datagram = cb_recv_datagram;
	cb->path_validation = cb_path_validation;
	cb->extend_max_stream_data = cb_extend_max_stream_data;
}

static void quic_settings(ngtcp2_settings *settings, ngtcp2_transport_params *params) {
	ngtcp2_settings_default(settings);
	settings->initial_ts = quic_now();
	settings->handshake_timeout = (ngtcp2_duration)pingtimeout * NGTCP2_SECONDS;

	ngtcp2_transport_params_default(params);
	params->initial_max_streams_bidi = 1;
	params->initial_max_streams_uni = 0;
	params->initial_max_stream_data_bidi_local = 256 * 1024;
	params->initial_max_stream_data_bidi_remote = 256 * 1024;
	params->initial_max_data = 1024 * 1024;
	params->max_datagram_frame_size = 65535;
	params->max_idle_timeout = (ngtcp2_duration)(3 * pingtimeout) * NGTCP2_SECONDS;
	/* Must exceed the default 2 or a second migration in one session fails with
	   ERR_CONNECTION_ID_LIMIT (stream-Q finding). */
	params->active_connection_id_limit = 8;
}

/* ---- flush and timer ----------------------------------------------------- */

static void quic_flush(quic_session_t *s) {
	if(s->dead || !s->conn) {
		return;
	}

	uint8_t buf[QUIC_PKT_BUF];
	ngtcp2_path_storage ps;
	ngtcp2_pkt_info pi;
	ngtcp2_tstamp ts = quic_now();
	ngtcp2_path_storage_zero(&ps);

	for(;;) {
		ngtcp2_ssize nwrite;

		if(s->dgram_n) {
			ngtcp2_vec v = {s->dgram[s->dgram_head].data, s->dgram[s->dgram_head].len};
			int accepted = 0;
			nwrite = ngtcp2_conn_writev_datagram(s->conn, &ps.path, &pi, buf, sizeof(buf), &accepted, 0,
			                                     ++s->dgram_id, &v, 1, ts);

			if(nwrite < 0) {
				ngtcp2_ccerr_set_liberr(&s->ccerr, (int)nwrite, NULL, 0);
				quic_fail(s, true);
				return;
			}

			if(accepted) {
				s->dgram_head = (s->dgram_head + 1) % QUIC_DGRAM_QUEUE;
				s->dgram_n--;
			}

			if(nwrite == 0) {
				break;
			}
		} else {
			ngtcp2_vec v = {NULL, 0};
			size_t cnt = 0;
			int64_t sid = -1;
			ngtcp2_ssize pdatalen = 0;

			if(s->stream_id >= 0 && !s->stream_blocked && s->tx_sent < s->tx_base + s->tx_len) {
				size_t off = (size_t)(s->tx_sent - s->tx_base);
				v.base = s->tx + off;
				v.len = s->tx_len - off;
				cnt = 1;
				sid = s->stream_id;
			}

			nwrite = ngtcp2_conn_writev_stream(s->conn, &ps.path, &pi, buf, sizeof(buf), &pdatalen, 0, sid, &v, cnt, ts);

			if(nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
				s->stream_blocked = true;
				continue;
			}

			if(nwrite < 0) {
				ngtcp2_ccerr_set_liberr(&s->ccerr, (int)nwrite, NULL, 0);
				quic_fail(s, true);
				return;
			}

			if(pdatalen > 0) {
				s->tx_sent += (uint64_t)pdatalen;
			}

			if(nwrite == 0) {
				break;
			}
		}

		/* ngtcp2 filled ps.path with the path this packet belongs to (the
		   validated one, or a probe of a new one during migration). */
		const struct sockaddr *to = ps.path.remote.addrlen ? (const struct sockaddr *)ps.path.remote.addr : &s->peer.sa;
		socklen_t tolen = ps.path.remote.addrlen ? ps.path.remote.addrlen : SALEN(s->peer.sa);

		if(sendto(s->fd, (void *)buf, (size_t)nwrite, 0, to, tolen) < 0 && !sockwouldblock(sockerrno) && !sockmsgsize(sockerrno)) {
			logger(DEBUG_TRAFFIC, LOG_WARNING, "quic: sendto %s failed: %s", s->c->hostname, sockstrerror(sockerrno));
		}
	}

	ngtcp2_conn_update_pkt_tx_time(s->conn, ts);
	quic_arm_timer(s);
}

static void quic_timer(void *data) {
	quic_session_t *s = data;

	if(s->dead) {
		return;
	}

	s->reading = true;
	int rv = ngtcp2_conn_handle_expiry(s->conn, quic_now());
	s->reading = false;

	if(rv) {
		ngtcp2_ccerr_set_liberr(&s->ccerr, rv, NULL, 0);
		quic_fail(s, rv != NGTCP2_ERR_IDLE_CLOSE);
		return;
	}

	quic_flush(s);
}

static void quic_arm_timer(quic_session_t *s) {
	if(s->dead || !s->conn) {
		return;
	}

	ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(s->conn);

	if(expiry == UINT64_MAX) {
		timeout_del(&s->timer);
		return;
	}

	ngtcp2_tstamp n = quic_now();
	ngtcp2_tstamp delta = expiry > n ? expiry - n : 0;
	struct timeval tv = {
		(time_t)(delta / NGTCP2_SECONDS),
		(suseconds_t)((delta % NGTCP2_SECONDS) / NGTCP2_MICROSECONDS)
	};

	if(s->timer.cb) {
		timeout_set(&s->timer, &tv);
	} else {
		timeout_add(&s->timer, quic_timer, s, &tv);
	}
}

/* ---- session lifecycle --------------------------------------------------- */

static int pick_socket(const sockaddr_t *peer) {
	for(int i = 0; i < listen_sockets; i++) {
		if(listen_socket[i].sa.sa.sa_family == peer->sa.sa_family) {
			return i;
		}
	}

	return -1;
}

/* The extra QuicPort socket of a family, or -1 (then the main socket is used). */
static int quic_extra_fd(int family) {
	for(int i = 0; i < quic_listens; i++) {
		if(quic_listen[i].sa.sa.sa_family == family) {
			return quic_listen[i].udp.fd;
		}
	}

	return -1;
}

static quic_session_t *new_session(connection_t *c, int fd, size_t sock, const sockaddr_t *peer, bool is_server) {
	quic_session_t *s = xzalloc(sizeof(*s));
	s->c = c;
	s->fd = fd;
	s->sock = sock;
	s->peer = *peer;
	s->is_server = is_server;
	s->stream_id = -1;
	ngtcp2_ccerr_default(&s->ccerr);
	c->transport_data = s;
	c->socket = -1;
	list_insert_tail(&quic_sessions, s);
	return s;
}

static void free_session(quic_session_t *s) {
	timeout_del(&s->timer);

	if(s->conn) {
		ngtcp2_conn_del(s->conn);
		s->conn = NULL;
	}

	quic_tls_session_free(&s->tls);
	free(s->tx);
	list_delete(&quic_sessions, s);
	free(s);
}

/* ---- inbound: accept and receive ----------------------------------------- */

static void quic_accept(listen_socket_t *ls, const uint8_t *buf, size_t len, const sockaddr_t *addr) {
	/* Admission control, in the spirit of sf_accept(). */
	static time_t burst_time;
	static int burst;

	if(now.tv_sec != burst_time) {
		burst_time = now.tv_sec;
		burst = 0;
	}

	if(++burst > max_connection_burst) {
		logger(DEBUG_CONNECTIONS, LOG_WARNING, "quic: too many new sessions, dropping one");
		return;
	}

	ngtcp2_pkt_hd hd;

	if(ngtcp2_accept(&hd, buf, len) != 0) {
		return;
	}

	char *alpn = NULL;
	get_config_string(lookup_config(&config_tree, "QuicAlpn"), &alpn);

	connection_t *c = new_connection();
	c->name = xstrdup("<unknown>");
	c->outmaclength = myself->connection->outmaclength;
	c->address = *addr;
	c->hostname = sockaddr2hostname(addr);
	c->last_ping_time = now.tv_sec;
	c->transport = transport_get(TRANSPORT_QUIC);
	c->allow_request = ID;

	/* `ls' may be a QuicPort listener (not in listen_socket[]): keep its fd for
	   sending, and a same-family main socket index for tinc's bookkeeping. */
	int sock = pick_socket(addr);

	if(sock < 0) {
		free(alpn);
		free_connection(c);
		return;
	}

	quic_session_t *s = new_session(c, ls->udp.fd, (size_t)sock, addr, true);

	if(!quic_tls_session_init(&s->tls, true, get_conn, &s->tls, alpn ? alpn : QUIC_ALPN_DEFAULT, NULL, NULL)) {
		free(alpn);
		logger(DEBUG_CONNECTIONS, LOG_ERR, "quic: TLS init failed for a session from %s", c->hostname);
		free_session(s);
		free_connection(c);
		return;
	}

	free(alpn);

	ngtcp2_callbacks cb;
	ngtcp2_settings settings;
	ngtcp2_transport_params params;
	quic_callbacks(&cb, true);
	quic_settings(&settings, &params);
	params.original_dcid = hd.dcid;
	params.original_dcid_present = 1;

	ngtcp2_cid scid = {.datalen = TRANSPORT_QUIC_CIDLEN};
	gnutls_rnd(GNUTLS_RND_RANDOM, scid.data, scid.datalen);

	if(ngtcp2_crypto_generate_stateless_reset_token(params.stateless_reset_token, static_secret, sizeof(static_secret), &scid)) {
		free_session(s);
		free_connection(c);
		return;
	}

	params.stateless_reset_token_present = 1;

	ngtcp2_path path = {
		.local = {(ngtcp2_sockaddr *)&listen_socket[s->sock].sa.sa, SALEN(listen_socket[s->sock].sa.sa)},
		.remote = {(ngtcp2_sockaddr *)&s->peer.sa, SALEN(s->peer.sa)},
	};

	if(ngtcp2_conn_server_new(&s->conn, &hd.scid, &scid, &path, hd.version, &cb, &settings, &params, NULL, s)) {
		free_session(s);
		free_connection(c);
		return;
	}

	/* Register the CIDs a peer can reach us by: our chosen scid, and the
	   client's original dcid so its Initial retransmits map here. */
	cid_add(s, scid.data, scid.datalen);
	cid_add(s, hd.dcid.data, hd.dcid.datalen);

	ngtcp2_conn_set_tls_native_handle(s->conn, s->tls.session);
	connection_add(c);

	logger(DEBUG_CONNECTIONS, LOG_NOTICE, "quic: connection from %s", c->hostname);

	s->reading = true;
	ngtcp2_pkt_info pi = {0};
	int rv = ngtcp2_conn_read_pkt(s->conn, &path, &pi, buf, len, quic_now());
	s->reading = false;

	if(rv) {
		if(rv == NGTCP2_ERR_CRYPTO) {
			ngtcp2_ccerr_set_tls_alert(&s->ccerr, ngtcp2_conn_get_tls_alert(s->conn), NULL, 0);
		} else {
			ngtcp2_ccerr_set_liberr(&s->ccerr, rv, NULL, 0);
		}

		quic_fail(s, rv != NGTCP2_ERR_DRAINING && rv != NGTCP2_ERR_CLOSING && rv != NGTCP2_ERR_DROP_CONN);
		return;
	}

	quic_flush(s);
}

bool quic_udp_try(listen_socket_t *ls, const uint8_t *buf, size_t len, const sockaddr_t *vaddr) {
	if(!quic_ready) {
		return false;
	}

	sockaddr_t addr = *vaddr;
	sockaddrunmap(&addr);

	ngtcp2_version_cid vc;
	int rv = ngtcp2_pkt_decode_version_cid(&vc, buf, len, TRANSPORT_QUIC_CIDLEN);

	if(rv < 0) {
		/* Not a QUIC packet we can parse (or a version we do not speak): let
		   the obfs keyed check and the SPTPS path have it. */
		return false;
	}

	quic_session_t *s = session_by_cid(vc.dcid, vc.dcidlen);

	if(!s) {
		/* Unknown CID. Only a well-formed v1 Initial (>= 1200 bytes, parsed by
		   ngtcp2_accept) opens a new session; anything else is not claimed, so
		   a data packet that merely looks like a long header falls through. */
		ngtcp2_pkt_hd hd;

		if((buf[0] & 0x80) && ngtcp2_accept(&hd, buf, len) == 0) {
			quic_accept(ls, buf, len, &addr);
			return true;
		}

		return false;
	}

	if(s->dead) {
		return true;
	}

	/* The path's remote is the datagram's real source: a NAT rebind shows up
	   here as a new remote and ngtcp2 starts path validation on its own. */
	ngtcp2_path path = {
		.local = {(ngtcp2_sockaddr *)&listen_socket[s->sock].sa.sa, SALEN(listen_socket[s->sock].sa.sa)},
		.remote = {(ngtcp2_sockaddr *)&addr.sa, SALEN(addr.sa)},
	};
	ngtcp2_pkt_info pi = {0};

	s->reading = true;
	rv = ngtcp2_conn_read_pkt(s->conn, &path, &pi, buf, len, quic_now());
	s->reading = false;

	if(rv) {
		if(rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_CLOSING || rv == NGTCP2_ERR_DROP_CONN) {
			quic_fail(s, false);
		} else if(rv == NGTCP2_ERR_CRYPTO) {
			ngtcp2_ccerr_set_tls_alert(&s->ccerr, ngtcp2_conn_get_tls_alert(s->conn), NULL, 0);
			logger(DEBUG_CONNECTIONS, LOG_DEBUG, "quic: TLS alert from %s", s->c->hostname);
			quic_fail(s, true);
		} else {
			ngtcp2_ccerr_set_liberr(&s->ccerr, rv, NULL, 0);
			quic_fail(s, true);
		}

		return true;
	}

	if(!s->dead) {
		quic_flush(s);
	}

	return true;
}

/* Table hook (void): the dispatcher calls quic_udp_try() directly so a
   non-claimed packet can fall through; this satisfies the carrier contract. */
void quic_udp_receive(listen_socket_t *ls, const uint8_t *buf, size_t len, const sockaddr_t *addr) {
	quic_udp_try(ls, buf, len, addr);
}

/* ---- outbound: dial ------------------------------------------------------ */

static char *choose_sni(connection_t *c) {
	char *sni = NULL;

	if(get_config_string(lookup_config(&config_tree, "QuicSni"), &sni) && sni && *sni) {
		return sni;
	}

	free(sni);

	if(get_config_string(lookup_config(&config_tree, "HttpsSni"), &sni) && sni && *sni) {
		return sni;
	}

	free(sni);

	/* The peer's Address if it is a hostname (shaping only, never validated). */
	splay_tree_t *tree = create_configuration();
	char *addr = NULL;

	if(read_host_config(tree, c->name, false)) {
		char *a = NULL;

		if(get_config_string(lookup_config(tree, "Address"), &a) && a && *a) {
			bool looks_like_name = false;

			for(char *p = a; *p; p++) {
				if(isalpha((uint8_t) *p) && !strchr("abcdefABCDEF", *p)) {
					looks_like_name = true;
					break;
				}
			}

			if(strchr(a, ':')) {
				looks_like_name = false;
			}

			if(looks_like_name) {
				addr = xstrdup(a);
			}
		}

		free(a);
	}

	exit_configuration(tree);
	return addr;
}

bool quic_dial(connection_t *c) {
	if(!quic_ready) {
		return false;
	}

	/* The peer's pinned TlsFingerprint, if any (else accept-on-first-use). */
	char pin[QUIC_FP_HEX_LEN] = "";
	splay_tree_t *tree = create_configuration();

	if(read_host_config(tree, c->name, false)) {
		char *fp = NULL;

		if(get_config_string(lookup_config(tree, "TlsFingerprint"), &fp) && fp && tls_fingerprint_valid(fp) && strlen(fp) < sizeof(pin)) {
			strncpy(pin, fp, sizeof(pin) - 1);
		}

		free(fp);
	}

	exit_configuration(tree);

	int sock = pick_socket(&c->address);

	if(sock < 0) {
		logger(DEBUG_CONNECTIONS, LOG_ERR, "quic: no UDP socket for the address family of %s (%s)", c->name, c->hostname);
		return false;
	}

	char *alpn = NULL;
	get_config_string(lookup_config(&config_tree, "QuicAlpn"), &alpn);
	char *sni = choose_sni(c);

	/* Destination port: the peer's host-record QuicPort, else our own QuicPort
	   (a network-wide option, propagated by invitations), else the peer's tinc
	   port as dialled. Source socket: the QuicPort listener when one exists. */
	sockaddr_t peer = c->address;
	int port = quic_port;
	tree = create_configuration();

	if(read_host_config(tree, c->name, false)) {
		get_config_int(lookup_config(tree, "QuicPort"), &port);
	}

	exit_configuration(tree);

	if(port > 0 && port < 65536) {
		if(peer.sa.sa_family == AF_INET) {
			peer.in.sin_port = htons((uint16_t)port);
		} else if(peer.sa.sa_family == AF_INET6) {
			peer.in6.sin6_port = htons((uint16_t)port);
		}
	}

	int fd = quic_extra_fd(peer.sa.sa_family);

	if(fd < 0) {
		fd = listen_socket[sock].udp.fd;
	}

	quic_session_t *s = new_session(c, fd, (size_t)sock, &peer, false);

	if(!quic_tls_session_init(&s->tls, false, get_conn, &s->tls, alpn ? alpn : QUIC_ALPN_DEFAULT, sni, pin)) {
		logger(DEBUG_CONNECTIONS, LOG_ERR, "quic: TLS init failed dialling %s", c->name);
		free(alpn);
		free(sni);
		free_session(s);
		return false;
	}

	free(alpn);
	free(sni);

	ngtcp2_callbacks cb;
	ngtcp2_settings settings;
	ngtcp2_transport_params params;
	quic_callbacks(&cb, false);
	quic_settings(&settings, &params);

	ngtcp2_cid dcid = {.datalen = NGTCP2_MIN_INITIAL_DCIDLEN}, scid = {.datalen = TRANSPORT_QUIC_CIDLEN};
	gnutls_rnd(GNUTLS_RND_RANDOM, dcid.data, dcid.datalen);
	gnutls_rnd(GNUTLS_RND_RANDOM, scid.data, scid.datalen);

	ngtcp2_path path = {
		.local = {(ngtcp2_sockaddr *)&listen_socket[s->sock].sa.sa, SALEN(listen_socket[s->sock].sa.sa)},
		.remote = {(ngtcp2_sockaddr *)&s->peer.sa, SALEN(s->peer.sa)},
	};

	if(ngtcp2_conn_client_new(&s->conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1, &cb, &settings, &params, NULL, s)) {
		free_session(s);
		return false;
	}

	cid_add(s, scid.data, scid.datalen);
	ngtcp2_conn_set_tls_native_handle(s->conn, s->tls.session);

	c->status.connecting = false;
	connection_add(c);

	logger(DEBUG_CONNECTIONS, LOG_INFO, "Dialling %s (%s) via quic", c->name, c->hostname);

	/* finish_connecting() runs later, from handshake_completed, so the
	   authenticator is the first thing on the stream (docs/transports.md §9.4). */
	quic_flush(s);   /* sends the Initial */
	return true;
}

/* ---- carrier hooks ------------------------------------------------------- */

bool quic_send(connection_t *c) {
	quic_session_t *s = c->transport_data;

	if(!s || s->dead) {
		return false;
	}

	uint32_t avail = c->outbuf.len - c->outbuf.offset;

	if(avail) {
		if(s->tx_len + avail > s->tx_cap) {
			s->tx_cap = s->tx_len + avail + 4096;
			s->tx = xrealloc(s->tx, s->tx_cap);
		}

		memcpy(s->tx + s->tx_len, c->outbuf.data + c->outbuf.offset, avail);
		s->tx_len += avail;
		buffer_read(&c->outbuf, avail);
	}

	if(!s->reading) {
		quic_flush(s);
	}

	return true;
}

bool quic_send_datagram(connection_t *c, const void *buf, size_t len) {
	quic_session_t *s = c->transport_data;

	if(!s || s->dead || !s->conn) {
		return false;
	}

	size_t max = ngtcp2_conn_get_max_tx_udp_payload_size(s->conn);

	if(len > QUIC_MAX_DGRAM || (max > 35 && len > max - 35)) {
		return false; /* caller treats it like EMSGSIZE -> reduce_mtu */
	}

	if(s->dgram_n == QUIC_DGRAM_QUEUE) {
		return true; /* queue full: drop, SPTPS recovers */
	}

	size_t i = (s->dgram_head + s->dgram_n) % QUIC_DGRAM_QUEUE;
	memcpy(s->dgram[i].data, buf, len);
	s->dgram[i].len = len;
	s->dgram_n++;

	if(!s->reading) {
		quic_flush(s);
	}

	return true;
}

void quic_close(connection_t *c) {
	quic_session_t *s = c->transport_data;

	if(!s) {
		return;
	}

	/* Best-effort CONNECTION_CLOSE if still live and not already tearing down. */
	if(!s->dead && s->conn && !ngtcp2_conn_in_closing_period(s->conn) && !ngtcp2_conn_in_draining_period(s->conn)) {
		uint8_t buf[QUIC_PKT_BUF];
		ngtcp2_path_storage ps;
		ngtcp2_pkt_info pi;
		ngtcp2_path_storage_zero(&ps);

		if(!s->ccerr.error_code) {
			ngtcp2_ccerr_set_application_error(&s->ccerr, 0, NULL, 0);
		}

		ngtcp2_ssize n = ngtcp2_conn_write_connection_close(s->conn, &ps.path, &pi, buf, sizeof(buf), &s->ccerr, quic_now());

		if(n > 0) {
			sendto(s->fd, (void *)buf, (size_t)n, 0, &s->peer.sa, SALEN(s->peer.sa));
		}
	}

	c->transport_data = NULL;
	free_session(s);
}

bool quic_local_address(connection_t *c, sockaddr_t *sa) {
	quic_session_t *s = c->transport_data;

	if(!s) {
		return false;
	}

	socklen_t salen = sizeof(*sa);
	return getsockname(listen_socket[s->sock].udp.fd, &sa->sa, &salen) >= 0;
}

/* ---- init / exit --------------------------------------------------------- */

bool quic_init(void) {
	if(!tls_init()) {
		logger(DEBUG_ALWAYS, LOG_ERR, "quic carrier: node certificate not available");
		return false;
	}

	char *cert_pem = NULL, *key_pem = NULL;

	if(!tls_current_pem(&cert_pem, &key_pem)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "quic carrier: could not load the node certificate PEM");
		return false;
	}

	if(!quic_ready && !quic_tls_global_init()) {
		free(cert_pem);

		if(key_pem) {
			memzero(key_pem, strlen(key_pem));
		}

		free(key_pem);
		logger(DEBUG_ALWAYS, LOG_ERR, "quic carrier: GnuTLS init failed");
		return false;
	}

	bool ok = quic_tls_set_server_cert(cert_pem, key_pem);
	free(cert_pem);

	if(key_pem) {
		memzero(key_pem, strlen(key_pem));
	}

	free(key_pem);

	if(!ok) {
		logger(DEBUG_ALWAYS, LOG_ERR, "quic carrier: could not build the server credential");
		return false;
	}

	if(!quic_ready) {
		gnutls_rnd(GNUTLS_RND_RANDOM, static_secret, sizeof(static_secret));
		transport_set_quic_cid_matcher(quic_cid_match);
		quic_ready = true;

		/* QuicPort: an extra UDP listener per address family, fed to the same
		   receive path as the main sockets. Only when it differs from the
		   tinc port; otherwise the shared socket is the QUIC socket. */
		quic_port = 0;
		get_config_int(lookup_config(&config_tree, "QuicPort"), &quic_port);

		if(quic_port > 0 && quic_port < 65536 && quic_port != atoi(myport.udp)) {
			for(int i = 0; i < listen_sockets && quic_listens < MAXSOCKETS; i++) {
				sockaddr_t sa = listen_socket[i].sa;

				if(sa.sa.sa_family == AF_INET) {
					sa.in.sin_port = htons((uint16_t)quic_port);
				} else if(sa.sa.sa_family == AF_INET6) {
					sa.in6.sin6_port = htons((uint16_t)quic_port);
				} else {
					continue;
				}

				bool dup = false;

				for(int j = 0; j < quic_listens; j++) {
					if(!sockaddrcmp(&quic_listen[j].sa, &sa)) {
						dup = true;
					}
				}

				if(dup) {
					continue;
				}

				int fd = setup_vpn_in_socket(&sa);

				if(fd < 0) {
					logger(DEBUG_ALWAYS, LOG_WARNING, "quic: could not bind QuicPort %d; using the tinc port", quic_port);
					continue;
				}

				listen_socket_t *ls = &quic_listen[quic_listens++];
				ls->sa = sa;
				ls->tcp.fd = -1;
				io_add(&ls->udp, handle_incoming_vpn_data, ls, fd, IO_READ);
				char *h = sockaddr2hostname(&sa);
				logger(DEBUG_ALWAYS, LOG_INFO, "quic: listening on %s (QuicPort)", h);
				free(h);
			}
		} else {
			quic_port = 0;
		}

		logger(DEBUG_ALWAYS, LOG_INFO, "QUIC carrier ready (ngtcp2 %s, GnuTLS)%s", ngtcp2_version(0)->version_str,
		       quic_port ? "" : ", on the tinc port");
	}

	return true;
}

/* Reload: a replaced certificate is served without restart (QuicSni/QuicAlpn
   are read per dial; QuicPort needs a restart). */
bool quic_read_config(void) {
	if(!quic_ready) {
		return true;
	}

	char before[TLS_FP_HEX_LEN];
	strncpy(before, tls_own_fp_hex, sizeof(before));

	if(!tls_init()) {
		return false;
	}

	if(strcmp(before, tls_own_fp_hex)) {
		logger(DEBUG_ALWAYS, LOG_INFO, "quic: node certificate changed; rebuilding the server credential");
		return quic_init();
	}

	return true;
}

void quic_exit(void) {
	if(!quic_ready) {
		return;
	}

	transport_set_quic_cid_matcher(NULL);
	timeout_del(&quic_reaper);

	while(quic_sessions.head) {
		quic_session_t *s = quic_sessions.head->data;
		free_session(s);
	}

	for(int i = 0; i < quic_listens; i++) {
		io_del(&quic_listen[i].udp);
		closesocket(quic_listen[i].udp.fd);
	}

	quic_listens = 0;
	quic_tls_free_server_cert();
	quic_tls_global_deinit();
	quic_ready = false;
}

#endif /* HAVE_QUIC */
