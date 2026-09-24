/*
    transport_quic.c -- the `quic' carrier: SPTPS meta on one QUIC stream and
                        SPTPS data records in QUIC DATAGRAM frames, over tinc's
                        own UDP listen socket (ngtcp2 + OpenSSL).

    QUIC is an outer carrier: SPTPS (Ed25519 identity, ChaCha20-Poly1305, the
    meta+data records) runs unchanged inside it (principle 1). ngtcp2 owns no
    socket, no threads and no timers -- this file feeds it datagrams read from
    the M4 front's UDP socket, drains what it wants to send, and drives one
    timeout_t from ngtcp2_conn_get_expiry(), exactly as the stream-Q spike
    proved (testing/quic-spike/). The TLS-backend-specific lines are in
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

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#ifndef NGTCP2_TINCSTACK_WIRE
#error "ngtcp2 without core/ngtcp2/tincstack-wire.patch: the dialler would announce ngtcp2's transport parameters, not curl's"
#endif

#include "authn.h"
#include "conf.h"
#include "connection.h"
#include "decoy.h"
#include "h3.h"
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
#define QUIC_UNI_STREAMS 3              /* control, QPACK encoder, QPACK decoder */
#define QUIC_REQ_SLOTS 8                /* request streams a server answers per connection */
#define QUIC_OK_HDR_CAP 64              /* client: the listener's response HEADERS, kept to check */
#define QUIC_DGRAM_FRAME_MAX 65536      /* max_datagram_frame_size we accept */
#define QUIC_CURL_UDP_PAYLOAD 1200      /* curl's max_udp_payload_size, and all it ever sends */
#define QUIC_CURL_CID_LIMIT 2           /* curl's active_connection_id_limit */
/* What a DATAGRAM costs in a 1-RTT packet besides its payload: header byte,
   destination connection id (TRANSPORT_QUIC_CIDLEN; the dialler's is empty),
   4-byte packet number, frame type, 2-byte length, AEAD tag -- with slack. */
#define QUIC_DGRAM_OVERHEAD 35
#define QUIC_IDLE_MIN 30                /* s; what curl and Chromium announce */

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
	                                   (datagram delivery) */
	sockaddr_t local;               /* the local end of the path ngtcp2 sees */
	sockaddr_t peer;                /* current validated remote path */
	io_t own_io;                    /* client: its own ephemeral socket (fd), */
	bool own_socket;                /* read here and closed with the session */

	char *authority;                /* client: :authority of the request (SNI or address) */
	int64_t stream_id;              /* meta stream (the tinc request), -1 until
	                                   opened (client) or authenticated (server) */
	h3_parser_t rx;                 /* HTTP/3 frames on the meta stream */
	uint8_t ok_hdr[QUIC_OK_HDR_CAP];/* client: HEADERS payload of the answer */
	size_t ok_hdr_len;
	bool ok_checked;                /* client: the answer is a tinc listener's */
	bool dgram_marked;              /* client: the listener sent H3_FRAME_TINC_DGRAM */

	/* Our unidirectional streams (control + SETTINGS, QPACK encoder and
	   decoder). Their bytes are constant (h3_uni_preamble), so nothing needs
	   to be kept for retransmission. */
	int64_t uni_id[QUIC_UNI_STREAMS];
	size_t uni_sent[QUIC_UNI_STREAMS];
	bool uni_blocked[QUIC_UNI_STREAMS];
	int nuni;

	/* Server: request streams that are not (yet) the tinc session. Each gets
	   an HTTP/3 answer -- the decoy -- like any web server would give. */
	struct {
		int64_t id;
		h3_parser_t rx;
		uint8_t *resp;          /* HEADERS + DATA; kept until the session ends */
		size_t resp_len, resp_sent;
		bool responded, blocked, done;
	} req[QUIC_REQ_SLOTS];
	int nreq;

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
	bool auth_slot_taken;           /* a request stream is sending an authenticator */
	int auth_slot;
	uint8_t authbuf[QUIC_AUTH_CAP];
	size_t authlen;

	quic_cid_t cids[QUIC_CID_SLOTS];
	int ncids;

	timeout_t timer;
	bool reading;                   /* inside read_pkt / handle_expiry: defer flush */
	bool dead;                      /* failed; the reaper will terminate it */
	bool pin_pending;               /* client: pin tls.peer_fp once SPTPS authenticates (M5-7) */
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
static bool quic_port_configured;       /* set by the operator, not the 443 default */
static int quic_port_option;            /* that setting, bound here or not (dial fallback) */

static void quic_flush(quic_session_t *s);
static void quic_arm_timer(quic_session_t *s);
static size_t dgram_room(quic_session_t *s);

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
			ngtcp2_ccerr_set_application_error(&s->ccerr, H3_NO_ERROR, NULL, 0);
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
	quic_tls_random(dest, destlen);
}

static int cb_get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid, ngtcp2_stateless_reset_token *token,
                                    size_t cidlen, void *user_data) {
	(void)conn;
	quic_session_t *s = user_data;

	if(!quic_tls_random(cid->data, cidlen)) {
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

/* Client: the connection is activated (c->edge is set by ack_h once the SPTPS
   handshake proved the peer's Ed25519 identity), so the certificate this
   session was dialled through is the peer's: pin it, replacing any old pin. */
static void learn_pin(quic_session_t *s) {
	if(!s->pin_pending || s->is_server || !s->c->edge) {
		return;
	}

	s->pin_pending = false;
	logger(DEBUG_ALWAYS, LOG_NOTICE, "quic: SPTPS authenticated %s; pinning TlsFingerprint %s", s->c->name, s->tls.peer_fp_hex);

	if(!replace_config_file(s->c->name, "TlsFingerprint", s->tls.peer_fp_hex)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "quic: could not store the TlsFingerprint of %s", s->c->name);
	}
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

	learn_pin(s);
	return true;
}

/* ---- HTTP/3 streams (h3.h) ------------------------------------------------ */

static const uint64_t uni_types[QUIC_UNI_STREAMS] = {H3_STREAM_CONTROL, H3_STREAM_QPACK_ENCODER, H3_STREAM_QPACK_DECODER};

static bool stream_is_uni(int64_t id) {
	return id & 0x2;
}

/* Append raw bytes to the meta stream's TX ring. */
static void tx_append(quic_session_t *s, const void *data, size_t len) {
	if(s->tx_len + len > s->tx_cap) {
		s->tx_cap = s->tx_len + len + 4096;
		s->tx = xrealloc(s->tx, s->tx_cap);
	}

	memcpy(s->tx + s->tx_len, data, len);
	s->tx_len += len;
}

/* Append one DATA frame carrying `len' bytes of the tinc stream. */
static void tx_append_data(quic_session_t *s, const void *data, size_t len) {
	uint8_t hdr[H3_DATA_HDR_MAX];
	tx_append(s, hdr, h3_data_header(hdr, len));
	tx_append(s, data, len);
}

/* Our control stream (SETTINGS) and QPACK streams, which every HTTP/3
   endpoint opens as soon as it can. */
static bool open_uni_streams(quic_session_t *s) {
	for(int i = 0; i < QUIC_UNI_STREAMS; i++) {
		if(ngtcp2_conn_open_uni_stream(s->conn, &s->uni_id[i], NULL)) {
			return false;
		}

		s->nuni = i + 1;
	}

	return true;
}

/* The HEADERS payload a tinc listener answers with (h3_response_ok without
   its frame header), which the dialler checks the answer against. */
static const uint8_t *ok_headers_payload(size_t *len) {
	static uint8_t payload[QUIC_OK_HDR_CAP];
	static size_t plen;

	if(!plen) {
		size_t flen;
		uint8_t *f = h3_response_ok(&flen);
		uint64_t type, l;
		size_t n1 = h3_varint_get(f, flen, &type);
		size_t n2 = h3_varint_get(f + n1, flen - n1, &l);

		if(n1 && n2 && l == flen - n1 - n2 && l <= sizeof(payload)) {
			memcpy(payload, f + n1 + n2, (size_t)l);
			plen = (size_t)l;
		}

		free(f);
	}

	*len = plen;
	return payload;
}

/* Server: the slot of a request stream, created on first sight. -1 when all
   slots are taken (the stream is refused, as a server at its limit would). */
static int req_slot(quic_session_t *s, int64_t id) {
	for(int i = 0; i < s->nreq; i++) {
		if(s->req[i].id == id) {
			return i;
		}
	}

	if(s->nreq == QUIC_REQ_SLOTS) {
		return -1;
	}

	int i = s->nreq++;
	memset(&s->req[i], 0, sizeof(s->req[i]));
	s->req[i].id = id;
	return i;
}

/* Server: answer a request stream with the decoy page, the way an HTTP/3
   web server answers a browser. The connection stays up; an unauthenticated
   one is ended later by tinc's authentication timeout. */
static void req_respond_decoy(quic_session_t *s, int i) {
	if(s->req[i].responded) {
		return;
	}

	static const char request[] = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
	size_t rl;
	char *r = decoy_respond_static(request, sizeof(request) - 1, &rl);
	s->req[i].resp = h3_from_http1(r, rl, &s->req[i].resp_len);
	free(r);
	s->req[i].responded = true;

	if(!s->req[i].resp) {
		s->req[i].done = true;
		ngtcp2_conn_shutdown_stream(s->conn, 0, s->req[i].id, H3_REQUEST_REJECTED);
		return;
	}

	logger(DEBUG_CONNECTIONS, LOG_INFO, "quic: serving the decoy to an HTTP/3 request from %s", s->c->hostname);
}

typedef struct rx_ctx_t {
	quic_session_t *s;
	int slot;               /* server: request slot, -1 on the client */
	int64_t id;
} rx_ctx_t;

/* Server: authenticator bytes from the first DATA of a request. Returns the
   bytes consumed; sets *verdict to 1 (authenticated), -1 (rejected) or 0
   (need more). */
static size_t server_auth(quic_session_t *s, const uint8_t *p, size_t remain, int *verdict) {
	size_t used = 0;
	*verdict = 0;

	while(remain) {
		size_t expected = authn_expected_len(s->authbuf, s->authlen);

		if(expected == (size_t) -1) {
			logger(DEBUG_CONNECTIONS, LOG_INFO, "quic: malformed authenticator from %s", s->c->hostname);
			*verdict = -1;
			return used;
		}

		size_t want = expected ? expected - s->authlen : 1;

		if(want > QUIC_AUTH_CAP - s->authlen) {
			logger(DEBUG_CONNECTIONS, LOG_INFO, "quic: oversized authenticator from %s", s->c->hostname);
			*verdict = -1;
			return used;
		}

		size_t take = want < remain ? want : remain;
		memcpy(s->authbuf + s->authlen, p, take);
		s->authlen += take;
		p += take;
		remain -= take;
		used += take;

		expected = authn_expected_len(s->authbuf, s->authlen);

		if(expected && expected != (size_t) -1 && s->authlen == expected) {
			uint8_t exporter[AUTHN_EXPORTER_LEN];
			char *name = NULL;

			if(!quic_tls_exporter(&s->tls, exporter, sizeof(exporter)) ||
			                !authn_verify(s->authbuf, s->authlen, tls_own_fp, exporter, "quic", s->c->hostname, &name)) {
				logger(DEBUG_CONNECTIONS, LOG_INFO, "quic: authenticator from %s rejected", s->c->hostname);
				*verdict = -1;
				return used;
			}

			free(s->c->name);
			s->c->name = name;
			s->authenticated = true;
			logger(DEBUG_CONNECTIONS, LOG_NOTICE, "quic: authenticated peer %s (%s)", s->c->name, s->c->hostname);
			*verdict = 1;
			return used;
		}
	}

	return used;
}

static bool server_frame(void *data, uint64_t type, const uint8_t *payload, size_t len) {
	rx_ctx_t *x = data;
	quic_session_t *s = x->s;

	if(s->dead) {
		return false;
	}

	if(type != H3_FRAME_DATA || !len) {
		return true;    /* HEADERS, SETTINGS-like or reserved frames: nothing we need */
	}

	if(x->id == s->stream_id) {
		return deliver_meta(s, payload, len);
	}

	if(s->req[x->slot].responded || s->authenticated || (s->auth_slot_taken && s->auth_slot != x->slot)) {
		return true;    /* a request body nobody is waiting for */
	}

	s->auth_slot_taken = true;
	s->auth_slot = x->slot;
	int verdict;
	size_t used = server_auth(s, payload, len, &verdict);

	if(verdict < 0) {
		/* Not a tinc peer: an HTTP/3 client POSTing something. Answer it like
		   a web server; its later requests get the same. */
		s->authlen = 0;
		s->auth_slot_taken = false;
		req_respond_decoy(s, x->slot);
		return true;
	}

	if(verdict > 0) {
		s->stream_id = x->id;
		s->req[x->slot].done = true;    /* its answer is the meta stream's TX ring */

		size_t hlen;
		uint8_t *h = h3_response_ok(&hlen);
		tx_append(s, h, hlen);
		free(h);

		/* A current dialler takes DATAGRAM frames without announcing it (its
		   Initial is curl's, and curl has none): allow them to it, and tell it
		   we know, with a frame only an authenticated peer ever sees. An
		   earlier dialler announced them itself and skips the frame. */
		const ngtcp2_transport_params *rp = ngtcp2_conn_get_remote_transport_params(s->conn);

		if(rp && !rp->max_datagram_frame_size) {
			ngtcp2_conn_set_remote_max_datagram_frame_size(s->conn, QUIC_DGRAM_FRAME_MAX);
		}

		uint8_t mark[16];
		size_t mlen = h3_varint_put(mark, H3_FRAME_TINC_DGRAM);
		mlen += h3_varint_put(mark + mlen, 0);
		tx_append(s, mark, mlen);

		if(used < len) {
			return deliver_meta(s, payload + used, len - used);
		}
	}

	return true;
}

static bool client_frame(void *data, uint64_t type, const uint8_t *payload, size_t len) {
	rx_ctx_t *x = data;
	quic_session_t *s = x->s;

	if(s->dead) {
		return false;
	}

	if(type == H3_FRAME_HEADERS && !s->ok_checked) {
		if(s->ok_hdr_len + len > sizeof(s->ok_hdr)) {
			s->ok_hdr_len = sizeof(s->ok_hdr) + 1;  /* too long to be ours */
		} else {
			memcpy(s->ok_hdr + s->ok_hdr_len, payload, len);
			s->ok_hdr_len += len;
		}

		return true;
	}

	if(type == H3_FRAME_TINC_DGRAM) {
		s->dgram_marked = true;
		return true;
	}

	if(type != H3_FRAME_DATA || !len) {
		return true;
	}

	if(!s->ok_checked) {
		size_t oklen;
		const uint8_t *ok = ok_headers_payload(&oklen);

		if(!s->rx.seen_headers || s->ok_hdr_len != oklen || memcmp(s->ok_hdr, ok, oklen)) {
			/* A web server's answer (a decoy, or not a tinc node at all). */
			logger(DEBUG_CONNECTIONS, LOG_INFO, "quic: %s (%s) answered like a web server, not a tinc peer",
			       s->c->name, s->c->hostname);
			ngtcp2_ccerr_set_application_error(&s->ccerr, H3_NO_ERROR, NULL, 0);
			quic_fail(s, true);
			return false;
		}

		if(!s->dgram_marked) {
			/* A listener from before 2026-09-24: it cannot send us datagrams,
			   since we do not announce them. Give up before the link is
			   activated, so the next carrier is tried. */
			logger(DEBUG_CONNECTIONS, LOG_WARNING, "quic: %s (%s) runs a tinc too old to send datagrams to this one; not using quic",
			       s->c->name, s->c->hostname);
			ngtcp2_ccerr_set_application_error(&s->ccerr, H3_NO_ERROR, NULL, 0);
			quic_fail(s, true);
			return false;
		}

		s->ok_checked = true;
	}

	return deliver_meta(s, payload, len);
}

static int cb_recv_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t offset,
                               const uint8_t *data, size_t datalen, void *user_data, void *stream_user_data) {
	(void)offset;
	(void)stream_user_data;
	quic_session_t *s = user_data;
	bool fin = flags & NGTCP2_STREAM_DATA_FLAG_FIN;

	if(s->dead) {
		return 0;
	}

	if(stream_is_uni(stream_id)) {
		/* The peer's control and QPACK streams: SETTINGS we accept as they
		   are, and no QPACK instructions can come (our dynamic table
		   capacity is 0). Consumed and credited. */
	} else if(!s->is_server) {
		if(stream_id != s->stream_id) {
			ngtcp2_conn_shutdown_stream(conn, 0, stream_id, H3_GENERAL_PROTOCOL_ERROR);
		} else {
			rx_ctx_t x = {s, -1, stream_id};

			if(!h3_parse(&s->rx, data, datalen, client_frame, &x) && !s->dead) {
				ngtcp2_ccerr_set_application_error(&s->ccerr, H3_GENERAL_PROTOCOL_ERROR, NULL, 0);
				quic_fail(s, true);
			}

			if(fin && !s->dead) {
				logger(DEBUG_CONNECTIONS, LOG_INFO, "quic: %s (%s) ended the request stream", s->c->name, s->c->hostname);
				quic_fail(s, true);
			}
		}
	} else {
		int i = req_slot(s, stream_id);

		if(i < 0) {
			ngtcp2_conn_shutdown_stream(conn, 0, stream_id, H3_REQUEST_REJECTED);
		} else {
			rx_ctx_t x = {s, i, stream_id};

			if(!h3_parse(&s->req[i].rx, data, datalen, server_frame, &x) && !s->dead) {
				if(stream_id == s->stream_id) {
					ngtcp2_ccerr_set_application_error(&s->ccerr, H3_GENERAL_PROTOCOL_ERROR, NULL, 0);
					quic_fail(s, true);
				} else {
					req_respond_decoy(s, i);
				}
			}

			if(fin && !s->dead) {
				if(stream_id == s->stream_id) {
					logger(DEBUG_CONNECTIONS, LOG_INFO, "quic: %s (%s) ended the request stream", s->c->name, s->c->hostname);
					quic_fail(s, true);
				} else {
					req_respond_decoy(s, i);
				}
			}
		}
	}

	/* Return the flow-control credit for everything consumed, even if the
	   connection just died (ngtcp2 still owns the conn until the reaper
	   runs). */
	ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
	ngtcp2_conn_extend_max_offset(conn, datalen);
	return 0;
}

static int cb_acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id, uint64_t offset, uint64_t datalen,
                                       void *user_data, void *stream_user_data) {
	(void)conn;
	(void)stream_user_data;
	quic_session_t *s = user_data;
	uint64_t acked = offset + datalen;

	if(stream_id != s->stream_id) {
		return 0;       /* uni preambles are static; decoy answers live to session end */
	}

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
	/* The server's meta stream is the request whose body authenticates
	   (server_frame), not simply the first one a client opens. */
	(void)conn;
	(void)stream_id;
	(void)user_data;
	return 0;
}

static int cb_recv_datagram(ngtcp2_conn *conn, uint32_t flags, const uint8_t *data, size_t datalen, void *user_data) {
	(void)conn;
	(void)flags;
	quic_session_t *s = user_data;

	if(s->dead || !datalen || s->stream_id < 0) {
		return 0;
	}

	/* HTTP/3 datagram (RFC 9297): the quarter stream id of the request it
	   belongs to comes first. */
	uint64_t qsid;
	size_t n = h3_varint_get(data, datalen, &qsid);

	if(!n || qsid != (uint64_t)s->stream_id / 4 || n == datalen) {
		return 0;
	}

	data += n;
	datalen -= n;

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
	quic_session_t *s = user_data;
	s->stream_blocked = false;

	for(int i = 0; i < s->nuni; i++) {
		s->uni_blocked[i] = false;
	}

	for(int i = 0; i < s->nreq; i++) {
		s->req[i].blocked = false;
	}

	return 0;
}

static int cb_handshake_completed(ngtcp2_conn *conn, void *user_data) {
	(void)conn;
	quic_session_t *s = user_data;

	if(s->dead) {
		return 0;
	}

	/* Both ends open their control and QPACK streams first, as HTTP/3
	   endpoints do. A peer that allows no unidirectional streams is not an
	   HTTP/3 server -- nor a tinc node that speaks this carrier (the quic
	   carrier before 2026-09-23 was not HTTP/3): fall back. */
	if(!open_uni_streams(s)) {
		logger(DEBUG_CONNECTIONS, LOG_INFO, "quic: %s (%s) allows no HTTP/3 control stream", s->c->name, s->c->hostname);
		ngtcp2_ccerr_set_application_error(&s->ccerr, H3_GENERAL_PROTOCOL_ERROR, NULL, 0);
		quic_fail(s, true);
		return 0;
	}

	if(s->is_server) {
		return 0;
	}

	/* The server must have chosen our protocol (GnuTLS enforced this with
	   GNUTLS_ALPN_MANDATORY; OpenSSL completes a handshake without one). */
	if(!quic_tls_alpn_selected(&s->tls)) {
		logger(DEBUG_CONNECTIONS, LOG_INFO, "quic: %s (%s) chose no HTTP/3 ALPN", s->c->name, s->c->hostname);
		ngtcp2_ccerr_set_application_error(&s->ccerr, H3_NO_ERROR, NULL, 0);
		quic_fail(s, true);
		return 0;
	}

	/* Client: the tinc session is one HTTP/3 request. Open it, queue the
	   request HEADERS and the authenticator as the first DATA frame, then
	   drive the tinc handshake so the ID line is the next DATA frame. All
	   appends only -- the post-read flush sends them (we are in a
	   callback).

	   An unpinned certificate -- or one that replaced the pin (verify_pin) --
	   is NOT pinned here: a completed TLS handshake proves nothing about who
	   is on the other end, and pinning it now would let an attacker on path at
	   first contact lock this peer out for good (review M5-7, which was fixed
	   for https only). learn_pin() pins it once SPTPS has authenticated. */
	if(s->tls.have_peer_fp && (!s->tls.pin[0] || s->tls.repin)) {
		if(!s->tls.pin[0]) {
			logger(DEBUG_ALWAYS, LOG_NOTICE, "quic: no pinned TlsFingerprint for %s; will pin %s once SPTPS authenticates the peer",
			       s->c->name, s->tls.peer_fp_hex);
		}

		s->pin_pending = true;
	}

	int64_t sid;

	if(ngtcp2_conn_open_bidi_stream(conn, &sid, NULL)) {
		quic_fail(s, false);
		return 0;
	}

	s->stream_id = sid;

	size_t hlen;
	uint8_t *h = h3_request(s->authority, "/", &hlen);
	tx_append(s, h, hlen);
	free(h);

	uint8_t exporter[AUTHN_EXPORTER_LEN];
	uint8_t auth[AUTHN_MAX_LEN];
	size_t authlen;

	if(!quic_tls_exporter(&s->tls, exporter, sizeof(exporter)) ||
	                !(authlen = authn_build(s->tls.peer_fp, exporter, auth, sizeof(auth)))) {
		logger(DEBUG_CONNECTIONS, LOG_ERR, "quic: could not build the authenticator for %s", s->c->name);
		quic_fail(s, false);
		return 0;
	}

	tx_append_data(s, auth, authlen);

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

static void quic_settings(ngtcp2_settings *settings, ngtcp2_transport_params *params, bool server) {
	ngtcp2_settings_default(settings);
	settings->initial_ts = quic_now();
	settings->handshake_timeout = (ngtcp2_duration)pingtimeout * NGTCP2_SECONDS;

	/* What an HTTP/3 endpoint announces (testing/fingerprint: curl 8.14 and
	   Chromium 153 both allow 100 bidirectional and >= 100 unidirectional
	   streams). The client's parameters travel in the Initial, which anyone
	   can decrypt: "ALPN h3 but no unidirectional streams" was a one-field
	   rule. A server announces what nginx does: 3 unidirectional streams. */
	ngtcp2_transport_params_default(params);
	params->initial_max_streams_bidi = 100;
	params->initial_max_streams_uni = server ? 3 : 100;
	params->initial_max_stream_data_bidi_local = 512 * 1024;
	params->initial_max_stream_data_bidi_remote = 512 * 1024;
	params->initial_max_stream_data_uni = 512 * 1024;
	params->initial_max_data = 768 * 1024;
	params->max_datagram_frame_size = QUIC_DGRAM_FRAME_MAX;
	ngtcp2_duration idle = (ngtcp2_duration)(3 * pingtimeout);
	params->max_idle_timeout = (idle > QUIC_IDLE_MIN ? idle : QUIC_IDLE_MIN) * NGTCP2_SECONDS;
	/* Must exceed the default 2 or a second migration in one session fails with
	   ERR_CONNECTION_ID_LIMIT (stream-Q finding). The dialler writes curl's 2
	   on the wire (quic_dial); 8 is only what it accepts. */
	params->active_connection_id_limit = 8;

	if(!server) {
		/* The rest of curl's Initial (OpenSSL 3.5's QUIC client): it forbids
		   migration towards it, takes and sends packets of 1200 bytes at
		   most, and never probes for more. An observer who decrypts the
		   Initial -- anyone can -- would see a larger packet as a lie. */
		params->disable_active_migration = 1;
		params->max_udp_payload_size = QUIC_CURL_UDP_PAYLOAD;
		settings->max_tx_udp_payload_size = QUIC_CURL_UDP_PAYLOAD;
		settings->no_pmtud = 1;
	}
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

			/* ngtcp2 leaves a DATAGRAM that does not fit the packet unwritten,
			   for us to offer again -- for ever, if it never will fit (the
			   path shrank after it was queued): drop that one, or it blocks
			   everything behind it, the meta stream included. SPTPS copes. */
			if(accepted || s->dgram[s->dgram_head].len > dgram_room(s)) {
				s->dgram_head = (s->dgram_head + 1) % QUIC_DGRAM_QUEUE;
				s->dgram_n--;
			}

			if(nwrite == 0) {
				break;
			}
		} else {
			/* One stream per packet, in this order: our unidirectional
			   preambles, decoy answers, the meta stream; with none pending,
			   sid -1 lets ngtcp2 send ACKs and control frames. */
			ngtcp2_vec v = {NULL, 0};
			size_t cnt = 0;
			int64_t sid = -1;
			uint32_t wflags = 0;
			int uni = -1, req = -1;
			ngtcp2_ssize pdatalen = 0;

			for(int i = 0; i < s->nuni && sid < 0; i++) {
				size_t plen;
				const uint8_t *pre = h3_uni_preamble(uni_types[i], &plen);

				if(!s->uni_blocked[i] && s->uni_sent[i] < plen) {
					v.base = (uint8_t *)pre + s->uni_sent[i];
					v.len = plen - s->uni_sent[i];
					cnt = 1;
					sid = s->uni_id[i];
					uni = i;
				}
			}

			for(int i = 0; i < s->nreq && sid < 0; i++) {
				if(s->req[i].resp && !s->req[i].done && !s->req[i].blocked) {
					v.base = s->req[i].resp + s->req[i].resp_sent;
					v.len = s->req[i].resp_len - s->req[i].resp_sent;
					cnt = v.len ? 1 : 0;
					sid = s->req[i].id;
					wflags = NGTCP2_WRITE_STREAM_FLAG_FIN;
					req = i;
				}
			}

			if(sid < 0 && s->stream_id >= 0 && !s->stream_blocked && s->tx_sent < s->tx_base + s->tx_len) {
				size_t off = (size_t)(s->tx_sent - s->tx_base);
				v.base = s->tx + off;
				v.len = s->tx_len - off;
				cnt = 1;
				sid = s->stream_id;
			}

			nwrite = ngtcp2_conn_writev_stream(s->conn, &ps.path, &pi, buf, sizeof(buf), &pdatalen, wflags, sid, &v, cnt, ts);

			if(nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
				if(uni >= 0) {
					s->uni_blocked[uni] = true;
				} else if(req >= 0) {
					s->req[req].blocked = true;
				} else {
					s->stream_blocked = true;
				}

				continue;
			}

			if((nwrite == NGTCP2_ERR_STREAM_SHUT_WR || nwrite == NGTCP2_ERR_STREAM_NOT_FOUND) && req >= 0) {
				s->req[req].done = true;        /* the client gave up on that request */
				continue;
			}

			if(nwrite < 0) {
				ngtcp2_ccerr_set_liberr(&s->ccerr, (int)nwrite, NULL, 0);
				quic_fail(s, true);
				return;
			}

			if(pdatalen >= 0 && sid >= 0) {
				if(uni >= 0) {
					s->uni_sent[uni] += (size_t)pdatalen;
				} else if(req >= 0) {
					s->req[req].resp_sent += (size_t)pdatalen;

					/* All of it, FIN included, is in a packet. */
					if(s->req[req].resp_sent == s->req[req].resp_len && nwrite > 0) {
						s->req[req].done = true;
					}
				} else {
					s->tx_sent += (uint64_t)pdatalen;
				}
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
		(long)((delta % NGTCP2_SECONDS) / NGTCP2_MICROSECONDS)   /* tv_usec: suseconds_t, long on Windows */
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

static quic_session_t *new_session(connection_t *c, int fd, size_t sock, const sockaddr_t *peer, bool is_server) {
	quic_session_t *s = xzalloc(sizeof(*s));
	s->c = c;
	s->fd = fd;
	s->sock = sock;
	s->local = listen_socket[sock].sa;
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

	if(s->own_socket) {
		io_del(&s->own_io);
		closesocket(s->fd);
		s->own_socket = false;
	}

	if(s->conn) {
		ngtcp2_conn_del(s->conn);
		s->conn = NULL;
	}

	quic_tls_session_free(&s->tls);

	for(int i = 0; i < s->nreq; i++) {
		free(s->req[i].resp);
	}

	free(s->authority);
	free(s->tx);
	list_delete(&quic_sessions, s);
	free(s);
}

/* ---- inbound: accept and receive ----------------------------------------- */

static void quic_accept(listen_socket_t *ls, const uint8_t *buf, size_t len, const sockaddr_t *addr) {
	/* Admission control as an HTTP/3 server does it: a cap on concurrent
	   clients, not a per-second budget that leaves the eleventh Initial of a
	   burst unanswered (decoy.h). */
	if(decoy_front_full()) {
		logger(DEBUG_CONNECTIONS, LOG_WARNING, "quic: %d web clients already, dropping a new one", DECOY_MAX_WEB_CLIENTS);
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
	c->status.web_front = true;     /* an HTTP/3 server until a peer authenticates */

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
	quic_settings(&settings, &params, true);
	params.original_dcid = hd.dcid;
	params.original_dcid_present = 1;

	ngtcp2_cid scid = {.datalen = TRANSPORT_QUIC_CIDLEN};
	quic_tls_random(scid.data, scid.datalen);

	if(ngtcp2_crypto_generate_stateless_reset_token(params.stateless_reset_token, static_secret, sizeof(static_secret), &scid)) {
		free_session(s);
		free_connection(c);
		return;
	}

	params.stateless_reset_token_present = 1;

	ngtcp2_path path = {
		.local = {(ngtcp2_sockaddr *)&s->local.sa, SALEN(s->local.sa)},
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

	ngtcp2_conn_set_tls_native_handle(s->conn, quic_tls_native_handle(&s->tls));
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

/* Feed one datagram to an existing session and flush what it produced. */
static void session_read(quic_session_t *s, const uint8_t *buf, size_t len, const sockaddr_t *vaddr) {
	sockaddr_t addr = *vaddr;
	int rv;

	if(s->dead) {
		return;
	}

	/* The path's remote is the datagram's real source: a NAT rebind shows up
	   here as a new remote and ngtcp2 starts path validation on its own. */
	ngtcp2_path path = {
		.local = {(ngtcp2_sockaddr *)&s->local.sa, SALEN(s->local.sa)},
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

		return;
	}

	if(!s->dead) {
		quic_flush(s);
	}
}

/* Client sessions: one datagram from the session's own socket. Anything that
   is not a QUIC packet for our (empty) connection id -- a stray, or someone
   probing the ephemeral port -- is dropped; this socket never accepts a
   connection. */
static void quic_client_read(void *data, int flags) {
	(void)flags;
	quic_session_t *s = data;
	uint8_t buf[MAXSIZE];
	sockaddr_t addr;
	socklen_t addrlen = sizeof(addr);
	ssize_t len = recvfrom(s->fd, (void *)buf, sizeof(buf), 0, &addr.sa, &addrlen);

	if(len <= 0) {
		if(len < 0 && !sockwouldblock(sockerrno)) {
			logger(DEBUG_TRAFFIC, LOG_WARNING, "quic: receive on the socket for %s failed: %s", s->c->hostname, sockstrerror(sockerrno));
		}

		return;
	}

	sockaddrunmap(&addr);
	ngtcp2_version_cid vc;

	/* Our connection id is empty, so every packet for us carries an empty
	   destination connection id. */
	if(ngtcp2_pkt_decode_version_cid(&vc, buf, (size_t)len, 0) < 0 || vc.dcidlen) {
		return;
	}

	session_read(s, buf, (size_t)len, &addr);
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

	/* A client session reads its own ephemeral socket (quic_client_read);
	   its connection ids never arrive on a listening socket legitimately. */
	if(!s->own_socket) {
		session_read(s, buf, len, &addr);
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

	/* Destination port: the peer's host-record QuicPort (a node advertises
	   the one it listens on), else our own QuicPort if the operator set it
	   (a network-wide choice, propagated by invitations), else the peer's
	   tinc port as dialled. */
	sockaddr_t peer = c->address;
	int port = quic_port_option;
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

	/* Source socket: a fresh one on an ephemeral port, like every QUIC
	   client. Dialling from the listening socket put our tinc port (or 443)
	   in the source port of every packet, which no browser does
	   (testing/fingerprint, 2026-09-23). Same local address as the listener,
	   so BindToAddress still decides the interface. */
	sockaddr_t local = listen_socket[sock].sa;

	if(local.sa.sa_family == AF_INET) {
		local.in.sin_port = 0;
	} else if(local.sa.sa_family == AF_INET6) {
		local.in6.sin6_port = 0;
	}

	int fd = setup_vpn_in_socket(&local);

	if(fd < 0) {
		logger(DEBUG_CONNECTIONS, LOG_ERR, "quic: could not open a socket to dial %s", c->name);
		free(alpn);
		free(sni);
		return false;
	}

	socklen_t locallen = sizeof(local);

	if(getsockname(fd, &local.sa, &locallen) < 0) {
		logger(DEBUG_CONNECTIONS, LOG_ERR, "quic: getsockname failed dialling %s: %s", c->name, sockstrerror(sockerrno));
		closesocket(fd);
		free(alpn);
		free(sni);
		return false;
	}

	sockaddrunmap(&local);
	quic_session_t *s = new_session(c, fd, (size_t)sock, &peer, false);
	s->local = local;
	s->own_socket = true;
	io_add(&s->own_io, quic_client_read, s, fd, IO_READ);

	if(!quic_tls_session_init(&s->tls, false, get_conn, &s->tls, alpn ? alpn : QUIC_ALPN_DEFAULT, sni, pin)) {
		logger(DEBUG_CONNECTIONS, LOG_ERR, "quic: TLS init failed dialling %s", c->name);
		free(alpn);
		free(sni);
		free_session(s);
		return false;
	}

	free(alpn);

	/* :authority of the request: the name the TLS handshake presents, else
	   the address dialled, the way a browser writes it. */
	{
		char *host, *port;
		sockaddr2str(&s->peer, &host, &port);
		bool v6 = !sni && s->peer.sa.sa_family == AF_INET6;
		bool dflt = !strcmp(port, "443");
		xasprintf(&s->authority, "%s%s%s%s%s", v6 ? "[" : "", sni ? sni : host, v6 ? "]" : "",
		          dflt ? "" : ":", dflt ? "" : port);
		free(host);
		free(port);
		free(sni);
	}

	ngtcp2_callbacks cb;
	ngtcp2_settings settings;
	ngtcp2_transport_params params;
	quic_callbacks(&cb, false);
	quic_settings(&settings, &params, false);

	/* A zero-length source connection id, as curl and Chromium use: the
	   session has a socket of its own, so nothing needs to route by it (an
	   8-byte one was a field no reference client shares). */
	ngtcp2_cid dcid = {.datalen = NGTCP2_MIN_INITIAL_DCIDLEN}, scid = {.datalen = 0};
	quic_tls_random(dcid.data, dcid.datalen);

	ngtcp2_path path = {
		.local = {(ngtcp2_sockaddr *)&s->local.sa, SALEN(s->local.sa)},
		.remote = {(ngtcp2_sockaddr *)&s->peer.sa, SALEN(s->peer.sa)},
	};

	if(ngtcp2_conn_client_new(&s->conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1, &cb, &settings, &params, NULL, s)) {
		free_session(s);
		return false;
	}

	/* The transport parameters and the ClientHello's packing as curl's
	   OpenSSL QUIC client writes them (core/ngtcp2/tincstack-wire.patch). */
	ngtcp2_conn_set_openssl_client_wire(s->conn, QUIC_CURL_CID_LIMIT);

	ngtcp2_conn_set_tls_native_handle(s->conn, quic_tls_native_handle(&s->tls));

	c->status.connecting = false;
	connection_add(c);

	/* The address actually dialled: c->hostname still names the tinc port. */
	char *where = sockaddr2hostname(&s->peer);
	logger(DEBUG_CONNECTIONS, LOG_INFO, "Dialling %s (%s) via quic", c->name, where);
	free(where);

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
		tx_append_data(s, c->outbuf.data + c->outbuf.offset, avail);
		buffer_read(&c->outbuf, avail);
	}

	if(!s->reading) {
		quic_flush(s);
	}

	return true;
}

/* The largest DATAGRAM payload a packet on the current path takes. The
   path's limit, not the configured one: a peer announcing
   max_udp_payload_size 1200 (every dialler since 2026-09-24, as curl does)
   caps it there, and so does a path whose MTU is not yet probed. */
static size_t dgram_room(quic_session_t *s) {
	size_t max = ngtcp2_conn_get_path_max_tx_udp_payload_size(s->conn);
	return max > QUIC_DGRAM_OVERHEAD ? max - QUIC_DGRAM_OVERHEAD : 0;
}

bool quic_send_datagram(connection_t *c, const void *buf, size_t len, size_t *excess) {
	quic_session_t *s = c->transport_data;

	if(!s || s->dead || !s->conn) {
		return false;
	}

	if(s->stream_id < 0) {
		return false;
	}

	/* HTTP/3 datagram: the request's quarter stream id, then the record. */
	uint8_t qsid[8];
	size_t qlen = h3_varint_put(qsid, (uint64_t)s->stream_id / 4);
	size_t room = dgram_room(s);

	if(room > QUIC_MAX_DGRAM) {
		room = QUIC_MAX_DGRAM;
	}

	if(len + qlen > room) {
		*excess = len + qlen - room;
		return false; /* caller treats it like EMSGSIZE -> reduce_mtu */
	}

	if(s->dgram_n == QUIC_DGRAM_QUEUE) {
		return true; /* queue full: drop, SPTPS recovers */
	}

	size_t i = (s->dgram_head + s->dgram_n) % QUIC_DGRAM_QUEUE;
	memcpy(s->dgram[i].data, qsid, qlen);
	memcpy(s->dgram[i].data + qlen, buf, len);
	s->dgram[i].len = qlen + len;
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
			ngtcp2_ccerr_set_application_error(&s->ccerr, H3_NO_ERROR, NULL, 0);
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
	return getsockname(s->fd, &sa->sa, &salen) >= 0;
}

/* ---- init / exit --------------------------------------------------------- */

/* A QuicPort listener: QUIC only. Anything quic_udp_try() does not claim is
   dropped, as a QUIC server drops what it cannot parse -- the tinc port's
   SPTPS and obfs handling never answer on the front port. */
static void quic_listen_read(void *data, int flags) {
	(void)flags;
	listen_socket_t *ls = data;
	uint8_t buf[MAXSIZE];
	sockaddr_t addr;
	socklen_t addrlen = sizeof(addr);
	ssize_t len = recvfrom(ls->udp.fd, (void *)buf, sizeof(buf), 0, &addr.sa, &addrlen);

	if(len <= 0) {
		if(len < 0 && !sockwouldblock(sockerrno)) {
			logger(DEBUG_TRAFFIC, LOG_WARNING, "quic: receive on the QuicPort socket failed: %s", sockstrerror(sockerrno));
		}

		return;
	}

	quic_udp_try(ls, buf, (size_t)len, &addr);
}

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
		logger(DEBUG_ALWAYS, LOG_ERR, "quic carrier: TLS (OpenSSL) init failed");
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
		quic_tls_random(static_secret, sizeof(static_secret));
		transport_set_quic_cid_matcher(quic_cid_match);
		quic_ready = true;

		/* QuicPort: an extra UDP listener per address family -- 443 by
		   default on a node that accepts inbound connections
		   (transport_front_port), because QUIC on tinc's port 655 needs no
		   fingerprinting to be spotted (testing/fingerprint, 2026-09-23).
		   It takes QUIC only (quic_listen_read); plain and obfs stay on the
		   tinc port. Only when it differs from the tinc port; otherwise the
		   shared socket is the QUIC socket. */
		quic_port = transport_front_port("QuicPort", &quic_port_configured);
		quic_port_option = quic_port_configured ? quic_port : 0;

		if(quic_port && quic_port != atoi(myport.udp)) {
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

				int fd = setup_udp_socket(&sa, false);

				if(fd < 0) {
					logger(DEBUG_ALWAYS, LOG_WARNING, "quic: could not listen on UDP port %d%s; peers reach the quic front on the tinc port %s, "
					       "where it is easy to spot. Grant the port (root, CAP_NET_BIND_SERVICE) or set QuicPort", quic_port,
					       quic_port_configured ? "" : " (the default)", myport.udp);
					continue;
				}

				listen_socket_t *ls = &quic_listen[quic_listens++];
				ls->sa = sa;
				ls->tcp.fd = -1;
				io_add(&ls->udp, quic_listen_read, ls, fd, IO_READ);
				char *h = sockaddr2hostname(&sa);
				logger(DEBUG_ALWAYS, LOG_INFO, "quic: listening on %s (QuicPort)", h);
				free(h);
			}
		} else {
			quic_port = 0;
		}

		if(!quic_listens) {
			quic_port = 0;
		}

		transport_advertise_port("QuicPort", quic_port);
		logger(DEBUG_ALWAYS, LOG_INFO, "QUIC carrier ready (ngtcp2 %s, %s)%s", ngtcp2_version(0)->version_str,
		       OpenSSL_version(OPENSSL_VERSION), quic_port ? "" : ", on the tinc port");
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
