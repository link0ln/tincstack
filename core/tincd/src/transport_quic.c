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
    the same bytes the https carrier uses) in a cookie of its request's
    HEADERS; the acceptor verifies it before a single byte reaches
    receive_meta_bytes(). Any other request gets the decoy, as from a web
    server, and a dialler that gets one falls back to the next carrier (M4).
    Design: docs/transports.md §9.

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
#include "quic_txq.h"
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
#define QUIC_UNI_STREAMS 3              /* control, QPACK encoder, QPACK decoder */
#define QUIC_PEER_UNI 3                 /* the peer's: our initial_max_streams_uni (server) */
#define QUIC_REQ_SLOTS 8                /* request streams a server answers per connection */
#define QUIC_OK_HDR_CAP 64              /* client: the listener's response HEADERS, kept to check */
#define QUIC_DGRAM_FRAME_MAX 65536      /* max_datagram_frame_size we accept */
#define QUIC_TX_VECS 4                  /* send queue pieces offered per packet */
#define QUIC_CURL_UDP_PAYLOAD 1200      /* curl's max_udp_payload_size, and all it ever sends */
#define QUIC_CURL_CID_LIMIT 2           /* curl's active_connection_id_limit */
/* What a DATAGRAM costs in a 1-RTT packet besides its payload: header byte,
   destination connection id (TRANSPORT_QUIC_CIDLEN; the dialler's is empty),
   4-byte packet number, frame type, 2-byte length, AEAD tag -- with slack. */
#define QUIC_DGRAM_OVERHEAD (1 + TRANSPORT_QUIC_CIDLEN + 4 + 1 + 2 + 16 + 3)
#define QUIC_IDLE_MIN 30                /* s; what curl and Chromium announce */
#define QUIC_NGINX_IDLE 75              /* s; nginx's max_idle_timeout */
#define QUIC_KEEPALIVE 15               /* s; Chromium's PING while a request is open */

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

	/* Our unidirectional streams: control + SETTINGS, and the QPACK
	   streams (the dialler: encoder and decoder; the listener, as nginx:
	   decoder only). Only the listener's decoder stream grows (Section
	   Acknowledgment, Insert Count Increment, Stream Cancellation), and
	   any HTTP/3 client can make it grow: its bytes, like the meta
	   stream's, live in a quic_txq_t, where they never move while ngtcp2
	   may retransmit them. */
	int64_t uni_id[QUIC_UNI_STREAMS];
	uint64_t uni_type[QUIC_UNI_STREAMS];
	quic_txq_t uni_tx[QUIC_UNI_STREAMS];
	bool uni_blocked[QUIC_UNI_STREAMS];
	int nuni;

	/* The peer's unidirectional streams, by type once its first bytes have
	   come. The listener reads a client's QPACK encoder stream into its
	   dynamic table; everything else on them is consumed unread. */
	struct {
		int64_t id;
		uint8_t type_buf[8];
		size_t type_len;
		bool typed;
		uint64_t type;
	} peer_uni[QUIC_PEER_UNI];
	int npeer_uni;
	h3_qpack_t *qpack;              /* server: the client's dynamic table */
	int nblocked;                   /* server: requests waiting for it */

	/* Server: request streams that are not (yet) the tinc session. Each gets
	   an HTTP/3 answer -- the decoy -- like any web server would give. */
	struct quic_req {
		int64_t id;
		struct quic_session_t *owner;   /* for the upstream's callback */
		decoy_fetch_t *fetch;   /* HttpsDecoyUpstream: the answer on its way */
		h3_parser_t rx;
		uint8_t *hdr;           /* the request's HEADERS payload, until decoded */
		size_t hdr_len;
		h3_req_fields_t *fields;        /* decoded; NULL if not (yet) */
		bool hdr_seen, hdr_bad;
		bool hdr_blocked;       /* HEADERS whole, waiting for the dynamic table */
		bool respond_pending;   /* answer as soon as they are decoded */
		uint8_t *resp;          /* HEADERS + DATA; one allocation, never moved,
		                           kept until the session ends */
		size_t resp_len, resp_sent;
		bool responded, blocked, done;
	} req[QUIC_REQ_SLOTS];
	int nreq;

	/* The meta stream's send queue: bytes stay where they are until
	   acked_stream_data_offset covers them (quic_txq.h). Until 2026-09-26
	   this was a ring that realloc()ed on growth and memmove()d on every
	   acknowledgment, under ngtcp2's retransmission pointers: with packet
	   loss a retransmission carried shifted or freed bytes, and the link
	   died (testing/transports/quic-loss-test.sh). */
	quic_txq_t tx;
	bool stream_blocked;

	/* Data TX queue (DATAGRAM frames). ngtcp2 copies on accept, small ring. */
	struct {
		uint8_t data[QUIC_MAX_DGRAM];
		size_t len;
	} dgram[QUIC_DGRAM_QUEUE];
	size_t dgram_head, dgram_n;
	uint64_t dgram_id;

	/* Server-side authenticator gate: the one a request's cookie carried,
	   and how much of the copy that opens the dialler's body has gone by. */
	bool is_server;
	bool authenticated;
	uint8_t authbuf[AUTHN_MAX_LEN];
	size_t authlen;
	size_t auth_skip;

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

/* The CONNECTION_CLOSE for a failed TLS handshake. The listener's carries
   nginx's reason phrase: in an Initial packet, anyone can read it. */
static void set_tls_alert(quic_session_t *s) {
	static const char reason[] = "handshake failed";

	if(s->is_server) {
		ngtcp2_ccerr_set_tls_alert(&s->ccerr, ngtcp2_conn_get_tls_alert(s->conn), (const uint8_t *)reason, sizeof(reason) - 1);
	} else {
		ngtcp2_ccerr_set_tls_alert(&s->ccerr, ngtcp2_conn_get_tls_alert(s->conn), NULL, 0);
	}
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

/* The dialler's, as curl's; the listener's, as nginx's (no encoder stream:
   it never uses a dynamic table of its own). */
static const uint64_t uni_types_client[] = {H3_STREAM_CONTROL, H3_STREAM_QPACK_ENCODER, H3_STREAM_QPACK_DECODER};
static const uint64_t uni_types_server[] = {H3_STREAM_CONTROL, H3_STREAM_QPACK_DECODER};

static bool stream_is_uni(int64_t id) {
	return id & 0x2;
}

/* Append raw bytes to the meta stream's send queue. */
static void tx_append(quic_session_t *s, const void *data, size_t len) {
	quic_txq_append(&s->tx, data, len);
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
	const uint64_t *types = s->is_server ? uni_types_server : uni_types_client;
	int n = s->is_server ? (int)(sizeof(uni_types_server) / sizeof(uni_types_server[0]))
	        : (int)(sizeof(uni_types_client) / sizeof(uni_types_client[0]));

	for(int i = 0; i < n; i++) {
		if(ngtcp2_conn_open_uni_stream(s->conn, &s->uni_id[i], NULL)) {
			return false;
		}

		size_t plen;
		const uint8_t *pre = h3_uni_preamble(types[i], s->is_server, &plen);
		s->uni_type[i] = types[i];
		quic_txq_append(&s->uni_tx[i], pre, plen);
		s->nuni = i + 1;
	}

	return true;
}

/* Server: queue a QPACK decoder instruction on our decoder stream. */
static void decoder_append(quic_session_t *s, const uint8_t *data, size_t len) {
	for(int i = 0; i < s->nuni; i++) {
		if(s->uni_type[i] == H3_STREAM_QPACK_DECODER) {
			quic_txq_append(&s->uni_tx[i], data, len);
			return;
		}
	}
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
static bool field_ok(const char *v, bool token) {
	if(!*v) {
		return false;
	}

	for(; *v; v++) {
		unsigned char c = (unsigned char) * v;

		if(token ? !(c >= 'A' && c <= 'Z') : (c <= 0x20 || c >= 0x7f)) {
			return false;
		}
	}

	return true;
}

/* The request as the decoy's HTTP/1.1 parser takes it: the stream's real
   method, path and authority, so a path that does not exist gets 404, a
   method other than GET or HEAD 405, and HEAD no body -- nginx's answers --
   and, since 2026-09-26, every other field of the request, so conditional
   requests, Range and Accept-Encoding are answered as over TCP, and an
   upstream (HttpsDecoyUpstream) is sent what the client sent. A request
   whose fields were not decoded, or that no HTTP/1.1 parser would accept,
   becomes a request line it rejects: 400. */
static char *req_as_http1(const h3_req_fields_t *f) {
	char *r = NULL;
	const char *host = f && *f->authority ? f->authority : f && *f->host ? f->host : "localhost";

	if(f && field_ok(f->method, true) && field_ok(f->path, false) && field_ok(host, false)) {
		xasprintf(&r, "%s %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", f->method, f->path, host, f->headers);
	} else {
		r = xstrdup("\r\n\r\n");
	}

	return r;
}

static void req_decoy_fetched(void *data, char *resp, size_t len) {
	struct quic_req *q = data;
	quic_session_t *s = q->owner;
	q->fetch = NULL;
	q->resp = h3_from_http1(resp, len, &q->resp_len);
	free(resp);

	if(!q->resp) {
		q->done = true;
		ngtcp2_conn_shutdown_stream(s->conn, 0, q->id, H3_REQUEST_REJECTED);
	}

	quic_flush(s);
}

static void req_respond_decoy(quic_session_t *s, int i) {
	if(s->req[i].responded) {
		return;
	}

	if(s->req[i].hdr_blocked) {
		s->req[i].respond_pending = true;       /* once its HEADERS decode */
		return;
	}

	char *request = req_as_http1(s->req[i].fields);
	size_t rl;
	s->req[i].responded = true;

	/* With HttpsDecoyUpstream the upstream answers, as through the TCP
	   front (nginx proxies HTTP/3 requests like any other). */
	decoy_origin_t at = {.tls = true, .h3 = true, .port = quic_port ? quic_port : 443};
	s->req[i].owner = s;
	s->req[i].fetch = decoy_fetch_start(request, strlen(request), &at, req_decoy_fetched, &s->req[i]);

	if(s->req[i].fetch) {
		free(request);
		return;
	}

	char *r = decoy_respond(request, strlen(request), &at, &rl);
	free(request);
	s->req[i].resp = h3_from_http1(r, rl, &s->req[i].resp_len);
	free(r);

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

/* Server: a POST whose cookie carries a valid authenticator (§8.3, the
   dialler's) -- the value of any of its cookie pairs, base64url. Only the
   first value shaped like one is checked, so a request stuffed with cookies
   costs one verification. Returns true and sets up the session on success;
   the request is then the meta stream. */
static bool req_token(quic_session_t *s, int i) {
	const h3_req_fields_t *f = s->req[i].fields;
	const char *p = f->cookie;

	while(*p) {
		const char *end = strchr(p, ';');
		size_t plen = end ? (size_t)(end - p) : strlen(p);
		const char *eq = memchr(p, '=', plen);

		if(eq) {
			const char *v = eq + 1;
			size_t vlen = plen - (size_t)(v - p);
			char b64[B64_SIZE(AUTHN_MAX_LEN)];
			uint8_t payload[AUTHN_MAX_LEN + 3];

			if(vlen && vlen < sizeof(b64)) {
				memcpy(b64, v, vlen);
				b64[vlen] = 0;
				size_t n = b64decode_tinc(b64, payload, vlen);
				size_t expected = n ? authn_expected_len(payload, n) : 0;

				if(expected && expected != (size_t) -1 && expected == n) {
					uint8_t exporter[AUTHN_EXPORTER_LEN];
					char *name = NULL;

					if(!quic_tls_exporter(&s->tls, exporter, sizeof(exporter)) ||
					                !authn_verify(payload, n, tls_own_fp, exporter, "quic", s->c->hostname, &name)) {
						logger(DEBUG_CONNECTIONS, LOG_INFO, "quic: authenticator from %s rejected", s->c->hostname);
						return false;
					}

					memcpy(s->authbuf, payload, n);
					s->authlen = n;
					free(s->c->name);
					s->c->name = name;
					s->authenticated = true;
					logger(DEBUG_CONNECTIONS, LOG_NOTICE, "quic: authenticated peer %s (%s) by its request headers", s->c->name, s->c->hostname);
					return true;
				}
			}
		}

		if(!end) {
			break;
		}

		for(p = end + 1; *p == ' '; p++) {
		}
	}

	return false;
}

/* Server: the authenticated request becomes the meta stream; its answer is
   the listener's 200, then the datagram mark. */
static void req_become_meta(quic_session_t *s, int i) {
	s->stream_id = s->req[i].id;
	s->req[i].done = true;  /* its answer is the meta stream's send queue */
	s->req[i].responded = true;

	size_t hlen;
	uint8_t *h = h3_response_ok(&hlen);
	tx_append(s, h, hlen);
	free(h);

	/* A current dialler takes DATAGRAM frames without announcing it (its
	   Initial is curl's, and curl has none): allow them to it, and tell it
	   we know, with a frame only an authenticated peer ever sees. */
	const ngtcp2_transport_params *rp = ngtcp2_conn_get_remote_transport_params(s->conn);

	if(rp && !rp->max_datagram_frame_size) {
		ngtcp2_conn_set_remote_max_datagram_frame_size(s->conn, QUIC_DGRAM_FRAME_MAX);
	}

	uint8_t mark[16];
	size_t mlen = h3_varint_put(mark, H3_FRAME_TINC_DGRAM);
	mlen += h3_varint_put(mark + mlen, 0);
	tx_append(s, mark, mlen);
}

/* Server: decode slot i's whole HEADERS with the client's dynamic table.
   A section that needs entries not here yet waits (up to the 128 blocked
   streams our SETTINGS allow, as nginx); one that references the table is
   acknowledged on our decoder stream. */
static void req_decode(quic_session_t *s, int i) {
	h3_req_fields_t *f = xzalloc(sizeof(*f));
	uint64_t ric = 0;
	h3_decode_t r = s->req[i].hdr_bad ? H3_DECODE_ERROR :
	                h3_decode_request(s->qpack, s->req[i].hdr, s->req[i].hdr_len, f, &ric);

	if(r == H3_DECODE_BLOCKED) {
		free(f);

		if(!s->req[i].hdr_blocked) {
			if(s->nblocked == H3_QPACK_BLOCKED_STREAMS) {
				ngtcp2_ccerr_set_application_error(&s->ccerr, H3_QPACK_DECOMPRESSION_FAILED, NULL, 0);
				quic_fail(s, true);
				return;
			}

			s->req[i].hdr_blocked = true;
			s->nblocked++;
		}

		return;
	}

	if(s->req[i].hdr_blocked) {
		s->req[i].hdr_blocked = false;
		s->nblocked--;
	}

	if(r == H3_DECODE_OK) {
		s->req[i].fields = f;

		if(ric) {
			uint8_t ack[16];
			decoder_append(s, ack, h3_qpack_section_ack(s->qpack, ric, s->req[i].id, ack));
		}
	} else {
		free(f);
	}

	free(s->req[i].hdr);
	s->req[i].hdr = NULL;
	s->req[i].hdr_len = 0;

	/* The request is decided on its HEADERS, as nginx decides it: a POST
	   whose cookie authenticates a tinc dialler is the tinc session; every
	   other request -- a POST without one included, body or not -- gets
	   the web server's answer now (405 for a POST, as nginx's to a static
	   file). Until 2026-09-26 the authenticator was the body's first
	   bytes, and a POST was answered only once they had come: nginx
	   answers before, and a POST without a body not at all (stream F,
	   testing/fingerprint/post405-timing.sh). */
	if(s->req[i].fields && s->stream_id < 0 && !strcmp(s->req[i].fields->method, "POST") && req_token(s, i)) {
		req_become_meta(s, i);
		return;
	}

	req_respond_decoy(s, i);
}

/* Server: requests blocked on the dynamic table, after it grew. */
static void req_unblock(quic_session_t *s) {
	for(int i = 0; i < s->nreq && s->nblocked && !s->dead; i++) {
		if(s->req[i].hdr_blocked) {
			req_decode(s, i);
		}
	}
}

/* Server: a piece of a request stream's first HEADERS frame. Once it is
   whole, the request is decoded, and anything but a POST -- the only method
   a tinc dialler uses -- is answered at once, as nginx answers it without
   waiting for a body. A POST waits for its authenticator; if it fails, the
   answer is nginx's to a POST of a static file: 405. */
#define QUIC_REQ_HDR_CAP 16384

static void server_headers(quic_session_t *s, int i, const uint8_t *payload, size_t len) {
	bool end = len == s->req[i].rx.remain;

	if(s->req[i].hdr_seen || s->req[i].responded) {
		return;         /* trailers, or a request already answered */
	}

	if(!s->req[i].hdr_bad) {
		if(s->req[i].hdr_len + len > QUIC_REQ_HDR_CAP) {
			s->req[i].hdr_bad = true;
		} else if(len) {
			s->req[i].hdr = xrealloc(s->req[i].hdr, s->req[i].hdr_len + len);
			memcpy(s->req[i].hdr + s->req[i].hdr_len, payload, len);
			s->req[i].hdr_len += len;
		}
	}

	if(!end) {
		return;
	}

	s->req[i].hdr_seen = true;
	req_decode(s, i);
}

static bool server_frame(void *data, uint64_t type, const uint8_t *payload, size_t len) {
	rx_ctx_t *x = data;
	quic_session_t *s = x->s;

	if(s->dead) {
		return false;
	}

	if(type == H3_FRAME_HEADERS && x->id != s->stream_id) {
		server_headers(s, x->slot, payload, len);
		return true;
	}

	if(type != H3_FRAME_DATA || !len || x->id != s->stream_id) {
		/* SETTINGS-like or reserved frames (the dialler's datagram mark),
		   and bodies of requests answered as a web server: nothing we
		   need. */
		return true;
	}

	/* The dialler's body opens with the authenticator its cookie carried,
	   for a listener from before 2026-09-26, which reads it there: skip
	   that copy. A dialler that sends none starts with its ID line, whose
	   first byte is never an authenticator's. */
	if(s->auth_skip < s->authlen) {
		if(!s->auth_skip && payload[0] != s->authbuf[0]) {
			s->auth_skip = s->authlen;
		} else {
			size_t n = s->authlen - s->auth_skip < len ? s->authlen - s->auth_skip : len;

			if(memcmp(payload, s->authbuf + s->auth_skip, n)) {
				logger(DEBUG_CONNECTIONS, LOG_INFO, "quic: %s (%s) sent a body that does not start with its authenticator",
				       s->c->name, s->c->hostname);
				return false;
			}

			s->auth_skip += n;
			payload += n;
			len -= n;
		}
	}

	return deliver_meta(s, payload, len);
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
		/* The listener takes DATAGRAM frames from us. Since 2026-09-25 its
		   transport parameters do not say so (nginx's have no
		   max_datagram_frame_size); this frame, which only an authenticated
		   peer sees, does. */
		s->dgram_marked = true;
		const ngtcp2_transport_params *rp = ngtcp2_conn_get_remote_transport_params(s->conn);

		if(rp && !rp->max_datagram_frame_size) {
			ngtcp2_conn_set_remote_max_datagram_frame_size(s->conn, QUIC_DGRAM_FRAME_MAX);
		}

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

/* Server: bytes of one of the client's unidirectional streams. Its type
   comes first; an encoder stream feeds the dynamic table, and requests
   waiting for it are decoded as soon as they can be. */
static void peer_uni_data(quic_session_t *s, int64_t id, const uint8_t *data, size_t len) {
	int k;

	for(k = 0; k < s->npeer_uni && s->peer_uni[k].id != id; k++) {
	}

	if(k == s->npeer_uni) {
		if(k == QUIC_PEER_UNI) {
			return;         /* ngtcp2 enforces our stream limit; not reached */
		}

		memset(&s->peer_uni[k], 0, sizeof(s->peer_uni[k]));
		s->peer_uni[k].id = id;
		s->npeer_uni++;
	}

	while(len && !s->peer_uni[k].typed) {
		if(s->peer_uni[k].type_len == sizeof(s->peer_uni[k].type_buf)) {
			return;
		}

		s->peer_uni[k].type_buf[s->peer_uni[k].type_len++] = *data++;
		len--;

		if(h3_varint_get(s->peer_uni[k].type_buf, s->peer_uni[k].type_len, &s->peer_uni[k].type)) {
			s->peer_uni[k].typed = true;
		}
	}

	if(!len || s->peer_uni[k].type != H3_STREAM_QPACK_ENCODER || !s->qpack) {
		return;
	}

	if(!h3_qpack_encoder_data(s->qpack, data, len)) {
		ngtcp2_ccerr_set_application_error(&s->ccerr, H3_QPACK_ENCODER_STREAM_ERROR, NULL, 0);
		quic_fail(s, true);
		return;
	}

	req_unblock(s);
}

static int cb_recv_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t offset,
                               const uint8_t *data, size_t datalen, void *user_data, void *stream_user_data) {
	(void)stream_user_data;
	quic_session_t *s = user_data;
	bool fin = flags & NGTCP2_STREAM_DATA_FLAG_FIN;

	if(s->dead) {
		return 0;
	}

	if(stream_is_uni(stream_id)) {
		/* The peer's control and QPACK streams: SETTINGS we accept as they
		   are; the dialler announces no dynamic table, so only the
		   listener reads a client's encoder stream. Consumed and
		   credited. */
		if(s->is_server) {
			peer_uni_data(s, stream_id, data, datalen);
		}
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
			/* nginx tells the encoder when it drops an unread stream. */
			if(!offset) {
				uint8_t cancel[16];
				decoder_append(s, cancel, h3_qpack_stream_cancel(stream_id, cancel));
			}

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

	if(stream_id == s->stream_id) {
		quic_txq_ack(&s->tx, acked);
		return 0;
	}

	for(int i = 0; i < s->nuni; i++) {
		if(s->uni_id[i] == stream_id) {
			quic_txq_ack(&s->uni_tx[i], acked);
			return 0;
		}
	}

	return 0;       /* a decoy answer: one allocation, freed with the session */
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
	   request HEADERS -- the authenticator in a cookie -- and the
	   authenticator again as the first DATA frame, then drive the tinc
	   handshake so the ID line is the next DATA frame. All appends only --
	   the post-read flush sends them (we are in a callback).

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

	uint8_t exporter[AUTHN_EXPORTER_LEN];
	uint8_t auth[AUTHN_MAX_LEN];
	size_t authlen;

	if(!quic_tls_exporter(&s->tls, exporter, sizeof(exporter)) ||
	                !(authlen = authn_build(s->tls.peer_fp, exporter, auth, sizeof(auth)))) {
		logger(DEBUG_CONNECTIONS, LOG_ERR, "quic: could not build the authenticator for %s", s->c->name);
		quic_fail(s, false);
		return 0;
	}

	/* The authenticator rides a session cookie, as the https carrier's
	   does, so that the listener decides on the request's HEADERS, as
	   nginx does (docs/transports.md §9.4). Bound to this connection's
	   exporter, it is worth nothing outside it; only the TLS peer sees
	   it. */
	char cookie[4 + B64_SIZE(AUTHN_MAX_LEN)] = "sid=";
	b64encode_tinc_urlsafe(auth, cookie + 4, authlen);

	size_t hlen;
	uint8_t *h = h3_request(s->authority, "/", cookie, &hlen);
	tx_append(s, h, hlen);
	free(h);

	/* "Send me datagrams without my announcing them; I send you mine
	   without yours": see H3_FRAME_TINC_DGRAM. A web server ignores it. */
	uint8_t mark[16];
	size_t mlen = h3_varint_put(mark, H3_FRAME_TINC_DGRAM);
	mlen += h3_varint_put(mark + mlen, 0);
	tx_append(s, mark, mlen);

	/* The same authenticator opens the body, where a listener from before
	   2026-09-26 reads it; a current one skips it. */
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

	if(server) {
		/* nginx 1.26's transport parameters (quic-listener-wire-test.sh);
		   ngtcp2_conn_set_nginx_server_wire writes them in its order, and
		   leaves max_datagram_frame_size out: the dialler learns from
		   H3_FRAME_TINC_DGRAM that we take datagrams. The windows are
		   starting values; ngtcp2 grows them as data flows. The idle
		   timeout is nginx's 75 s unless tinc's PingTimeout asks for
		   more. */
		params->initial_max_data = 8585216;
		params->initial_max_streams_uni = 3;
		params->initial_max_streams_bidi = 128;
		params->initial_max_stream_data_bidi_local = 65536;
		params->initial_max_stream_data_bidi_remote = 65536;
		params->initial_max_stream_data_uni = 65536;
		params->max_idle_timeout = (idle > QUIC_NGINX_IDLE ? idle : QUIC_NGINX_IDLE) * NGTCP2_SECONDS;
		params->max_udp_payload_size = NGTCP2_DEFAULT_MAX_RECV_UDP_PAYLOAD_SIZE;
		/* How many ids the client may give us: ours has an empty source
		   id and gives none, so 2 cannot bite (the 8 above is for the
		   dialler, which does take new ids from the listener). */
		params->active_connection_id_limit = 2;
		params->max_ack_delay = NGTCP2_DEFAULT_MAX_ACK_DELAY;
		params->ack_delay_exponent = NGTCP2_DEFAULT_ACK_DELAY_EXPONENT;
	} else {
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

/* A stream's pending bytes as ngtcp2 takes them: pointers into the send
   queue, which stay valid until the peer acknowledges them. */
static size_t tx_vecs(quic_txq_t *q, ngtcp2_vec *v, size_t max) {
	quic_txq_vec_t qv[QUIC_TX_VECS];
	size_t n = quic_txq_pending(q, qv, QUIC_TX_VECS, max);

	for(size_t i = 0; i < n; i++) {
		v[i].base = qv[i].base;
		v[i].len = qv[i].len;
	}

	return n;
}

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
			   sid -1 lets ngtcp2 send ACKs and control frames. The
			   listener, as nginx, packs its unidirectional streams into
			   one packet (the one with the session tickets), the stream
			   type in a STREAM frame of its own. */
			ngtcp2_vec v[QUIC_TX_VECS] = {{NULL, 0}};
			size_t cnt = 0;
			int64_t sid = -1;
			uint32_t wflags = 0;
			int uni = -1, req = -1;
			ngtcp2_ssize pdatalen = 0;

			for(int i = 0; i < s->nuni && sid < 0; i++) {
				if(!s->uni_blocked[i] && quic_txq_unsent(&s->uni_tx[i])) {
					size_t max = SIZE_MAX;
					sid = s->uni_id[i];
					uni = i;

					if(s->is_server) {
						uint8_t tb[8];
						size_t tlen = h3_varint_put(tb, s->uni_type[i]);

						if(s->uni_tx[i].sent < tlen) {
							max = tlen - (size_t)s->uni_tx[i].sent;
						}

						wflags = NGTCP2_WRITE_STREAM_FLAG_MORE;
					}

					cnt = tx_vecs(&s->uni_tx[i], v, max);
				}
			}

			for(int i = 0; i < s->nreq && sid < 0; i++) {
				if(s->req[i].resp && !s->req[i].done && !s->req[i].blocked) {
					v[0].base = s->req[i].resp + s->req[i].resp_sent;
					v[0].len = s->req[i].resp_len - s->req[i].resp_sent;
					cnt = v[0].len ? 1 : 0;
					sid = s->req[i].id;
					wflags = NGTCP2_WRITE_STREAM_FLAG_FIN;
					req = i;
				}
			}

			if(sid < 0 && s->stream_id >= 0 && !s->stream_blocked && quic_txq_unsent(&s->tx)) {
				cnt = tx_vecs(&s->tx, v, SIZE_MAX);
				sid = s->stream_id;
			}

			nwrite = ngtcp2_conn_writev_stream(s->conn, &ps.path, &pi, buf, sizeof(buf), &pdatalen, wflags, sid, v, cnt, ts);

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

			/* The packet has room for more: the next stream goes in too. */
			if(nwrite == NGTCP2_ERR_WRITE_MORE) {
				if(uni >= 0 && pdatalen > 0) {
					quic_txq_sent(&s->uni_tx[uni], (size_t)pdatalen);
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
					quic_txq_sent(&s->uni_tx[uni], (size_t)pdatalen);
				} else if(req >= 0) {
					s->req[req].resp_sent += (size_t)pdatalen;

					/* All of it, FIN included, is in a packet. */
					if(s->req[req].resp_sent == s->req[req].resp_len && nwrite > 0) {
						s->req[req].done = true;
					}
				} else {
					quic_txq_sent(&s->tx, (size_t)pdatalen);
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
		decoy_fetch_cancel(s->req[i].fetch);
		free(s->req[i].resp);
		free(s->req[i].hdr);
		free(s->req[i].fields);
	}

	for(int i = 0; i < s->nuni; i++) {
		quic_txq_free(&s->uni_tx[i]);
	}

	h3_qpack_free(s->qpack);

	free(s->authority);
	quic_txq_free(&s->tx);
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

	/* The handshake as nginx writes it: minimal Length fields, a CRYPTO
	   frame per TLS message, nothing in 1-RTT before it completes. */
	ngtcp2_conn_set_nginx_server_wire(s->conn);
	s->qpack = h3_qpack_new(H3_QPACK_CAPACITY);

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
			set_tls_alert(s);
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
			set_tls_alert(s);
			logger(DEBUG_CONNECTIONS, LOG_DEBUG, "quic: TLS alert from %s", s->c->hostname);
			quic_fail(s, true);
		} else {
			ngtcp2_ccerr_set_liberr(&s->ccerr, rv, NULL, 0);
			quic_fail(s, true);
		}

		return;
	}

	/* What the encoder stream inserted and no Section Acknowledgment has
	   covered, told once per datagram (nginx: once per read event). */
	if(!s->dead && s->qpack) {
		uint8_t inc[16];
		size_t n = h3_qpack_increment(s->qpack, inc);

		if(n) {
			decoder_append(s, inc, n);
		}
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

	/* An idle link is a request left open: a browser PINGs it every 15 s
	   and the server only acknowledges; tinc sends nothing of its own over
	   a quic datagram path once it is confirmed (carrier_datagram_path() in
	   net_packet.c). This keeps the connection within its idle timeout and
	   a NAT's binding fresh. */
	ngtcp2_conn_set_keep_alive_timeout(s->conn, QUIC_KEEPALIVE * NGTCP2_SECONDS);

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

/* Front socket: Version Negotiation for a long header of any version but 1,
   as nginx sends it (measured, nginx 1.26.3 / Debian 13): no minimum
   datagram size, connection ids up to 20 bytes echoed swapped, version 1
   the only one listed. Version 0 (itself a VN) is never answered. Returns
   true if the datagram was such a packet. */
static bool front_version_negotiation(int fd, const uint8_t *buf, size_t len, const sockaddr_t *addr, socklen_t addrlen) {
	if(len < 7 || !(buf[0] & 0x80)) {
		return false;
	}

	uint32_t version = (uint32_t)buf[1] << 24 | (uint32_t)buf[2] << 16 | (uint32_t)buf[3] << 8 | buf[4];

	if(version == 1) {
		return false;
	}

	size_t dcidlen = buf[5];

	if(version == 0 || dcidlen > 20 || len < 7 + dcidlen) {
		return true;
	}

	size_t scidlen = buf[6 + dcidlen];

	if(scidlen > 20 || len < 7 + dcidlen + scidlen) {
		return true;
	}

	const uint8_t *dcid = buf + 6;
	const uint8_t *scid = buf + 7 + dcidlen;
	uint8_t vn[7 + 20 + 20 + 4];
	size_t n = 0;
	vn[n++] = 0xc0;                 /* nginx's; the unused bits are not randomised */
	memset(vn + n, 0, 4);
	n += 4;
	vn[n++] = (uint8_t)scidlen;
	memcpy(vn + n, scid, scidlen);
	n += scidlen;
	vn[n++] = (uint8_t)dcidlen;
	memcpy(vn + n, dcid, dcidlen);
	n += dcidlen;
	memcpy(vn + n, "\x00\x00\x00\x01", 4);
	n += 4;

	if(sendto(fd, (const void *)vn, n, 0, &addr->sa, addrlen) < 0) {
		logger(DEBUG_TRAFFIC, LOG_DEBUG, "quic: sending version negotiation failed: %s", sockstrerror(sockerrno));
	}

	return true;
}

/* Front socket: a stateless reset for a short-header packet no session
   claimed, as nginx sends it (measured): only with the fixed bit set, not to
   a datagram of 21 bytes or less, one byte shorter than the trigger up to
   43 bytes, a random length in [43, min(3 * len, 1200)) above that. The
   token is the one a session with that connection id announces. */
static void front_stateless_reset(int fd, const uint8_t *buf, size_t len, const sockaddr_t *addr, socklen_t addrlen) {
	if((buf[0] & 0xc0) != 0x40 || len <= 21) {
		return;
	}

	uint8_t out[1200];
	size_t n;

	if(len <= 43) {
		n = len - 1;
	} else {
		size_t max = 3 * len < sizeof(out) ? 3 * len : sizeof(out);
		uint32_t r;
		quic_tls_random((uint8_t *)&r, sizeof(r));
		n = 43 + r % (max - 43);
	}

	ngtcp2_cid cid;
	ngtcp2_cid_init(&cid, buf + 1, TRANSPORT_QUIC_CIDLEN);

	if(!quic_tls_random(out, n - NGTCP2_STATELESS_RESET_TOKENLEN) ||
	                ngtcp2_crypto_generate_stateless_reset_token(out + n - NGTCP2_STATELESS_RESET_TOKENLEN,
	                                static_secret, sizeof(static_secret), &cid)) {
		return;
	}

	out[0] = (out[0] & 0x3f) | 0x40;

	if(sendto(fd, (const void *)out, n, 0, &addr->sa, addrlen) < 0) {
		logger(DEBUG_TRAFFIC, LOG_DEBUG, "quic: sending a stateless reset failed: %s", sockstrerror(sockerrno));
	}
}

/* A QuicPort listener: QUIC only, answered as nginx answers it. A version
   it does not speak gets Version Negotiation; a short-header packet for no
   connection gets a stateless reset; anything else quic_udp_try() does not
   claim is dropped. The tinc port's SPTPS and obfs handling never answer on
   the front port -- and these answers are sent from the front port only,
   since on the tinc port unclaimed packets are SPTPS's and obfs's. */
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

	if(!quic_ready || front_version_negotiation(ls->udp.fd, buf, (size_t)len, &addr, addrlen)) {
		return;
	}

	if(!quic_udp_try(ls, buf, (size_t)len, &addr)) {
		front_stateless_reset(ls->udp.fd, buf, (size_t)len, &addr, addrlen);
	}
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
		decoy_set_h3_port(quic_port);   /* Alt-Svc on the TCP front's answers */
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
