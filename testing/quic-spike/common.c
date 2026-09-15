/*
    common.c -- shared QUIC endpoint for the stream-Q spike (ngtcp2 + GnuTLS).

    See common.h. Nothing here is tinc-specific; it is the minimal glue a
    carrier needs around ngtcp2: TLS session setup with fingerprint pinning,
    the callback table, a write loop (datagrams first, then the stream), a
    read loop that passes the real source address of every datagram to the
    library (that is what makes NAT rebinding work), and timer handling.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include "common.h"

/* TLS 1.3 only, the cipher suites QUIC allows, no middlebox compat mode. */
static const char tls_priority[] =
        "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:"
        "+CHACHA20-POLY1305:-GROUP-ALL:+GROUP-X25519:+GROUP-SECP256R1:"
        "%DISABLE_TLS13_COMPAT_MODE";

static char pinned_fingerprint[65];      /* client: expected server cert SHA-256, lowercase hex */

ngtcp2_tstamp spike_now(void) {
	struct timespec tp;
	clock_gettime(CLOCK_MONOTONIC, &tp);
	return (ngtcp2_tstamp)tp.tv_sec * NGTCP2_SECONDS + (ngtcp2_tstamp)tp.tv_nsec;
}

const char *spike_addr_str(const struct sockaddr *sa, socklen_t len, char *buf, size_t buflen) {
	char host[NI_MAXHOST], serv[NI_MAXSERV];

	if(getnameinfo(sa, len, host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV)) {
		snprintf(buf, buflen, "?");
	} else {
		snprintf(buf, buflen, "%s:%s", host, serv);
	}

	return buf;
}

int spike_addr_port(const struct sockaddr *sa) {
	if(sa->sa_family == AF_INET6) {
		return ntohs(((const struct sockaddr_in6 *)sa)->sin6_port);
	}

	return ntohs(((const struct sockaddr_in *)sa)->sin_port);
}

int spike_bind(spike_conn_t *sc, const char *host, const char *port) {
	struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_DGRAM, .ai_flags = AI_PASSIVE};
	struct addrinfo *res;
	int rv = getaddrinfo(host, port, &hints, &res);

	if(rv) {
		fprintf(stderr, "getaddrinfo(%s:%s): %s\n", host, port, gai_strerror(rv));
		return -1;
	}

	int fd = socket(res->ai_family, SOCK_DGRAM, 0);

	if(fd < 0 || bind(fd, res->ai_addr, res->ai_addrlen) < 0) {
		fprintf(stderr, "bind(%s:%s): %s\n", host, port, strerror(errno));
		freeaddrinfo(res);
		return -1;
	}

	freeaddrinfo(res);

	sc->locallen = sizeof(sc->local);

	if(getsockname(fd, (struct sockaddr *)&sc->local, &sc->locallen) < 0) {
		fprintf(stderr, "getsockname: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	sc->fd = fd;
	return 0;
}

/* --- TLS ---------------------------------------------------------------- */

static void normalise_hex(const char *in, char *out, size_t outlen) {
	size_t n = 0;

	for(; *in && n + 1 < outlen; in++) {
		if(*in == ':' || *in == ' ') {
			continue;
		}

		out[n++] = (char)((*in >= 'A' && *in <= 'F') ? *in - 'A' + 'a' : *in);
	}

	out[n] = 0;
}

/* Client: verify the server certificate by SHA-256 fingerprint of its DER
   encoding, nothing else. No CA, no name check: the identity we care about
   is the tinc node's, and its host record carries this fingerprint. */
static int verify_pin(gnutls_session_t session) {
	unsigned int n = 0;
	const gnutls_datum_t *certs = gnutls_certificate_get_peers(session, &n);

	if(!certs || !n) {
		fprintf(stderr, "PIN no certificate presented\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	uint8_t digest[32];
	size_t digestlen = sizeof(digest);

	if(gnutls_fingerprint(GNUTLS_DIG_SHA256, &certs[0], digest, &digestlen) < 0) {
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	char hex[65];

	for(size_t i = 0; i < 32; i++) {
		snprintf(hex + 2 * i, 3, "%02x", digest[i]);
	}

	if(strcmp(hex, pinned_fingerprint)) {
		fprintf(stderr, "PIN mismatch: got %s expected %s\n", hex, pinned_fingerprint);
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	fprintf(stderr, "PIN ok sha256=%s\n", hex);
	return 0;
}

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *ref) {
	return ((spike_conn_t *)ref->user_data)->conn;
}

int spike_tls_init(spike_conn_t *sc, bool server, const char *cert_pem, const char *key_pem,
                   const char *pin, const char *alpn, const char *sni) {
	int rv;

	sc->server = server;
	sc->conn_ref.get_conn = get_conn;
	sc->conn_ref.user_data = sc;

	if((rv = gnutls_certificate_allocate_credentials(&sc->cred)) < 0) {
		fprintf(stderr, "gnutls_certificate_allocate_credentials: %s\n", gnutls_strerror(rv));
		return -1;
	}

	if(server) {
		if((rv = gnutls_certificate_set_x509_key_file(sc->cred, cert_pem, key_pem, GNUTLS_X509_FMT_PEM)) < 0) {
			fprintf(stderr, "gnutls_certificate_set_x509_key_file(%s, %s): %s\n", cert_pem, key_pem, gnutls_strerror(rv));
			return -1;
		}
	} else {
		normalise_hex(pin, pinned_fingerprint, sizeof(pinned_fingerprint));
		gnutls_certificate_set_verify_function(sc->cred, verify_pin);
	}

	unsigned int flags = (server ? GNUTLS_SERVER : GNUTLS_CLIENT) | GNUTLS_ENABLE_EARLY_DATA | GNUTLS_NO_END_OF_EARLY_DATA;

	if(server) {
		flags |= GNUTLS_NO_AUTO_SEND_TICKET;
	}

	if((rv = gnutls_init(&sc->session, flags)) < 0) {
		fprintf(stderr, "gnutls_init: %s\n", gnutls_strerror(rv));
		return -1;
	}

	rv = server ? ngtcp2_crypto_gnutls_configure_server_session(sc->session)
	     : ngtcp2_crypto_gnutls_configure_client_session(sc->session);

	if(rv) {
		fprintf(stderr, "ngtcp2_crypto_gnutls_configure_%s_session failed\n", server ? "server" : "client");
		return -1;
	}

	if((rv = gnutls_priority_set_direct(sc->session, tls_priority, NULL)) < 0) {
		fprintf(stderr, "gnutls_priority_set_direct: %s\n", gnutls_strerror(rv));
		return -1;
	}

	gnutls_session_set_ptr(sc->session, &sc->conn_ref);

	if((rv = gnutls_credentials_set(sc->session, GNUTLS_CRD_CERTIFICATE, sc->cred)) < 0) {
		fprintf(stderr, "gnutls_credentials_set: %s\n", gnutls_strerror(rv));
		return -1;
	}

	gnutls_datum_t alpn_datum = {(uint8_t *)alpn, (unsigned int)strlen(alpn)};
	gnutls_alpn_set_protocols(sc->session, &alpn_datum, 1,
	                          GNUTLS_ALPN_MANDATORY | (server ? GNUTLS_ALPN_SERVER_PRECEDENCE : 0));

	if(!server && sni && *sni) {
		gnutls_server_name_set(sc->session, GNUTLS_NAME_DNS, sni, strlen(sni));
	}

	return 0;
}

void spike_report_tls(spike_conn_t *sc, const char *who) {
	gnutls_datum_t alpn = {0};
	char sni[256] = "";
	size_t snilen = sizeof(sni);
	unsigned int type;

	gnutls_alpn_get_selected_protocol(sc->session, &alpn);

	if(gnutls_server_name_get(sc->session, sni, &snilen, &type, 0) != 0) {
		snprintf(sni, sizeof(sni), sc->server ? "(none)" : "(n/a on client)");
	}

	fprintf(stderr, "%s HANDSHAKE ok alpn=%.*s sni=%s tls=%s cipher=%s group=%s\n", who,
	        (int)alpn.size, (const char *)alpn.data, sni,
	        gnutls_protocol_get_name(gnutls_protocol_get_version(sc->session)),
	        gnutls_cipher_get_name(gnutls_cipher_get(sc->session)),
	        gnutls_group_get_name(gnutls_group_get(sc->session)));
}

/* --- ngtcp2 callbacks --------------------------------------------------- */

static void cb_rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *ctx) {
	(void)ctx;
	gnutls_rnd(GNUTLS_RND_RANDOM, dest, destlen);
}

static int cb_get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid, ngtcp2_stateless_reset_token *token,
                                    size_t cidlen, void *user_data) {
	(void)conn;
	(void)user_data;

	if(gnutls_rnd(GNUTLS_RND_RANDOM, cid->data, cidlen) || gnutls_rnd(GNUTLS_RND_RANDOM, token->data, sizeof(token->data))) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	cid->datalen = cidlen;
	return 0;
}

static int cb_handshake_completed(ngtcp2_conn *conn, void *user_data) {
	(void)conn;
	spike_conn_t *sc = user_data;
	sc->handshake_done = true;

	if(sc->on_handshake) {
		sc->on_handshake(sc);
	}

	return 0;
}

static int cb_recv_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t offset,
                               const uint8_t *data, size_t datalen, void *user_data, void *stream_user_data) {
	(void)flags;
	(void)offset;
	(void)stream_user_data;
	spike_conn_t *sc = user_data;

	if(sc->stream_id < 0) {
		sc->stream_id = stream_id;      /* server: adopt the client's stream */
	}

	if(sc->on_stream_data && datalen) {
		sc->on_stream_data(sc, data, datalen);
	}

	/* The bytes were consumed; give the flow-control credit back. */
	ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
	ngtcp2_conn_extend_max_offset(conn, datalen);
	return 0;
}

static int cb_recv_datagram(ngtcp2_conn *conn, uint32_t flags, const uint8_t *data, size_t datalen, void *user_data) {
	(void)conn;
	(void)flags;
	spike_conn_t *sc = user_data;

	if(sc->on_datagram) {
		sc->on_datagram(sc, data, datalen);
	}

	return 0;
}

static int cb_path_validation(ngtcp2_conn *conn, uint32_t flags, const ngtcp2_path *path, const ngtcp2_path *fallback,
                              ngtcp2_path_validation_result res, void *user_data) {
	(void)conn;
	(void)flags;
	(void)fallback;
	spike_conn_t *sc = user_data;

	if(sc->on_path_validation) {
		sc->on_path_validation(sc, path, res);
	}

	return 0;
}

static int cb_extend_max_stream_data(ngtcp2_conn *conn, int64_t stream_id, uint64_t max_data, void *user_data, void *stream_user_data) {
	(void)conn;
	(void)stream_id;
	(void)max_data;
	(void)stream_user_data;
	((spike_conn_t *)user_data)->stream_blocked = false;
	return 0;
}

static void cb_log(void *user_data, const char *fmt, ...) {
	(void)user_data;
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

void spike_callbacks(ngtcp2_callbacks *cb, bool server) {
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
	cb->handshake_completed = cb_handshake_completed;
	cb->recv_stream_data = cb_recv_stream_data;
	cb->recv_datagram = cb_recv_datagram;
	cb->path_validation = cb_path_validation;
	cb->extend_max_stream_data = cb_extend_max_stream_data;
}

void spike_settings(ngtcp2_settings *settings, ngtcp2_transport_params *params) {
	ngtcp2_settings_default(settings);
	settings->initial_ts = spike_now();

	if(getenv("SPIKE_DEBUG")) {
		settings->log_printf = cb_log;
	}

	ngtcp2_transport_params_default(params);
	params->initial_max_streams_bidi = 4;
	params->initial_max_streams_uni = 0;
	params->initial_max_stream_data_bidi_local = 256 * 1024;
	params->initial_max_stream_data_bidi_remote = 256 * 1024;
	params->initial_max_data = 1024 * 1024;
	params->max_idle_timeout = 30 * NGTCP2_SECONDS;
	params->max_datagram_frame_size = 65535;    /* DATAGRAM frames on (RFC 9221) */
	/* The default (2) allows exactly one migration with a fresh connection
	   id before the peer runs out of ids to offer; a laptop that sleeps
	   and wakes several times per session needs more. Found by the spike:
	   with 2, the second migration killed the server with
	   ERR_CONNECTION_ID_LIMIT. */
	params->active_connection_id_limit = 8;
}

/* --- application data ---------------------------------------------------- */

int spike_stream_send(spike_conn_t *sc, const void *data, size_t len) {
	if(sc->stream_id < 0 || sc->stream_len + len > sizeof(sc->stream_buf)) {
		return -1;
	}

	memcpy(sc->stream_buf + sc->stream_len, data, len);
	sc->stream_len += len;
	return 0;
}

int spike_dgram_send(spike_conn_t *sc, const void *data, size_t len) {
	if(len > SPIKE_MAX_DGRAM || sc->dgram_n == SPIKE_DGRAM_QUEUE) {
		return -1;
	}

	size_t i = (sc->dgram_head + sc->dgram_n) % SPIKE_DGRAM_QUEUE;
	memcpy(sc->dgram[i].data, data, len);
	sc->dgram[i].len = len;
	sc->dgram_n++;
	return 0;
}

/* --- I/O ------------------------------------------------------------------ */

static int send_packet(spike_conn_t *sc, const uint8_t *pkt, size_t len, const ngtcp2_path *path) {
	if(!sc->pkts_sent && sc->on_first_packet) {
		sc->on_first_packet(sc, pkt, len);
	}

	ssize_t n;

	do {
		n = sendto(sc->fd, pkt, len, 0, path->remote.addr, path->remote.addrlen);
	} while(n < 0 && errno == EINTR);

	if(n < 0) {
		fprintf(stderr, "sendto: %s\n", strerror(errno));
		return -1;
	}

	sc->pkts_sent++;
	return 0;
}

int spike_flush(spike_conn_t *sc) {
	uint8_t buf[SPIKE_PKT_BUF];
	ngtcp2_path_storage ps;
	ngtcp2_pkt_info pi;
	ngtcp2_tstamp ts = spike_now();

	if(sc->closed) {
		return 0;
	}

	ngtcp2_path_storage_zero(&ps);

	for(;;) {
		ngtcp2_ssize nwrite;

		if(sc->dgram_n) {
			ngtcp2_vec v = {sc->dgram[sc->dgram_head].data, sc->dgram[sc->dgram_head].len};
			int accepted = 0;

			nwrite = ngtcp2_conn_writev_datagram(sc->conn, &ps.path, &pi, buf, sizeof(buf), &accepted, 0,
			                                     ++sc->dgram_id, &v, 1, ts);

			if(nwrite < 0) {
				fprintf(stderr, "ngtcp2_conn_writev_datagram: %s\n", ngtcp2_strerror((int)nwrite));
				ngtcp2_ccerr_set_liberr(&sc->last_error, (int)nwrite, NULL, 0);
				return -1;
			}

			if(accepted) {
				sc->dgram_head = (sc->dgram_head + 1) % SPIKE_DGRAM_QUEUE;
				sc->dgram_n--;
			}

			if(nwrite == 0) {
				break;      /* congestion / pacing limited; the timer will call us again */
			}
		} else {
			ngtcp2_vec v = {NULL, 0};
			size_t cnt = 0;
			int64_t sid = -1;
			ngtcp2_ssize wlen = 0;

			if(sc->stream_id >= 0 && !sc->stream_blocked && sc->stream_off < sc->stream_len) {
				v.base = sc->stream_buf + sc->stream_off;
				v.len = sc->stream_len - sc->stream_off;
				cnt = 1;
				sid = sc->stream_id;
			}

			nwrite = ngtcp2_conn_writev_stream(sc->conn, &ps.path, &pi, buf, sizeof(buf), &wlen, 0, sid, &v, cnt, ts);

			if(nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
				sc->stream_blocked = true;
				continue;
			}

			if(nwrite < 0) {
				fprintf(stderr, "ngtcp2_conn_writev_stream: %s\n", ngtcp2_strerror((int)nwrite));
				ngtcp2_ccerr_set_liberr(&sc->last_error, (int)nwrite, NULL, 0);
				return -1;
			}

			if(wlen > 0) {
				sc->stream_off += (size_t)wlen;
			}

			if(nwrite == 0) {
				break;
			}
		}

		if(send_packet(sc, buf, (size_t)nwrite, &ps.path)) {
			return -1;
		}
	}

	ngtcp2_conn_update_pkt_tx_time(sc->conn, ts);
	return 0;
}

int spike_read(spike_conn_t *sc) {
	uint8_t buf[65536];

	for(;;) {
		struct sockaddr_storage from;
		socklen_t fromlen = sizeof(from);
		ssize_t n = recvfrom(sc->fd, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *)&from, &fromlen);

		if(n < 0) {
			if(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
				return 0;
			}

			fprintf(stderr, "recvfrom: %s\n", strerror(errno));
			return -1;
		}

		/* The path carries the datagram's real source: a rebind on the far
		   side shows up here as a new remote, and ngtcp2 starts path
		   validation on its own. */
		ngtcp2_path path = {
			.local = {(struct sockaddr *)&sc->local, sc->locallen},
			.remote = {(struct sockaddr *)&from, fromlen},
		};
		ngtcp2_pkt_info pi = {0};

		int rv = ngtcp2_conn_read_pkt(sc->conn, &path, &pi, buf, (size_t)n, spike_now());

		if(rv == 0) {
			continue;
		}

		if(rv == NGTCP2_ERR_DRAINING) {
			fprintf(stderr, "%s CLOSED by peer (draining)\n", sc->server ? "server" : "client");
			sc->closed = true;
			return 0;
		}

		if(rv == NGTCP2_ERR_DROP_CONN || rv == NGTCP2_ERR_CLOSING) {
			sc->closed = true;
			return 0;
		}

		if(rv == NGTCP2_ERR_CRYPTO) {
			ngtcp2_ccerr_set_tls_alert(&sc->last_error, ngtcp2_conn_get_tls_alert(sc->conn), NULL, 0);
			fprintf(stderr, "%s HANDSHAKE failed: TLS alert %u\n", sc->server ? "server" : "client",
			        ngtcp2_conn_get_tls_alert(sc->conn));
		} else {
			ngtcp2_ccerr_set_liberr(&sc->last_error, rv, NULL, 0);
			fprintf(stderr, "ngtcp2_conn_read_pkt: %s\n", ngtcp2_strerror(rv));
		}

		return -1;
	}
}

int spike_run_until(spike_conn_t *sc, bool (*pred)(spike_conn_t *sc), int timeout_ms) {
	ngtcp2_tstamp deadline = spike_now() + (ngtcp2_tstamp)timeout_ms * NGTCP2_MILLISECONDS;

	for(;;) {
		if(spike_flush(sc)) {
			return -1;
		}

		if(sc->closed) {
			return pred && pred(sc) ? 0 : -1;
		}

		if(pred && pred(sc)) {
			return 0;
		}

		ngtcp2_tstamp now = spike_now();

		if(now >= deadline) {
			return 1;
		}

		ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(sc->conn);
		ngtcp2_tstamp until = expiry < deadline ? expiry : deadline;
		int wait = until <= now ? 0 : (int)((until - now) / NGTCP2_MILLISECONDS) + 1;

		struct pollfd pfd = {.fd = sc->fd, .events = POLLIN};
		int rv = poll(&pfd, 1, wait);

		if(rv < 0 && errno != EINTR) {
			fprintf(stderr, "poll: %s\n", strerror(errno));
			return -1;
		}

		if(rv > 0 && spike_read(sc)) {
			return -1;
		}

		if(spike_now() >= ngtcp2_conn_get_expiry(sc->conn)) {
			int erv = ngtcp2_conn_handle_expiry(sc->conn, spike_now());

			if(erv) {
				fprintf(stderr, "ngtcp2_conn_handle_expiry: %s\n", ngtcp2_strerror(erv));
				ngtcp2_ccerr_set_liberr(&sc->last_error, erv, NULL, 0);
				return -1;
			}
		}
	}
}

void spike_close(spike_conn_t *sc) {
	uint8_t buf[SPIKE_PKT_BUF];
	ngtcp2_path_storage ps;
	ngtcp2_pkt_info pi;

	if(sc->closed || !sc->conn || ngtcp2_conn_in_closing_period(sc->conn) || ngtcp2_conn_in_draining_period(sc->conn)) {
		sc->closed = true;
		return;
	}

	ngtcp2_path_storage_zero(&ps);

	if(!sc->last_error.error_code) {
		ngtcp2_ccerr_set_application_error(&sc->last_error, 0, NULL, 0);
	}

	ngtcp2_ssize n = ngtcp2_conn_write_connection_close(sc->conn, &ps.path, &pi, buf, sizeof(buf), &sc->last_error, spike_now());

	if(n > 0) {
		send_packet(sc, buf, (size_t)n, &ps.path);
	}

	sc->closed = true;
}
