/*
    https.c -- the `https' carrier: SPTPS meta+data inside one TLS flow, with
               a tinc-key authenticator and a default-on decoy.

    A dial opens a TLS client connection to the peer's front port with a
    plausible SNI, pins the peer's certificate by SHA-256 fingerprint
    (accept-on-first-use), and proves it is a tinc peer with an Ed25519
    authenticator bound to the TLS session (RFC 5705 exporter) -- carried in an
    ordinary-looking WebSocket upgrade request. The server verifies the
    authenticator against its host DB; on success it answers 101 Switching
    Protocols and the raw tinc meta byte stream then runs inside the TLS
    session. On ANY failure the server silently serves the decoy (decoy.c) --
    that identical treatment IS the active-probing resistance.

    SPTPS is never touched: this carrier is a pipe for its already-authenticated
    records (principle 1). The link is marked TCP-only-equivalent, so tinc's own
    data path frames the SPTPS data records over the meta stream and no separate
    UDP flow is attempted: a single outward TLS flow (also PLAN point 5).

    Wire format and authenticator are specified in docs/transports.md.

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

#ifdef HAVE_OPENSSL

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include "authn.h"
#include "conf.h"
#include "connection.h"
#include "event.h"
#include "logger.h"
#include "meta.h"
#include "names.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "tls.h"
#include "utils.h"
#include "xalloc.h"

#define TINC_TRANSPORT_DAEMON
#include "transport.h"

#include "decoy.h"

/* The authenticator itself (format, signature, replay cache) is shared with
   the quic carrier: authn.{c,h}. Here it only rides a Cookie value. */
#define HTTPS_MAX_HEAD 16384           /* cap on the HTTP request/response head */
#define WS_MAGIC "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

typedef enum https_state_t {
	HS_TCP_CONNECTING,
	HS_TLS_HANDSHAKE,
	HS_CLIENT_WRITE_REQ,
	HS_CLIENT_READ_RESP,
	HS_SERVER_READ_REQ,
	HS_SERVER_WRITE,        /* writing the 101 response, then established */
	HS_SERVER_WRITE_DECOY,  /* writing the decoy, then close */
	HS_ESTABLISHED,
	HS_DYING,
} https_state_t;

typedef struct https_session_t {
	connection_t *c;
	SSL *ssl;
	https_state_t state;
	bool is_server;

	char *sni;              /* client: SNI / Host value to present */

	char *wbuf;            /* pending outbound handshake/decoy bytes */
	size_t wlen, woff;

	char *rbuf;            /* accumulated HTTP head */
	size_t rlen, rcap;

	uint8_t server_fp[TLS_FP_LEN]; /* client: the verified server cert fingerprint */

	bool established_after_write; /* server: become established once wbuf drains */
} https_session_t;

/* ---- forward decls ------------------------------------------------------- */

static void https_io(void *data, int flags);

/* ---- lifecycle ----------------------------------------------------------- */

bool https_init(void) {
	if(!tls_init()) {
		logger(DEBUG_ALWAYS, LOG_ERR, "https carrier: TLS certificate not available");
		return false;
	}

	decoy_read_config();
	return true;
}

void https_exit(void) {
	decoy_exit();
	tls_exit();
}

static https_session_t *new_session(connection_t *c, bool is_server) {
	https_session_t *s = xzalloc(sizeof(*s));
	s->c = c;
	s->is_server = is_server;
	c->transport_data = s;
	return s;
}

void https_close(connection_t *c) {
	https_session_t *s = c->transport_data;

	if(!s) {
		return;
	}

	if(s->ssl) {
		SSL_free(s->ssl);
	}

	free(s->sni);
	free(s->wbuf);
	free(s->rbuf);
	free(s);
	c->transport_data = NULL;
}

/* ---- small io helpers ---------------------------------------------------- */

static void set_io(https_session_t *s, int want) {
	io_set(&s->c->io, want);
}

static void fail(https_session_t *s) {
	/* Not activated: terminate_connection() will advance the outgoing to the
	   next carrier candidate. */
	s->state = HS_DYING;
	connection_t *c = s->c;
	c->status.tarpit = false;
	terminate_connection(c, c->edge);
}

static void set_wbuf(https_session_t *s, const void *buf, size_t len) {
	free(s->wbuf);
	s->wbuf = xmalloc(len);
	memcpy(s->wbuf, buf, len);
	s->wlen = len;
	s->woff = 0;
}

/* Returns 1 = fully written, 0 = would block (io set), -1 = error. */
static int flush_wbuf(https_session_t *s) {
	while(s->woff < s->wlen) {
		int n = SSL_write(s->ssl, s->wbuf + s->woff, (int)(s->wlen - s->woff));

		if(n > 0) {
			s->woff += (size_t) n;
			continue;
		}

		int err = SSL_get_error(s->ssl, n);

		if(err == SSL_ERROR_WANT_READ) {
			set_io(s, IO_READ);
			return 0;
		}

		if(err == SSL_ERROR_WANT_WRITE) {
			set_io(s, IO_READ | IO_WRITE);
			return 0;
		}

		return -1;
	}

	return 1;
}

/* Append available decrypted head bytes into rbuf until "\r\n\r\n" or cap.
   Returns 1 = head complete, 0 = need more (io set), -1 = error/eof. */
static int read_head(https_session_t *s) {
	for(;;) {
		if(s->rlen + 1 >= s->rcap) {
			if(s->rcap >= HTTPS_MAX_HEAD) {
				return -1;
			}

			s->rcap = s->rcap ? s->rcap * 2 : 2048;
			s->rbuf = xrealloc(s->rbuf, s->rcap);
		}

		int n = SSL_read(s->ssl, s->rbuf + s->rlen, (int)(s->rcap - s->rlen - 1));

		if(n > 0) {
			s->rlen += (size_t) n;
			s->rbuf[s->rlen] = 0;

			if(s->rlen >= 4 && memmem(s->rbuf, s->rlen, "\r\n\r\n", 4)) {
				return 1;
			}

			continue;
		}

		int err = SSL_get_error(s->ssl, n);

		if(err == SSL_ERROR_WANT_READ) {
			set_io(s, IO_READ);
			return 0;
		}

		if(err == SSL_ERROR_WANT_WRITE) {
			set_io(s, IO_READ | IO_WRITE);
			return 0;
		}

		return -1;
	}
}

/* ---- authenticator (authn.c) binding: the TLS-session exporter ---------- */

static bool exporter_value(SSL *ssl, uint8_t *out) {
	return SSL_export_keying_material(ssl, out, AUTHN_EXPORTER_LEN,
	                                  AUTHN_EXPORTER_LABEL, strlen(AUTHN_EXPORTER_LABEL),
	                                  NULL, 0, 0) == 1;
}

/* ---- client: build the upgrade request ----------------------------------- */

static bool verify_server_cert(https_session_t *s) {
	X509 *cert = SSL_get_peer_certificate(s->ssl);

	if(!cert) {
		return false;
	}

	uint8_t fp[TLS_FP_LEN];
	char fp_hex[TLS_FP_HEX_LEN];
	bool ok = tls_x509_fingerprint(cert, fp, fp_hex);
	X509_free(cert);

	if(!ok) {
		return false;
	}

	/* Remember it: the authenticator is signed over the *server's* cert
	   fingerprint, which the server checks against its own (tls_own_fp). */
	memcpy(s->server_fp, fp, TLS_FP_LEN);

	/* Pinned fingerprint from the peer's host record. */
	splay_tree_t *tree = create_configuration();
	char *pinned = NULL;

	if(read_host_config(tree, s->c->name, false)) {
		get_config_string(lookup_config(tree, "TlsFingerprint"), &pinned);
	}

	exit_configuration(tree);

	if(pinned && tls_fingerprint_valid(pinned)) {
		bool match = !strcmp(pinned, fp_hex);
		free(pinned);

		if(!match) {
			logger(DEBUG_ALWAYS, LOG_ERR, "https: certificate fingerprint of %s does not match the pinned TlsFingerprint; refusing", s->c->name);
			return false;
		}

		return true;
	}

	free(pinned);

	/* Accept on first use, then pin. */
	logger(DEBUG_ALWAYS, LOG_NOTICE, "https: no pinned TlsFingerprint for %s; accepting %s on first use and pinning it", s->c->name, fp_hex);
	append_config_file(s->c->name, "TlsFingerprint", fp_hex);
	return true;
}

static bool build_client_request(https_session_t *s) {
	uint8_t exporter[AUTHN_EXPORTER_LEN];

	if(!exporter_value(s->ssl, exporter)) {
		return false;
	}

	/* The shared authenticator (authn.c), signed over the SERVER's cert
	   fingerprint (the one we just verified) and this TLS session's
	   exporter; the server checks it against its own tls_own_fp. */
	uint8_t payload[AUTHN_MAX_LEN];
	size_t plen = authn_build(s->server_fp, exporter, payload, sizeof(payload));

	if(!plen) {
		return false;
	}

	char b64[B64_SIZE(AUTHN_MAX_LEN)];
	b64encode_tinc_urlsafe(payload, b64, plen);

	uint8_t wskey_raw[16];
	RAND_bytes(wskey_raw, sizeof(wskey_raw));
	char wskey[32];
	b64encode_tinc(wskey_raw, wskey, sizeof(wskey_raw));

	char req[HTTPS_MAX_HEAD];
	int rl = snprintf(req, sizeof(req),
	                  "GET /ws HTTP/1.1\r\n"
	                  "Host: %s\r\n"
	                  "User-Agent: Mozilla/5.0\r\n"
	                  "Upgrade: websocket\r\n"
	                  "Connection: Upgrade\r\n"
	                  "Sec-WebSocket-Version: 13\r\n"
	                  "Sec-WebSocket-Key: %s\r\n"
	                  "Cookie: sid=%s\r\n"
	                  "\r\n",
	                  s->sni ? s->sni : TLS_DEFAULT_CN, wskey, b64);

	if(rl <= 0 || rl >= (int) sizeof(req)) {
		return false;
	}

	set_wbuf(s, req, (size_t) rl);
	return true;
}

/* ---- server: parse and verify the request -------------------------------- */

/* Extract the sid= cookie value into `out` (NUL-terminated). False if absent. */
static bool cookie_sid(const char *head, char *out, size_t outlen) {
	const char *c = head;

	while((c = strcasestr(c, "cookie:"))) {
		const char *sid = strstr(c, "sid=");
		const char *eol = strstr(c, "\r\n");

		if(sid && (!eol || sid < eol)) {
			sid += 4;
			size_t n = 0;

			while(sid[n] && sid[n] != ';' && sid[n] != '\r' && sid[n] != '\n' && sid[n] != ' ' && n + 1 < outlen) {
				out[n] = sid[n];
				n++;
			}

			out[n] = 0;
			return n > 0;
		}

		c += 7;
	}

	return false;
}

/* Verify the authenticator; on success set *out_name to the node name (caller
   frees). Returns false (serve decoy) on any problem. */
static bool verify_client_auth(https_session_t *s, char **out_name) {
	char sid[2048];

	if(!cookie_sid(s->rbuf, sid, sizeof(sid))) {
		return false;
	}

	uint8_t payload[1024];
	size_t plen = b64decode_tinc(sid, payload, sizeof(payload));

	if(!plen) {
		return false;
	}

	uint8_t exporter[AUTHN_EXPORTER_LEN];

	if(!exporter_value(s->ssl, exporter)) {
		return false;
	}

	/* Shared verification (authn.c): name known, signature over our own cert
	   fingerprint + this session's exporter, freshness, replay cache. */
	return authn_verify(payload, plen, tls_own_fp, exporter, "https", s->c->hostname, out_name);
}

static void build_ws_accept(const char *head, char *out, size_t outlen) {
	const char *k = strcasestr(head, "sec-websocket-key:");
	char key[128] = "";

	if(k) {
		k += strlen("sec-websocket-key:");

		while(*k == ' ') {
			k++;
		}

		size_t n = 0;

		while(k[n] && k[n] != '\r' && k[n] != '\n' && n + 1 < sizeof(key)) {
			key[n] = k[n];
			n++;
		}

		key[n] = 0;
	}

	char concat[256];
	snprintf(concat, sizeof(concat), "%s%s", key, WS_MAGIC);
	uint8_t sha[SHA_DIGEST_LENGTH];
	SHA1((const uint8_t *) concat, strlen(concat), sha);
	b64encode_tinc(sha, out, sizeof(sha));
	(void) outlen;
}

/* ---- become an established meta-over-TLS connection ---------------------- */

static void become_established(https_session_t *s) {
	connection_t *c = s->c;
	s->state = HS_ESTABLISHED;

	/* One TLS flow carries meta and data: mark the link TCP-only-equivalent so
	   tinc frames SPTPS data records over the meta stream and never tries a
	   separate UDP flow. Set before the ACK exchange so it propagates to the
	   edge and the peer. */
	c->options |= OPTION_TCPONLY | OPTION_INDIRECT;
	c->last_ping_time = now.tv_sec;

	free(s->rbuf);
	s->rbuf = NULL;
	s->rlen = s->rcap = 0;
	free(s->wbuf);
	s->wbuf = NULL;
	s->wlen = s->woff = 0;

	set_io(s, IO_READ);
}

/* ---- established: meta stream over TLS ------------------------------------ */

bool https_send(connection_t *c) {
	https_session_t *s = c->transport_data;

	if(!s || s->state != HS_ESTABLISHED) {
		return false;
	}

	while(c->outbuf.len > c->outbuf.offset) {
		int n = SSL_write(s->ssl, c->outbuf.data + c->outbuf.offset, (int)(c->outbuf.len - c->outbuf.offset));

		if(n > 0) {
			buffer_read(&c->outbuf, (uint32_t) n);
			continue;
		}

		int err = SSL_get_error(s->ssl, n);

		if(err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
			set_io(s, IO_READ | IO_WRITE);
			return true;
		}

		terminate_connection(c, c->edge);
		return false;
	}

	set_io(s, IO_READ);
	return true;
}

static void established_read(https_session_t *s) {
	connection_t *c = s->c;
	char buf[MAXBUFSIZE];

	for(;;) {
		int n = SSL_read(s->ssl, buf, sizeof(buf));

		if(n > 0) {
			if(!receive_meta_bytes(c, buf, n)) {
				c->status.tarpit = false;
				terminate_connection(c, c->edge);
				return;
			}

			continue;
		}

		int err = SSL_get_error(s->ssl, n);

		if(err == SSL_ERROR_WANT_READ) {
			return;
		}

		if(err == SSL_ERROR_WANT_WRITE) {
			set_io(s, IO_READ | IO_WRITE);
			return;
		}

		if(err == SSL_ERROR_ZERO_RETURN) {
			logger(DEBUG_CONNECTIONS, LOG_NOTICE, "https: peer %s (%s) closed the TLS session", c->name, c->hostname);
		}

		terminate_connection(c, c->edge);
		return;
	}
}

/* ---- the TLS/HTTP state machine ------------------------------------------ */

static void drive_tls_handshake(https_session_t *s) {
	int r = s->is_server ? SSL_accept(s->ssl) : SSL_connect(s->ssl);

	if(r == 1) {
		if(s->is_server) {
			s->state = HS_SERVER_READ_REQ;
			set_io(s, IO_READ);
		} else {
			if(!verify_server_cert(s) || !build_client_request(s)) {
				fail(s);
				return;
			}

			s->state = HS_CLIENT_WRITE_REQ;
			set_io(s, IO_READ | IO_WRITE);
		}

		return;
	}

	int err = SSL_get_error(s->ssl, r);

	if(err == SSL_ERROR_WANT_READ) {
		set_io(s, IO_READ);
	} else if(err == SSL_ERROR_WANT_WRITE) {
		set_io(s, IO_READ | IO_WRITE);
	} else {
		logger(DEBUG_CONNECTIONS, LOG_DEBUG, "https: TLS handshake with %s failed", s->c->hostname);
		fail(s);
	}
}

static void serve_decoy(https_session_t *s) {
	size_t resplen = 0;
	char *resp = decoy_respond(s->rbuf ? s->rbuf : "", s->rlen, &resplen);

	if(!resp) {
		fail(s);
		return;
	}

	set_wbuf(s, resp, resplen);
	free(resp);
	s->state = HS_SERVER_WRITE_DECOY;
	logger(DEBUG_CONNECTIONS, LOG_INFO, "https: serving the decoy to a TLS probe from %s", s->c->hostname);

	int f = flush_wbuf(s);

	if(f == 1) {
		terminate_connection(s->c, false);
	} else if(f < 0) {
		fail(s);
	}
}

static void server_handle_request(https_session_t *s) {
	char *name = NULL;

	if(!verify_client_auth(s, &name)) {
		serve_decoy(s);
		return;
	}

	/* Authenticated tinc peer: answer 101 and switch to the meta stream. */
	free(s->c->name);
	s->c->name = name;

	char accept[64];
	build_ws_accept(s->rbuf, accept, sizeof(accept));

	char resp[256];
	int rl = snprintf(resp, sizeof(resp),
	                  "HTTP/1.1 101 Switching Protocols\r\n"
	                  "Upgrade: websocket\r\n"
	                  "Connection: Upgrade\r\n"
	                  "Sec-WebSocket-Accept: %s\r\n"
	                  "\r\n",
	                  accept);
	set_wbuf(s, resp, (size_t) rl);
	s->established_after_write = true;
	s->state = HS_SERVER_WRITE;

	logger(DEBUG_CONNECTIONS, LOG_NOTICE, "https: authenticated peer %s (%s) over TLS", s->c->name, s->c->hostname);

	int f = flush_wbuf(s);

	if(f == 1) {
		become_established(s);
	} else if(f < 0) {
		fail(s);
	}
}

static void client_read_response(https_session_t *s) {
	int r = read_head(s);

	if(r == 0) {
		return;
	}

	if(r < 0) {
		fail(s);
		return;
	}

	/* Expect "HTTP/1.1 101". Anything else (e.g. the server served us a decoy
	   because it did not accept our auth) is a handshake failure: fall back. */
	if(strncmp(s->rbuf, "HTTP/1.1 101", 12) && strncmp(s->rbuf, "HTTP/1.0 101", 12)) {
		logger(DEBUG_CONNECTIONS, LOG_INFO, "https: peer %s did not accept the carrier (no 101); falling back", s->c->name);
		fail(s);
		return;
	}

	become_established(s);

	/* Kick the tinc handshake: this sends the ID line over TLS. */
	finish_connecting(s->c);
}

static void https_io(void *data, int flags) {
	connection_t *c = data;
	https_session_t *s = c->transport_data;

	if(!s || s->state == HS_DYING) {
		return;
	}

	if(s->state == HS_TCP_CONNECTING) {
		/* Verify the non-blocking connect() completed (mirrors handle_meta_io). */
		if(send(c->socket, NULL, 0, 0) != 0) {
			if(sockwouldblock(sockerrno)) {
				return;
			}

			int socket_error;

			if(!socknotconn(sockerrno)) {
				socket_error = sockerrno;
			} else {
				socklen_t len = sizeof(socket_error);
				getsockopt(c->socket, SOL_SOCKET, SO_ERROR, (void *)&socket_error, &len);
			}

			if(socket_error) {
				logger(DEBUG_CONNECTIONS, LOG_DEBUG, "https: connect to %s (%s) failed: %s", c->name, c->hostname, sockstrerror(socket_error));
				fail(s);
			}

			return;
		}

		c->status.connecting = false;
		s->ssl = SSL_new(tls_client_ctx);

		if(!s->ssl) {
			fail(s);
			return;
		}

		SSL_set_fd(s->ssl, c->socket);

		if(s->sni) {
			SSL_set_tlsext_host_name(s->ssl, s->sni);
		}

		SSL_set_connect_state(s->ssl);
		s->state = HS_TLS_HANDSHAKE;
		drive_tls_handshake(s);
		return;
	}

	switch(s->state) {
	case HS_TLS_HANDSHAKE:
		drive_tls_handshake(s);
		return;

	case HS_CLIENT_WRITE_REQ: {
		int f = flush_wbuf(s);

		if(f == 1) {
			free(s->wbuf);
			s->wbuf = NULL;
			s->wlen = s->woff = 0;
			s->state = HS_CLIENT_READ_RESP;
			set_io(s, IO_READ);
		} else if(f < 0) {
			fail(s);
		}

		return;
	}

	case HS_CLIENT_READ_RESP:
		client_read_response(s);
		return;

	case HS_SERVER_READ_REQ: {
		int r = read_head(s);

		if(r == 0) {
			return;
		}

		if(r < 0) {
			fail(s);
			return;
		}

		server_handle_request(s);
		return;
	}

	case HS_SERVER_WRITE: {
		int f = flush_wbuf(s);

		if(f == 1) {
			become_established(s);
		} else if(f < 0) {
			fail(s);
		}

		return;
	}

	case HS_SERVER_WRITE_DECOY: {
		int f = flush_wbuf(s);

		if(f == 1) {
			terminate_connection(c, false);
		} else if(f < 0) {
			fail(s);
		}

		return;
	}

	case HS_ESTABLISHED:
		if(flags & IO_WRITE) {
			https_send(c);
		}

		if(flags & IO_READ) {
			established_read(s);
		}

		return;

	case HS_TCP_CONNECTING: /* handled above */
	case HS_DYING:
	default:
		return;
	}
}

/* ---- dial (outbound) ----------------------------------------------------- */

/* Choose the SNI: HttpsSni if set, else the peer's Address if it is a name,
   else the generic default. */
static char *choose_sni(connection_t *c) {
	char *sni = NULL;

	if(get_config_string(lookup_config(&config_tree, "HttpsSni"), &sni) && sni && *sni) {
		return sni;
	}

	free(sni);

	/* The peer's Address, if it is a hostname rather than an IP literal. */
	splay_tree_t *tree = create_configuration();
	char *addr = NULL;

	if(read_host_config(tree, c->name, false)) {
		char *a = NULL;

		if(get_config_string(lookup_config(tree, "Address"), &a) && a && *a) {
			/* A name has a letter that is not a hex/':'/'.' IP char. */
			bool looks_like_name = false;

			for(char *p = a; *p; p++) {
				if(isalpha((uint8_t) *p) && *p != ':') {
					/* still could be hex in IPv6; require a non-hex letter */
					if(!strchr("abcdefABCDEF", *p)) {
						looks_like_name = true;
						break;
					}
				}
			}

			/* An IPv6 literal contains ':'; a dotted IPv4 is all digits/dots. */
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

	if(addr) {
		return addr;
	}

	return xstrdup(TLS_DEFAULT_CN);
}

bool https_dial(connection_t *c) {
	if(!tls_ready) {
		return false;
	}

	int fd = socket(c->address.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);

	if(fd < 0) {
		return false;
	}

#ifdef FD_CLOEXEC
	fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
#ifdef O_NONBLOCK
	{
		int fl = fcntl(fd, F_GETFL);
		fcntl(fd, F_SETFL, fl | O_NONBLOCK);
	}
#endif

	int r = connect(fd, &c->address.sa, SALEN(c->address.sa));

	if(r == -1 && !sockinprogress(sockerrno)) {
		logger(DEBUG_CONNECTIONS, LOG_DEBUG, "https: could not connect to %s (%s): %s", c->name, c->hostname, sockstrerror(sockerrno));
		closesocket(fd);
		return false;
	}

	c->socket = fd;
	c->status.connecting = true;

	https_session_t *s = new_session(c, false);
	s->state = HS_TCP_CONNECTING;
	s->sni = choose_sni(c);

	connection_add(c);
	io_add(&c->io, https_io, c, c->socket, IO_READ | IO_WRITE);

	logger(DEBUG_CONNECTIONS, LOG_INFO, "Dialling %s (%s) via https (SNI %s)", c->name, c->hostname, s->sni);
	return true;
}

/* ---- accept (inbound) ---------------------------------------------------- */

bool https_accept(connection_t *c, const uint8_t *peek, size_t len) {
	(void) peek;
	(void) len;

	if(!tls_ready) {
		c->status.tarpit = true;
		terminate_connection(c, false);
		return false;
	}

	https_session_t *s = new_session(c, true);
	s->ssl = SSL_new(tls_server_ctx);

	if(!s->ssl) {
		fail(s);
		return false;
	}

	SSL_set_fd(s->ssl, c->socket);
	SSL_set_accept_state(s->ssl);
	s->state = HS_TLS_HANDSHAKE;

	/* Re-point this connection's io at the TLS state machine (the peeked
	   ClientHello is still in the socket for SSL_accept to read). */
	io_del(&c->io);
	io_add(&c->io, https_io, c, c->socket, IO_READ);

	drive_tls_handshake(s);
	return false; /* not a tinc meta connection yet */
}

#endif /* HAVE_OPENSSL */
