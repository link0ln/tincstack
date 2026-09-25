/*
    transport_quic_tls.c -- OpenSSL backend for the quic carrier.

    The only backend-specific code in the carrier (docs/transports.md §9.10):
    the server context built from the node certificate, the SHA-256
    fingerprint-pinning verify callback (§9.7: a pin that moved is re-pinned
    after SPTPS), ALPN/SNI, the RFC 5705 exporter and the random source.
    OpenSSL >= 3.5 carries the QUIC TLS API that ngtcp2_crypto_ossl drives.

    Until 2026-09-23 this was GnuTLS 3.7.9 (ngtcp2_crypto_gnutls); its QUIC
    ClientHello had a JA4 no reference client shares, and the ServerHello
    differed from the https front's OpenSSL one on the same host
    (testing/fingerprint). The handshake now uses OpenSSL's defaults, as
    curl 8.14 and nginx on Debian 13 do; nothing here tunes the ClientHello.

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

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include "authn.h"
#include "logger.h"
#include "transport_quic_tls.h"

/* The shared server context built from the node certificate. */
static SSL_CTX *server_ctx;
static SSL_CTX *client_ctx;

#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))

static quic_tls_t *tls_of(SSL *ssl) {
	ngtcp2_crypto_conn_ref *ref = SSL_get_app_data(ssl);
	return ref ? container_of(ref, quic_tls_t, conn_ref) : NULL;
}

static void log_ossl_errors(const char *what) {
	unsigned long e;

	while((e = ERR_get_error())) {
		char buf[256];
		ERR_error_string_n(e, buf, sizeof(buf));
		logger(DEBUG_ALWAYS, LOG_ERR, "quic: %s: %s", what, buf);
	}
}

/* Server: offer only the configured protocol; a client that asks for none of
   it gets no_application_protocol, as an HTTP/3 server does (RFC 9001 §8.1). */
static int alpn_select(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                       const unsigned char *in, unsigned int inlen, void *arg) {
	(void)arg;
	quic_tls_t *t = tls_of(ssl);

	if(!t || !t->alpn_wire[0]) {
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}

	if(SSL_select_next_proto((unsigned char **)out, outlen, t->alpn_wire, t->alpn_wire[0] + 1u, in, inlen) != OPENSSL_NPN_NEGOTIATED) {
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}

	return SSL_TLSEXT_ERR_OK;
}

/* Client: verify the server certificate by SHA-256 of its DER, nothing else
   (no chain, no name: a peer is pinned, then proven by the authenticator
   and SPTPS). */
static int verify_pin(X509_STORE_CTX *xs, void *arg) {
	(void)arg;
	SSL *ssl = X509_STORE_CTX_get_ex_data(xs, SSL_get_ex_data_X509_STORE_CTX_idx());
	quic_tls_t *t = ssl ? tls_of(ssl) : NULL;
	X509 *leaf = X509_STORE_CTX_get0_cert(xs);
	unsigned int len = 0;

	if(!t || !leaf || X509_digest(leaf, EVP_sha256(), t->peer_fp, &len) != 1 || len != QUIC_FP_LEN) {
		X509_STORE_CTX_set_error(xs, X509_V_ERR_UNSPECIFIED);
		return 0;
	}

	for(size_t i = 0; i < QUIC_FP_LEN; i++) {
		snprintf(t->peer_fp_hex + 2 * i, 3, "%02x", t->peer_fp[i]);
	}

	t->have_peer_fp = true;

	/* Unpinned: accept on first use (transport_quic.c pins it afterwards). */
	if(!t->pin[0] || !strcmp(t->peer_fp_hex, t->pin)) {
		return 1;
	}

	/* The pin moved: a renewal, a re-issued certificate, or someone on path.
	   Accept it for this session like a first contact -- the authenticator is
	   bound to this session's exporter and SPTPS proves the peer's key, so a
	   session through anyone else's certificate never activates -- and let
	   transport_quic.c re-pin it once SPTPS has authenticated the peer. No
	   bad_certificate alert: the handshake completes like any other. */
	logger(DEBUG_ALWAYS, LOG_NOTICE, "quic: the peer presents certificate %s, not the pinned %s; "
	       "it replaces the pin only if SPTPS authenticates the peer over this session", t->peer_fp_hex, t->pin);
	t->repin = true;
	return 1;
}

bool quic_tls_global_init(void) {
	if(ngtcp2_crypto_ossl_init() != 0) {
		return false;
	}

	if(!client_ctx) {
		client_ctx = SSL_CTX_new(TLS_client_method());

		if(!client_ctx) {
			log_ossl_errors("client context");
			return false;
		}

		SSL_CTX_set_min_proto_version(client_ctx, TLS1_3_VERSION);
		SSL_CTX_set_max_proto_version(client_ctx, TLS1_3_VERSION);
		SSL_CTX_set_verify(client_ctx, SSL_VERIFY_PEER, NULL);
		SSL_CTX_set_cert_verify_callback(client_ctx, verify_pin, NULL);
		/* curl 8.14's QUIC ClientHello has no session_ticket extension;
		   with it ours was curl's plus one (testing/fingerprint). */
		SSL_CTX_set_options(client_ctx, SSL_OP_NO_TICKET);
	}

	return true;
}

void quic_tls_global_deinit(void) {
	if(client_ctx) {
		SSL_CTX_free(client_ctx);
		client_ctx = NULL;
	}

	quic_tls_free_server_cert();
}

/* The session tickets as nginx 1.26 issues them with its defaults
   (ngx_ssl_session_cache: ssl_session_cache none, ssl_session_timeout 5m):
   a 300 s lifetime, and the session id context -- SHA-1 of "HTTP" and of
   each certificate's SHA-1 -- inside every ticket. A client reads the
   lifetime and the ticket's length (quic-listener-wire-test.sh: 7200 s and
   208 B without this, nginx's 300 s and 224 B). Tickets stay OpenSSL's own
   stateless ones, as nginx's without ssl_session_ticket_key. */
static bool nginx_session_cache(SSL_CTX *ctx) {
	static const char sess_ctx[] = "HTTP";
	unsigned char md[EVP_MAX_MD_SIZE], cmd[EVP_MAX_MD_SIZE];
	unsigned int mdlen = 0, cmdlen = 0;
	X509 *cert = SSL_CTX_get0_certificate(ctx);
	EVP_MD_CTX *h = EVP_MD_CTX_new();
	bool ok = h && cert &&
	          EVP_DigestInit_ex(h, EVP_sha1(), NULL) == 1 &&
	          EVP_DigestUpdate(h, sess_ctx, sizeof(sess_ctx) - 1) == 1 &&
	          X509_digest(cert, EVP_sha1(), cmd, &cmdlen) == 1 &&
	          EVP_DigestUpdate(h, cmd, cmdlen) == 1 &&
	          EVP_DigestFinal_ex(h, md, &mdlen) == 1 &&
	          SSL_CTX_set_session_id_context(ctx, md, mdlen) == 1;

	EVP_MD_CTX_free(h);

	if(!ok) {
		return false;
	}

	SSL_CTX_set_timeout(ctx, 300);
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_AUTO_CLEAR | SSL_SESS_CACHE_NO_INTERNAL_STORE);
	SSL_CTX_sess_set_cache_size(ctx, 1);
	return true;
}

bool quic_tls_set_server_cert(const char *cert_pem, const char *key_pem) {
	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

	if(!ctx) {
		log_ossl_errors("server context");
		return false;
	}

	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

	BIO *cbio = BIO_new_mem_buf(cert_pem, -1);
	BIO *kbio = BIO_new_mem_buf(key_pem, -1);
	X509 *cert = cbio ? PEM_read_bio_X509(cbio, NULL, NULL, NULL) : NULL;
	EVP_PKEY *key = kbio ? PEM_read_bio_PrivateKey(kbio, NULL, NULL, NULL) : NULL;
	bool ok = cert && key && SSL_CTX_use_certificate(ctx, cert) == 1 &&
	          SSL_CTX_use_PrivateKey(ctx, key) == 1 && SSL_CTX_check_private_key(ctx) == 1;

	/* Intermediates after the leaf, as tls.c does for the https front. */
	if(ok && cbio) {
		X509 *ca;

		while((ca = PEM_read_bio_X509(cbio, NULL, NULL, NULL))) {
			if(SSL_CTX_add_extra_chain_cert(ctx, ca) != 1) {
				X509_free(ca);
			}
		}
	}

	ERR_clear_error(); /* the chain loop ends on a PEM "no start line" */
	BIO_free(cbio);
	BIO_free(kbio);
	X509_free(cert);
	EVP_PKEY_free(key);

	if(!ok) {
		log_ossl_errors("loading the server certificate");
		SSL_CTX_free(ctx);
		return false;
	}

	SSL_CTX_set_alpn_select_cb(ctx, alpn_select, NULL);

	if(!nginx_session_cache(ctx)) {
		log_ossl_errors("session cache");
		SSL_CTX_free(ctx);
		return false;
	}

	quic_tls_free_server_cert();
	server_ctx = ctx;
	return true;
}

void quic_tls_free_server_cert(void) {
	if(server_ctx) {
		SSL_CTX_free(server_ctx);
		server_ctx = NULL;
	}
}

bool quic_tls_session_init(quic_tls_t *t, bool server,
                           ngtcp2_conn *(*get_conn)(ngtcp2_crypto_conn_ref *),
                           void *user_data, const char *alpn, const char *sni, const char *pin_hex) {
	t->server = server;
	t->conn_ref.get_conn = get_conn;
	t->conn_ref.user_data = user_data;

	size_t alen = alpn ? strlen(alpn) : 0;

	if(!alen || alen >= sizeof(t->alpn_wire) - 1) {
		return false;
	}

	t->alpn_wire[0] = (uint8_t)alen;
	memcpy(t->alpn_wire + 1, alpn, alen);

	SSL_CTX *ctx = server ? server_ctx : client_ctx;

	if(!ctx || !(t->ssl = SSL_new(ctx))) {
		return false;
	}

	SSL_set_app_data(t->ssl, &t->conn_ref);

	if(server) {
		if(ngtcp2_crypto_ossl_configure_server_session(t->ssl) != 0) {
			goto fail;
		}

		SSL_set_accept_state(t->ssl);
	} else {
		if(pin_hex) {
			strncpy(t->pin, pin_hex, sizeof(t->pin) - 1);
		}

		if(ngtcp2_crypto_ossl_configure_client_session(t->ssl) != 0 ||
		                SSL_set_alpn_protos(t->ssl, t->alpn_wire, (unsigned int)alen + 1) != 0) {
			goto fail;
		}

		if(sni && *sni && SSL_set_tlsext_host_name(t->ssl, sni) != 1) {
			goto fail;
		}

		SSL_set_connect_state(t->ssl);
	}

	if(ngtcp2_crypto_ossl_ctx_new(&t->octx, t->ssl) != 0) {
		goto fail;
	}

	return true;

fail:
	log_ossl_errors("session setup");
	quic_tls_session_free(t);
	return false;
}

void quic_tls_session_free(quic_tls_t *t) {
	if(t->octx) {
		ngtcp2_crypto_ossl_ctx_del(t->octx);
		t->octx = NULL;
	}

	if(t->ssl) {
		/* ngtcp2's callbacks must not find a conn_ref whose ngtcp2_conn is
		   already gone (ngtcp2_crypto_ossl.h). */
		SSL_set_app_data(t->ssl, NULL);
		SSL_free(t->ssl);
		t->ssl = NULL;
	}
}

bool quic_tls_alpn_selected(quic_tls_t *t) {
	const unsigned char *sel = NULL;
	unsigned int len = 0;
	SSL_get0_alpn_selected(t->ssl, &sel, &len);
	return sel && len == t->alpn_wire[0] && !memcmp(sel, t->alpn_wire + 1, len);
}

void *quic_tls_native_handle(quic_tls_t *t) {
	return t->octx;
}

bool quic_tls_exporter(quic_tls_t *t, uint8_t *out, size_t outlen) {
	/* TLS 1.3 (RFC 8446 §7.5): no context and an empty one are the same, so
	   this matches the GnuTLS backend's value on the wire. */
	return t->ssl && SSL_export_keying_material(t->ssl, out, outlen, AUTHN_EXPORTER_LABEL,
	                strlen(AUTHN_EXPORTER_LABEL), NULL, 0, 0) == 1;
}

bool quic_tls_random(uint8_t *out, size_t len) {
	return RAND_bytes(out, (int)len) == 1;
}

#endif /* HAVE_QUIC */
