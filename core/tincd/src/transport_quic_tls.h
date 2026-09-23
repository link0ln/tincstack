#ifndef TINC_TRANSPORT_QUIC_TLS_H
#define TINC_TRANSPORT_QUIC_TLS_H

/*
    transport_quic_tls.h -- the TLS-backend-specific glue for the quic carrier.

    Everything that differs between TLS backends lives behind this interface
    (docs/transports.md §9.10): the server context, the fingerprint-pinning
    verify callback, ALPN/SNI, the RFC 5705 exporter and the random source.
    transport_quic.c is backend-independent and talks only to these functions.
    The implementation is transport_quic_tls.c (OpenSSL >= 3.5 through
    ngtcp2_crypto_ossl; GnuTLS until 2026-09-23).

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

#include <openssl/ssl.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>

#define QUIC_FP_LEN 32                  /* SHA-256 of the server certificate (DER) */
#define QUIC_FP_HEX_LEN (2 * QUIC_FP_LEN + 1)

/* Per-session TLS object. `conn_ref' is embedded and set as the SSL's app
   data, so the callbacks recover this struct (container_of) from the SSL. */
typedef struct quic_tls_t {
	SSL *ssl;
	ngtcp2_crypto_ossl_ctx *octx;          /* ngtcp2's native handle */
	ngtcp2_crypto_conn_ref conn_ref;
	bool server;
	uint8_t alpn_wire[64];                 /* the one protocol, length-prefixed */

	/* Client pinning: expected fp (empty = accept-on-first-use) and the fp of
	   the certificate the server actually presented (filled by verify). */
	char pin[QUIC_FP_HEX_LEN];
	uint8_t peer_fp[QUIC_FP_LEN];
	char peer_fp_hex[QUIC_FP_HEX_LEN];
	bool have_peer_fp;

	/* Client: the certificate differed from the pin; re-pin it after SPTPS. */
	bool repin;
} quic_tls_t;

/* Process-wide init/deinit. */
bool quic_tls_global_init(void);
void quic_tls_global_deinit(void);

/* Build (or rebuild) the shared server context from the node certificate
   PEM. Called from quic_init and again on reload when the cert changed. */
bool quic_tls_set_server_cert(const char *cert_pem, const char *key_pem);
void quic_tls_free_server_cert(void);

/* Initialise a per-session TLS object. `get_conn'/`user_data' wire the
   ngtcp2 crypto conn_ref; `alpn' and (client) `sni' shape the handshake;
   client `pin_hex' is the expected server fingerprint ("" = first use). */
bool quic_tls_session_init(quic_tls_t *t, bool server,
                           ngtcp2_conn *(*get_conn)(ngtcp2_crypto_conn_ref *),
                           void *user_data, const char *alpn, const char *sni, const char *pin_hex);
void quic_tls_session_free(quic_tls_t *t);

/* Client: the server selected the protocol we offered. */
bool quic_tls_alpn_selected(quic_tls_t *t);

/* What ngtcp2_conn_set_tls_native_handle() takes for this session. */
void *quic_tls_native_handle(quic_tls_t *t);

/* RFC 5705 exporter (32 bytes) binding the authenticator to this session. */
bool quic_tls_exporter(quic_tls_t *t, uint8_t *out, size_t outlen);

/* Cryptographically secure random bytes (connection ids, ngtcp2's rand). */
bool quic_tls_random(uint8_t *out, size_t len);

#endif /* HAVE_QUIC */

#endif /* TINC_TRANSPORT_QUIC_TLS_H */
