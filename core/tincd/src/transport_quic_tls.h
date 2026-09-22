#ifndef TINC_TRANSPORT_QUIC_TLS_H
#define TINC_TRANSPORT_QUIC_TLS_H

/*
    transport_quic_tls.h -- the TLS-backend-specific glue for the quic carrier.

    Everything that differs between GnuTLS / wolfSSL / BoringSSL lives behind
    this interface (docs/transports.md §9.10): credential setup, the
    fingerprint-pinning verify callback, the priority string, ALPN/SNI, and the
    RFC 5705 exporter. transport_quic.c is backend-independent and talks only to
    these functions. The current implementation is transport_quic_tls.c (GnuTLS,
    ~backend lines only).

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

#include <gnutls/gnutls.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#define QUIC_FP_LEN 32                  /* SHA-256 of the server certificate (DER) */
#define QUIC_FP_HEX_LEN (2 * QUIC_FP_LEN + 1)

/* Per-session TLS object. `conn_ref' is embedded so the verify callback can
   recover this struct (container_of) from the gnutls session pointer. */
typedef struct quic_tls_t {
	gnutls_session_t session;
	gnutls_certificate_credentials_t cred; /* client: own; server: the shared cred */
	ngtcp2_crypto_conn_ref conn_ref;
	bool server;
	bool own_cred;                         /* free cred in _free (client only) */

	/* Client pinning: expected fp (empty = accept-on-first-use) and the fp of
	   the certificate the server actually presented (filled by verify). */
	char pin[QUIC_FP_HEX_LEN];
	uint8_t peer_fp[QUIC_FP_LEN];
	char peer_fp_hex[QUIC_FP_HEX_LEN];
	bool have_peer_fp;

	/* Client: the SNI we sent, and whether the certificate differed from the
	   pin but was one a public CA issued for that name (a renewal). */
	char sni[256];
	bool repin;
} quic_tls_t;

/* Process-wide init/deinit. */
bool quic_tls_global_init(void);
void quic_tls_global_deinit(void);

/* Build (or rebuild) the shared server credential from the node certificate
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

/* RFC 5705 exporter (32 bytes) binding the authenticator to this session. */
bool quic_tls_exporter(gnutls_session_t session, uint8_t *out, size_t outlen);

#endif /* HAVE_QUIC */

#endif /* TINC_TRANSPORT_QUIC_TLS_H */
