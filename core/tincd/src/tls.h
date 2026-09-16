#ifndef TINC_TLS_H
#define TINC_TLS_H

/*
    tls.h -- the node certificate: generation, loading, fingerprint, and the
             libssl contexts shared by the HTTPS front and the QUIC carrier.

    One certificate per node (PLAN decision 1). `TlsCert`/`TlsKey` name a real
    certificate if the operator has one; otherwise a self-signed certificate is
    generated at first start and persisted (YAML: keys.tls_cert/tls_key;
    classic confbase: tls_cert.pem/tls_key.pem) so it is stable across
    restarts. Its SHA-256 fingerprint is what peers pin (`TlsFingerprint` in
    the host record, propagated through invitations).

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
#include <openssl/x509.h>

#define TLS_FP_LEN 32                      /* SHA-256 over the DER certificate */
#define TLS_FP_HEX_LEN (2 * TLS_FP_LEN + 1)

/* The subject a generated certificate gets when no better name is known. A
   self-signed `localhost` certificate is what countless default installs
   present; it names no product and no node. */
#define TLS_DEFAULT_CN "localhost"
#define TLS_CERT_VALIDITY_DAYS 3650

/* ---- pure helpers (usable from the CLI and zeroconf) --------------------- */

/* Generate a P-256 key and a self-signed X.509v3 certificate (CN = SAN =
   `cn`, 10 years). Both are returned as PEM text without trailing newline;
   caller frees. */
bool tls_generate_pem(const char *cn, char **cert_pem, char **key_pem);

/* SHA-256 fingerprint of the first certificate in a PEM text, as lower-case
   hex into `hex` (TLS_FP_HEX_LEN bytes). False if it does not parse. */
bool tls_cert_pem_fingerprint(const char *cert_pem, char *hex);

/* Fingerprint of a parsed certificate; `raw` (TLS_FP_LEN) and `hex` may each
   be NULL. */
bool tls_x509_fingerprint(X509 *cert, uint8_t *raw, char *hex);

/* Whole file as a string (caller frees), or NULL. */
char *tls_read_file(const char *path);

/* True if `s` is a syntactically valid lower/upper-case hex fingerprint;
   normalises it to lower case in place. */
bool tls_fingerprint_valid(char *s);

/* ---- daemon state (tls_init/tls_exit; tls_ready gates everything) -------- */

extern bool tls_ready;
extern SSL_CTX *tls_server_ctx;             /* our certificate, TLS 1.2+, ALPN http/1.1 */
extern SSL_CTX *tls_client_ctx;             /* no verification: peers are pinned by fingerprint */
extern uint8_t tls_own_fp[TLS_FP_LEN];
extern char tls_own_fp_hex[TLS_FP_HEX_LEN];
extern char *tls_cert_source;               /* human-readable origin, for the log */

/* Load the node certificate (TlsCert/TlsKey files, else the YAML keys, else
   classic-mode files generated on demand) and build the contexts. Safe to
   call again on reload: contexts are rebuilt only if the material changed. */
bool tls_init(void);
void tls_exit(void);

/* The node certificate/key as PEM text (the same source tls_init() uses),
   for a carrier that needs the raw PEM (the quic carrier's GnuTLS backend).
   Both are heap strings the caller frees; the key should be zeroed after use.
   False if the certificate cannot be loaded/generated. */
bool tls_current_pem(char **cert_pem, char **key_pem);

#endif /* HAVE_OPENSSL */

#endif /* TINC_TLS_H */
