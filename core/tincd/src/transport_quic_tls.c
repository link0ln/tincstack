/*
    transport_quic_tls.c -- GnuTLS backend for the quic carrier.

    The only backend-specific code in the carrier (docs/transports.md §9.10):
    certificate credentials, the SHA-256 fingerprint-pinning verify callback
    (the pin is the identity, §9.7; a CA and the name are consulted only when
    a pin moved), the QUIC TLS 1.3
    priority string, ALPN/SNI, and the RFC 5705 exporter. Replace this file to
    move the carrier to wolfSSL / BoringSSL on another platform.

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

#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include "authn.h"
#include "logger.h"
#include "transport_quic_tls.h"

/* TLS 1.3 only, the cipher suites QUIC allows, no middlebox compat mode
   (identical to the spike). */
static const char tls_priority[] =
        "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:"
        "+CHACHA20-POLY1305:-GROUP-ALL:+GROUP-X25519:+GROUP-SECP256R1:"
        "%DISABLE_TLS13_COMPAT_MODE";

/* The shared server credential built from the node certificate. */
static gnutls_certificate_credentials_t server_cred;
static bool server_cred_ready;

#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))

/* The public trust store, loaded on the first moved pin. SSL_CERT_FILE wins
   (the lab's CA; the same variable the https carrier's OpenSSL honours), else
   the system store GnuTLS was built to find. */
static gnutls_x509_trust_list_t public_list;
static bool public_list_ready;

bool quic_tls_global_init(void) {
	return gnutls_global_init() >= 0;
}

void quic_tls_global_deinit(void) {
	if(public_list_ready) {
		gnutls_x509_trust_list_deinit(public_list, 1);
		public_list_ready = false;
	}

	gnutls_global_deinit();
}

/* The GnuTLS twin of tls_cert_public_for() (tls.c): is the chain the server
   presented valid today, rooted in a public CA, and issued for `host'? */
static bool chain_public_for(const gnutls_datum_t *certs, unsigned int n, const char *host, char *why, size_t whylen) {
	*why = 0;

	if(!host || !*host || !strcasecmp(host, "localhost")) {
		snprintf(why, whylen, "it was dialled by no name a CA could vouch for (SNI %.64s)", host && *host ? host : "none");
		return false;
	}

	if(!public_list_ready) {
		if(gnutls_x509_trust_list_init(&public_list, 0) < 0) {
			snprintf(why, whylen, "no trust store");
			return false;
		}

		const char *file = getenv("SSL_CERT_FILE");

		if(file && *file) {
			gnutls_x509_trust_list_add_trust_file(public_list, file, NULL, GNUTLS_X509_FMT_PEM, 0, 0);
		} else {
			gnutls_x509_trust_list_add_system_trust(public_list, 0, 0);
		}

		public_list_ready = true;
	}

	gnutls_x509_crt_t crts[16];
	unsigned int count = 0;

	for(unsigned int i = 0; i < n && count < 16; i++) {
		if(gnutls_x509_crt_init(&crts[count]) < 0) {
			break;
		}

		if(gnutls_x509_crt_import(crts[count], &certs[i], GNUTLS_X509_FMT_DER) < 0) {
			gnutls_x509_crt_deinit(crts[count]);
			break;
		}

		count++;
	}

	bool ok = false;

	if(count) {
		gnutls_typed_vdata_st data[2] = {
			{.type = GNUTLS_DT_DNS_HOSTNAME, .data = (unsigned char *)host, .size = 0},
			{.type = GNUTLS_DT_KEY_PURPOSE_OID, .data = (unsigned char *)GNUTLS_KP_TLS_WWW_SERVER, .size = 0},
		};
		unsigned int status = 0;

		if(gnutls_x509_trust_list_verify_crt2(public_list, crts, count, data, 2, 0, &status, NULL) >= 0 && !status) {
			ok = true;
		} else {
			gnutls_datum_t text = {NULL, 0};

			if(status && gnutls_certificate_verification_status_print(status, GNUTLS_CRT_X509, &text, 0) >= 0) {
				snprintf(why, whylen, "%s", text.data);
				gnutls_free(text.data);
			} else {
				snprintf(why, whylen, "it could not be verified");
			}
		}
	}

	for(unsigned int i = 0; i < count; i++) {
		gnutls_x509_crt_deinit(crts[i]);
	}

	return ok;
}

bool quic_tls_set_server_cert(const char *cert_pem, const char *key_pem) {
	gnutls_certificate_credentials_t cred;

	if(gnutls_certificate_allocate_credentials(&cred) < 0) {
		return false;
	}

	gnutls_datum_t cert = {(unsigned char *)cert_pem, (unsigned int)strlen(cert_pem)};
	gnutls_datum_t key = {(unsigned char *)key_pem, (unsigned int)strlen(key_pem)};

	if(gnutls_certificate_set_x509_key_mem(cred, &cert, &key, GNUTLS_X509_FMT_PEM) < 0) {
		gnutls_certificate_free_credentials(cred);
		return false;
	}

	if(server_cred_ready) {
		gnutls_certificate_free_credentials(server_cred);
	}

	server_cred = cred;
	server_cred_ready = true;
	return true;
}

void quic_tls_free_server_cert(void) {
	if(server_cred_ready) {
		gnutls_certificate_free_credentials(server_cred);
		server_cred_ready = false;
	}
}

/* Client: verify the server certificate by SHA-256 of its DER, nothing else.
   The expected fingerprint (if any) and the presented one both live in the
   quic_tls_t we recover from the session pointer. */
static int verify_pin(gnutls_session_t session) {
	ngtcp2_crypto_conn_ref *ref = gnutls_session_get_ptr(session);

	if(!ref) {
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	quic_tls_t *t = container_of(ref, quic_tls_t, conn_ref);

	unsigned int n = 0;
	const gnutls_datum_t *certs = gnutls_certificate_get_peers(session, &n);

	if(!certs || !n) {
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	size_t digestlen = QUIC_FP_LEN;

	if(gnutls_fingerprint(GNUTLS_DIG_SHA256, &certs[0], t->peer_fp, &digestlen) < 0 || digestlen != QUIC_FP_LEN) {
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	for(size_t i = 0; i < QUIC_FP_LEN; i++) {
		snprintf(t->peer_fp_hex + 2 * i, 3, "%02x", t->peer_fp[i]);
	}

	t->have_peer_fp = true;

	/* Unpinned: accept on first use (transport_quic.c pins it afterwards). */
	if(!t->pin[0]) {
		return 0;
	}

	if(!strcmp(t->peer_fp_hex, t->pin)) {
		return 0;
	}

	/* The pin moved: a renewal, or someone on path. Only a certificate a
	   public CA issued for the name we dialled gets through, unpinned, and it
	   is re-pinned once SPTPS authenticates the peer (transport_quic.c). */
	char why[160];

	if(!chain_public_for(certs, n, t->sni, why, sizeof(why))) {
		logger(DEBUG_ALWAYS, LOG_ERR, "quic: certificate fingerprint %s does not match the pinned %s, and the new certificate "
		       "is not one a CA issued for %s (%s); refusing. If the peer replaced its certificate, update TlsFingerprint "
		       "in its host record", t->peer_fp_hex, t->pin, t->sni[0] ? t->sni : "localhost", why);
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	logger(DEBUG_ALWAYS, LOG_NOTICE, "quic: the peer presents a new certificate (%s, was %s), issued by a public CA for %s; "
	       "will re-pin it once SPTPS authenticates the peer", t->peer_fp_hex, t->pin, t->sni);
	t->repin = true;
	return 0;
}

bool quic_tls_session_init(quic_tls_t *t, bool server,
                           ngtcp2_conn *(*get_conn)(ngtcp2_crypto_conn_ref *),
                           void *user_data, const char *alpn, const char *sni, const char *pin_hex) {
	int rv;

	t->server = server;
	t->conn_ref.get_conn = get_conn;
	t->conn_ref.user_data = user_data;

	if(server) {
		if(!server_cred_ready) {
			return false;
		}

		t->cred = server_cred;
		t->own_cred = false;
	} else {
		if(gnutls_certificate_allocate_credentials(&t->cred) < 0) {
			return false;
		}

		t->own_cred = true;

		if(pin_hex) {
			strncpy(t->pin, pin_hex, sizeof(t->pin) - 1);
		}

		if(sni) {
			strncpy(t->sni, sni, sizeof(t->sni) - 1);
		}

		gnutls_certificate_set_verify_function(t->cred, verify_pin);
	}

	unsigned int flags = server ? GNUTLS_SERVER : GNUTLS_CLIENT;

	if(server) {
		flags |= GNUTLS_NO_AUTO_SEND_TICKET;
	}

	if((rv = gnutls_init(&t->session, flags)) < 0) {
		goto fail;
	}

	rv = server ? ngtcp2_crypto_gnutls_configure_server_session(t->session)
	     : ngtcp2_crypto_gnutls_configure_client_session(t->session);

	if(rv) {
		goto fail;
	}

	if((rv = gnutls_priority_set_direct(t->session, tls_priority, NULL)) < 0) {
		goto fail;
	}

	gnutls_session_set_ptr(t->session, &t->conn_ref);

	if((rv = gnutls_credentials_set(t->session, GNUTLS_CRD_CERTIFICATE, t->cred)) < 0) {
		goto fail;
	}

	if(alpn && *alpn) {
		gnutls_datum_t ad = {(unsigned char *)alpn, (unsigned int)strlen(alpn)};
		gnutls_alpn_set_protocols(t->session, &ad, 1,
		                          GNUTLS_ALPN_MANDATORY | (server ? GNUTLS_ALPN_SERVER_PRECEDENCE : 0));
	}

	if(!server && sni && *sni) {
		gnutls_server_name_set(t->session, GNUTLS_NAME_DNS, sni, strlen(sni));
	}

	return true;

fail:

	if(t->session) {
		gnutls_deinit(t->session);
		t->session = NULL;
	}

	if(t->own_cred) {
		gnutls_certificate_free_credentials(t->cred);
		t->own_cred = false;
	}

	return false;
}

void quic_tls_session_free(quic_tls_t *t) {
	if(t->session) {
		gnutls_deinit(t->session);
		t->session = NULL;
	}

	if(t->own_cred) {
		gnutls_certificate_free_credentials(t->cred);
		t->own_cred = false;
	}
}

bool quic_tls_exporter(gnutls_session_t session, uint8_t *out, size_t outlen) {
	return gnutls_prf_rfc5705(session, strlen(AUTHN_EXPORTER_LABEL), AUTHN_EXPORTER_LABEL,
	                          0, NULL, outlen, (char *)out) >= 0;
}

#endif /* HAVE_QUIC */
