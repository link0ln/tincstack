/*
    tls.c -- node certificate automation and the shared libssl contexts.

    See tls.h. This file owns everything OpenSSL-TLS: generating and persisting
    the node's self-signed certificate, loading a real one when configured,
    computing the SHA-256 fingerprint that peers pin, and building the server
    and client SSL_CTX objects the https carrier and the decoy use.

    Peer authenticity on an `https` link is NOT established by the TLS PKI: the
    client verifies the server by the pinned SHA-256 fingerprint (see
    https.c / transports.md), and the server verifies the client by an
    Ed25519 authenticator carried inside the TLS session. TLS here is a
    carrier and an active-probing decoy, not the trust root -- that stays
    SPTPS/Ed25519 (principle 1).

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

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "conf.h"
#include "logger.h"
#include "names.h"
#include "tls.h"
#include "xalloc.h"
#include "yamlconf.h"

bool tls_ready;
SSL_CTX *tls_server_ctx;
SSL_CTX *tls_client_ctx;
uint8_t tls_own_fp[TLS_FP_LEN];
char tls_own_fp_hex[TLS_FP_HEX_LEN];
char *tls_cert_source;

/* When the loaded certificate stops being valid, and when we last said so.
   Both zero until a certificate is loaded. */
static time_t tls_cert_expires_at;
static time_t tls_expiry_warned_at;

/* http/1.1 ALPN wire form: one length-prefixed protocol name. */
static const uint8_t alpn_http11[] = { 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };

/* ---- small helpers ------------------------------------------------------- */

static void tls_log_errors(const char *what) {
	unsigned long e;

	while((e = ERR_get_error())) {
		logger(DEBUG_ALWAYS, LOG_ERR, "TLS %s: %s", what, ERR_error_string(e, NULL));
	}
}

char *tls_read_file(const char *path) {
	FILE *f = fopen(path, "rb");

	if(!f) {
		return NULL;
	}

	if(fseek(f, 0, SEEK_END)) {
		fclose(f);
		return NULL;
	}

	long sz = ftell(f);

	if(sz < 0) {
		fclose(f);
		return NULL;
	}

	rewind(f);
	char *buf = xmalloc((size_t)sz + 1);
	size_t rd = fread(buf, 1, (size_t)sz, f);
	fclose(f);
	buf[rd] = 0;
	return buf;
}

bool tls_fingerprint_valid(char *s) {
	if(!s) {
		return false;
	}

	size_t n = strlen(s);

	if(n != 2 * TLS_FP_LEN) {
		return false;
	}

	for(size_t i = 0; i < n; i++) {
		if(!isxdigit((uint8_t) s[i])) {
			return false;
		}

		s[i] = (char) tolower((uint8_t) s[i]);
	}

	return true;
}

/* ---- fingerprint --------------------------------------------------------- */

bool tls_x509_fingerprint(X509 *cert, uint8_t *raw, char *hex) {
	uint8_t md[EVP_MAX_MD_SIZE];
	unsigned int mdlen = 0;

	if(!X509_digest(cert, EVP_sha256(), md, &mdlen) || mdlen != TLS_FP_LEN) {
		return false;
	}

	if(raw) {
		memcpy(raw, md, TLS_FP_LEN);
	}

	if(hex) {
		for(unsigned int i = 0; i < TLS_FP_LEN; i++) {
			snprintf(hex + 2 * i, 3, "%02x", md[i]);
		}
	}

	return true;
}

static X509 *cert_from_pem(const char *cert_pem) {
	BIO *bio = BIO_new_mem_buf(cert_pem, -1);

	if(!bio) {
		return NULL;
	}

	X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	BIO_free(bio);
	return cert;
}

bool tls_cert_pem_fingerprint(const char *cert_pem, char *hex) {
	X509 *cert = cert_from_pem(cert_pem);

	if(!cert) {
		return false;
	}

	bool ok = tls_x509_fingerprint(cert, NULL, hex);
	X509_free(cert);
	return ok;
}

/* ---- generation ---------------------------------------------------------- */

static EVP_PKEY *generate_ec_key(void) {
	/* P-256: universally supported for TLS server auth on OpenSSL 3.0; a
	   scanner sees exactly the key type a typical HTTPS server uses. */
	return EVP_EC_gen("P-256");
}

static bool add_ext(X509 *cert, int nid, const char *value) {
	X509V3_CTX ctx;
	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);

	if(!ext) {
		return false;
	}

	bool ok = X509_add_ext(cert, ext, -1) != 0;
	X509_EXTENSION_free(ext);
	return ok;
}

static bool pem_to_string(int (*writer)(BIO *, const void *), const void *obj, char **out) {
	BIO *bio = BIO_new(BIO_s_mem());

	if(!bio) {
		return false;
	}

	if(!writer(bio, obj)) {
		BIO_free(bio);
		return false;
	}

	char *data = NULL;
	long len = BIO_get_mem_data(bio, &data);
	char *s = xmalloc((size_t) len + 1);
	memcpy(s, data, (size_t) len);
	s[len] = 0;

	while(len && (s[len - 1] == '\n' || s[len - 1] == '\r')) {
		s[--len] = 0;
	}

	*out = s;
	BIO_free(bio);
	return true;
}

static int write_privkey(BIO *bio, const void *key) {
	return PEM_write_bio_PrivateKey(bio, (EVP_PKEY *) key, NULL, NULL, 0, NULL, NULL);
}

static int write_cert(BIO *bio, const void *cert) {
	return PEM_write_bio_X509(bio, (X509 *)(uintptr_t) cert);
}

bool tls_generate_pem(const char *cn, char **cert_pem, char **key_pem) {
	bool ok = false;
	EVP_PKEY *pkey = generate_ec_key();
	X509 *cert = NULL;

	if(!pkey) {
		tls_log_errors("key generation");
		goto end;
	}

	cert = X509_new();

	if(!cert) {
		goto end;
	}

	X509_set_version(cert, 2); /* v3 */

	/* Random 64-bit serial, like a real CA-issued or ACME cert. */
	uint8_t serial[8];

	if(RAND_bytes(serial, sizeof(serial)) != 1) {
		goto end;
	}

	serial[0] &= 0x7f; /* keep it positive */
	BIGNUM *bn = BN_bin2bn(serial, sizeof(serial), NULL);

	if(bn) {
		BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(cert));
		BN_free(bn);
	}

	X509_gmtime_adj(X509_getm_notBefore(cert), 0);
	X509_gmtime_adj(X509_getm_notAfter(cert), (long) TLS_CERT_VALIDITY_DAYS * 24 * 3600);

	if(!X509_set_pubkey(cert, pkey)) {
		goto end;
	}

	X509_NAME *name = X509_get_subject_name(cert);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const uint8_t *) cn, -1, -1, 0);
	X509_set_issuer_name(cert, name); /* self-signed */

	/* Minimal, plausible extension set for a TLS server certificate. */
	add_ext(cert, NID_basic_constraints, "critical,CA:FALSE");
	add_ext(cert, NID_key_usage, "critical,digitalSignature,keyEncipherment");
	add_ext(cert, NID_ext_key_usage, "serverAuth");
	add_ext(cert, NID_subject_key_identifier, "hash");

	char san[300];
	snprintf(san, sizeof(san), "DNS:%s", cn);
	add_ext(cert, NID_subject_alt_name, san);

	if(!X509_sign(cert, pkey, EVP_sha256())) {
		tls_log_errors("certificate signing");
		goto end;
	}

	if(!pem_to_string(write_privkey, pkey, key_pem)) {
		goto end;
	}

	if(!pem_to_string(write_cert, cert, cert_pem)) {
		free(*key_pem);
		*key_pem = NULL;
		goto end;
	}

	ok = true;

end:

	if(cert) {
		X509_free(cert);
	}

	if(pkey) {
		EVP_PKEY_free(pkey);
	}

	return ok;
}

/* ---- context building ---------------------------------------------------- */

static int alpn_select_cb(SSL *ssl, const uint8_t **out, uint8_t *outlen,
                          const uint8_t *in, unsigned int inlen, void *arg) {
	(void) ssl;
	(void) arg;

	/* Offer http/1.1 if the client listed it; otherwise let the handshake
	   proceed with no negotiated protocol (a plain HTTPS client is happy). */
	if(SSL_select_next_proto((uint8_t **) out, outlen, alpn_http11, sizeof(alpn_http11), in, inlen) == OPENSSL_NPN_NEGOTIATED) {
		return SSL_TLSEXT_ERR_OK;
	}

	return SSL_TLSEXT_ERR_NOACK;
}

static SSL_CTX *build_server_ctx(const char *cert_pem, const char *key_pem) {
	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

	if(!ctx) {
		tls_log_errors("server context");
		return NULL;
	}

	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);
	SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	BIO *cbio = BIO_new_mem_buf(cert_pem, -1);
	X509 *cert = cbio ? PEM_read_bio_X509(cbio, NULL, NULL, NULL) : NULL;

	if(cbio) {
		BIO_free(cbio);
	}

	BIO *kbio = BIO_new_mem_buf(key_pem, -1);
	EVP_PKEY *key = kbio ? PEM_read_bio_PrivateKey(kbio, NULL, NULL, NULL) : NULL;

	if(kbio) {
		BIO_free(kbio);
	}

	if(!cert || !key || SSL_CTX_use_certificate(ctx, cert) != 1 || SSL_CTX_use_PrivateKey(ctx, key) != 1 || SSL_CTX_check_private_key(ctx) != 1) {
		tls_log_errors("loading server certificate");
		SSL_CTX_free(ctx);
		ctx = NULL;
	}

	/* Append any intermediates in the PEM chain after the leaf. */
	if(ctx) {
		BIO *chain = BIO_new_mem_buf(cert_pem, -1);

		if(chain) {
			X509 *leaf = PEM_read_bio_X509(chain, NULL, NULL, NULL); /* skip leaf */

			if(leaf) {
				X509_free(leaf);
			}

			X509 *ca;

			while((ca = PEM_read_bio_X509(chain, NULL, NULL, NULL))) {
				if(SSL_CTX_add_extra_chain_cert(ctx, ca) != 1) {
					X509_free(ca);
				}
			}

			BIO_free(chain);
		}

		SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, NULL);
	}

	if(cert) {
		X509_free(cert);
	}

	if(key) {
		EVP_PKEY_free(key);
	}

	return ctx;
}

static SSL_CTX *build_client_ctx(void) {
	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

	if(!ctx) {
		tls_log_errors("client context");
		return NULL;
	}

	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

	/* No PKI verification on purpose: an `https` peer is pinned by its
	   SHA-256 fingerprint (accept-on-first-use, then pinned) and then
	   authenticated with an Ed25519 authenticator bound to the TLS exporter.
	   Chasing a public CA chain here would leak nothing useful and would
	   break the self-signed default. See https.c. */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_alpn_protos(ctx, alpn_http11, sizeof(alpn_http11));
	return ctx;
}

/* ---- persistence of the generated certificate ---------------------------- */

/* Where the certificate/key come from and how a freshly generated one is
   persisted differs between YAML mode and classic confbase mode; both keep
   the pattern zeroconf.c uses for the Ed25519 key. */

static bool load_or_generate(char **cert_pem, char **key_pem, const char **source) {
	char *tls_cert_opt = NULL, *tls_key_opt = NULL;
	get_config_string(lookup_config(&config_tree, "TlsCert"), &tls_cert_opt);
	get_config_string(lookup_config(&config_tree, "TlsKey"), &tls_key_opt);

	/* 1. Explicit files win and are never persisted (they are the operator's). */
	if(tls_cert_opt && tls_key_opt) {
		*cert_pem = tls_read_file(tls_cert_opt);
		*key_pem = tls_read_file(tls_key_opt);
		free(tls_cert_opt);
		free(tls_key_opt);

		if(!*cert_pem || !*key_pem) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not read TlsCert/TlsKey files");
			free(*cert_pem);
			free(*key_pem);
			*cert_pem = *key_pem = NULL;
			return false;
		}

		*source = "TlsCert/TlsKey files";
		return true;
	}

	free(tls_cert_opt);
	free(tls_key_opt);

	/* 2. YAML mode: the persisted PEMs live in keys.tls_cert/tls_key. */
	if(yamlconf_global && netname) {
		const char *c = yamlconf_key_pem(yamlconf_global, netname, "tls_cert");
		const char *k = yamlconf_key_pem(yamlconf_global, netname, "tls_key");

		if(c && k) {
			*cert_pem = xstrdup(c);
			*key_pem = xstrdup(k);
			*source = "generated self-signed (YAML keys)";
			return true;
		}

		/* Generate + persist (a config that predates M5, or an edited-away
		   key). Uses the node name if valid, else the generic default. */
		/* CN/SAN = a generic "localhost": a self-signed localhost certificate is
	   the ordinary default of countless idle servers and IoT devices, so a
	   scanner learns nothing. Using the node name would let a scanner
	   correlate the port with a specific mesh node (the mistake the
	   tinc-vless front made with a cert named after itself). */
	const char *cn = TLS_DEFAULT_CN;

		if(!tls_generate_pem(cn, cert_pem, key_pem)) {
			return false;
		}

		yamlconf_set_key_pem(yamlconf_global, netname, "tls_cert", *cert_pem);
		yamlconf_set_key_pem(yamlconf_global, netname, "tls_key", *key_pem);

		if(!yamlconf_save(yamlconf_global, yamlconf_path)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not persist generated TLS certificate to `%s'", yamlconf_path);
			/* Keep running with the in-memory cert; it will regenerate next
			   start, changing the fingerprint. Warn loudly. */
		} else {
			logger(DEBUG_ALWAYS, LOG_NOTICE, "Generated a self-signed TLS certificate into `%s' [%s]", yamlconf_path, netname);
		}

		*source = "generated self-signed (YAML keys)";
		return true;
	}

	/* 3. Classic confbase mode: tls_cert.pem / tls_key.pem next to the keys. */
	char certpath[PATH_MAX], keypath[PATH_MAX];
	snprintf(certpath, sizeof(certpath), "%s" SLASH "tls_cert.pem", confbase);
	snprintf(keypath, sizeof(keypath), "%s" SLASH "tls_key.pem", confbase);

	*cert_pem = tls_read_file(certpath);
	*key_pem = tls_read_file(keypath);

	if(*cert_pem && *key_pem) {
		*source = "generated self-signed (confbase files)";
		return true;
	}

	free(*cert_pem);
	free(*key_pem);
	*cert_pem = *key_pem = NULL;

	/* CN/SAN = a generic "localhost": a self-signed localhost certificate is
	   the ordinary default of countless idle servers and IoT devices, so a
	   scanner learns nothing. Using the node name would let a scanner
	   correlate the port with a specific mesh node (the mistake the
	   tinc-vless front made with a cert named after itself). */
	const char *cn = TLS_DEFAULT_CN;

	if(!tls_generate_pem(cn, cert_pem, key_pem)) {
		return false;
	}

	FILE *cf = fopen(certpath, "w");

	if(cf) {
		fprintf(cf, "%s\n", *cert_pem);
		fclose(cf);
	}

	/* The key file is created with mode 0600 from the start (M5-11): no
	   window in which it exists with umask permissions. A stale file is
	   replaced rather than truncated in place. */
	unlink(keypath);
	int kfd = open(keypath, O_WRONLY | O_CREAT | O_EXCL, 0600);
	FILE *kf = kfd >= 0 ? fdopen(kfd, "w") : NULL;

	if(kf) {
		fprintf(kf, "%s\n", *key_pem);
		fclose(kf);
	} else if(kfd >= 0) {
		close(kfd);
	}

	logger(DEBUG_ALWAYS, LOG_NOTICE, "Generated a self-signed TLS certificate into `%s'", confbase);
	*source = "generated self-signed (confbase files)";
	return true;
}

/* Hand the node certificate's PEM to another carrier (the quic carrier's
   GnuTLS backend) without a second load path: the same load_or_generate() the
   HTTPS front uses. Caller frees both; the key PEM should be zeroed after use. */
bool tls_current_pem(char **cert_pem, char **key_pem) {
	const char *source = NULL;
	*cert_pem = *key_pem = NULL;
	return load_or_generate(cert_pem, key_pem, &source);
}

/* ---- init / exit --------------------------------------------------------- */

/* ---- expiry ------------------------------------------------------------- */

/* When the first certificate in `cert_pem` stops being valid, or 0 if that
   cannot be worked out. ASN1_TIME_diff against "now" rather than a conversion
   to time_t: it is the portable path, and it is what `tinc cert status` uses,
   so the two never disagree. */
static time_t cert_pem_expiry(const char *cert_pem) {
	X509 *cert = cert_from_pem(cert_pem);

	if(!cert) {
		return 0;
	}

	int days = 0, secs = 0;
	time_t at = 0;

	if(ASN1_TIME_diff(&days, &secs, NULL, X509_get0_notAfter(cert))) {
		at = time(NULL) + (time_t) days * 86400 + secs;
	}

	X509_free(cert);
	return at;
}

/* Say something while there is still time to act.

   Nothing renews a certificate on its own -- `tinc cert renew` is a command
   someone or something has to run -- so a node whose certificate quietly
   expires keeps working (peers pin the fingerprint, they never check dates)
   while the front it presents becomes *more* remarkable than the self-signed
   one it replaced. An expired certificate on a public HTTPS port is a thing
   an observer notices; that is the whole property the certificate was bought
   to have. This is the daemon's only way to say so.

   Called from the periodic handler, so it throttles itself to one line a day. */
void tls_expiry_warn(void) {
	if(!tls_ready || !tls_cert_expires_at) {
		return;
	}

	time_t now = time(NULL);

	if(tls_expiry_warned_at && now - tls_expiry_warned_at < 86400) {
		return;
	}

	int days = (int)((tls_cert_expires_at - now) / 86400);
	int threshold = 30;                    /* AcmeRenewDays, same default */
	get_config_int(lookup_config(&config_tree, "AcmeRenewDays"), &threshold);

	if(threshold < 1) {
		threshold = 1;
	}

	if(days < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR,
		       "The TLS certificate for the https/quic front (%s) expired %d days ago. "
		       "Run `tinc cert renew' -- peers still connect (they pin the fingerprint), but the "
		       "front now looks broken to anything else.",
		       tls_cert_source ? tls_cert_source : "unknown source", -days);
		tls_expiry_warned_at = now;
	} else if(days <= threshold) {
		logger(DEBUG_ALWAYS, LOG_WARNING,
		       "The TLS certificate for the https/quic front (%s) expires in %d days. Run `tinc cert renew'.",
		       tls_cert_source ? tls_cert_source : "unknown source", days);
		tls_expiry_warned_at = now;
	}
}

bool tls_init(void) {
	char *cert_pem = NULL, *key_pem = NULL;
	const char *source = "unknown";

	if(!load_or_generate(&cert_pem, &key_pem, &source)) {
		return false;
	}

	uint8_t fp[TLS_FP_LEN];
	char fp_hex[TLS_FP_HEX_LEN];

	if(!tls_cert_pem_fingerprint(cert_pem, fp_hex)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not compute the TLS certificate fingerprint");
		free(cert_pem);
		free(key_pem);
		return false;
	}

	tls_cert_expires_at = cert_pem_expiry(cert_pem);

	/* On a reload with an unchanged certificate, keep the existing contexts. */
	if(tls_ready && !strcmp(fp_hex, tls_own_fp_hex)) {
		free(cert_pem);
		free(key_pem);
		return true;
	}

	SSL_CTX *sctx = build_server_ctx(cert_pem, key_pem);
	SSL_CTX *cctx = build_client_ctx();

	memzero(key_pem, strlen(key_pem));
	free(cert_pem);
	free(key_pem);

	if(!sctx || !cctx) {
		if(sctx) {
			SSL_CTX_free(sctx);
		}

		if(cctx) {
			SSL_CTX_free(cctx);
		}

		return false;
	}

	if(tls_server_ctx) {
		SSL_CTX_free(tls_server_ctx);
	}

	if(tls_client_ctx) {
		SSL_CTX_free(tls_client_ctx);
	}

	tls_server_ctx = sctx;
	tls_client_ctx = cctx;
	strncpy(tls_own_fp_hex, fp_hex, sizeof(tls_own_fp_hex));

	for(unsigned int i = 0; i < TLS_FP_LEN; i++) {
		unsigned int b;
		sscanf(fp_hex + 2 * i, "%02x", &b);
		fp[i] = (uint8_t) b;
	}

	memcpy(tls_own_fp, fp, TLS_FP_LEN);
	free(tls_cert_source);
	tls_cert_source = xstrdup(source);
	tls_ready = true;

	logger(DEBUG_ALWAYS, LOG_INFO, "TLS certificate ready (%s), fingerprint %s", source, tls_own_fp_hex);
	return true;
}

void tls_exit(void) {
	if(tls_server_ctx) {
		SSL_CTX_free(tls_server_ctx);
		tls_server_ctx = NULL;
	}

	if(tls_client_ctx) {
		SSL_CTX_free(tls_client_ctx);
		tls_client_ctx = NULL;
	}

	free(tls_cert_source);
	tls_cert_source = NULL;
	tls_ready = false;
}

#endif /* HAVE_OPENSSL */
