#ifndef TINC_ACME_H
#define TINC_ACME_H

/*
    acme.h -- issue the node's TLS certificate from an ACME CA using the
              DNS-01 challenge and Cloudflare as the DNS provider.

    Why this exists: the HTTPS front and the QUIC carrier present the node
    certificate, and by default that certificate is self-signed (tls.c). A
    self-signed certificate is fine for peers -- they pin its fingerprint
    (`TlsFingerprint`) -- but it is exactly what a passive observer expects
    NOT to see on a real HTTPS service, and it is useless to anything that
    validates a chain. An operator who owns a domain in Cloudflare can hand
    the node a token and get a publicly trusted certificate for it instead.

    Where it runs: in `tinc cert ...`, never in the daemon. Every call here
    blocks for as long as a CA takes.

    What it never does: it does not weaken SPTPS, it does not change how peers
    authenticate each other, and it does not make the certificate authoritative
    for anything. Peers still pin the fingerprint; the certificate only changes
    what a third party sees.

    This program is free software; see the GPL v2+ (same as the rest of tinc).
*/

#include "system.h"

/* Every way this can fail, separated because the fix is different for each.
   Nothing here is "unknown error": if a new failure mode appears it gets its
   own code and its own sentence. */
typedef enum {
	ACME_OK = 0,
	ACME_ERR_CONFIG,          /* missing/garbled CertDomain or CloudflareToken */
	ACME_ERR_CF_TOKEN,        /* Cloudflare rejected the token, or it is not active */
	ACME_ERR_CF_PERMISSION,   /* token authenticates but lacks Zone:DNS:Edit / Zone:Read */
	ACME_ERR_CF_ZONE,         /* token is fine but owns no zone covering CertDomain */
	ACME_ERR_CF_API,          /* Cloudflare answered something else we cannot use */
	ACME_ERR_DIRECTORY,       /* the ACME directory did not load or lacks endpoints */
	ACME_ERR_ACCOUNT,         /* account creation refused (ToS, contact, key) */
	ACME_ERR_ORDER,           /* newOrder refused (domain not allowed, policy, CAA) */
	ACME_ERR_CHALLENGE,       /* the CA could not validate the TXT record */
	ACME_ERR_RATELIMIT,       /* the CA is rate-limiting this account or domain */
	ACME_ERR_FINALIZE,        /* CSR refused, or the order never became valid */
	ACME_ERR_NETWORK,         /* DNS, connect, TLS or a malformed HTTP response */
	ACME_ERR_CRYPTO,          /* local key, CSR or signature failure */
	ACME_ERR_INTERNAL,
} acme_rc_t;

typedef struct {
	const char *domain;         /* CertDomain, e.g. vpn.example.com */
	const char *cf_token;       /* CloudflareToken */
	const char *directory;      /* AcmeDirectory; Let's Encrypt when NULL */
	const char *contact;        /* AcmeContact, e.g. mailto:me@example.com; optional */
	const char *ca_file;        /* AcmeCaFile: trust anchor for the CA, tests only */
	const char *cf_api;         /* CloudflareApi: API base URL override, tests only */
	int propagation_s;          /* wait after writing the TXT record (default 20) */
	int poll_s;                 /* how long to wait for validation (default 120) */
	bool (*progress)(const char *step, void *ctx);   /* optional, for the UI/log */
	void *progress_ctx;
} acme_params_t;

typedef struct {
	char *cert_pem;             /* leaf + chain, PEM */
	char *key_pem;              /* the new certificate's private key, PEM */
	char *account_key_pem;      /* the ACME account key: keep it, reuse it */
	char *zone_name;            /* the Cloudflare zone that was used */
	char detail[1024];          /* what went wrong, in one sentence */
	char hint[1024];            /* what to do about it */
} acme_result_t;

/* Issue a certificate for p->domain. `account_key_pem` may be NULL (a new
   account key is generated and returned in out->account_key_pem). On any
   outcome, out->detail and out->hint are filled in and the caller must free
   the strings with acme_result_free(). The TXT record this creates is always
   removed again, success or failure. */
acme_rc_t acme_issue(const acme_params_t *p, const char *account_key_pem, acme_result_t *out);

/* Check the token and the zone without touching the CA -- what the UI calls
   when the operator pastes a token. */
acme_rc_t acme_check_token(const acme_params_t *p, acme_result_t *out);

void acme_result_free(acme_result_t *out);

/* Short stable name of the code, for logs and for the GUI to switch on. */
const char *acme_rc_name(acme_rc_t rc);

#endif
