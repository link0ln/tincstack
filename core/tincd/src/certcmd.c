/*
    certcmd.c -- `tinc cert': show, check and obtain the node's TLS certificate.

    The daemon never does this work (see acme.h): issuing blocks for as long as
    a CA takes, and the daemon's main loop is not allowed to block. This runs
    in the CLI, writes the result into the config, and asks a running daemon to
    reload.

    Subcommands:
      tinc cert status          what certificate this node presents today
      tinc cert check           is the Cloudflare token usable for CertDomain?
      tinc cert issue [--force] [--staging]
      tinc cert renew  [--staging]   issue only when it is about to expire

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

#include "certcmd.h"

#ifdef HAVE_OPENSSL

#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "acme.h"
#include "control_common.h"
#include "names.h"
#include "tincctl.h"
#include "tls.h"
#include "utils.h"
#include "xalloc.h"
#include "yamlconf.h"

#define LE_STAGING "https://acme-staging-v02.api.letsencrypt.org/directory"
/* Renew this far before expiry: the same margin every ACME client uses, and
   far enough from Let's Encrypt's 90 days that a week of failures is
   survivable. AcmeRenewDays overrides it, for a CA that issues shorter-lived
   certificates than Let's Encrypt does. */
#define RENEW_DAYS_DEFAULT 30

static const char *opt(const char *key, const char *fallback) {
	const char *v = yamlconf_get_option(yamlconf_global, netname, key);
	return v && *v ? v : fallback;
}

static bool progress(const char *step, void *ctx) {
	(void) ctx;
	fprintf(stderr, "  ... %s\n", step);
	return true;
}

/* ---- certificate inspection --------------------------------------------- */

static X509 *first_cert(const char *pem) {
	if(!pem || !*pem) {
		return NULL;
	}

	BIO *bio = BIO_new_mem_buf(pem, -1);

	if(!bio) {
		return NULL;
	}

	X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	BIO_free(bio);
	return cert;
}

/* Days until notAfter; negative when it has already expired, INT_MIN when the
   certificate carries no usable date. */
static int days_left(X509 *cert) {
	int days = 0, secs = 0;

	if(!ASN1_TIME_diff(&days, &secs, NULL, X509_get0_notAfter(cert))) {
		return INT_MIN;
	}

	return days;
}

static bool cert_covers(X509 *cert, const char *domain) {
	return domain && *domain && X509_check_host(cert, domain, strlen(domain), 0, NULL) == 1;
}

static bool is_self_signed(X509 *cert) {
	return X509_NAME_cmp(X509_get_subject_name(cert), X509_get_issuer_name(cert)) == 0;
}

static void print_name(const char *label, X509_NAME *name) {
	char buf[256] = "";

	if(X509_NAME_get_text_by_NID(name, NID_commonName, buf, sizeof(buf)) > 0) {
		printf("%-14s %s\n", label, buf);
	}
}

/* What the certificate is actually valid for. The subject CN is optional and
   increasingly absent -- the SAN list is the answer, so print that. */
static void print_san(X509 *cert) {
	GENERAL_NAMES *names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);

	if(!names) {
		printf("%-14s none (this certificate is valid for no name at all)\n", "Valid for");
		return;
	}

	char list[512] = "";

	for(int i = 0; i < sk_GENERAL_NAME_num(names); i++) {
		const GENERAL_NAME *gn = sk_GENERAL_NAME_value(names, i);

		if(gn->type != GEN_DNS) {
			continue;
		}

		const char *dns = (const char *) ASN1_STRING_get0_data(gn->d.dNSName);
		size_t used = strlen(list);
		snprintf(list + used, sizeof(list) - used, "%s%s", used ? ", " : "", dns ? dns : "?");
	}

	GENERAL_NAMES_free(names);
	printf("%-14s %s\n", "Valid for", *list ? list : "no DNS names");
}

static int cmd_status(void) {
	const char *pem = yamlconf_key_pem(yamlconf_global, netname, "tls_cert");
	const char *domain = opt("CertDomain", NULL);

	printf("%-14s %s\n", "CertDomain", domain ? domain : "(unset)");
	printf("%-14s %s\n", "Cloudflare", opt("CloudflareToken", NULL) ? "token set" : "no token set");

	X509 *cert = first_cert(pem);

	if(!cert) {
		printf("%-14s none stored yet -- the daemon generates a self-signed one at first start\n",
		       "Certificate");
		return 0;
	}

	print_name("Subject", X509_get_subject_name(cert));
	print_name("Issuer", X509_get_issuer_name(cert));
	print_san(cert);

	char fp[TLS_FP_HEX_LEN] = "";

	if(tls_cert_pem_fingerprint(pem, fp)) {
		printf("%-14s %s\n", "Fingerprint", fp);
	}

	int d = days_left(cert);

	if(d == INT_MIN) {
		printf("%-14s unreadable\n", "Expires");
	} else if(d < 0) {
		printf("%-14s EXPIRED %d days ago\n", "Expires", -d);
	} else {
		printf("%-14s in %d days\n", "Expires", d);
	}

	printf("%-14s %s\n", "Kind", is_self_signed(cert)
	       ? "self-signed (peers pin the fingerprint; nothing else trusts it)"
	       : "issued by a CA");

	if(domain && !cert_covers(cert, domain)) {
		printf("\nThis certificate is not valid for %s. `tinc cert issue' would replace it.\n", domain);
	}

	X509_free(cert);
	return 0;
}

/* ---- writing the result back -------------------------------------------- */

/* Our own host record carries TlsFingerprint, and zeroconf only ever writes it
   when it is absent -- so replacing the certificate without rewriting this
   line would leave every future invitation handing out a pin for a certificate
   that no longer exists. */
static char *host_text_with_fingerprint(const char *text, const char *fp) {
	size_t cap = (text ? strlen(text) : 0) + TLS_FP_HEX_LEN + 32;
	char *out = xmalloc(cap);
	size_t len = 0;
	bool replaced = false;

	for(const char *line = text; line && *line;) {
		const char *eol = strchr(line, '\n');
		size_t linelen = eol ? (size_t)(eol - line) : strlen(line);

		if(!strncasecmp(line, "TlsFingerprint", 14)) {
			len += (size_t) snprintf(out + len, cap - len, "TlsFingerprint = %s\n", fp);
			replaced = true;
		} else {
			memcpy(out + len, line, linelen);
			len += linelen;
			out[len++] = '\n';
		}

		line = eol ? eol + 1 : NULL;
	}

	if(!replaced) {
		len += (size_t) snprintf(out + len, cap - len, "TlsFingerprint = %s\n", fp);
	}

	out[len] = 0;
	return out;
}

static bool store_result(const acme_result_t *res, const char *fp, char **why) {
	if(!yamlconf_lock(yamlconf_path)) {
		xasprintf(why, "could not lock %s: %s", yamlconf_path, strerror(errno));
		return false;
	}

	if(!yamlconf_reload_global() || !yamlconf_global) {
		yamlconf_unlock();
		xasprintf(why, "could not re-read %s", yamlconf_path);
		return false;
	}

	yamlconf_set_key_pem(yamlconf_global, netname, "tls_cert", res->cert_pem);
	yamlconf_set_key_pem(yamlconf_global, netname, "tls_key", res->key_pem);

	if(res->account_key_pem) {
		yamlconf_set_key_pem(yamlconf_global, netname, "acme_account", res->account_key_pem);
	}

	const char *myname = yamlconf_get_option(yamlconf_global, netname, "Name");

	if(myname && yamlconf_has_host(yamlconf_global, netname, myname)) {
		char *text = yamlconf_host_text(yamlconf_global, netname, myname);
		char *updated = host_text_with_fingerprint(text, fp);
		yamlconf_host_set_text(yamlconf_global, netname, myname, updated);
		free(text);
		free(updated);
	}

	bool saved = yamlconf_save(yamlconf_global, yamlconf_path);
	yamlconf_unlock();

	if(!saved) {
		xasprintf(why, "could not write %s: %s", yamlconf_path, strerror(errno));
		return false;
	}

	return true;
}

/* ---- issue / renew ------------------------------------------------------- */

static void report(acme_rc_t rc, const acme_result_t *res) {
	if(rc == ACME_OK) {
		fprintf(stderr, "%s\n", res->detail);
		return;
	}

	fprintf(stderr, "\ntinc cert: FAILED (%s)\n  %s\n", acme_rc_name(rc), res->detail);

	if(*res->hint) {
		fprintf(stderr, "  %s\n", res->hint);
	}
}

static int issue(bool staging, bool force, bool renew_only) {
	if(!yamlconf_path || !yamlconf_global) {
		fprintf(stderr, "tinc cert needs a YAML config; this network uses a confbase tree.\n");
		return 1;
	}

	/* Our own copy: store_result() re-reads the config, which frees every
	   string yamlconf_global owned -- including the one opt() just returned. */
	const char *configured = opt("CertDomain", NULL);
	char *domain = configured ? xstrdup(configured) : NULL;

	if(renew_only && domain) {
		const char *pem = yamlconf_key_pem(yamlconf_global, netname, "tls_cert");
		X509 *cert = first_cert(pem);

		if(cert) {
			int d = days_left(cert);
			bool covers = cert_covers(cert, domain);
			bool ca_issued = !is_self_signed(cert);
			X509_free(cert);

			int margin = atoi(opt("AcmeRenewDays", "0"));

			if(margin <= 0) {
				margin = RENEW_DAYS_DEFAULT;
			}

			if(covers && ca_issued && d != INT_MIN && d > margin && !force) {
				printf("The certificate for %s is valid for another %d days; nothing to do.\n", domain, d);
				printf("Use `tinc cert issue --force' to replace it anyway.\n");
				free(domain);
				return 0;
			}
		}
	}

	acme_params_t p = {
		.domain = domain,
		.cf_token = opt("CloudflareToken", NULL),
		.directory = staging ? LE_STAGING : opt("AcmeDirectory", NULL),
		.contact = opt("AcmeContact", NULL),
		.ca_file = opt("AcmeCaFile", NULL),
		.cf_api = opt("CloudflareApi", NULL),
		.propagation_s = atoi(opt("AcmePropagation", "0")),
		.poll_s = atoi(opt("AcmePollTimeout", "0")),
		.progress = progress,
	};

	if(staging) {
		fprintf(stderr, "Using the Let's Encrypt staging CA: the certificate will NOT be publicly trusted.\n");
	}

	const char *account = yamlconf_key_pem(yamlconf_global, netname, "acme_account");
	acme_result_t res;
	acme_rc_t rc = acme_issue(&p, account, &res);
	report(rc, &res);

	if(rc != ACME_OK) {
		acme_result_free(&res);
		free(domain);
		return 1;
	}

	char fp[TLS_FP_HEX_LEN] = "";

	if(!tls_cert_pem_fingerprint(res.cert_pem, fp)) {
		fprintf(stderr, "The CA returned something that is not a certificate; nothing was stored.\n");
		acme_result_free(&res);
		free(domain);
		return 1;
	}

	char *why = NULL;

	if(!store_result(&res, fp, &why)) {
		fprintf(stderr, "The certificate was issued but could not be stored: %s\n", why);
		fprintf(stderr, "Nothing is lost -- run `tinc cert issue' again once that is fixed.\n");
		free(why);
		acme_result_free(&res);
		free(domain);
		return 1;
	}

	printf("Stored the certificate for %s.\n", domain);
	printf("New TlsFingerprint: %s\n", fp);
	printf("\nTwo things peers need before this helps them:\n"
	       "  1. TlsFingerprint. Peers that pinned the old one will refuse an https or quic\n"
	       "     connection to this node until they learn the new one -- re-issue their\n"
	       "     invitation, or update TlsFingerprint in their host record for this node.\n"
	       "  2. Address = %s in this node's host record, so that the SNI they send matches\n"
	       "     the certificate. An IP address there makes the connection look like a\n"
	       "     certificate presented to a bare IP, which is exactly what it was before.\n",
	       domain);

	acme_result_free(&res);
	free(domain);

	/* Tell a running daemon to re-read the config; tls.c picks up the stored
	   certificate on reload, so no restart is needed. */
	if(connect_tincd(false)) {
		sendline(fd, "%d %d", CONTROL, REQ_RELOAD);
		recvline(fd, line, sizeof(line));
		printf("Asked the running daemon to reload its configuration.\n");
	} else {
		printf("No daemon is running here; the new certificate is used at its next start.\n");
	}

	return 0;
}

static int check(void) {
	acme_params_t p = {
		.domain = opt("CertDomain", NULL),
		.cf_token = opt("CloudflareToken", NULL),
		.ca_file = opt("AcmeCaFile", NULL),
		.cf_api = opt("CloudflareApi", NULL),
	};
	acme_result_t res;
	acme_rc_t rc = acme_check_token(&p, &res);
	report(rc, &res);
	acme_result_free(&res);
	return rc == ACME_OK ? 0 : 1;
}

int cert_command(int argc, char *argv[]) {
	bool staging = false, force = false;
	const char *sub = NULL;

	for(int i = 1; i < argc; i++) {
		if(!strcmp(argv[i], "--staging")) {
			staging = true;
		} else if(!strcmp(argv[i], "--force")) {
			force = true;
		} else if(!sub) {
			sub = argv[i];
		} else {
			fprintf(stderr, "Unknown argument `%s'.\n", argv[i]);
			return 1;
		}
	}

	if(!sub || !strcmp(sub, "status")) {
		return cmd_status();
	}

	if(!strcmp(sub, "check")) {
		return check();
	}

	if(!strcmp(sub, "issue")) {
		return issue(staging, force, false);
	}

	if(!strcmp(sub, "renew")) {
		return issue(staging, force, true);
	}

	fprintf(stderr, "Usage: tinc cert [status | check | issue | renew] [--staging] [--force]\n");
	return 1;
}

#else

int cert_command(int argc, char *argv[]) {
	(void) argc;
	(void) argv;
	fprintf(stderr, "This build has no OpenSSL, so it has no TLS certificate to manage.\n");
	return 1;
}

#endif
