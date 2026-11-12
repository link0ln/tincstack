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

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "acme.h"
#include "conf.h"
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

	if(days == 0 && secs < 0) {
		return -1;
	}

	return days;
}

static bool cert_covers(X509 *cert, const char *domain) {
	return domain && *domain && X509_check_host(cert, domain, strlen(domain), 0, NULL) == 1;
}

static bool is_self_signed(X509 *cert) {
	return X509_NAME_cmp(X509_get_subject_name(cert), X509_get_issuer_name(cert)) == 0;
}

static bool cert_matches_key_pem(const char *cert_pem, const char *key_pem) {
	if(!cert_pem || !*cert_pem || !key_pem || !*key_pem) {
		return false;
	}

	X509 *cert = first_cert(cert_pem);

	if(!cert) {
		return false;
	}

	BIO *kbio = BIO_new_mem_buf(key_pem, -1);
	EVP_PKEY *pkey = kbio ? PEM_read_bio_PrivateKey(kbio, NULL, NULL, NULL) : NULL;
	BIO_free(kbio);

	bool ok = pkey && X509_check_private_key(cert, pkey) == 1;
	ERR_clear_error();
	EVP_PKEY_free(pkey);
	X509_free(cert);
	return ok;
}

static void print_name(const char *label, X509_NAME *name) {
	char buf[256] = "";

	if(X509_NAME_get_text_by_NID(name, NID_commonName, buf, sizeof(buf)) > 0) {
		for(char *p = buf; *p; p++) {
			unsigned char ch = (unsigned char) *p;

			if(ch < 0x20 || ch >= 0x7f) {
				*p = '?';
			}
		}

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

		const unsigned char *raw = ASN1_STRING_get0_data(gn->d.dNSName);
		int rawlen = ASN1_STRING_length(gn->d.dNSName);
		char clean[256];

		if(!raw || rawlen <= 0) {
			strcpy(clean, "?");
		} else {
			int clen = rawlen < (int) sizeof(clean) - 1 ? rawlen : (int) sizeof(clean) - 1;

			for(int j = 0; j < clen; j++) {
				unsigned char ch = raw[j];
				clean[j] = (ch > 0x20 && ch < 0x7f) ? (char) ch : '?';
			}

			clean[clen] = '\0';
		}

		size_t used = strlen(list);

		if(used + 2 >= sizeof(list)) {
			break;
		}

		snprintf(list + used, sizeof(list) - used, "%s%s", used ? ", " : "", clean);
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
   that no longer exists. host_text_set_var() (conf.c) does the rewrite. */

static bool store_result(const acme_result_t *res, const char *fp, char **why) {
	if(!cert_matches_key_pem(res->cert_pem, res->key_pem)) {
		xasprintf(why, "certificate does not match private key");
		return false;
	}

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

	const char *self = yamlconf_get_option(yamlconf_global, netname, "Name");

	if(self && yamlconf_has_host(yamlconf_global, netname, self)) {
		char *text = yamlconf_host_text(yamlconf_global, netname, self);
		char *updated = host_text_set_var(text, "TlsFingerprint", fp);
		yamlconf_host_set_text(yamlconf_global, netname, self, updated);
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

static int issue(bool staging, bool forced, bool renew_only) {
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
		const char *kpem = yamlconf_key_pem(yamlconf_global, netname, "tls_key");
		X509 *cert = first_cert(pem);

		if(cert) {
			int d = days_left(cert);
			bool covers = cert_covers(cert, domain) && cert_matches_key_pem(pem, kpem);
			bool ca_issued = !is_self_signed(cert);
			X509_free(cert);

			int margin = atoi(opt("AcmeRenewDays", "0"));

			if(margin <= 0) {
				margin = RENEW_DAYS_DEFAULT;
			}

			if(covers && ca_issued && d != INT_MIN && d > margin && !forced) {
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
		if(res.account_key_pem && yamlconf_lock(yamlconf_path)) {
			if(yamlconf_reload_global() && yamlconf_global) {
				yamlconf_set_key_pem(yamlconf_global, netname, "acme_account", res.account_key_pem);
				yamlconf_save(yamlconf_global, yamlconf_path);
			}
			yamlconf_unlock();
		}
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

	if(!cert_matches_key_pem(res.cert_pem, res.key_pem)) {
		fprintf(stderr, "The issued certificate does not match the generated private key; nothing was stored.\n");
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
	printf("\nPeers that pinned the old certificate follow on their own: they accept the new\n"
	       "one for the next connection and re-pin it once SPTPS has authenticated this node.\n"
	       "For the certificate to be worth anything to an observer, peers should reach this\n"
	       "node as Address = %s in its host record, so that the SNI they send matches the\n"
	       "certificate. An IP address there makes the connection look like a certificate\n"
	       "presented to a bare IP, which is exactly what it was before.\n",
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
	bool staging = false, forced = false;
	const char *sub = NULL;

	for(int i = 1; i < argc; i++) {
		if(!strcmp(argv[i], "--staging")) {
			staging = true;
		} else if(!strcmp(argv[i], "--force")) {
			forced = true;
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
		return issue(staging, forced, false);
	}

	if(!strcmp(sub, "renew")) {
		return issue(staging, forced, true);
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
