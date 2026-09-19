/*
    acme.c -- ACME (RFC 8555) with the DNS-01 challenge, Cloudflare provider.

    See acme.h for what this is for and where it may run. The code is written
    so that every failure is attributable: each remote step maps to one
    acme_rc_t and one sentence naming the fix, because the whole point of the
    feature is that an operator pastes a token and either gets a certificate or
    learns exactly which of the six things that can be wrong with a token is
    wrong with theirs.

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

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509v3.h>

#include "acme.h"
#include "httpc.h"
#include "json.h"
#include "xalloc.h"

#define LE_DIRECTORY "https://acme-v02.api.letsencrypt.org/directory"
#define CF_API_DEFAULT "https://api.cloudflare.com/client/v4"

/* Base URL of the Cloudflare API. Overridable only so the test harness can
   point it at a local mock (see testing/acme/); nothing in production should
   set it. */
#define CF_API (c->p->cf_api && *c->p->cf_api ? c->p->cf_api : CF_API_DEFAULT)
#define ACME_DEFAULT_PROPAGATION 20
#define ACME_DEFAULT_POLL 120
#define ACME_HTTP_TIMEOUT 30

typedef struct {
	const acme_params_t *p;
	acme_result_t *out;

	/* ACME */
	char *dir_new_nonce;
	char *dir_new_account;
	char *dir_new_order;
	char *nonce;
	char *kid;                  /* account URL, once registered */
	EVP_PKEY *account_key;

	/* Cloudflare */
	char *zone_id;
	char *record_id;
	char *fqdn;                 /* _acme-challenge.<domain> */
} acme_ctx_t;

/* ---- small helpers ------------------------------------------------------- */

static void say(acme_ctx_t *c, const char *step) {
	if(c->p->progress) {
		c->p->progress(step, c->p->progress_ctx);
	}
}

/* Both of these format through a temporary. Several callers pass c->out->detail
   back in as the detail -- "keep what the transport already said, add a hint" --
   and printing a buffer into itself is undefined behaviour that in practice
   leaves the message empty, which is exactly the report we would then lose. */
static acme_rc_t fail(acme_ctx_t *c, acme_rc_t rc, const char *detail, const char *hint) {
	char buf[sizeof(c->out->detail)];
	snprintf(buf, sizeof(buf), "%s", detail ? detail : "");
	snprintf(c->out->detail, sizeof(c->out->detail), "%s", buf);
	snprintf(buf, sizeof(buf), "%s", hint ? hint : "");
	snprintf(c->out->hint, sizeof(c->out->hint), "%s", buf);
	return rc;
}

static acme_rc_t failf(acme_ctx_t *c, acme_rc_t rc, const char *hint, const char *fmt, ...) ATTR_FORMAT(printf, 4, 5);
static acme_rc_t failf(acme_ctx_t *c, acme_rc_t rc, const char *hint, const char *fmt, ...) {
	char buf[sizeof(c->out->detail)];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	snprintf(c->out->detail, sizeof(c->out->detail), "%s", buf);
	snprintf(buf, sizeof(buf), "%s", hint ? hint : "");
	snprintf(c->out->hint, sizeof(c->out->hint), "%s", buf);
	return rc;
}

const char *acme_rc_name(acme_rc_t rc) {
	switch(rc) {
	case ACME_OK:
		return "ok";

	case ACME_ERR_CONFIG:
		return "config";

	case ACME_ERR_CF_TOKEN:
		return "cloudflare-token";

	case ACME_ERR_CF_PERMISSION:
		return "cloudflare-permission";

	case ACME_ERR_CF_ZONE:
		return "cloudflare-zone";

	case ACME_ERR_CF_API:
		return "cloudflare-api";

	case ACME_ERR_DIRECTORY:
		return "acme-directory";

	case ACME_ERR_ACCOUNT:
		return "acme-account";

	case ACME_ERR_ORDER:
		return "acme-order";

	case ACME_ERR_CHALLENGE:
		return "acme-challenge";

	case ACME_ERR_RATELIMIT:
		return "acme-ratelimit";

	case ACME_ERR_FINALIZE:
		return "acme-finalize";

	case ACME_ERR_NETWORK:
		return "network";

	case ACME_ERR_CRYPTO:
		return "crypto";

	case ACME_ERR_INTERNAL:
	default:
		return "internal";
	}
}

void acme_result_free(acme_result_t *out) {
	if(!out) {
		return;
	}

	free(out->cert_pem);
	free(out->key_pem);
	free(out->account_key_pem);
	free(out->zone_name);
	out->cert_pem = out->key_pem = out->account_key_pem = out->zone_name = NULL;
}

static char *b64url(const void *data, size_t len) {
	size_t outlen = ((len + 2) / 3) * 4 + 1;
	char *tmp = xmalloc(outlen);
	int n = EVP_EncodeBlock((unsigned char *) tmp, data, (int) len);

	if(n < 0) {
		free(tmp);
		return NULL;
	}

	for(int i = 0; i < n; i++) {
		if(tmp[i] == '+') {
			tmp[i] = '-';
		} else if(tmp[i] == '/') {
			tmp[i] = '_';
		} else if(tmp[i] == '=') {
			tmp[i] = 0;
			n = i;
			break;
		}
	}

	tmp[n] = 0;
	return tmp;
}

static void sha256(const void *data, size_t len, uint8_t out[32]) {
	unsigned int n = 32;
	EVP_MD_CTX *md = EVP_MD_CTX_new();
	EVP_DigestInit_ex(md, EVP_sha256(), NULL);
	EVP_DigestUpdate(md, data, len);
	EVP_DigestFinal_ex(md, out, &n);
	EVP_MD_CTX_free(md);
}

static char *pem_of_key(EVP_PKEY *key) {
	BIO *bio = BIO_new(BIO_s_mem());

	if(!bio) {
		return NULL;
	}

	char *out = NULL;

	if(PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL)) {
		char *data = NULL;
		long len = BIO_get_mem_data(bio, &data);
		out = xmalloc((size_t) len + 1);
		memcpy(out, data, (size_t) len);
		out[len] = 0;
	}

	BIO_free(bio);
	return out;
}

static EVP_PKEY *key_of_pem(const char *pem) {
	BIO *bio = BIO_new_mem_buf(pem, -1);

	if(!bio) {
		return NULL;
	}

	EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	BIO_free(bio);
	return key;
}

/* ---- JWS (ES256) --------------------------------------------------------- */

/* The account key's public point as the two base64url coordinates. */
static bool ec_coords(EVP_PKEY *key, char **x64, char **y64) {
	BIGNUM *x = NULL, *y = NULL;

	if(!EVP_PKEY_get_bn_param(key, "qx", &x) || !EVP_PKEY_get_bn_param(key, "qy", &y)) {
		BN_free(x);
		BN_free(y);
		return false;
	}

	uint8_t xb[32], yb[32];
	bool ok = BN_bn2binpad(x, xb, 32) == 32 && BN_bn2binpad(y, yb, 32) == 32;
	BN_free(x);
	BN_free(y);

	if(!ok) {
		return false;
	}

	*x64 = b64url(xb, 32);
	*y64 = b64url(yb, 32);
	return *x64 && *y64;
}

static char *jwk_json(EVP_PKEY *key) {
	char *x = NULL, *y = NULL;

	if(!ec_coords(key, &x, &y)) {
		return NULL;
	}

	char *out = NULL;
	xasprintf(&out, "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}", x, y);
	free(x);
	free(y);
	return out;
}

/* RFC 7638 thumbprint of the account key, base64url(SHA-256(canonical JWK)).
   The canonical form is the members in lexicographic order with no whitespace,
   which is exactly what jwk_json() already writes. */
static char *jwk_thumbprint(EVP_PKEY *key) {
	char *jwk = jwk_json(key);

	if(!jwk) {
		return NULL;
	}

	uint8_t h[32];
	sha256(jwk, strlen(jwk), h);
	free(jwk);
	return b64url(h, 32);
}

static char *es256_sign(EVP_PKEY *key, const char *data, size_t len) {
	EVP_MD_CTX *md = EVP_MD_CTX_new();
	uint8_t *der = NULL;
	char *out = NULL;
	size_t derlen = 0;

	if(!md || EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, key) != 1) {
		goto end;
	}

	if(EVP_DigestSign(md, NULL, &derlen, (const uint8_t *) data, len) != 1) {
		goto end;
	}

	der = xmalloc(derlen);

	if(EVP_DigestSign(md, der, &derlen, (const uint8_t *) data, len) != 1) {
		goto end;
	}

	{
		const uint8_t *p = der;
		ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &p, (long) derlen);

		if(!sig) {
			goto end;
		}

		uint8_t raw[64];
		const BIGNUM *r = ECDSA_SIG_get0_r(sig), *s = ECDSA_SIG_get0_s(sig);

		if(BN_bn2binpad(r, raw, 32) == 32 && BN_bn2binpad(s, raw + 32, 32) == 32) {
			out = b64url(raw, 64);
		}

		ECDSA_SIG_free(sig);
	}

end:
	free(der);
	EVP_MD_CTX_free(md);
	return out;
}

/* ---- HTTP plumbing ------------------------------------------------------- */

static bool http(acme_ctx_t *c, const char *method, const char *url, const char *ctype,
                 const char *const *headers, size_t nheaders,
                 const void *body, size_t body_len, http_response_t *res) {
	httpc_request_t req = {
		.url = url,
		.method = method,
		.content_type = ctype,
		.headers = headers,
		.nheaders = nheaders,
		.body = body,
		.body_len = body_len,
		.ca_file = c->p->ca_file,
		.timeout_s = ACME_HTTP_TIMEOUT,
	};
	char err[512] = "";

	if(!httpc_request(&req, res, err, sizeof(err))) {
		snprintf(c->out->detail, sizeof(c->out->detail), "%s", err);
		return false;
	}

	return true;
}

/* Remember the nonce the CA handed back, whatever the status was. */
static void take_nonce(acme_ctx_t *c, const http_response_t *res) {
	char *n = httpc_header(res, "Replay-Nonce");

	if(n) {
		free(c->nonce);
		c->nonce = n;
	}
}

static bool fetch_nonce(acme_ctx_t *c) {
	http_response_t res;

	if(!http(c, "HEAD", c->dir_new_nonce, NULL, NULL, 0, NULL, 0, &res)) {
		return false;
	}

	take_nonce(c, &res);
	httpc_free(&res);

	if(!c->nonce) {
		snprintf(c->out->detail, sizeof(c->out->detail),
		         "%s answered without a Replay-Nonce header (HTTP %d)", c->dir_new_nonce, res.status);
		return false;
	}

	return true;
}

/* One signed ACME request. `payload` NULL means POST-as-GET. */
static bool acme_post(acme_ctx_t *c, const char *url, const char *payload, http_response_t *res) {
	if(!c->nonce && !fetch_nonce(c)) {
		return false;
	}

	char *protected_json = NULL;

	if(c->kid) {
		xasprintf(&protected_json, "{\"alg\":\"ES256\",\"kid\":\"%s\",\"nonce\":\"%s\",\"url\":\"%s\"}",
		          c->kid, c->nonce, url);
	} else {
		char *jwk = jwk_json(c->account_key);

		if(!jwk) {
			snprintf(c->out->detail, sizeof(c->out->detail), "cannot express the account key as a JWK");
			return false;
		}

		xasprintf(&protected_json, "{\"alg\":\"ES256\",\"jwk\":%s,\"nonce\":\"%s\",\"url\":\"%s\"}",
		          jwk, c->nonce, url);
		free(jwk);
	}

	char *protected64 = b64url(protected_json, strlen(protected_json));
	char *payload64 = payload ? b64url(payload, strlen(payload)) : xstrdup("");
	free(protected_json);

	if(!protected64 || !payload64) {
		free(protected64);
		free(payload64);
		snprintf(c->out->detail, sizeof(c->out->detail), "cannot encode the request");
		return false;
	}

	char *signing_input = NULL;
	xasprintf(&signing_input, "%s.%s", protected64, payload64);
	char *sig = es256_sign(c->account_key, signing_input, strlen(signing_input));
	free(signing_input);

	if(!sig) {
		free(protected64);
		free(payload64);
		snprintf(c->out->detail, sizeof(c->out->detail), "cannot sign the request with the account key");
		return false;
	}

	char *body = NULL;
	xasprintf(&body, "{\"protected\":\"%s\",\"payload\":\"%s\",\"signature\":\"%s\"}",
	          protected64, payload64, sig);
	free(protected64);
	free(payload64);
	free(sig);

	bool ok = http(c, "POST", url, "application/jose+json", NULL, 0, body, strlen(body), res);
	free(body);

	if(ok) {
		take_nonce(c, res);
	}

	return ok;
}

/* The ACME problem document, if that is what came back. */
static const char *problem_type(const json_t *doc) {
	return doc ? json_member_string(doc, "type") : NULL;
}

static const char *problem_detail(const json_t *doc) {
	const char *d = doc ? json_member_string(doc, "detail") : NULL;
	return d ? d : "no detail given";
}

static bool is_problem(const json_t *doc, const char *suffix) {
	const char *t = problem_type(doc);
	return t && strstr(t, suffix);
}

/* A signed request that retries once when the CA says the nonce was stale --
   the one ACME error that is expected in normal operation. */
static bool acme_post_retry(acme_ctx_t *c, const char *url, const char *payload,
                            http_response_t *res, json_t **doc) {
	for(int attempt = 0; attempt < 2; attempt++) {
		if(!acme_post(c, url, payload, res)) {
			return false;
		}

		*doc = json_parse(res->body, res->body_len);

		if(res->status >= 400 && is_problem(*doc, "badNonce") && attempt == 0) {
			json_free(*doc);
			*doc = NULL;
			httpc_free(res);
			continue;
		}

		return true;
	}

	snprintf(c->out->detail, sizeof(c->out->detail),
	         "the CA rejected our replay nonce twice in a row at %s", url);
	return false;
}

/* ---- Cloudflare ---------------------------------------------------------- */

/* Cloudflare answers 200 with {"success":false,"errors":[...]} as often as it
   answers a 4xx, so both paths have to be read. */
static bool cf_ok(const json_t *doc) {
	return doc && json_is_true(json_member(doc, "success"));
}

static void cf_error_text(const json_t *doc, char *buf, size_t len) {
	const json_t *errors = doc ? json_member(doc, "errors") : NULL;
	const json_t *first = json_index(errors, 0);

	if(first) {
		const char *msg = json_member_string(first, "message");
		double code = json_number(json_member(first, "code"), 0);
		snprintf(buf, len, "%s (Cloudflare code %d)", msg ? msg : "refused", (int) code);
	} else {
		snprintf(buf, len, "no error message");
	}
}

static bool cf_request(acme_ctx_t *c, const char *method, const char *url,
                       const char *body, http_response_t *res) {
	char auth[512];
	snprintf(auth, sizeof(auth), "Authorization: Bearer %s", c->p->cf_token);
	const char *headers[] = { auth };
	return http(c, method, url, body ? "application/json" : NULL, headers, 1,
	            body, body ? strlen(body) : 0, res);
}

/* Build an absolute Cloudflare API URL from a path like "/zones". */
static void cf_url(acme_ctx_t *c, char *buf, size_t len, const char *fmt, ...) {
	int n = snprintf(buf, len, "%s", CF_API);

	if(n < 0 || (size_t) n >= len) {
		return;
	}

	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf + n, len - (size_t) n, fmt, ap);
	va_end(ap);
}

/* Map a Cloudflare reply that is not a success onto our taxonomy. */
static acme_rc_t cf_classify(acme_ctx_t *c, const http_response_t *res, const json_t *doc,
                             const char *what) {
	char msg[512];
	cf_error_text(doc, msg, sizeof(msg));

	if(res->status == 401 || res->status == 400) {
		return failf(c, ACME_ERR_CF_TOKEN,
		             "Create a token at https://dash.cloudflare.com/profile/api-tokens with the "
		             "\"Edit zone DNS\" template, scoped to the zone of this domain, and put it in "
		             "CloudflareToken. An Account-level Global API Key is not a token and will not work.",
		             "Cloudflare rejected the token while %s: %s", what, msg);
	}

	if(res->status == 403) {
		return failf(c, ACME_ERR_CF_PERMISSION,
		             "The token authenticates but is not allowed to do this. It needs Zone:Read and "
		             "Zone:DNS:Edit on the zone that contains the domain -- check the token's "
		             "permissions and its zone resources.",
		             "Cloudflare refused the token's permissions while %s: %s", what, msg);
	}

	if(res->status == 429) {
		return failf(c, ACME_ERR_CF_API,
		             "Wait and try again; Cloudflare is rate-limiting this token.",
		             "Cloudflare is rate-limiting us while %s: %s", what, msg);
	}

	return failf(c, ACME_ERR_CF_API, "Retry; if it persists, the message above is Cloudflare's own.",
	             "Cloudflare failed while %s (HTTP %d): %s", what, res->status, msg);
}

/* Is the token usable at all? This is the check the UI runs when a token is
   pasted, so it has to distinguish "wrong token" from "token with the wrong
   permissions" without creating anything. */
static acme_rc_t cf_verify_token(acme_ctx_t *c) {
	say(c, "checking the Cloudflare token");
	http_response_t res;

	char url[512];
	cf_url(c, url, sizeof(url), "/user/tokens/verify");

	if(!cf_request(c, "GET", url, NULL, &res)) {
		return fail(c, ACME_ERR_NETWORK, c->out->detail,
		            "Check that this host can reach api.cloudflare.com over HTTPS.");
	}

	json_t *doc = json_parse(res.body, res.body_len);
	acme_rc_t rc = ACME_OK;

	if(!cf_ok(doc)) {
		rc = cf_classify(c, &res, doc, "verifying the token");
	} else {
		const char *status = json_member_string(json_member(doc, "result"), "status");

		if(status && strcmp(status, "active")) {
			rc = failf(c, ACME_ERR_CF_TOKEN,
			           "Issue a new token, or re-enable this one in the Cloudflare dashboard.",
			           "The Cloudflare token is not active: its status is \"%s\".", status);
		}
	}

	json_free(doc);
	httpc_free(&res);
	return rc;
}

/* The zone that contains `domain`: try the full name, then each parent. A
   token scoped to one zone can only see that zone, which is why "no zone
   found" has to name what the token CAN see -- that is nearly always the
   mistake (token for example.net, CertDomain under example.com). */
static acme_rc_t cf_find_zone(acme_ctx_t *c) {
	say(c, "looking for the Cloudflare zone");
	const char *domain = c->p->domain;

	for(const char *candidate = domain; candidate && strchr(candidate, '.');) {
		char url[512];
		cf_url(c, url, sizeof(url), "/zones?name=%s&status=active", candidate);
		http_response_t res;

		if(!cf_request(c, "GET", url, NULL, &res)) {
			return fail(c, ACME_ERR_NETWORK, c->out->detail,
			            "Check that this host can reach api.cloudflare.com over HTTPS.");
		}

		json_t *doc = json_parse(res.body, res.body_len);

		if(!cf_ok(doc)) {
			acme_rc_t rc = cf_classify(c, &res, doc, "listing zones");
			json_free(doc);
			httpc_free(&res);
			return rc;
		}

		const json_t *zone = json_index(json_member(doc, "result"), 0);
		const char *id = zone ? json_member_string(zone, "id") : NULL;

		if(id) {
			c->zone_id = xstrdup(id);
			const char *name = json_member_string(zone, "name");
			c->out->zone_name = xstrdup(name ? name : candidate);
			json_free(doc);
			httpc_free(&res);
			return ACME_OK;
		}

		json_free(doc);
		httpc_free(&res);
		candidate = strchr(candidate, '.') + 1;
	}

	/* Nothing matched: say which zones this token does reach. */
	char visible[512] = "";
	http_response_t res;

	char listurl[512];
	cf_url(c, listurl, sizeof(listurl), "/zones?per_page=5");

	if(cf_request(c, "GET", listurl, NULL, &res)) {
		json_t *doc = json_parse(res.body, res.body_len);

		if(cf_ok(doc)) {
			const json_t *list = json_member(doc, "result");
			size_t n = json_count(list);

			for(size_t i = 0; i < n && i < 5; i++) {
				const char *name = json_member_string(json_index(list, i), "name");

				if(name) {
					size_t used = strlen(visible);
					snprintf(visible + used, sizeof(visible) - used, "%s%s", used ? ", " : "", name);
				}
			}
		}

		json_free(doc);
		httpc_free(&res);
	}

	if(*visible) {
		return failf(c, ACME_ERR_CF_ZONE,
		             "Either point CertDomain at a name inside one of those zones, or issue a token "
		             "whose zone resources include the zone of this domain.",
		             "The Cloudflare token sees no zone that contains %s. The zones it can see are: %s.",
		             domain, visible);
	}

	return failf(c, ACME_ERR_CF_ZONE,
	             "Give the token Zone:Read on the zone that contains the domain, and check that the "
	             "zone is active in this Cloudflare account.",
	             "The Cloudflare token sees no zone that contains %s, and no zones at all.", domain);
}

static acme_rc_t cf_create_txt(acme_ctx_t *c, const char *value) {
	say(c, "writing the DNS challenge record");
	char url[512];
	cf_url(c, url, sizeof(url), "/zones/%s/dns_records", c->zone_id);

	char *name = json_escape(c->fqdn);
	char *content = json_escape(value);
	char *body = NULL;
	xasprintf(&body, "{\"type\":\"TXT\",\"name\":\"%s\",\"content\":\"%s\",\"ttl\":60,"
	          "\"comment\":\"tincstack ACME challenge\"}", name, content);
	free(name);
	free(content);

	http_response_t res;
	bool sent = cf_request(c, "POST", url, body, &res);
	free(body);

	if(!sent) {
		return fail(c, ACME_ERR_NETWORK, c->out->detail,
		            "Check that this host can reach api.cloudflare.com over HTTPS.");
	}

	json_t *doc = json_parse(res.body, res.body_len);
	acme_rc_t rc = ACME_OK;

	if(!cf_ok(doc)) {
		rc = cf_classify(c, &res, doc, "creating the _acme-challenge TXT record");
	} else {
		const char *id = json_member_string(json_member(doc, "result"), "id");

		if(id) {
			c->record_id = xstrdup(id);
		} else {
			rc = fail(c, ACME_ERR_CF_API, "Cloudflare accepted the TXT record but returned no record id.",
			          "Remove any stale _acme-challenge record by hand and try again.");
		}
	}

	json_free(doc);
	httpc_free(&res);
	return rc;
}

/* Best effort: a leftover TXT record is harmless but untidy, and leaving one
   behind after every failed attempt is how a zone ends up with fifty. */
static void cf_delete_txt(acme_ctx_t *c) {
	if(!c->zone_id || !c->record_id) {
		return;
	}

	say(c, "removing the DNS challenge record");
	char url[512];
	cf_url(c, url, sizeof(url), "/zones/%s/dns_records/%s", c->zone_id, c->record_id);
	http_response_t res;

	if(cf_request(c, "DELETE", url, NULL, &res)) {
		httpc_free(&res);
	}

	free(c->record_id);
	c->record_id = NULL;
}

/* ---- ACME flow ----------------------------------------------------------- */

static acme_rc_t load_directory(acme_ctx_t *c) {
	const char *url = c->p->directory && *c->p->directory ? c->p->directory : LE_DIRECTORY;
	say(c, "loading the ACME directory");
	http_response_t res;

	if(!http(c, "GET", url, NULL, NULL, 0, NULL, 0, &res)) {
		return fail(c, ACME_ERR_NETWORK, c->out->detail,
		            "Check that this host can reach the CA over HTTPS, and that AcmeDirectory is a URL.");
	}

	json_t *doc = json_parse(res.body, res.body_len);
	const char *nn = json_member_string(doc, "newNonce");
	const char *na = json_member_string(doc, "newAccount");
	const char *no = json_member_string(doc, "newOrder");

	if(res.status != 200 || !nn || !na || !no) {
		acme_rc_t rc = failf(c, ACME_ERR_DIRECTORY,
		                     "Check AcmeDirectory: it must be the CA's directory URL, for example "
		                     LE_DIRECTORY " .",
		                     "%s did not answer with an ACME directory (HTTP %d).", url, res.status);
		json_free(doc);
		httpc_free(&res);
		return rc;
	}

	c->dir_new_nonce = xstrdup(nn);
	c->dir_new_account = xstrdup(na);
	c->dir_new_order = xstrdup(no);
	json_free(doc);
	httpc_free(&res);
	return ACME_OK;
}

static acme_rc_t register_account(acme_ctx_t *c) {
	say(c, "registering with the CA");
	char *payload = NULL;

	if(c->p->contact && *c->p->contact) {
		char *contact = json_escape(c->p->contact);
		xasprintf(&payload, "{\"termsOfServiceAgreed\":true,\"contact\":[\"%s\"]}", contact);
		free(contact);
	} else {
		payload = xstrdup("{\"termsOfServiceAgreed\":true}");
	}

	http_response_t res;
	json_t *doc = NULL;
	bool sent = acme_post_retry(c, c->dir_new_account, payload, &res, &doc);
	free(payload);

	if(!sent) {
		return fail(c, ACME_ERR_NETWORK, c->out->detail, "Check this host's connection to the CA.");
	}

	acme_rc_t rc = ACME_OK;

	if(res.status == 200 || res.status == 201) {
		char *loc = httpc_header(&res, "Location");

		if(loc) {
			c->kid = loc;
		} else {
			rc = fail(c, ACME_ERR_ACCOUNT, "The CA created the account but returned no account URL.",
			          "Retry; if it persists the CA is misbehaving.");
		}
	} else if(is_problem(doc, "rateLimited")) {
		rc = failf(c, ACME_ERR_RATELIMIT,
		           "Wait for the window named in the message to pass. Let's Encrypt allows a limited "
		           "number of accounts and certificates per period; use AcmeDirectory to point at the "
		           "staging CA while testing.",
		           "The CA is rate-limiting this account: %s", problem_detail(doc));
	} else {
		rc = failf(c, ACME_ERR_ACCOUNT,
		           "Check AcmeContact (it must be a mailto: address the CA accepts) and that the "
		           "directory URL is the CA you mean to use.",
		           "The CA refused to create an account (HTTP %d): %s", res.status, problem_detail(doc));
	}

	json_free(doc);
	httpc_free(&res);
	return rc;
}

static acme_rc_t new_order(acme_ctx_t *c, char **order_url, char **authz_url, char **finalize_url) {
	say(c, "asking the CA for a certificate order");
	char *domain = json_escape(c->p->domain);
	char *payload = NULL;
	xasprintf(&payload, "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"%s\"}]}", domain);
	free(domain);

	http_response_t res;
	json_t *doc = NULL;
	bool sent = acme_post_retry(c, c->dir_new_order, payload, &res, &doc);
	free(payload);

	if(!sent) {
		return fail(c, ACME_ERR_NETWORK, c->out->detail, "Check this host's connection to the CA.");
	}

	acme_rc_t rc = ACME_OK;

	if(res.status == 201) {
		char *loc = httpc_header(&res, "Location");
		const char *fin = json_member_string(doc, "finalize");
		const char *authz = json_string(json_index(json_member(doc, "authorizations"), 0));

		if(loc && fin && authz) {
			*order_url = loc;
			*finalize_url = xstrdup(fin);
			*authz_url = xstrdup(authz);
		} else {
			free(loc);
			rc = fail(c, ACME_ERR_ORDER, "The CA's order is missing the authorization or finalize URL.",
			          "Retry; if it persists the CA is misbehaving.");
		}
	} else if(is_problem(doc, "rateLimited")) {
		rc = failf(c, ACME_ERR_RATELIMIT,
		           "Wait for the window to pass, or point AcmeDirectory at the CA's staging endpoint "
		           "while you are testing.",
		           "The CA is rate-limiting orders for this domain: %s", problem_detail(doc));
	} else if(is_problem(doc, "rejectedIdentifier") || is_problem(doc, "malformed")) {
		rc = failf(c, ACME_ERR_ORDER,
		           "Check CertDomain: it must be a public DNS name the CA is willing to issue for -- "
		           "not an internal name, not an IP address, and not a name under a suffix the CA "
		           "refuses.",
		           "The CA refused to issue for %s: %s", c->p->domain, problem_detail(doc));
	} else {
		rc = failf(c, ACME_ERR_ORDER,
		           "The message above is the CA's own; a CAA record on the zone that forbids this CA "
		           "is the usual cause.",
		           "The CA refused the order (HTTP %d): %s", res.status, problem_detail(doc));
	}

	json_free(doc);
	httpc_free(&res);
	return rc;
}

/* Read the authorization. `*already_valid` comes back true when the CA still
   remembers a successful validation for this name: Let's Encrypt caches an
   authorization for 30 days, so every renewal inside that window lands here,
   and re-triggering a challenge that is already valid is an error ("Cannot
   update challenge with status valid"). When it is set, there is nothing to
   write into DNS and nothing to wait for. */
static acme_rc_t dns_challenge(acme_ctx_t *c, const char *authz_url, char **challenge_url,
                               char **token, bool *already_valid) {
	say(c, "reading the DNS-01 challenge");
	http_response_t res;
	json_t *doc = NULL;
	*already_valid = false;

	if(!acme_post_retry(c, authz_url, NULL, &res, &doc)) {
		return fail(c, ACME_ERR_NETWORK, c->out->detail, "Check this host's connection to the CA.");
	}

	const char *authz_status = json_member_string(doc, "status");

	if(authz_status && !strcmp(authz_status, "valid")) {
		say(c, "the CA already has a valid authorization for this name");
		*already_valid = true;
		json_free(doc);
		httpc_free(&res);
		return ACME_OK;
	}

	acme_rc_t rc = ACME_ERR_CHALLENGE;
	const json_t *challenges = json_member(doc, "challenges");
	size_t n = json_count(challenges);

	for(size_t i = 0; i < n; i++) {
		const json_t *ch = json_index(challenges, i);
		const char *type = json_member_string(ch, "type");

		if(type && !strcmp(type, "dns-01")) {
			const char *url = json_member_string(ch, "url");
			const char *tok = json_member_string(ch, "token");

			if(url && tok) {
				*challenge_url = xstrdup(url);
				*token = xstrdup(tok);
				rc = ACME_OK;
			}

			break;
		}
	}

	if(rc != ACME_OK) {
		failf(c, ACME_ERR_CHALLENGE,
		      "This CA does not offer DNS-01 for this domain, which is the only challenge this "
		      "implementation can answer.",
		      "The authorization carries no usable dns-01 challenge (HTTP %d).", res.status);
	}

	json_free(doc);
	httpc_free(&res);
	return rc;
}

/* Tell the CA to validate, then poll the authorization. The CA's own error is
   the most useful thing we can print here -- it says whether it saw no record,
   a stale record, or the wrong value. */
static acme_rc_t run_challenge(acme_ctx_t *c, const char *challenge_url, const char *authz_url) {
	say(c, "asking the CA to validate the record");
	http_response_t res;
	json_t *doc = NULL;

	if(!acme_post_retry(c, challenge_url, "{}", &res, &doc)) {
		return fail(c, ACME_ERR_NETWORK, c->out->detail, "Check this host's connection to the CA.");
	}

	if(res.status >= 400) {
		acme_rc_t rc = failf(c, ACME_ERR_CHALLENGE,
		                     "The CA refused to start validation; the message above is its own.",
		                     "Validation could not be started (HTTP %d): %s", res.status, problem_detail(doc));
		json_free(doc);
		httpc_free(&res);
		return rc;
	}

	json_free(doc);
	httpc_free(&res);

	int deadline = c->p->poll_s > 0 ? c->p->poll_s : ACME_DEFAULT_POLL;

	for(int waited = 0; waited < deadline; waited += 3) {
		sleep(3);
		say(c, "waiting for the CA to validate");

		if(!acme_post_retry(c, authz_url, NULL, &res, &doc)) {
			return fail(c, ACME_ERR_NETWORK, c->out->detail, "Check this host's connection to the CA.");
		}

		const char *status = json_member_string(doc, "status");

		if(status && !strcmp(status, "valid")) {
			json_free(doc);
			httpc_free(&res);
			return ACME_OK;
		}

		if(status && !strcmp(status, "invalid")) {
			const char *why = "the CA gave no reason";
			const json_t *challenges = json_member(doc, "challenges");

			for(size_t i = 0; i < json_count(challenges); i++) {
				const json_t *err = json_member(json_index(challenges, i), "error");

				if(err) {
					why = problem_detail(err);
					break;
				}
			}

			acme_rc_t rc = failf(c, ACME_ERR_CHALLENGE,
			                     "The TXT record was written to Cloudflare but the CA did not accept it. "
			                     "If the message says no record was found, the zone needs longer to "
			                     "publish: raise AcmePropagation. If it says the value was wrong, an old "
			                     "_acme-challenge record is still in the zone -- delete it.",
			                     "The CA could not validate %s: %s", c->fqdn, why);
			json_free(doc);
			httpc_free(&res);
			return rc;
		}

		json_free(doc);
		doc = NULL;
		httpc_free(&res);
	}

	return failf(c, ACME_ERR_CHALLENGE,
	             "Raise AcmePropagation (the wait before validation) or AcmePollTimeout, and check in "
	             "the Cloudflare dashboard that the record really is there.",
	             "The CA had still not validated %s after %d seconds.", c->fqdn, deadline);
}

/* CSR for the domain, with the SAN the CA actually looks at. */
static bool make_csr(const char *domain, EVP_PKEY **key_out, char **csr_b64) {
	EVP_PKEY *key = EVP_EC_gen("P-256");
	X509_REQ *req = X509_REQ_new();
	bool ok = false;
	uint8_t *der = NULL;

	if(!key || !req) {
		goto end;
	}

	X509_REQ_set_version(req, 0);
	X509_NAME *name = X509_REQ_get_subject_name(req);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const uint8_t *) domain, -1, -1, 0);

	{
		char san[300];
		snprintf(san, sizeof(san), "DNS:%s", domain);
		STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
		X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, san);

		if(!ext) {
			sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
			goto end;
		}

		sk_X509_EXTENSION_push(exts, ext);
		ok = X509_REQ_add_extensions(req, exts) != 0;
		sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

		if(!ok) {
			goto end;
		}

		ok = false;
	}

	if(!X509_REQ_set_pubkey(req, key) || !X509_REQ_sign(req, key, EVP_sha256())) {
		goto end;
	}

	{
		int len = i2d_X509_REQ(req, &der);

		if(len <= 0) {
			goto end;
		}

		*csr_b64 = b64url(der, (size_t) len);
		ok = *csr_b64 != NULL;
	}

end:

	if(ok) {
		*key_out = key;
	} else {
		EVP_PKEY_free(key);
	}

	OPENSSL_free(der);
	X509_REQ_free(req);
	return ok;
}

static acme_rc_t finalize_order(acme_ctx_t *c, const char *finalize_url, const char *order_url,
                                const char *csr_b64, char **cert_url) {
	say(c, "sending the certificate request");
	char *payload = NULL;
	xasprintf(&payload, "{\"csr\":\"%s\"}", csr_b64);

	http_response_t res;
	json_t *doc = NULL;
	bool sent = acme_post_retry(c, finalize_url, payload, &res, &doc);
	free(payload);

	if(!sent) {
		return fail(c, ACME_ERR_NETWORK, c->out->detail, "Check this host's connection to the CA.");
	}

	if(res.status >= 400) {
		acme_rc_t rc = failf(c, ACME_ERR_FINALIZE,
		                     "The CA refused the certificate request; the message above is its own.",
		                     "Finalize failed (HTTP %d): %s", res.status, problem_detail(doc));
		json_free(doc);
		httpc_free(&res);
		return rc;
	}

	json_free(doc);
	httpc_free(&res);

	for(int waited = 0; waited < 60; waited += 3) {
		if(!acme_post_retry(c, order_url, NULL, &res, &doc)) {
			return fail(c, ACME_ERR_NETWORK, c->out->detail, "Check this host's connection to the CA.");
		}

		const char *status = json_member_string(doc, "status");
		const char *cert = json_member_string(doc, "certificate");

		if(status && !strcmp(status, "valid") && cert) {
			*cert_url = xstrdup(cert);
			json_free(doc);
			httpc_free(&res);
			return ACME_OK;
		}

		if(status && !strcmp(status, "invalid")) {
			acme_rc_t rc = failf(c, ACME_ERR_FINALIZE,
			                     "The order was valid when it was created and invalid by the time the "
			                     "CSR arrived; retrying from scratch is the right move.",
			                     "The CA marked the order invalid: %s", problem_detail(doc));
			json_free(doc);
			httpc_free(&res);
			return rc;
		}

		json_free(doc);
		doc = NULL;
		httpc_free(&res);
		say(c, "waiting for the CA to issue");
		sleep(3);
	}

	return fail(c, ACME_ERR_FINALIZE, "The CA did not issue the certificate within 60 seconds.",
	            "Retry: the order may still complete, and a repeat run will pick it up.");
}

static acme_rc_t download_cert(acme_ctx_t *c, const char *cert_url) {
	say(c, "downloading the certificate");
	http_response_t res;
	json_t *doc = NULL;

	if(!acme_post_retry(c, cert_url, NULL, &res, &doc)) {
		return fail(c, ACME_ERR_NETWORK, c->out->detail, "Check this host's connection to the CA.");
	}

	json_free(doc);

	if(res.status != 200 || !strstr(res.body, "BEGIN CERTIFICATE")) {
		acme_rc_t rc = failf(c, ACME_ERR_FINALIZE, "Retry; the certificate is issued and can be fetched again.",
		                     "The CA did not return a certificate (HTTP %d).", res.status);
		httpc_free(&res);
		return rc;
	}

	c->out->cert_pem = xstrdup(res.body);
	httpc_free(&res);
	return ACME_OK;
}

/* ---- entry points -------------------------------------------------------- */

/* Syntax only: a name we can put in a CSR and in a DNS record. Catching this
   here means the operator gets a useful sentence instead of a CA error. */
static bool domain_sane(const char *d) {
	size_t len = d ? strlen(d) : 0;

	if(len < 3 || len > 253 || *d == '.' || d[len - 1] == '.' || !strchr(d, '.')) {
		return false;
	}

	int label = 0;

	for(const char *p = d; *p; p++) {
		if(*p == '.') {
			if(!label) {
				return false;
			}

			label = 0;
			continue;
		}

		if(!isalnum((uint8_t) * p) && *p != '-' && *p != '_') {
			return false;
		}

		if(++label > 63) {
			return false;
		}
	}

	return label > 0;
}

static acme_rc_t check_config(acme_ctx_t *c) {
	if(!c->p->domain || !*c->p->domain) {
		return fail(c, ACME_ERR_CONFIG, "No CertDomain is set.",
		            "Set CertDomain to the public name this node should present, e.g. vpn.example.com.");
	}

	if(!domain_sane(c->p->domain)) {
		return failf(c, ACME_ERR_CONFIG,
		             "CertDomain must be a plain DNS name: letters, digits and hyphens, at least one "
		             "dot, no scheme, no port, no wildcard.",
		             "CertDomain \"%s\" is not a DNS name this can issue for.", c->p->domain);
	}

	if(!c->p->cf_token || !*c->p->cf_token) {
		return fail(c, ACME_ERR_CONFIG, "No CloudflareToken is set.",
		            "Create an API token with the \"Edit zone DNS\" template for this domain's zone "
		            "and put it in CloudflareToken.");
	}

	if(strlen(c->p->cf_token) < 20 || strchr(c->p->cf_token, ' ')) {
		return fail(c, ACME_ERR_CONFIG, "CloudflareToken does not look like an API token.",
		            "Copy the token itself, not the token's name or an email address; a Global API Key "
		            "is not a token and will not work.");
	}

	return ACME_OK;
}

acme_rc_t acme_check_token(const acme_params_t *p, acme_result_t *out) {
	acme_ctx_t c = {.p = p, .out = out};
	memset(out, 0, sizeof(*out));

	acme_rc_t rc = check_config(&c);

	if(rc == ACME_OK) {
		rc = cf_verify_token(&c);
	}

	if(rc == ACME_OK) {
		rc = cf_find_zone(&c);
	}

	if(rc == ACME_OK) {
		snprintf(out->detail, sizeof(out->detail),
		         "The token is active and can edit DNS in the zone %s, which contains %s.",
		         out->zone_name ? out->zone_name : "?", p->domain);
	}

	free(c.zone_id);
	return rc;
}

acme_rc_t acme_issue(const acme_params_t *p, const char *account_key_pem, acme_result_t *out) {
	acme_ctx_t c = {.p = p, .out = out};
	memset(out, 0, sizeof(*out));

	char *order_url = NULL, *authz_url = NULL, *finalize_url = NULL;
	char *challenge_url = NULL, *token = NULL, *cert_url = NULL, *csr_b64 = NULL;
	char *thumb = NULL, *keyauth = NULL, *txt = NULL;
	EVP_PKEY *cert_key = NULL;

	acme_rc_t rc = check_config(&c);

	if(rc != ACME_OK) {
		goto end;
	}

	/* The account key is the identity the CA knows us by: reuse it across
	   renewals, or every renewal registers a new account and walks into the
	   CA's account rate limit. */
	if(account_key_pem && *account_key_pem) {
		c.account_key = key_of_pem(account_key_pem);

		if(!c.account_key) {
			rc = fail(&c, ACME_ERR_CRYPTO, "The stored ACME account key is not a usable private key.",
			          "Remove keys.acme_account from the config to start over with a fresh account.");
			goto end;
		}
	} else {
		c.account_key = EVP_EC_gen("P-256");

		if(!c.account_key) {
			rc = fail(&c, ACME_ERR_CRYPTO, "Cannot generate an ACME account key.", "Check the OpenSSL build.");
			goto end;
		}

		out->account_key_pem = pem_of_key(c.account_key);
	}

	xasprintf(&c.fqdn, "_acme-challenge.%s", p->domain);

	if((rc = cf_verify_token(&c)) != ACME_OK) {
		goto end;
	}

	if((rc = cf_find_zone(&c)) != ACME_OK) {
		goto end;
	}

	if((rc = load_directory(&c)) != ACME_OK) {
		goto end;
	}

	if((rc = register_account(&c)) != ACME_OK) {
		goto end;
	}

	if((rc = new_order(&c, &order_url, &authz_url, &finalize_url)) != ACME_OK) {
		goto end;
	}

	bool already_valid = false;

	if((rc = dns_challenge(&c, authz_url, &challenge_url, &token, &already_valid)) != ACME_OK) {
		goto end;
	}

	if(already_valid) {
		goto csr;
	}

	thumb = jwk_thumbprint(c.account_key);

	if(!thumb) {
		rc = fail(&c, ACME_ERR_CRYPTO, "Cannot compute the account key thumbprint.", "Check the OpenSSL build.");
		goto end;
	}

	xasprintf(&keyauth, "%s.%s", token, thumb);
	{
		uint8_t h[32];
		sha256(keyauth, strlen(keyauth), h);
		txt = b64url(h, 32);
	}

	if(!txt) {
		rc = fail(&c, ACME_ERR_CRYPTO, "Cannot compute the challenge value.", "Check the OpenSSL build.");
		goto end;
	}

	if((rc = cf_create_txt(&c, txt)) != ACME_OK) {
		goto end;
	}

	/* Cloudflare's own resolvers publish in seconds, but the CA queries the
	   authoritative servers through its own resolver: give the record time to
	   be visible before claiming it is. */
	say(&c, "waiting for the record to publish");
	sleep((unsigned int)(p->propagation_s > 0 ? p->propagation_s : ACME_DEFAULT_PROPAGATION));

	if((rc = run_challenge(&c, challenge_url, authz_url)) != ACME_OK) {
		goto end;
	}

csr:

	if(!make_csr(p->domain, &cert_key, &csr_b64)) {
		rc = fail(&c, ACME_ERR_CRYPTO, "Cannot build the certificate request.", "Check the OpenSSL build.");
		goto end;
	}

	if((rc = finalize_order(&c, finalize_url, order_url, csr_b64, &cert_url)) != ACME_OK) {
		goto end;
	}

	if((rc = download_cert(&c, cert_url)) != ACME_OK) {
		goto end;
	}

	out->key_pem = pem_of_key(cert_key);

	if(!out->key_pem) {
		rc = fail(&c, ACME_ERR_CRYPTO, "Cannot serialise the new certificate key.", "Check the OpenSSL build.");
		goto end;
	}

	snprintf(out->detail, sizeof(out->detail), "Issued a certificate for %s in the zone %s.",
	         p->domain, out->zone_name ? out->zone_name : "?");
	out->hint[0] = 0;

end:
	cf_delete_txt(&c);
	EVP_PKEY_free(c.account_key);
	EVP_PKEY_free(cert_key);
	free(c.dir_new_nonce);
	free(c.dir_new_account);
	free(c.dir_new_order);
	free(c.nonce);
	free(c.kid);
	free(c.zone_id);
	free(c.fqdn);
	free(order_url);
	free(authz_url);
	free(finalize_url);
	free(challenge_url);
	free(token);
	free(cert_url);
	free(csr_b64);
	free(thumb);
	free(keyauth);
	free(txt);

	if(rc != ACME_OK) {
		free(out->cert_pem);
		out->cert_pem = NULL;
	}

	return rc;
}

#endif /* HAVE_OPENSSL */
