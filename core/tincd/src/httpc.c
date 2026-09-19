/*
    httpc.c -- a small blocking HTTPS client for the certificate commands.

    This is deliberately blocking, and it is deliberately NOT linked into the
    daemon's event loop: it runs inside `tinc cert ...`, a separate process.
    Defect M5-1 was exactly a synchronous fetch on the daemon's main loop (one
    black-holed upstream froze the node for 3 s per probe), so the certificate
    work does its network I/O where blocking costs nothing.

    Scope: HTTPS only, one request per connection (`Connection: close`), the
    whole response read into memory under a cap. That is all ACME and the
    Cloudflare API need, and it keeps the code small enough to audit.

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
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "httpc.h"
#include "utils.h"
#include "xalloc.h"

#ifndef HAVE_WINDOWS
#define closesocket(s) close(s)
#endif

/* A response larger than this is a server malfunction for these APIs: the
   biggest thing we fetch is a certificate chain. */
#define HTTPC_MAX_BODY (1024 * 1024)

void httpc_free(http_response_t *res) {
	if(!res) {
		return;
	}

	free(res->headers);
	free(res->body);
	res->headers = NULL;
	res->body = NULL;
	res->body_len = 0;
	res->status = 0;
}

/* Case-insensitive header lookup. Returns a malloc'd value (trimmed) or NULL. */
char *httpc_header(const http_response_t *res, const char *name) {
	if(!res || !res->headers) {
		return NULL;
	}

	size_t namelen = strlen(name);
	const char *p = res->headers;

	while(*p) {
		const char *eol = strchr(p, '\n');
		size_t linelen = eol ? (size_t)(eol - p) : strlen(p);

		if(linelen > namelen && !strncasecmp(p, name, namelen) && p[namelen] == ':') {
			const char *v = p + namelen + 1;
			size_t vlen = linelen - namelen - 1;

			while(vlen && (*v == ' ' || *v == '\t')) {
				v++;
				vlen--;
			}

			while(vlen && (v[vlen - 1] == '\r' || v[vlen - 1] == ' ' || v[vlen - 1] == '\t')) {
				vlen--;
			}

			char *out = xmalloc(vlen + 1);
			memcpy(out, v, vlen);
			out[vlen] = 0;
			return out;
		}

		if(!eol) {
			break;
		}

		p = eol + 1;
	}

	return NULL;
}

/* https://host[:port]/path -> the three pieces. False if it is not an https
   URL we can dial. */
static bool split_url(const char *url, char *host, size_t hostlen, char *port, size_t portlen,
                      char *path, size_t pathlen) {
	if(strncmp(url, "https://", 8)) {
		return false;
	}

	const char *h = url + 8;
	const char *slash = strchr(h, '/');
	const char *hostend = slash ? slash : h + strlen(h);
	const char *colon = memchr(h, ':', (size_t)(hostend - h));

	size_t hl = (size_t)((colon ? colon : hostend) - h);

	if(!hl || hl >= hostlen) {
		return false;
	}

	memcpy(host, h, hl);
	host[hl] = 0;

	if(colon) {
		size_t pl = (size_t)(hostend - colon - 1);

		if(!pl || pl >= portlen) {
			return false;
		}

		memcpy(port, colon + 1, pl);
		port[pl] = 0;

		for(const char *d = port; *d; d++) {
			if(!isdigit((uint8_t) * d)) {
				return false;
			}
		}
	} else {
		if(portlen < 4) {
			return false;
		}

		strcpy(port, "443");
	}

	if(slash) {
		if(strlen(slash) >= pathlen) {
			return false;
		}

		strcpy(path, slash);
	} else {
		if(pathlen < 2) {
			return false;
		}

		strcpy(path, "/");
	}

	return true;
}

static int connect_timeout(const char *host, const char *port, int timeout_s, char *err, size_t errlen) {
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
	};
	struct addrinfo *ai = NULL;
	int gai = getaddrinfo(host, port, &hints, &ai);

	if(gai || !ai) {
		snprintf(err, errlen, "cannot resolve %s: %s", host, gai_strerror(gai));
		return -1;
	}

	int fd = -1;

	for(struct addrinfo *a = ai; a; a = a->ai_next) {
		fd = (int) socket(a->ai_family, a->ai_socktype, a->ai_protocol);

		if(fd < 0) {
			continue;
		}

		struct timeval tv = {.tv_sec = timeout_s, .tv_usec = 0};

		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (void *) &tv, sizeof(tv));

		setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (void *) &tv, sizeof(tv));

		if(!connect(fd, a->ai_addr, a->ai_addrlen)) {
			freeaddrinfo(ai);
			return fd;
		}

		snprintf(err, errlen, "cannot connect to %s port %s: %s", host, port, sockstrerror(sockerrno));
		closesocket(fd);
		fd = -1;
	}

	freeaddrinfo(ai);

	if(!*err) {
		snprintf(err, errlen, "cannot connect to %s port %s", host, port);
	}

	return -1;
}

static void ssl_error(char *err, size_t errlen, const char *what, SSL *ssl) {
	long verify = ssl ? SSL_get_verify_result(ssl) : X509_V_OK;

	if(verify != X509_V_OK) {
		snprintf(err, errlen, "%s: the server's certificate did not verify: %s",
		         what, X509_verify_cert_error_string(verify));
		return;
	}

	unsigned long e = ERR_get_error();

	if(e) {
		char buf[256] = "";
		ERR_error_string_n(e, buf, sizeof(buf));
		snprintf(err, errlen, "%s: %s", what, buf);
	} else {
		snprintf(err, errlen, "%s", what);
	}
}

/* Case-insensitive substring test, for header values like
   "Transfer-Encoding: chunked". */
static bool header_has(const char *value, const char *word) {
	size_t wl = strlen(word);

	for(const char *p = value; *p; p++) {
		if(!strncasecmp(p, word, wl)) {
			return true;
		}
	}

	return false;
}

/* Dechunk in place; returns the new length. */
static size_t dechunk(char *body, size_t len) {
	size_t in = 0, out = 0;

	while(in < len) {
		char *eol = memchr(body + in, '\n', len - in);

		if(!eol) {
			break;
		}

		size_t chunk = (size_t) strtoul(body + in, NULL, 16);
		in = (size_t)(eol - body) + 1;

		if(!chunk || in + chunk > len) {
			break;
		}

		memmove(body + out, body + in, chunk);
		out += chunk;
		in += chunk;

		while(in < len && (body[in] == '\r' || body[in] == '\n')) {
			in++;
		}
	}

	body[out] = 0;
	return out;
}

bool httpc_request(const httpc_request_t *req, http_response_t *res, char *err, size_t errlen) {
	if(err && errlen) {
		*err = 0;
	}

	memset(res, 0, sizeof(*res));

	char host[256], port[8], path[2048];

	if(!split_url(req->url, host, sizeof(host), port, sizeof(port), path, sizeof(path))) {
		snprintf(err, errlen, "not a usable https URL: %s", req->url);
		return false;
	}

	int fd = connect_timeout(host, port, req->timeout_s > 0 ? req->timeout_s : 30, err, errlen);

	if(fd < 0) {
		return false;
	}

	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

	if(!ctx) {
		ssl_error(err, errlen, "cannot create a TLS context", NULL);
		closesocket(fd);
		return false;
	}

	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	/* A CA file is how the test harness trusts its throwaway ACME server. In
	   production it is unset and the system trust store is used; there is no
	   "skip verification" switch, on purpose. */
	if(req->ca_file && *req->ca_file) {
		if(!SSL_CTX_load_verify_locations(ctx, req->ca_file, NULL)) {
			snprintf(err, errlen, "cannot read the CA bundle %s", req->ca_file);
			SSL_CTX_free(ctx);
			closesocket(fd);
			return false;
		}
	} else if(!SSL_CTX_set_default_verify_paths(ctx)) {
		snprintf(err, errlen, "no system CA store to verify %s against", host);
		SSL_CTX_free(ctx);
		closesocket(fd);
		return false;
	}

	SSL *ssl = SSL_new(ctx);

	if(!ssl) {
		ssl_error(err, errlen, "cannot create a TLS session", NULL);
		SSL_CTX_free(ctx);
		closesocket(fd);
		return false;
	}

	SSL_set_tlsext_host_name(ssl, host);
	SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

	if(!SSL_set1_host(ssl, host)) {
		snprintf(err, errlen, "cannot pin the hostname %s", host);
		goto fail;
	}

	SSL_set_fd(ssl, fd);

	if(SSL_connect(ssl) != 1) {
		ssl_error(err, errlen, "TLS handshake failed", ssl);
		goto fail;
	}

	/* ---- request ---- */
	/* The Host header carries the port whenever it is not the default. Leaving
	   it off is not cosmetic: a server that builds absolute URLs from Host --
	   every ACME server does, for its directory -- then hands back URLs that
	   point at port 443, and the next request goes nowhere. */
	char hostport[280];

	if(!strcmp(port, "443")) {
		snprintf(hostport, sizeof(hostport), "%s", host);
	} else {
		snprintf(hostport, sizeof(hostport), "%s:%s", host, port);
	}

	char head[4096];
	int n = snprintf(head, sizeof(head),
	                 "%s %s HTTP/1.1\r\n"
	                 "Host: %s\r\n"
	                 "User-Agent: tincstack\r\n"
	                 "Accept: */*\r\n"
	                 "Connection: close\r\n",
	                 req->method, path, hostport);

	if(n < 0 || (size_t) n >= sizeof(head)) {
		snprintf(err, errlen, "request line too long");
		goto fail;
	}

	if(req->content_type && *req->content_type) {
		n += snprintf(head + n, sizeof(head) - (size_t) n, "Content-Type: %s\r\n", req->content_type);
	}

	for(size_t i = 0; i < req->nheaders && n > 0 && (size_t) n < sizeof(head); i++) {
		n += snprintf(head + n, sizeof(head) - (size_t) n, "%s\r\n", req->headers[i]);
	}

	if(n < 0 || (size_t) n >= sizeof(head) - 32) {
		snprintf(err, errlen, "request headers too long");
		goto fail;
	}

	n += snprintf(head + n, sizeof(head) - (size_t) n, "Content-Length: %zu\r\n\r\n", req->body_len);

	if(SSL_write(ssl, head, n) != n) {
		ssl_error(err, errlen, "cannot send the request", ssl);
		goto fail;
	}

	if(req->body_len && SSL_write(ssl, req->body, (int) req->body_len) != (int) req->body_len) {
		ssl_error(err, errlen, "cannot send the request body", ssl);
		goto fail;
	}

	/* ---- response: read to EOF, then parse ---- */
	size_t cap = 8192, len = 0;
	char *buf = xmalloc(cap);

	for(;;) {
		if(len + 4096 > cap) {
			if(cap >= HTTPC_MAX_BODY) {
				snprintf(err, errlen, "response from %s is larger than %d bytes", host, HTTPC_MAX_BODY);
				free(buf);
				goto fail;
			}

			cap *= 2;
			buf = xrealloc(buf, cap);
		}

		int r = SSL_read(ssl, buf + len, (int)(cap - len - 1));

		if(r > 0) {
			len += (size_t) r;
			continue;
		}

		int e = SSL_get_error(ssl, r);

		if(e == SSL_ERROR_ZERO_RETURN || (e == SSL_ERROR_SYSCALL && !ERR_peek_error())) {
			break;                        /* clean close, or the peer just hung up */
		}

		if(!len) {
			ssl_error(err, errlen, "cannot read the response", ssl);
			free(buf);
			goto fail;
		}

		break;
	}

	buf[len] = 0;

	char *sep = strstr(buf, "\r\n\r\n");
	size_t seplen = 4;

	if(!sep) {
		sep = strstr(buf, "\n\n");
		seplen = 2;
	}

	if(!sep || strncmp(buf, "HTTP/", 5)) {
		snprintf(err, errlen, "malformed HTTP response from %s", host);
		free(buf);
		goto fail;
	}

	res->status = atoi(buf + 9);
	size_t headlen = (size_t)(sep - buf);
	res->headers = xmalloc(headlen + 1);
	memcpy(res->headers, buf, headlen);
	res->headers[headlen] = 0;

	size_t bodylen = len - headlen - seplen;
	res->body = xmalloc(bodylen + 1);
	memcpy(res->body, sep + seplen, bodylen);
	res->body[bodylen] = 0;
	res->body_len = bodylen;
	free(buf);

	char *te = httpc_header(res, "Transfer-Encoding");

	if(te) {
		if(header_has(te, "chunked")) {
			res->body_len = dechunk(res->body, res->body_len);
		}

		free(te);
	} else {
		char *cl = httpc_header(res, "Content-Length");

		if(cl) {
			size_t want = (size_t) strtoul(cl, NULL, 10);

			if(want < res->body_len) {
				res->body_len = want;
				res->body[want] = 0;
			}

			free(cl);
		}
	}

	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	closesocket(fd);
	return true;

fail:
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	closesocket(fd);
	httpc_free(res);
	return false;
}

#endif /* HAVE_OPENSSL */
