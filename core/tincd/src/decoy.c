/*
    decoy.c -- the HTTPS/HTTP decoy (active-probing resistance). See decoy.h.

    A prober gets a plausible web server: either a static page (the built-in
    default, or files under HttpsDecoyRoot) or the response of a real upstream
    site (HttpsDecoyUpstream), so scanning the port looks exactly like probing
    an ordinary website. Nothing here emits a tinc-identifying string.

    The upstream proxy fetches synchronously with a short timeout. A decoy
    connection is low-volume (one prober) and is torn down immediately after,
    so a bounded blocking fetch is an acceptable trade for not carrying a full
    async splice; documented in docs/transports.md.

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

#include <sys/socket.h>

#include "conf.h"
#include "connection.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "decoy.h"
#include "utils.h"
#include "xalloc.h"

static char *decoy_root;
static char *decoy_upstream;   /* "host:port" */

/* A generic, brandless landing page. It names no product and no node; it is
   the sort of placeholder countless idle web servers present. */
static const char default_page[] =
        "<!doctype html>\n"
        "<html lang=\"en\">\n"
        "<head><meta charset=\"utf-8\"><title>Welcome</title>\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        "<style>body{font-family:system-ui,Arial,sans-serif;margin:6em auto;max-width:40em;padding:0 1em;color:#333}h1{font-weight:600}</style>\n"
        "</head>\n"
        "<body>\n"
        "<h1>It works!</h1>\n"
        "<p>This is the default landing page for this server. The site is up and running.</p>\n"
        "<p>If you are the site administrator, replace this page with your own content.</p>\n"
        "</body>\n"
        "</html>\n";

void decoy_read_config(void) {
	free(decoy_root);
	free(decoy_upstream);
	decoy_root = NULL;
	decoy_upstream = NULL;
	get_config_string(lookup_config(&config_tree, "HttpsDecoyRoot"), &decoy_root);
	get_config_string(lookup_config(&config_tree, "HttpsDecoyUpstream"), &decoy_upstream);

	if(decoy_upstream && !*decoy_upstream) {
		free(decoy_upstream);
		decoy_upstream = NULL;
	}

	if(decoy_root && !*decoy_root) {
		free(decoy_root);
		decoy_root = NULL;
	}
}

void decoy_exit(void) {
	free(decoy_root);
	free(decoy_upstream);
	decoy_root = NULL;
	decoy_upstream = NULL;
}

/* ---- static content ------------------------------------------------------ */

/* Extract the request-target path (e.g. "/index.html") from the first line.
   Returns a normalised, traversal-safe relative path in `out` (without the
   leading '/'), defaulting to "index.html". */
static void request_path(const char *request, char *out, size_t outlen) {
	out[0] = 0;
	const char *sp = strchr(request, ' ');

	if(!sp) {
		snprintf(out, outlen, "index.html");
		return;
	}

	const char *p = sp + 1;
	const char *end = p;

	while(*end && *end != ' ' && *end != '?' && *end != '\r' && *end != '\n') {
		end++;
	}

	while(*p == '/') {
		p++;
	}

	size_t n = (size_t)(end - p);

	if(n >= outlen) {
		n = outlen - 1;
	}

	memcpy(out, p, n);
	out[n] = 0;

	/* Reject path traversal and absolute/odd names: fall back to the index. */
	if(!out[0] || strstr(out, "..") || out[0] == '/' || strchr(out, '\\')) {
		snprintf(out, outlen, "index.html");
	}
}

static const char *mime_for(const char *path) {
	const char *dot = strrchr(path, '.');

	if(!dot) {
		return "application/octet-stream";
	}

	if(!strcasecmp(dot, ".html") || !strcasecmp(dot, ".htm")) {
		return "text/html; charset=utf-8";
	}

	if(!strcasecmp(dot, ".css")) {
		return "text/css";
	}

	if(!strcasecmp(dot, ".js")) {
		return "application/javascript";
	}

	if(!strcasecmp(dot, ".png")) {
		return "image/png";
	}

	if(!strcasecmp(dot, ".jpg") || !strcasecmp(dot, ".jpeg")) {
		return "image/jpeg";
	}

	if(!strcasecmp(dot, ".svg")) {
		return "image/svg+xml";
	}

	if(!strcasecmp(dot, ".txt")) {
		return "text/plain; charset=utf-8";
	}

	return "application/octet-stream";
}

static char *read_root_file(const char *rel, size_t *len, const char **mime) {
	if(!decoy_root) {
		return NULL;
	}

	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s" SLASH "%s", decoy_root, rel);

	FILE *f = fopen(path, "rb");

	if(!f) {
		return NULL;
	}

	if(fseek(f, 0, SEEK_END)) {
		fclose(f);
		return NULL;
	}

	long sz = ftell(f);

	if(sz < 0 || sz > 8 * 1024 * 1024) {
		fclose(f);
		return NULL;
	}

	rewind(f);
	char *buf = xmalloc((size_t) sz);
	size_t rd = fread(buf, 1, (size_t) sz, f);
	fclose(f);
	*len = rd;
	*mime = mime_for(rel);
	return buf;
}

static char *build_static(const char *request, size_t *resplen) {
	char rel[512];
	request_path(request, rel, sizeof(rel));

	size_t blen = 0;
	const char *mime = "text/html; charset=utf-8";
	char *body = read_root_file(rel, &blen, &mime);
	int status = 200;
	const char *status_text = "OK";

	if(!body) {
		/* An unknown path under a configured root is a 404; with no root the
		   default page answers every path with 200 (a single-page site). */
		if(decoy_root) {
			status = 404;
			status_text = "Not Found";
			static const char nf[] = "<!doctype html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>\n";
			body = xstrdup(nf);
			blen = sizeof(nf) - 1;
			mime = "text/html; charset=utf-8";
		} else {
			body = xmalloc(sizeof(default_page));
			memcpy(body, default_page, sizeof(default_page));
			blen = sizeof(default_page) - 1;
		}
	}

	char header[512];
	int hlen = snprintf(header, sizeof(header),
	                    "HTTP/1.1 %d %s\r\n"
	                    "Server: nginx\r\n"
	                    "Content-Type: %s\r\n"
	                    "Content-Length: %zu\r\n"
	                    "Connection: close\r\n"
	                    "\r\n",
	                    status, status_text, mime, blen);

	char *resp = xmalloc((size_t) hlen + blen);
	memcpy(resp, header, (size_t) hlen);
	memcpy(resp + hlen, body, blen);
	free(body);
	*resplen = (size_t) hlen + blen;
	return resp;
}

/* ---- upstream proxy ------------------------------------------------------ */

/* Rewrite the Host: header of the request head to the upstream authority, so
   the upstream serves its own site. Returns a newly-allocated request. */
static char *rewrite_host(const char *request, size_t reqlen, const char *host) {
	/* Find the Host: line (case-insensitive) and replace its value. */
	const char *line = request;
	const char *hdr_end = request + reqlen;
	char *out = xmalloc(reqlen + strlen(host) + 32);
	size_t olen = 0;
	bool replaced = false;

	while(line < hdr_end) {
		const char *eol = memchr(line, '\n', (size_t)(hdr_end - line));
		size_t linelen = eol ? (size_t)(eol - line + 1) : (size_t)(hdr_end - line);

		if(linelen >= 5 && !strncasecmp(line, "Host:", 5)) {
			olen += (size_t) snprintf(out + olen, strlen(host) + 12, "Host: %s\r\n", host);
			replaced = true;
		} else {
			memcpy(out + olen, line, linelen);
			olen += linelen;
		}

		if(!eol) {
			break;
		}

		line = eol + 1;
	}

	(void) replaced;
	out[olen] = 0;
	return out;
}

static char *proxy_upstream(const char *request, size_t reqlen, size_t *resplen) {
	char host[256];
	char *colon;
	strncpy(host, decoy_upstream, sizeof(host) - 1);
	host[sizeof(host) - 1] = 0;
	colon = strrchr(host, ':');
	const char *port = "80";

	if(colon) {
		*colon = 0;
		port = colon + 1;
	}

	struct addrinfo *ai = str2addrinfo(host, port, SOCK_STREAM);

	if(!ai) {
		logger(DEBUG_CONNECTIONS, LOG_WARNING, "Decoy upstream %s did not resolve", decoy_upstream);
		return NULL;
	}

	int fd = socket(ai->ai_family, SOCK_STREAM, IPPROTO_TCP);

	if(fd < 0) {
		freeaddrinfo(ai);
		return NULL;
	}

	struct timeval tv = { 3, 0 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (void *) &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (void *) &tv, sizeof(tv));

	if(connect(fd, ai->ai_addr, ai->ai_addrlen)) {
		closesocket(fd);
		freeaddrinfo(ai);
		return NULL;
	}

	freeaddrinfo(ai);

	char *req = rewrite_host(request, reqlen, host);
	size_t sent = 0, tolen = strlen(req);

	while(sent < tolen) {
		ssize_t n = send(fd, req + sent, tolen - sent, 0);

		if(n <= 0) {
			break;
		}

		sent += (size_t) n;
	}

	free(req);

	size_t cap = 65536, len = 0;
	char *resp = xmalloc(cap);

	for(;;) {
		if(len == cap) {
			if(cap >= 4 * 1024 * 1024) {
				break;
			}

			cap *= 2;
			resp = xrealloc(resp, cap);
		}

		ssize_t n = recv(fd, resp + len, cap - len, 0);

		if(n <= 0) {
			break;
		}

		len += (size_t) n;
	}

	closesocket(fd);

	if(!len) {
		free(resp);
		return NULL;
	}

	*resplen = len;
	return resp;
}

char *decoy_respond(const char *request, size_t reqlen, size_t *resplen) {
	if(decoy_upstream) {
		char *r = proxy_upstream(request, reqlen, resplen);

		if(r) {
			return r;
		}

		/* Upstream unreachable: fall back to static so the port never breaks
		   character. */
	}

	return build_static(request, resplen);
}

/* ---- plain-HTTP path ----------------------------------------------------- */

static void send_all(int fd, const char *buf, size_t len) {
	size_t off = 0;

	while(off < len) {
		ssize_t n = send(fd, buf + off, len - off, 0);

		if(n <= 0) {
			if(n < 0 && sockwouldblock(sockerrno)) {
				continue;
			}

			break;
		}

		off += (size_t) n;
	}
}

void decoy_serve_plain(connection_t *c) {
	/* Read the request head (bounded), then answer and close. The socket is
	   non-blocking; a prober that dribbles bytes is bounded by the auth
	   timeout, but here we do one bounded read pass. */
	char req[8192];
	size_t rlen = 0;

	for(int spin = 0; spin < 64 && rlen < sizeof(req) - 1; spin++) {
		ssize_t n = recv(c->socket, req + rlen, sizeof(req) - 1 - rlen, 0);

		if(n > 0) {
			rlen += (size_t) n;

			if(rlen >= 4 && memmem(req, rlen, "\r\n\r\n", 4)) {
				break;
			}
		} else {
			break;
		}
	}

	req[rlen] = 0;

	size_t resplen = 0;
	char *resp = decoy_respond(req, rlen, &resplen);

	if(resp) {
		send_all(c->socket, resp, resplen);
		free(resp);
	}

	logger(DEBUG_CONNECTIONS, LOG_INFO, "Served the decoy to a plain-HTTP probe from %s", c->hostname);
	terminate_connection(c, false);
}
