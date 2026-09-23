/*
    decoy.c -- the HTTPS/HTTP decoy (active-probing resistance). See decoy.h.

    A prober gets a plausible web server: either a static page (the built-in
    default, or files under HttpsDecoyRoot) or the response of a real upstream
    site (HttpsDecoyUpstream), so scanning the port looks exactly like probing
    an ordinary website. Nothing here emits a tinc-identifying string.

    Everything here is driven by the daemon's event loop (event.c): the
    upstream fetch is a non-blocking connect/send/recv with a total deadline
    and a size cap (security review M5-1), and the plain-HTTP path reads and
    writes on readiness with no busy-wait (M5-8). The upstream address is
    resolved once when the config is read, never per probe. Request headers
    that carry a tinc authenticator are never forwarded (M5-10).

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

#include "conf.h"
#include "connection.h"
#include "event.h"
#include "list.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "decoy.h"
#include "utils.h"
#include "xalloc.h"

#define TINC_TRANSPORT_DAEMON
#include "transport.h"

/* memmem() is not in mingw's libc; the one caller only looks for the end of
   an HTTP head, so a small portable scan is enough. */
static bool mem_has(const void *hay, size_t haylen, const char *needle, size_t nlen) {
	const unsigned char *h = hay;

	if(nlen > haylen) {
		return false;
	}

	for(size_t i = 0; i + nlen <= haylen; i++) {
		if(!memcmp(h + i, needle, nlen)) {
			return true;
		}
	}

	return false;
}

static char *decoy_root;
static char *decoy_upstream;        /* "host:port" as configured */
static char *decoy_upstream_host;   /* host part, for the forwarded Host: header */
static sockaddr_t decoy_upstream_sa; /* resolved once in decoy_read_config() */
static bool decoy_upstream_ready;

/* Bounds of one upstream fetch (M5-1): total wall-clock budget from connect
   to last byte, and the largest response we relay. */
#define DECOY_FETCH_DEADLINE_MS 3000
#define DECOY_FETCH_MAX (1024 * 1024)
#define DECOY_REQ_MAX 8192

/* For log lines from a fetch that may outlive a config reload. */
#define UPSTREAM_NAME (decoy_upstream ? decoy_upstream : "(unset)")

/* nginx's own welcome page (nginx 1.27, /usr/share/nginx/html/index.html),
   byte for byte: every header already says nginx, and a server that says
   nginx and shows another server's page is a one-request check
   (testing/transports/decoy-conformance-test.sh compares the bodies). */
static const char default_page[] =
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        "<title>Welcome to nginx!</title>\n"
        "<style>\n"
        "html { color-scheme: light dark; }\n"
        "body { width: 35em; margin: 0 auto;\n"
        "font-family: Tahoma, Verdana, Arial, sans-serif; }\n"
        "</style>\n"
        "</head>\n"
        "<body>\n"
        "<h1>Welcome to nginx!</h1>\n"
        "<p>If you see this page, the nginx web server is successfully installed and\n"
        "working. Further configuration is required.</p>\n"
        "\n"
        "<p>For online documentation and support please refer to\n"
        "<a href=\"http://nginx.org/\">nginx.org</a>.<br/>\n"
        "Commercial support is available at\n"
        "<a href=\"http://nginx.com/\">nginx.com</a>.</p>\n"
        "\n"
        "<p><em>Thank you for using nginx.</em></p>\n"
        "</body>\n"
        "</html>\n";

static void decoy_reap_finished(void);
static void decoy_cancel_all(void);
static timeout_t decoy_reaper;

static void decoy_free_config(void) {
	free(decoy_root);
	free(decoy_upstream);
	free(decoy_upstream_host);
	decoy_root = NULL;
	decoy_upstream = NULL;
	decoy_upstream_host = NULL;
	decoy_upstream_ready = false;
}

/* Resolve HttpsDecoyUpstream once, here, at (re)load time. A blocking DNS
   lookup is acceptable while reading the config; it must never happen on the
   probe path (M5-1). */
static void resolve_upstream(void) {
	char host[256];
	strncpy(host, decoy_upstream, sizeof(host) - 1);
	host[sizeof(host) - 1] = 0;
	char *colon = strrchr(host, ':');
	const char *port = "80";

	if(colon) {
		*colon = 0;
		port = colon + 1;
	}

	struct addrinfo *ai = str2addrinfo(host, port, SOCK_STREAM);

	if(!ai) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Decoy upstream %s does not resolve; serving the static page instead", decoy_upstream);
		return;
	}

	if(ai->ai_addrlen <= sizeof(decoy_upstream_sa)) {
		memcpy(&decoy_upstream_sa, ai->ai_addr, ai->ai_addrlen);
		decoy_upstream_host = xstrdup(host);
		decoy_upstream_ready = true;
	}

	freeaddrinfo(ai);
}

void decoy_read_config(void) {
	decoy_free_config();
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

	if(decoy_upstream) {
		resolve_upstream();
	}
}

void decoy_exit(void) {
	decoy_cancel_all();
	decoy_free_config();
	timeout_del(&decoy_reaper);
}

/* ---- static content ------------------------------------------------------ */

/* What the decoy answers is measured against nginx 1.27 with
   `server_tokens off' (testing/transports/decoy-conformance-test.sh): the
   same status for the same request, the same headers in the same order, the
   same error pages byte for byte. */

/* Extract the request-target path (e.g. "/index.html") from the first line.
   Returns a normalised, traversal-safe relative path in `out` (without the
   leading '/'), "index.html" for "/". */
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

	if(!out[0]) {
		snprintf(out, outlen, "index.html");
	} else if(strstr(out, "..") || out[0] == '/' || strchr(out, '\\')) {
		snprintf(out, outlen, "..");     /* never a file: a 404 */
	}
}

/* nginx's mime.types for the extensions a decoy site plausibly has. */
static const char *mime_for(const char *path) {
	const char *dot = strrchr(path, '.');

	if(!dot) {
		return "application/octet-stream";
	}

	static const char *const map[][2] = {
		{".html", "text/html"}, {".htm", "text/html"}, {".css", "text/css"},
		{".js", "application/javascript"}, {".json", "application/json"},
		{".png", "image/png"}, {".jpg", "image/jpeg"}, {".jpeg", "image/jpeg"},
		{".gif", "image/gif"}, {".svg", "image/svg+xml"}, {".ico", "image/x-icon"},
		{".txt", "text/plain"}, {".xml", "text/xml"}, {".woff2", "font/woff2"},
	};

	for(size_t i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
		if(!strcasecmp(dot, map[i][0])) {
			return map[i][1];
		}
	}

	return "application/octet-stream";
}

static char *read_root_file(const char *rel, size_t *len, time_t *mtime) {
	if(!decoy_root) {
		return NULL;
	}

	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s" SLASH "%s", decoy_root, rel);

	struct stat st;

	if(stat(path, &st) || !S_ISREG(st.st_mode) || st.st_size > 8 * 1024 * 1024) {
		return NULL;
	}

	FILE *f = fopen(path, "rb");

	if(!f) {
		return NULL;
	}

	char *buf = xmalloc((size_t) st.st_size + 1);
	size_t rd = fread(buf, 1, (size_t) st.st_size, f);
	fclose(f);
	*len = rd;
	*mtime = st.st_mtime;
	return buf;
}

/* RFC 7231 IMF-fixdate, locale-independent. */
static void http_date(time_t t, char *out, size_t outlen) {
	static const char *const wd[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
	static const char *const mo[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
	struct tm tm;
#ifdef HAVE_WINDOWS
	tm = *gmtime(&t);
#else
	gmtime_r(&t, &tm);
#endif
	snprintf(out, outlen, "%s, %02d %s %04d %02d:%02d:%02d GMT", wd[tm.tm_wday], tm.tm_mday, mo[tm.tm_mon],
	         tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

/* The built-in page's Last-Modified: the file's mtime in the official
   nginx:1.27.5 image (Wed, 16 Apr 2025 12:01:11 GMT), so Last-Modified and
   ETag ("67ff9c07-267") are those of countless stock installs -- not the
   daemon's start time, which would change on every restart. */
#define DEFAULT_PAGE_MTIME ((time_t)0x67ff9c07)

typedef struct http_req_t {
	bool valid;             /* a well-formed HTTP/1.x request line */
	bool head;              /* HEAD: headers only */
	bool get;               /* GET or HEAD */
	bool http10;
	bool has_host;
	bool wants_close;       /* Connection: close */
} http_req_t;

static bool header_present(const char *request, const char *name) {
	size_t nlen = strlen(name);

	/* Stop at the blank line: what follows is a body or the next request. */
	for(const char *l = strchr(request, '\n'); l && l[1] && l[1] != '\r' && l[1] != '\n'; l = strchr(l + 1, '\n')) {
		if(!strncasecmp(l + 1, name, nlen) && l[1 + nlen] == ':') {
			return true;
		}
	}

	return false;
}

static bool header_has(const char *request, const char *name, const char *token) {
	size_t nlen = strlen(name);

	/* Stop at the blank line: what follows is a body or the next request. */
	for(const char *l = strchr(request, '\n'); l && l[1] && l[1] != '\r' && l[1] != '\n'; l = strchr(l + 1, '\n')) {
		if(!strncasecmp(l + 1, name, nlen) && l[1 + nlen] == ':') {
			const char *e = strchr(l + 1, '\n');
			size_t vlen = e ? (size_t)(e - (l + 2 + nlen)) : strlen(l + 2 + nlen);
			char v[256];

			if(vlen >= sizeof(v)) {
				vlen = sizeof(v) - 1;
			}

			memcpy(v, l + 2 + nlen, vlen);
			v[vlen] = 0;

			for(char *c = v; *c; c++) {
				*c = (char)tolower((unsigned char) * c);
			}

			if(strstr(v, token)) {
				return true;
			}
		}
	}

	return false;
}

/* "METHOD SP /target SP HTTP/1.x", method in upper-case letters. */
static http_req_t parse_request(const char *request) {
	http_req_t r = {0};
	const char *p = request;
	size_t mlen = 0;

	while(p[mlen] >= 'A' && p[mlen] <= 'Z') {
		mlen++;
	}

	if(!mlen || mlen > 16 || p[mlen] != ' ' || p[mlen + 1] != '/') {
		return r;
	}

	const char *target = p + mlen + 1;
	const char *sp = target;

	while(*sp && *sp != ' ' && *sp != '\r' && *sp != '\n') {
		sp++;
	}

	if(*sp != ' ' || strncmp(sp + 1, "HTTP/1.", 7) || (sp[8] != '0' && sp[8] != '1') ||
	                (sp[9] != '\r' && sp[9] != '\n')) {
		return r;
	}

	r.valid = true;
	r.http10 = sp[8] == '0';
	r.head = mlen == 4 && !strncmp(p, "HEAD", 4);
	r.get = r.head || (mlen == 3 && !strncmp(p, "GET", 3));
	r.has_host = header_present(request, "host");
	r.wants_close = header_has(request, "connection", "close");
	return r;
}

/* nginx's own error page, `server_tokens off'. */
static char *error_body(int status, const char *reason, const char *extra, size_t *len) {
	char *b;
	int n;

	if(extra) {
		n = xasprintf(&b, "<html>\r\n<head><title>%d %s</title></head>\r\n<body>\r\n"
		              "<center><h1>%d Bad Request</h1></center>\r\n<center>%s</center>\r\n"
		              "<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n", status, extra, status, extra);
	} else {
		n = xasprintf(&b, "<html>\r\n<head><title>%d %s</title></head>\r\n<body>\r\n"
		              "<center><h1>%d %s</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n",
		              status, reason, status, reason);
	}

	*len = n > 0 ? (size_t) n : 0;
	return b;
}

static char *assemble(int status, const char *reason, const char *mime, const char *body, size_t blen,
                      time_t mtime, bool keep_alive, bool head, size_t *resplen) {
	char date[64], lm[64] = "", etag[64] = "";
	http_date(time(NULL), date, sizeof(date));

	if(mtime) {
		char d[40];
		http_date(mtime, d, sizeof(d));
		snprintf(lm, sizeof(lm), "Last-Modified: %s\r\n", d);
		snprintf(etag, sizeof(etag), "ETag: \"%lx-%lx\"\r\n", (unsigned long) mtime, (unsigned long) blen);
	}

	char header[768];
	int hlen = snprintf(header, sizeof(header),
	                    "HTTP/1.1 %d %s\r\n"
	                    "Server: nginx\r\n"
	                    "Date: %s\r\n"
	                    "Content-Type: %s\r\n"
	                    "Content-Length: %lu\r\n"
	                    "%s"
	                    "Connection: %s\r\n"
	                    "%s%s"
	                    "\r\n",
	                    status, reason, date, mime, (unsigned long) blen, lm,
	                    keep_alive ? "keep-alive" : "close", etag, mtime ? "Accept-Ranges: bytes\r\n" : "");

	size_t out = (size_t) hlen + (head ? 0 : blen);
	char *resp = xmalloc(out);
	memcpy(resp, header, (size_t) hlen);

	if(!head) {
		memcpy(resp + hlen, body, blen);
	}

	*resplen = out;
	return resp;
}

/* The response nginx gives `request' on a TLS port (`plain_on_tls' false) or
   when plain HTTP arrives on its TLS port (true). */
static char *build_response(const char *request, bool plain_on_tls, size_t *resplen) {
	http_req_t r = parse_request(request);
	size_t blen;
	char *body;
	char *resp;

	/* A request nginx would not parse, or HTTP/1.1 without Host, or plain
	   HTTP on the TLS port: 400, and the connection is closed. */
	if(!r.valid || (!r.http10 && !r.has_host) || plain_on_tls) {
		body = error_body(400, "Bad Request", r.valid && plain_on_tls ? "The plain HTTP request was sent to HTTPS port" : NULL, &blen);
		resp = assemble(400, "Bad Request", "text/html", body, blen, 0, false, false, resplen);
		free(body);
		return resp;
	}

	bool keep_alive = !r.http10 && !r.wants_close;

	if(!r.get) {
		body = error_body(405, "Not Allowed", NULL, &blen);
		resp = assemble(405, "Not Allowed", "text/html", body, blen, 0, keep_alive, false, resplen);
		free(body);
		return resp;
	}

	char rel[512];
	request_path(request, rel, sizeof(rel));
	time_t mtime = 0;
	body = read_root_file(rel, &blen, &mtime);

	if(body) {
		resp = assemble(200, "OK", mime_for(rel), body, blen, mtime, keep_alive, r.head, resplen);
		free(body);
		return resp;
	}

	/* The built-in page is the site's index; with a configured root only
	   its files exist. */
	if(!decoy_root && !strcmp(rel, "index.html")) {
		return assemble(200, "OK", "text/html", default_page, sizeof(default_page) - 1, DEFAULT_PAGE_MTIME,
		                keep_alive, r.head, resplen);
	}

	body = error_body(404, "Not Found", NULL, &blen);
	resp = assemble(404, "Not Found", "text/html", body, blen, 0, keep_alive, r.head, resplen);
	free(body);
	return resp;
}

static char *build_static(const char *request, size_t *resplen) {
	return build_response(request, false, resplen);
}

char *decoy_respond_static(const char *request, size_t reqlen, size_t *resplen) {
	(void) reqlen;
	return build_static(request, resplen);
}

/* ---- upstream proxy (event-driven) --------------------------------------- */

/* Rewrite the request head for the upstream: Host: becomes the upstream
   authority, Connection: becomes close (so the upstream ends the response
   with EOF), and every header that can carry the tinc authenticator or
   betray the WebSocket upgrade shape is dropped (M5-10): Cookie, Upgrade,
   Sec-WebSocket-*. What the upstream sees is an ordinary request. */
static bool header_is(const char *line, size_t linelen, const char *name) {
	size_t n = strlen(name);
	return linelen >= n && !strncasecmp(line, name, n);
}

static char *rewrite_request(const char *request, size_t reqlen, const char *host) {
	const char *line = request;
	const char *hdr_end = request + reqlen;
	char *out = xmalloc(reqlen + strlen(host) + 64);
	size_t olen = 0;
	bool first = true;

	while(line < hdr_end) {
		const char *eol = memchr(line, '\n', (size_t)(hdr_end - line));
		size_t linelen = eol ? (size_t)(eol - line + 1) : (size_t)(hdr_end - line);

		if(first) {
			memcpy(out + olen, line, linelen);
			olen += linelen;
			first = false;
			/* Our own headers right after the request line; duplicates from
			   the client are dropped below. */
			olen += (size_t) sprintf(out + olen, "Host: %s\r\nConnection: close\r\n", host);
		} else if(header_is(line, linelen, "Host:") || header_is(line, linelen, "Connection:") ||
		          header_is(line, linelen, "Cookie:") || header_is(line, linelen, "Upgrade:") ||
		          header_is(line, linelen, "Sec-WebSocket-") || header_is(line, linelen, "Authorization:")) {
			/* dropped */
		} else {
			memcpy(out + olen, line, linelen);
			olen += linelen;
		}

		if(!eol) {
			break;
		}

		line = eol + 1;
	}

	out[olen] = 0;
	return out;
}

struct decoy_fetch_t {
	int fd;
	io_t io;
	timeout_t deadline;
	bool connected;
	bool done;              /* finished; waiting for the reaper to deliver */

	char *req;              /* rewritten request to send */
	size_t reqlen, reqoff;
	char *orig;             /* original head, for the static fallback's path */
	size_t origlen;

	char *resp;
	size_t rlen, rcap;

	decoy_cb_t cb;
	void *data;
	list_node_t *node;
};

static list_t fetches;

static void fetch_release(decoy_fetch_t *f) {
	io_del(&f->io);
	timeout_del(&f->deadline);

	if(f->fd >= 0) {
		closesocket(f->fd);
		f->fd = -1;
	}

	free(f->req);
	free(f->orig);
	free(f->resp);

	if(f->node) {
		list_delete_node(&fetches, f->node);
	}

	free(f);
}

/* Hand the result to the owner and free the handle. `f->resp` is consumed. */
static void fetch_deliver(decoy_fetch_t *f) {
	char *resp = f->resp;
	size_t len = f->rlen;
	f->resp = NULL;

	if(!resp || !len) {
		free(resp);
		logger(DEBUG_CONNECTIONS, LOG_INFO, "Decoy upstream %s gave no response; serving the static page", UPSTREAM_NAME);
		resp = build_static(f->orig, &len);
	}

	decoy_cb_t cb = f->cb;
	void *data = f->data;
	fetch_release(f);
	cb(data, resp, len);
}

/* A fetch whose deadline fired must not free itself inside its own timer
   callback (timeout_execute() touches the timeout after the callback), so
   it is marked done and delivered from this separate, static timer -- the
   same pattern transport_sf.c uses for its sessions. */
static void decoy_reap_finished(void) {
	for list_each(decoy_fetch_t, f, &fetches) {
		if(f->done) {
			fetch_deliver(f);
		}
	}
}

static void reaper_cb(void *data) {
	(void) data;
	decoy_reap_finished();
}

static void fetch_finish_later(decoy_fetch_t *f) {
	f->done = true;
	io_del(&f->io);

	struct timeval tv = { 0, 0 };

	if(decoy_reaper.cb) {
		timeout_set(&decoy_reaper, &tv);
	} else {
		timeout_add(&decoy_reaper, reaper_cb, NULL, &tv);
	}
}

static void fetch_deadline(void *data) {
	decoy_fetch_t *f = data;
	logger(DEBUG_CONNECTIONS, LOG_INFO, "Decoy upstream %s: %s after %d ms; %s", UPSTREAM_NAME,
	       f->connected ? "no end of response" : "connect timed out", DECOY_FETCH_DEADLINE_MS,
	       f->rlen ? "relaying what arrived" : "serving the static page");
	fetch_finish_later(f);
}

static void fetch_io(void *data, int flags) {
	decoy_fetch_t *f = data;

	if(f->done) {
		return;
	}

	if(!f->connected) {
		int err = 0;
		socklen_t len = sizeof(err);

		if(getsockopt(f->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len) || err) {
			logger(DEBUG_CONNECTIONS, LOG_INFO, "Decoy upstream %s: connect failed: %s", UPSTREAM_NAME, sockstrerror(err));
			fetch_deliver(f);
			return;
		}

		f->connected = true;
	}

	if(flags & IO_WRITE) {
		while(f->reqoff < f->reqlen) {
			ssize_t n = send(f->fd, f->req + f->reqoff, f->reqlen - f->reqoff, 0);

			if(n > 0) {
				f->reqoff += (size_t) n;
				continue;
			}

			if(n < 0 && sockwouldblock(sockerrno)) {
				return; /* stay on IO_WRITE */
			}

			fetch_deliver(f);
			return;
		}

		io_set(&f->io, IO_READ);
		return;
	}

	for(;;) {
		if(f->rlen == f->rcap) {
			if(f->rcap >= DECOY_FETCH_MAX) {
				fetch_deliver(f);
				return;
			}

			f->rcap = f->rcap ? f->rcap * 2 : 16384;
			f->resp = xrealloc(f->resp, f->rcap);
		}

		ssize_t n = recv(f->fd, f->resp + f->rlen, f->rcap - f->rlen, 0);

		if(n > 0) {
			f->rlen += (size_t) n;
			continue;
		}

		if(n < 0 && sockwouldblock(sockerrno)) {
			return;
		}

		/* EOF (Connection: close) or error: deliver what we have. */
		fetch_deliver(f);
		return;
	}
}

/* Bytes of buf[0..len) the first request takes: its head and whatever part
   of a Content-Length body has arrived. All of it without a complete head. */
static size_t request_span(const char *buf, size_t len) {
	size_t used = len;

	for(size_t i = 0; i + 4 <= len; i++) {
		if(!memcmp(buf + i, "\r\n\r\n", 4)) {
			used = i + 4;
			break;
		}
	}

	for(size_t i = 0; i + 16 <= used; i++) {
		if(buf[i] == '\n' && !strncasecmp(buf + i + 1, "content-length:", 15)) {
			long n = strtol(buf + i + 16, NULL, 10);

			if(n > 0) {
				used += (size_t)n < len - used ? (size_t)n : len - used;
			}

			break;
		}
	}

	return used;
}

size_t decoy_next_request(char *buf, size_t len) {
	size_t used = request_span(buf, len);
	memmove(buf, buf + used, len - used);
	return len - used;
}

decoy_fetch_t *decoy_fetch_start(const char *request, size_t reqlen, decoy_cb_t cb, void *data) {
	if(!decoy_upstream_ready) {
		return NULL;
	}

	int fd = socket(decoy_upstream_sa.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);

	if(fd < 0) {
		return NULL;
	}

#ifdef FD_CLOEXEC
	fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
#ifdef O_NONBLOCK
	{
		int fl = fcntl(fd, F_GETFL);
		fcntl(fd, F_SETFL, fl | O_NONBLOCK);
	}
#elif defined(HAVE_WINDOWS)
	{
		unsigned long arg = 1;
		ioctlsocket(fd, FIONBIO, &arg);
	}
#endif

	if(connect(fd, &decoy_upstream_sa.sa, SALEN(decoy_upstream_sa.sa)) && !sockinprogress(sockerrno)) {
		logger(DEBUG_CONNECTIONS, LOG_INFO, "Decoy upstream %s: connect failed: %s", decoy_upstream, sockstrerror(sockerrno));
		closesocket(fd);
		return NULL;
	}

	decoy_fetch_t *f = xzalloc(sizeof(*f));
	f->fd = fd;
	f->cb = cb;
	f->data = data;
	reqlen = request_span(request, reqlen); /* not a pipelined one after it */
	f->orig = xmalloc(reqlen + 1);
	memcpy(f->orig, request, reqlen);
	f->orig[reqlen] = 0;
	f->origlen = reqlen;
	f->req = rewrite_request(request, reqlen, decoy_upstream_host);
	f->reqlen = strlen(f->req);
	f->node = list_insert_tail(&fetches, f);

	io_add(&f->io, fetch_io, f, fd, IO_WRITE);
	timeout_add(&f->deadline, fetch_deadline, f, &(struct timeval) {
		DECOY_FETCH_DEADLINE_MS / 1000, (DECOY_FETCH_DEADLINE_MS % 1000) * 1000
	});
	return f;
}

void decoy_fetch_cancel(decoy_fetch_t *f) {
	if(f) {
		fetch_release(f);
	}
}

/* Shutdown: drop every outstanding fetch without calling back (the owning
   connections are being torn down as well). */
static void decoy_cancel_all(void) {
	while(fetches.head) {
		fetch_release(fetches.head->data);
	}
}

/* ---- plain-HTTP path (event-driven) -------------------------------------- */

typedef enum plain_state_t {
	PS_READ_REQ,
	PS_FETCHING,
	PS_WRITE,
} plain_state_t;

typedef struct plain_decoy_t {
	connection_t *c;
	plain_state_t state;
	char req[DECOY_REQ_MAX];
	size_t rlen;
	decoy_fetch_t *fetch;
	char *resp;
	size_t wlen, woff;
	bool on_tls_port;       /* plain HTTP on the HttpsPort listener */
} plain_decoy_t;

static void plain_close(connection_t *c) {
	plain_decoy_t *p = c->transport_data;

	if(!p) {
		return;
	}

	decoy_fetch_cancel(p->fetch);
	free(p->resp);
	free(p);
	c->transport_data = NULL;
}

/* A pseudo-carrier so the connection's private state is released through the
   normal transport_connection_close() path when it is terminated. */
static const transport_t decoy_plain_transport = {
	.id = TRANSPORT_PLAIN,
	.name = "decoy",
	.close = plain_close,
};

static void plain_respond(plain_decoy_t *p);

static void plain_write(plain_decoy_t *p) {
	connection_t *c = p->c;

	while(p->woff < p->wlen) {
		ssize_t n = send(c->socket, p->resp + p->woff, p->wlen - p->woff, 0);

		if(n > 0) {
			p->woff += (size_t) n;
			/* nginx's send_timeout: 60 s without progress, not 60 s in all */
			c->last_ping_time = now.tv_sec;
			continue;
		}

		if(n < 0 && sockwouldblock(sockerrno)) {
			/* The client is not reading: wait for write readiness (M5-8);
			   the web-front timeout reaps it if it never does. */
			io_set(&c->io, IO_WRITE);
			return;
		}

		logger(DEBUG_CONNECTIONS, LOG_INFO, "Decoy: plain-HTTP probe from %s went away mid-response", c->hostname);
		terminate_connection(c, false);
		return;
	}

	logger(DEBUG_CONNECTIONS, LOG_INFO, "Served the decoy to a plain-HTTP probe from %s", c->hostname);

	if(!decoy_keeps_alive(p->resp, p->wlen)) {
		terminate_connection(c, false);
		return;
	}

	/* Keep-alive, as the response said: wait for the next request, for
	   nginx's keepalive_timeout (the web-front reaper counts from
	   last_ping_time with the header timeout). */
	free(p->resp);
	p->resp = NULL;
	p->wlen = p->woff = 0;
	p->rlen = decoy_next_request(p->req, p->rlen);
	p->req[p->rlen] = 0;
	p->state = PS_READ_REQ;
	c->last_ping_time = now.tv_sec + DECOY_KEEPALIVE_TIMEOUT - DECOY_HEADER_TIMEOUT;
	io_set(&c->io, IO_READ);

	if(p->rlen >= 4 && mem_has(p->req, p->rlen, "\r\n\r\n", 4)) {
		plain_respond(p); /* a pipelined request is already here */
	}
}


bool decoy_keeps_alive(const char *resp, size_t len) {
	static const char ka[] = "\r\nConnection: keep-alive\r\n";
	const char *end = NULL;

	for(size_t i = 0; i + 4 <= len; i++) {
		if(!memcmp(resp + i, "\r\n\r\n", 4)) {
			end = resp + i + 2;
			break;
		}
	}

	return end && mem_has(resp, (size_t)(end - resp), ka, sizeof(ka) - 1);
}

static void plain_start_write(plain_decoy_t *p, char *resp, size_t len) {
	p->resp = resp;
	p->wlen = len;
	p->woff = 0;
	p->state = PS_WRITE;
	plain_write(p);
}

static void plain_fetched(void *data, char *resp, size_t len) {
	plain_decoy_t *p = data;
	p->fetch = NULL;
	plain_start_write(p, resp, len);
}

static void plain_respond(plain_decoy_t *p) {
	if(p->on_tls_port) {
		size_t len = 0;
		char *resp = build_response(p->req, true, &len);
		plain_start_write(p, resp, len);
		return;
	}

	p->state = PS_FETCHING;
	io_set(&p->c->io, 0); /* nothing to do on the client socket meanwhile */
	p->fetch = decoy_fetch_start(p->req, p->rlen, plain_fetched, p);

	if(!p->fetch) {
		size_t len = 0;
		char *resp = build_static(p->req, &len);
		plain_start_write(p, resp, len);
	}
}

static void plain_read(plain_decoy_t *p) {
	connection_t *c = p->c;

	for(;;) {
		if(p->rlen >= sizeof(p->req) - 1) {
			break; /* head too long: answer what we have */
		}

		ssize_t n = recv(c->socket, p->req + p->rlen, sizeof(p->req) - 1 - p->rlen, 0);

		if(n > 0) {
			p->rlen += (size_t) n;
			p->req[p->rlen] = 0;

			if(p->rlen >= 4 && mem_has(p->req, p->rlen, "\r\n\r\n", 4)) {
				break;
			}

			/* nginx answers a request line it cannot parse at once, without
			   waiting for the rest of a head that will never come. */
			if(memchr(p->req, '\n', p->rlen) && !parse_request(p->req).valid) {
				break;
			}

			continue;
		}

		if(n < 0 && sockwouldblock(sockerrno)) {
			return; /* wait for the rest of the head */
		}

		if(n == 0 && p->rlen) {
			break; /* client shut its side after a headless request */
		}

		terminate_connection(c, false);
		return;
	}

	p->req[p->rlen] = 0;
	plain_respond(p);
}

static void plain_io(void *data, int flags) {
	connection_t *c = data;
	plain_decoy_t *p = c->transport_data;

	if(!p) {
		return;
	}

	switch(p->state) {
	case PS_READ_REQ:
		plain_read(p);
		return;

	case PS_WRITE:
		if(flags & IO_WRITE) {
			plain_write(p);
		}

		return;

	case PS_FETCHING:
	default:
		return;
	}
}

static void serve_plain(connection_t *c, bool on_tls_port) {
	plain_decoy_t *p = xzalloc(sizeof(*p));
	p->c = c;
	p->on_tls_port = on_tls_port;
	c->status.web_front = true;
	p->state = PS_READ_REQ;
	c->transport = &decoy_plain_transport;
	c->transport_data = p;

	io_del(&c->io);
	io_add(&c->io, plain_io, c, c->socket, IO_READ);

	/* The peeked bytes are already in the socket: read them now. */
	plain_read(p);
}

void decoy_serve_plain(connection_t *c) {
	serve_plain(c, false);
}

void decoy_serve_plain_tls_port(connection_t *c) {
	serve_plain(c, true);
}

bool decoy_front_full(void) {
	int n = 0;

	for list_each(connection_t, c, &connection_list) {
		if(c->status.web_front && !c->edge && ++n >= DECOY_MAX_WEB_CLIENTS) {
			return true;
		}
	}

	return false;
}
