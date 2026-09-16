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

#include <sys/socket.h>

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

static void plain_write(plain_decoy_t *p) {
	connection_t *c = p->c;

	while(p->woff < p->wlen) {
		ssize_t n = send(c->socket, p->resp + p->woff, p->wlen - p->woff, 0);

		if(n > 0) {
			p->woff += (size_t) n;
			continue;
		}

		if(n < 0 && sockwouldblock(sockerrno)) {
			/* The client is not reading: wait for write readiness (M5-8);
			   pingtimeout reaps it if it never does. */
			io_set(&c->io, IO_WRITE);
			return;
		}

		logger(DEBUG_CONNECTIONS, LOG_INFO, "Decoy: plain-HTTP probe from %s went away mid-response", c->hostname);
		terminate_connection(c, false);
		return;
	}

	logger(DEBUG_CONNECTIONS, LOG_INFO, "Served the decoy to a plain-HTTP probe from %s", c->hostname);
	terminate_connection(c, false);
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

			if(p->rlen >= 4 && memmem(p->req, p->rlen, "\r\n\r\n", 4)) {
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

void decoy_serve_plain(connection_t *c) {
	plain_decoy_t *p = xzalloc(sizeof(*p));
	p->c = c;
	p->state = PS_READ_REQ;
	c->transport = &decoy_plain_transport;
	c->transport_data = p;

	io_del(&c->io);
	io_add(&c->io, plain_io, c, c->socket, IO_READ);

	/* The peeked bytes are already in the socket: read them now. */
	plain_read(p);
}
