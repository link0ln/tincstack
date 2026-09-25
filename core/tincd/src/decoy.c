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

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

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
#define DECOY_REQ_MAX DECOY_HEAD_MAX

/* For log lines from a fetch that may outlive a config reload. */
#define UPSTREAM_NAME (decoy_upstream ? decoy_upstream : "(unset)")

/* nginx's own welcome page (Debian 13's /usr/share/nginx/html/index.html,
   the same file as upstream nginx 1.26-1.29 ships),
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

/* ---- the responder --------------------------------------------------------- */

/* What the decoy answers is measured against Debian 13's nginx 1.26.3 with
   its own nginx.conf (`server_tokens off', `gzip on') and a site that serves
   HTTP/3 (testing/transports/decoy-conformance-test.sh): the same status for
   the same request, the same headers in the same order, the same pages and
   bodies byte for byte. The steps below follow nginx's own: the request
   line and headers (ngx_http_parse.c, ngx_http_request.c), the static and
   index handlers, then its header filters in the order nginx runs them --
   not_modified, headers (add_header), gzip, range -- and last the HTTP/1.1
   header filter's field order and the chunked filter. */

/* The built-in page's Last-Modified: the mtime of Debian 13's
   /usr/share/nginx/html/index.html (nginx-common 1.26.3, Wed, 05 Feb 2025
   11:07:30 GMT), so Last-Modified and ETag ("67a34672-267") are those of
   every stock Debian 13 install -- not the daemon's start time, which would
   change on every restart. */
#define DEFAULT_PAGE_MTIME ((time_t)0x67a34672)

/* nginx's large_client_header_buffers (4 8k): a request line or a header
   line longer than one buffer is refused (414 / 400). */
#define NGINX_LINE_MAX 8192

static int h3_port;

void decoy_set_h3_port(int port) {
	h3_port = port;
}

/* ---- request ---- */

static int hexval(int c) {
	if(c >= '0' && c <= '9') {
		return c - '0';
	}

	c |= 0x20;
	return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

/* Percent-decode `in' (up to `end'), merge slashes and resolve "." and ".."
   as nginx's complex URI parser does. False when nginx answers 400: a bad
   escape, a NUL, or ".." above the root. */
static bool normalise_uri(const char *in, const char *end, char *out, size_t outlen) {
	size_t o = 0;

	if(outlen < 2) {
		return false;
	}

	for(const char *p = in; p < end; p++) {
		int c = (unsigned char) * p;

		if(c == '%') {
			if(end - p < 3 || hexval(p[1]) < 0 || hexval(p[2]) < 0) {
				return false;
			}

			c = hexval(p[1]) * 16 + hexval(p[2]);
			p += 2;

			if(!c) {
				return false;
			}
		}

		if(o + 1 >= outlen) {
			return false;
		}

		if(c == '/' && o && out[o - 1] == '/') {
			continue;       /* merge_slashes */
		}

		out[o++] = (char) c;
		out[o] = 0;

		/* "/./" and "/../" (a trailing "/." or "/.." too, checked at the end) */
		if(c == '/' && o >= 3 && !strcmp(out + o - 3, "/./")) {
			o -= 2;
		} else if(c == '/' && o >= 4 && !strcmp(out + o - 4, "/../")) {
			if(o == 4) {
				return false;   /* above the root */
			}

			o -= 4;

			while(o && out[o - 1] != '/') {
				o--;
			}
		}

		out[o] = 0;
	}

	if(o >= 2 && !strcmp(out + o - 2, "/.")) {
		o--;
	} else if(o >= 3 && !strcmp(out + o - 3, "/..")) {
		if(o == 3) {
			return false;
		}

		o -= 3;

		while(o && out[o - 1] != '/') {
			o--;
		}
	}

	out[o] = 0;
	return o && out[0] == '/';
}

static void copy_value(char *dst, size_t dstlen, const char *v, size_t vlen) {
	while(vlen && (*v == ' ' || *v == '\t')) {
		v++;
		vlen--;
	}

	while(vlen && (v[vlen - 1] == ' ' || v[vlen - 1] == '\t')) {
		vlen--;
	}

	if(vlen >= dstlen) {
		vlen = dstlen - 1;
	}

	memcpy(dst, v, vlen);
	dst[vlen] = 0;
}

static bool contains_ci(const char *hay, const char *needle) {
	size_t n = strlen(needle);

	for(; *hay; hay++) {
		if(!strncasecmp(hay, needle, n)) {
			return true;
		}
	}

	return false;
}

/* nginx's ngx_http_validate_host(): lower case, no trailing dot, the port
   cut off; empty or with a '/' or ".." is invalid. */
static bool set_host(decoy_request_t *r, const char *v, size_t vlen) {
	char h[256];
	copy_value(h, sizeof(h), v, vlen);
	size_t n = strlen(h);
	bool bracket = n && h[0] == '[';

	for(size_t i = 0; i < n; i++) {
		if(h[i] == '/' || (h[i] == '.' && h[i + 1] == '.')) {
			return false;
		}

		if(bracket && h[i] == ']') {
			h[i + 1] = 0;
			n = i + 1;
			break;
		}

		if(!bracket && h[i] == ':') {
			h[i] = 0;
			n = i;
			break;
		}

		h[i] = (char)tolower((unsigned char)h[i]);
	}

	while(n && h[n - 1] == '.') {
		h[--n] = 0;
	}

	if(!n) {
		return false;
	}

	memcpy(r->host, h, n + 1);
	r->has_host = true;
	return true;
}

void decoy_parse_request(const char *head, size_t len, decoy_request_t *r) {
	memset(r, 0, sizeof(*r));
	r->status = 400;
	r->version = 1001;

	const char *end = head + len;
	const char *eol = memchr(head, '\n', len);

	if(!eol) {
		/* A request line that fills nginx's large header buffer without
		   ending is 414; one whose method already has a byte no method may
		   have is 400 at once; anything else waits for more. */
		if(len >= NGINX_LINE_MAX) {
			r->status = 414;
			return;
		}

		const char *p = head;

		while(p < end && ((*p >= 'A' && *p <= 'Z') || *p == '_' || *p == '-')) {
			p++;
		}

		r->incomplete = p == end || *p == ' ';
		return;
	}

	if(eol - head > NGINX_LINE_MAX) {
		r->status = 414;
		return;
	}

	/* Method: upper-case letters, '_' and '-'. */
	const char *p = head;

	while(p < eol && ((*p >= 'A' && *p <= 'Z') || *p == '_' || *p == '-')) {
		p++;
	}

	if(p == head || p >= eol || *p != ' ' || (size_t)(p - head) >= sizeof(r->method)) {
		return;
	}

	memcpy(r->method, head, (size_t)(p - head));

	while(p < eol && *p == ' ') {
		p++;
	}

	/* Target: origin-form, or absolute-form (whose host wins over Host). */
	const char *uri = p;
	char abs_host[256] = "";

	if(p < eol && isalpha((unsigned char) *p)) {
		while(p < eol && (isalnum((unsigned char) *p) || *p == '+' || *p == '-' || *p == '.')) {
			p++;
		}

		if(eol - p < 3 || strncmp(p, "://", 3)) {
			return;
		}

		p += 3;
		const char *h = p;

		while(p < eol && *p != '/' && *p != ' ' && *p != '\r' && *p != '?') {
			p++;
		}

		if((size_t)(p - h) >= sizeof(abs_host) || p == h) {
			return;
		}

		memcpy(abs_host, h, (size_t)(p - h));
		abs_host[p - h] = 0;
		uri = p;
	} else if(p >= eol || *p != '/') {
		return;
	}

	const char *uri_end = uri;

	while(uri_end < eol && *uri_end != ' ' && *uri_end != '\r' && *uri_end != '\n') {
		uri_end++;
	}

	const char *q = memchr(uri, '?', (size_t)(uri_end - uri));
	const char *hash = memchr(uri, '#', (size_t)(uri_end - uri));
	const char *path_end = q ? q : uri_end;

	if(hash && hash < path_end) {
		path_end = hash;
	}

	if(uri == path_end) {
		strcpy(r->uri, "/");
	} else if(!normalise_uri(uri, path_end, r->uri, sizeof(r->uri))) {
		return;
	}

	if(q) {
		const char *ae = hash && hash > q ? hash : uri_end;
		size_t al = (size_t)(ae - q - 1);

		if(al >= sizeof(r->args)) {
			al = sizeof(r->args) - 1;
		}

		memcpy(r->args, q + 1, al);
		r->args[al] = 0;
	}

	p = uri_end;

	while(p < eol && *p == ' ') {
		p++;
	}

	if(p == eol || (*p == '\r' && p + 1 == eol)) {
		/* HTTP/0.9: GET only, no headers. */
		r->version = 9;
		r->status = strcmp(r->method, "GET") ? 400 : 0;

		if(abs_host[0]) {
			set_host(r, abs_host, strlen(abs_host));
		}

		return;
	}

	if(eol - p < 8 || strncmp(p, "HTTP/", 5)) {
		return;
	}

	p += 5;
	int major = 0, minor = 0;

	if(!isdigit((unsigned char) *p)) {
		return;
	}

	while(isdigit((unsigned char) *p) && major < 1000) {
		major = major * 10 + (*p++ - '0');
	}

	if(*p++ != '.' || !isdigit((unsigned char) *p)) {
		return;
	}

	while(isdigit((unsigned char) *p) && minor < 1000) {
		minor = minor * 10 + (*p++ - '0');
	}

	while(*p == ' ') {
		p++;
	}

	if(!(*p == '\n' || (*p == '\r' && p[1] == '\n')) || major > 99 || minor > 99) {
		return;
	}

	if(major > 1) {
		r->status = 505;
		return;
	}

	r->version = major * 1000 + minor;

	/* Header lines up to the blank line. */
	bool host_seen = false, close = false, keep = false;
	bool ims_seen = false, ius_seen = false, ifr_seen = false, cl_seen = false;
	bool complete = false;

	for(const char *l = eol + 1; l < end; ) {
		const char *le = memchr(l, '\n', (size_t)(end - l));

		if(!le) {
			if((size_t)(end - l) > NGINX_LINE_MAX) {
				r->status = 494;        /* this line no longer fits a buffer */
				return;
			}

			break;
		}

		size_t ll = (size_t)(le - l);

		if(ll && l[ll - 1] == '\r') {
			ll--;
		}

		if(!ll) {
			if((size_t)(l - head) > DECOY_HEAD_MAX) {
				r->status = 494;        /* more than nginx's 4 large header buffers */
				return;
			}

			complete = true;
			break;
		}

		if(ll > NGINX_LINE_MAX) {
			r->status = 494;
			return;
		}

		const char *colon = memchr(l, ':', ll);

		if(!colon || colon == l) {
			return;         /* "client sent invalid header line" */
		}

		size_t nl = (size_t)(colon - l);
		const char *v = colon + 1;
		size_t vl = ll - nl - 1;

#define IS(name) (nl == sizeof(name) - 1 && !strncasecmp(l, name, nl))

		if(IS("Host")) {
			if(host_seen || !set_host(r, v, vl)) {
				r->has_host = false;
				return;
			}

			host_seen = true;
		} else if(IS("Connection")) {
			char c[256];
			copy_value(c, sizeof(c), v, vl);
			close = close || contains_ci(c, "close");
			keep = keep || contains_ci(c, "keep-alive");
		} else if(IS("Accept-Encoding") && !r->accept_encoding[0]) {
			copy_value(r->accept_encoding, sizeof(r->accept_encoding), v, vl);
		} else if(IS("If-Modified-Since")) {
			if(ims_seen) {
				return;
			}

			ims_seen = r->has_ims = true;
			copy_value(r->if_modified_since, sizeof(r->if_modified_since), v, vl);
		} else if(IS("If-Unmodified-Since")) {
			if(ius_seen) {
				return;
			}

			ius_seen = r->has_ius = true;
			copy_value(r->if_unmodified_since, sizeof(r->if_unmodified_since), v, vl);
		} else if(IS("If-Range")) {
			if(ifr_seen) {
				return;
			}

			ifr_seen = r->has_if_range = true;
			copy_value(r->if_range, sizeof(r->if_range), v, vl);
		} else if(IS("If-None-Match") && !r->has_inm) {
			r->has_inm = true;
			copy_value(r->if_none_match, sizeof(r->if_none_match), v, vl);
		} else if(IS("If-Match") && !r->has_im) {
			r->has_im = true;
			copy_value(r->if_match, sizeof(r->if_match), v, vl);
		} else if(IS("Range") && !r->has_range) {
			r->has_range = true;
			copy_value(r->range, sizeof(r->range), v, vl);
		} else if(IS("Via")) {
			r->has_via = true;
		} else if(IS("Content-Length")) {
			if(cl_seen) {
				return;
			}

			cl_seen = r->has_content_length = true;
		}

#undef IS
		l = le + 1;
	}

	if(!complete) {
		/* only a head nginx would not have buffered comes here unfinished */
		r->incomplete = true;
		r->status = 494;
		return;
	}

	if(abs_host[0]) {
		if(!set_host(r, abs_host, strlen(abs_host))) {
			return;
		}
	}

	if(r->version >= 1001 && !host_seen) {
		return;                 /* "client sent HTTP/1.1 request without Host header" */
	}

	r->keep_alive = close ? false : keep ? true : r->version >= 1001;
	r->status = 0;
}

/* ngx_parse_http_time(): RFC 1123, RFC 850 and asctime dates; -1 if none. */
static time_t parse_http_time(const char *s) {
	static const char mons[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
	int day = 0, mon = -1, year = 0, hh = 0, mm = 0, ss = 0;
	char m[4] = "";
	const char *p = strchr(s, ' ');

	if(!p) {
		return -1;
	}

	if(p > s && p[-1] == ',') {
		/* "Wed, 05 Feb 2025 11:07:30 GMT" or "Wednesday, 05-Feb-25 11:07:30 GMT" */
		if(sscanf(p + 1, "%2d %3s %4d %2d:%2d:%2d GMT", &day, m, &year, &hh, &mm, &ss) != 6 &&
		                sscanf(p + 1, "%2d-%3[A-Za-z]-%2d %2d:%2d:%2d GMT", &day, m, &year, &hh, &mm, &ss) != 6) {
			return -1;
		}

		if(year < 100) {
			year += year < 70 ? 2000 : 1900;
		}
	} else if(sscanf(p + 1, "%3s %2d %2d:%2d:%2d %4d", m, &day, &hh, &mm, &ss, &year) != 6) {
		return -1;              /* asctime: "Wed Feb  5 11:07:30 2025" */
	}

	for(int i = 0; i < 12; i++) {
		if(!strncmp(m, mons + 3 * i, 3) && strlen(m) == 3) {
			mon = i;
		}
	}

	if(mon < 0 || day < 1 || day > 31 || hh > 23 || mm > 59 || ss > 59 || year < 1970) {
		return -1;
	}

	/* days from civil (Howard Hinnant's algorithm), no timegm() on Windows */
	int y = year - (mon < 2);
	int era = y / 400;
	int yoe = y - era * 400;
	int mp = (mon + 10) % 12;      /* March = 0 */
	int doy = (153 * mp + 2) / 5 + day - 1;
	int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	long long days = (long long)era * 146097 + doe - 719468;
	return (time_t)(days * 86400 + hh * 3600 + mm * 60 + ss);
}

/* ---- answer ---- */

static void list_add(decoy_answer_t *a, const char *name, const char *value) {
	if(a->nlist < DECOY_LIST_MAX) {
		a->list[a->nlist].name = xstrdup(name);
		a->list[a->nlist].value = xstrdup(value);
		a->nlist++;
	}
}

static int list_find(const decoy_answer_t *a, const char *name) {
	for(int i = 0; i < a->nlist; i++) {
		if(!strcasecmp(a->list[i].name, name)) {
			return i;
		}
	}

	return -1;
}

static void list_del(decoy_answer_t *a, const char *name) {
	int i = list_find(a, name);

	if(i < 0) {
		return;
	}

	free(a->list[i].name);
	free(a->list[i].value);
	memmove(&a->list[i], &a->list[i + 1], (size_t)(a->nlist - i - 1) * sizeof(a->list[0]));
	a->nlist--;
}

void decoy_answer_free(decoy_answer_t *a) {
	free(a->reason);
	free(a->content_type);
	free(a->location);

	for(int i = 0; i < a->nlist; i++) {
		free(a->list[i].name);
		free(a->list[i].value);
	}

	free(a->body);
	memset(a, 0, sizeof(*a));
}

static void set_body(decoy_answer_t *a, const void *body, size_t len) {
	free(a->body);
	a->body = xmalloc(len ? len : 1);
	memcpy(a->body, body, len);
	a->blen = len;
	a->content_length = (long long) len;
}

static const char *reason_for(int status) {
	switch(status) {
	case 200: return "OK";
	case 206: return "Partial Content";
	case 301: return "Moved Permanently";
	case 304: return "Not Modified";
	case 400: return "Bad Request";
	case 403: return "Forbidden";
	case 404: return "Not Found";
	case 405: return "Not Allowed";
	case 412: return "Precondition Failed";
	case 414: return "Request-URI Too Large";
	case 416: return "Requested Range Not Satisfiable";
	case 505: return "HTTP Version Not Supported";
	default: return "Bad Request";
	}
}

/* nginx's special response (its error pages, `server_tokens off'). 494 and
   497 go out as 400 with their own title line. */
static void error_answer(decoy_answer_t *a, int status, bool keep_alive) {
	char *b;
	int n;
	const char *extra = status == 494 ? "Request Header Or Cookie Too Large" :
	                    status == 497 ? "The plain HTTP request was sent to HTTPS port" : NULL;

	if(extra) {
		n = xasprintf(&b, "<html>\r\n<head><title>400 %s</title></head>\r\n<body>\r\n"
		              "<center><h1>400 Bad Request</h1></center>\r\n<center>%s</center>\r\n"
		              "<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n", extra, extra);
		status = 400;
	} else {
		n = xasprintf(&b, "<html>\r\n<head><title>%d %s</title></head>\r\n<body>\r\n"
		              "<center><h1>%d %s</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n",
		              status, reason_for(status), status, reason_for(status));
	}

	a->status = status;
	free(a->reason);
	a->reason = xstrdup(reason_for(status));
	free(a->content_type);
	a->content_type = xstrdup("text/html");
	a->last_modified = 0;
	list_del(a, "ETag");
	list_del(a, "Accept-Ranges");
	set_body(a, b, n > 0 ? (size_t) n : 0);
	free(b);

	/* ngx_http_special_response_handler(): these end the connection. */
	a->keep_alive = keep_alive && status != 400 && status != 413 && status != 414 &&
	                status != 500 && status != 501 && status != 505;
}

/* nginx's mime.types for the extensions a decoy site plausibly has. */
static const char *mime_for(const char *path) {
	const char *slash = strrchr(path, '/');
	const char *dot = strrchr(slash ? slash : path, '.');

	if(!dot) {
		return "application/octet-stream";
	}

	static const char *const map[][2] = {
		{".html", "text/html"}, {".htm", "text/html"}, {".shtml", "text/html"}, {".css", "text/css"},
		{".js", "application/javascript"}, {".json", "application/json"},
		{".png", "image/png"}, {".jpg", "image/jpeg"}, {".jpeg", "image/jpeg"},
		{".gif", "image/gif"}, {".svg", "image/svg+xml"}, {".svgz", "image/svg+xml"},
		{".ico", "image/x-icon"}, {".webp", "image/webp"},
		{".txt", "text/plain"}, {".xml", "text/xml"}, {".woff", "font/woff"}, {".woff2", "font/woff2"},
		{".pdf", "application/pdf"}, {".zip", "application/zip"}, {".mp4", "video/mp4"},
	};

	for(size_t i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
		if(!strcasecmp(dot, map[i][0])) {
			return map[i][1];
		}
	}

	return "application/octet-stream";
}

/* What `uri' is under the site's root: a file (its contents), a directory,
   or nothing. The built-in site is a root directory holding index.html. */
typedef enum node_kind_t {
	NODE_NONE,
	NODE_FILE,
	NODE_DIR,
	NODE_FORBIDDEN,
} node_kind_t;

static node_kind_t site_lookup(const char *uri, char **data, size_t *len, time_t *mtime) {
	*data = NULL;

	if(!decoy_root) {
		if(!strcmp(uri, "/")) {
			return NODE_DIR;
		}

		if(!strcmp(uri, "/index.html")) {
			*data = xmalloc(sizeof(default_page));
			memcpy(*data, default_page, sizeof(default_page) - 1);
			*len = sizeof(default_page) - 1;
			*mtime = DEFAULT_PAGE_MTIME;
			return NODE_FILE;
		}

		return NODE_NONE;
	}

	char path[PATH_MAX];

	if((size_t)snprintf(path, sizeof(path), "%s%s", decoy_root, uri) >= sizeof(path)) {
		return NODE_NONE;
	}

#ifdef HAVE_WINDOWS

	for(char *c = path; *c; c++) {
		if(*c == '/') {
			*c = '\\';
		}
	}

#endif
	struct stat st;

	if(stat(path, &st)) {
		return errno == EACCES ? NODE_FORBIDDEN : NODE_NONE;
	}

	if(S_ISDIR(st.st_mode)) {
		return NODE_DIR;
	}

	/* a trailing '/' on a file: ENOTDIR for nginx */
	if(!S_ISREG(st.st_mode) || uri[strlen(uri) - 1] == '/' || st.st_size > 64 * 1024 * 1024) {
		return NODE_NONE;
	}

	FILE *f = fopen(path, "rb");

	if(!f) {
		return errno == EACCES ? NODE_FORBIDDEN : NODE_NONE;
	}

	*data = xmalloc((size_t) st.st_size + 1);
	*len = fread(*data, 1, (size_t) st.st_size, f);
	fclose(f);
	*mtime = st.st_mtime;
	return NODE_FILE;
}

/* nginx's ngx_http_test_if_match(): does the answer's ETag match a list
   (`weak': If-None-Match's weak comparison)? */
static bool etag_match(const decoy_answer_t *a, const char *hdr, bool weak) {
	if(!strcmp(hdr, "*")) {
		return true;
	}

	int i = list_find(a, "ETag");

	if(i < 0) {
		return false;
	}

	const char *etag = a->list[i].value;

	if(weak && etag[0] == 'W' && etag[1] == '/' && strlen(etag) > 2) {
		etag += 2;
	}

	size_t elen = strlen(etag);
	const char *s = hdr, *end = hdr + strlen(hdr);

	while(s < end) {
		if(weak && end - s > 2 && s[0] == 'W' && s[1] == '/') {
			s += 2;
		}

		if(elen > (size_t)(end - s)) {
			return false;
		}

		if(!strncmp(s, etag, elen)) {
			s += elen;

			while(s < end && (*s == ' ' || *s == '\t')) {
				s++;
			}

			if(s == end || *s == ',') {
				return true;
			}
		}

		while(s < end && *s != ',') {
			s++;
		}

		while(s < end && (*s == ' ' || *s == '\t' || *s == ',')) {
			s++;
		}
	}

	return false;
}

/* ngx_http_not_modified_filter: 412 or 304 for a 200 with validators. */
static void filter_not_modified(const decoy_request_t *r, decoy_answer_t *a) {
	if(a->status != 200 || !a->last_modified) {
		return;
	}

	if(r->has_ius && parse_http_time(r->if_unmodified_since) < a->last_modified) {
		error_answer(a, 412, r->keep_alive);
		return;
	}

	if(r->has_im && !etag_match(a, r->if_match, false)) {
		error_answer(a, 412, r->keep_alive);
		return;
	}

	if(!r->has_ims && !r->has_inm) {
		return;
	}

	/* if_modified_since exact: only the very date is "not modified" */
	if(r->has_ims && parse_http_time(r->if_modified_since) != a->last_modified) {
		return;
	}

	if(r->has_inm && !etag_match(a, r->if_none_match, true)) {
		return;
	}

	a->status = 304;
	free(a->reason);
	a->reason = xstrdup("Not Modified");
	free(a->content_type);
	a->content_type = NULL;
	a->content_length = -1;
	list_del(a, "Accept-Ranges");
	free(a->body);
	a->body = NULL;
	a->blen = 0;
	a->header_only = true;
}

/* add_header Alt-Svc 'h3=":<QuicPort>"; ma=86400' -- only for the statuses
   add_header covers without `always'. */
static void filter_headers(decoy_answer_t *a) {
	static const int ok[] = {200, 201, 204, 206, 301, 302, 303, 304, 307, 308};

	if(!h3_port) {
		return;
	}

	for(size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) {
		if(a->status == ok[i]) {
			char v[48];
			snprintf(v, sizeof(v), "h3=\":%d\"; ma=86400", h3_port);
			list_add(a, "Alt-Svc", v);
			return;
		}
	}
}

#ifdef HAVE_ZLIB
/* ngx_http_gzip_accept_encoding(): a "gzip" token whose q is not 0. */
static bool gzip_accepted(const char *ae) {
	const char *p = ae, *end = ae + strlen(ae);

	if(strlen(ae) < 4) {
		return false;
	}

	if(!strncmp(ae, "gzip,", 5)) {
		return true;
	}

	for(;;) {
		const char *g = NULL;

		for(const char *s = p; s + 4 <= end; s++) {
			if(!strncasecmp(s, "gzip", 4)) {
				g = s;
				break;
			}
		}

		if(!g) {
			return false;
		}

		if(g == ae || g[-1] == ',' || g[-1] == ' ') {
			p = g + 4;
			break;
		}

		p = g + 4;
	}

	while(p < end) {
		switch(*p++) {
		case ',':
			return true;

		case ';':
			goto quantity;

		case ' ':
			continue;

		default:
			return false;
		}
	}

	return true;

quantity:

	while(p < end) {
		switch(*p++) {
		case 'q':
		case 'Q':
			goto equal;

		case ' ':
			continue;

		default:
			return false;
		}
	}

	return true;

equal:

	if(p + 2 > end || *p++ != '=') {
		return false;
	}

	/* ngx_http_gzip_quantity(): "0" and "0.000" say no */
	if(*p != '0' && *p != '1') {
		return false;
	}

	int q = (*p++ - '0') * 100;

	if(p < end && *p == '.') {
		int n = 0, scale = 10;

		for(p++; p < end && *p != ',' && *p != ' '; p++) {
			if(*p < '0' || *p > '9' || ++n > 3) {
				return false;
			}

			q += (*p - '0') * scale;
			scale /= 10;
		}
	} else if(p < end && *p != ',' && *p != ' ') {
		return false;
	}

	return q > 0 && q <= 100;
}

/* nginx's gzip body: zlib's gzip wrapper (header with XFL 4 and OS 3, as
   measured) around deflate at gzip_comp_level 1, with the window and
   memory level nginx shrinks for a short body (ngx_http_gzip_filter_memory).
   zlib is Debian 13's 1.3.1 on both sides, so the bytes are nginx's. */
static bool gzip_encode(decoy_answer_t *a) {
	int wbits = 15, memlevel = 8;

	if(a->content_length > 0) {
		while(a->content_length < (1LL << (wbits - 1)) - 262) {
			wbits--;
			memlevel--;
		}

		if(memlevel < 1) {
			memlevel = 1;
		}
	}

	z_stream z;
	memset(&z, 0, sizeof(z));

	if(deflateInit2(&z, 1, Z_DEFLATED, wbits + 16, memlevel, Z_DEFAULT_STRATEGY) != Z_OK) {
		return false;
	}

	size_t cap = deflateBound(&z, (uLong) a->blen) + 64;
	uint8_t *out = xmalloc(cap);
	z.next_in = a->body;
	z.avail_in = (uInt) a->blen;
	z.next_out = out;
	z.avail_out = (uInt) cap;
	int rc = deflate(&z, Z_FINISH);
	size_t n = z.total_out;
	deflateEnd(&z);

	if(rc != Z_STREAM_END) {
		free(out);
		return false;
	}

	free(a->body);
	a->body = out;
	a->blen = n;
	return true;
}
#endif

/* ngx_http_gzip_header_filter with Debian's `gzip on' and the defaults
   (text/html, gzip_min_length 20, gzip_http_version 1.1, gzip_proxied off,
   gzip_vary off). */
static void filter_gzip(const decoy_request_t *r, decoy_answer_t *a) {
#ifdef HAVE_ZLIB

	if((a->status != 200 && a->status != 403 && a->status != 404) || list_find(a, "Content-Encoding") >= 0 ||
	                (a->content_length != -1 && a->content_length < 20) ||
	                !a->content_type || strncasecmp(a->content_type, "text/html", 9) ||
	                (a->content_type[9] && a->content_type[9] != ';') ||
	                r->version < 1001 || r->has_via || !gzip_accepted(r->accept_encoding)) {
		return;
	}

	if(!gzip_encode(a)) {
		return;
	}

	list_add(a, "Content-Encoding", "gzip");
	a->content_length = -1;
	list_del(a, "Accept-Ranges");

	/* ngx_http_weak_etag() */
	int i = list_find(a, "ETag");

	if(i >= 0) {
		char *e = a->list[i].value;

		if(e[0] == '"') {
			char *w;
			xasprintf(&w, "W/%s", e);
			free(e);
			a->list[i].value = w;
		} else if(!(e[0] == 'W' && e[1] == '/')) {
			list_del(a, "ETag");
		}
	}

#else
	(void) r;
	(void) a;
#endif
}

/* The multipart boundary: nginx's ngx_next_temp_number(), a counter. */
static unsigned long boundary_counter;

/* ngx_http_range_parse(): the ranges of a `len'-byte body, or 416 (-1), or
   none (0: a plain 200). */
static int parse_ranges(const char *v, long long len, long long *starts, long long *ends, int max) {
	const char *p = v + 6;
	int n = 0;
	long long size = 0;

	for(;;) {
		long long start = 0, end = 0;
		bool suffix = false;

		while(*p == ' ') {
			p++;
		}

		if(*p != '-') {
			if(*p < '0' || *p > '9') {
				return -1;
			}

			while(*p >= '0' && *p <= '9') {
				if(start > (LLONG_MAX - 9) / 10) {
					return -1;
				}

				start = start * 10 + (*p++ - '0');
			}

			while(*p == ' ') {
				p++;
			}

			if(*p++ != '-') {
				return -1;
			}

			while(*p == ' ') {
				p++;
			}

			if(*p == ',' || *p == '\0') {
				end = len;
				goto found;
			}
		} else {
			suffix = true;
			p++;
		}

		if(*p < '0' || *p > '9') {
			return -1;
		}

		while(*p >= '0' && *p <= '9') {
			if(end > (LLONG_MAX - 9) / 10) {
				return -1;
			}

			end = end * 10 + (*p++ - '0');
		}

		while(*p == ' ') {
			p++;
		}

		if(*p != ',' && *p != '\0') {
			return -1;
		}

		if(suffix) {
			start = end < len ? len - end : 0;
			end = len - 1;
		}

		if(end >= len) {
			end = len;
		} else {
			end++;
		}

found:

		if(start < end) {
			if(n == max) {
				return 0;
			}

			starts[n] = start;
			ends[n] = end;
			n++;
			size += end - start;
		} else if(start == 0) {
			return 0;
		}

		if(*p++ != ',') {
			break;
		}
	}

	if(!n) {
		return -1;
	}

	if(size > len) {
		return 0;
	}

	return n;
}

#define DECOY_MAX_RANGES 64

/* ngx_http_range_header_filter: 206 (one range, or multipart/byteranges),
   416, or Accept-Ranges on a plain 200. */
static void filter_range(const decoy_request_t *r, decoy_answer_t *a, bool allow_ranges) {
	if(r->version < 1000 || a->status != 200 || a->content_length == -1 || !allow_ranges) {
		return;
	}

	if(!r->has_range || strlen(r->range) < 7 || strncasecmp(r->range, "bytes=", 6)) {
		goto next;
	}

	if(r->has_if_range) {
		size_t il = strlen(r->if_range);

		if(il >= 2 && r->if_range[il - 1] == '"') {
			int i = list_find(a, "ETag");

			if(i < 0 || strcmp(a->list[i].value, r->if_range)) {
				goto next;
			}
		} else if(!a->last_modified || parse_http_time(r->if_range) != a->last_modified) {
			goto next;
		}
	}

	long long starts[DECOY_MAX_RANGES], ends[DECOY_MAX_RANGES];
	int n = parse_ranges(r->range, a->content_length, starts, ends, DECOY_MAX_RANGES);

	if(n == 0) {
		goto next;
	}

	char cr[96];

	if(n < 0) {
		/* ngx_http_range_not_satisfiable(): Content-Range, then the error page */
		snprintf(cr, sizeof(cr), "bytes */%lld", a->content_length);
		list_add(a, "Content-Range", cr);
		error_answer(a, 416, r->keep_alive);
		return;
	}

	a->status = 206;
	free(a->reason);
	a->reason = xstrdup("Partial Content");

	if(n == 1) {
		snprintf(cr, sizeof(cr), "bytes %lld-%lld/%lld", starts[0], ends[0] - 1, a->content_length);
		list_add(a, "Content-Range", cr);

		if(!a->header_only) {
			memmove(a->body, a->body + starts[0], (size_t)(ends[0] - starts[0]));
		}

		a->blen = a->header_only ? 0 : (size_t)(ends[0] - starts[0]);
		a->content_length = ends[0] - starts[0];
		return;
	}

	/* multipart/byteranges, nginx's layout */
	char boundary[24];
	snprintf(boundary, sizeof(boundary), "%020lu", ++boundary_counter);
	char *ct;
	xasprintf(&ct, "multipart/byteranges; boundary=%s", boundary);
	const char *part_type = a->content_type ? a->content_type : "";
	size_t cap = 64 + a->blen;

	for(int i = 0; i < n; i++) {
		cap += 128 + strlen(part_type) + (size_t)(ends[i] - starts[i]);
	}

	uint8_t *out = xmalloc(cap);
	size_t o = 0;

	for(int i = 0; i < n; i++) {
		o += (size_t)snprintf((char *)out + o, cap - o, "\r\n--%s\r\nContent-Type: %s\r\nContent-Range: bytes %lld-%lld/%lld\r\n\r\n",
		                      boundary, part_type, starts[i], ends[i] - 1, a->content_length);
		memcpy(out + o, a->body + starts[i], (size_t)(ends[i] - starts[i]));
		o += (size_t)(ends[i] - starts[i]);
	}

	o += (size_t)snprintf((char *)out + o, cap - o, "\r\n--%s--\r\n", boundary);
	free(a->content_type);
	a->content_type = ct;
	free(a->body);
	a->body = out;
	a->blen = a->header_only ? 0 : o;
	a->content_length = (long long) o;
	return;

next:

	if(list_find(a, "Accept-Ranges") < 0) {
		list_add(a, "Accept-Ranges", "bytes");
	}
}

/* The statuses nginx answers with a page of its own at the end of a
   request, run through the same header filters (gzip compresses 403/404). */
static void finish_error(const decoy_request_t *r, decoy_answer_t *a, int status) {
	error_answer(a, status, r->status ? false : r->keep_alive);
	filter_headers(a);
	filter_gzip(r, a);
}

/* A redirect's Location as nginx's header filter builds it
   (absolute_redirect on, server_name_in_redirect off, port_in_redirect on). */
static char *absolute_location(const decoy_request_t *r, const decoy_origin_t *at, const char *path) {
	char *loc;
	bool tls = at ? at->tls : true;
	int port = at ? at->port : 443;
	const char *host = r->has_host ? r->host : at && at->addr[0] ? at->addr : "localhost";
	char portstr[16] = "";

	if(port && port != (tls ? 443 : 80)) {
		snprintf(portstr, sizeof(portstr), ":%d", port);
	}

	xasprintf(&loc, "%s://%s%s%s", tls ? "https" : "http", host, portstr, path);
	return loc;
}

void decoy_answer(const decoy_request_t *r, const decoy_origin_t *at, decoy_answer_t *a) {
	memset(a, 0, sizeof(*a));
	a->content_length = -1;
	a->keep_alive = r->status ? false : r->keep_alive;
	a->http09 = r->version == 9;

	if(r->status) {
		finish_error(r, a, r->status);
		return;
	}

	bool get = !strcmp(r->method, "GET") || !strcmp(r->method, "HEAD");
	bool post = !strcmp(r->method, "POST");
	a->header_only = !strcmp(r->method, "HEAD");

	/* ngx_http_static_handler / ngx_http_index_handler */
	if(!get && !post) {
		finish_error(r, a, 405);
		return;
	}

	char uri[DECOY_PATH_MAX + 16];
	snprintf(uri, sizeof(uri), "%s", r->uri);
	size_t ul = strlen(uri);
	char *data = NULL;
	size_t len = 0;
	time_t mtime = 0;
	node_kind_t kind;

	if(uri[ul - 1] == '/') {
		/* the index module: <uri>index.html, else 403 for a directory that exists */
		char idx[DECOY_PATH_MAX + 32];
		snprintf(idx, sizeof(idx), "%sindex.html", uri);
		kind = site_lookup(idx, &data, &len, &mtime);

		if(kind == NODE_FILE) {
			snprintf(uri, sizeof(uri), "%s", idx);
		} else {
			free(data);
			node_kind_t dir = site_lookup(uri, &data, &len, &mtime);
			free(data);
			finish_error(r, a, dir == NODE_DIR || kind == NODE_FORBIDDEN ? 403 : 404);
			return;
		}
	} else {
		kind = site_lookup(uri, &data, &len, &mtime);
	}

	if(kind == NODE_FORBIDDEN) {
		free(data);
		finish_error(r, a, 403);
		return;
	}

	if(kind == NODE_DIR) {
		/* 301 to the directory with a slash (and the query) */
		char path[2 * DECOY_PATH_MAX + 8];
		snprintf(path, sizeof(path), "%s/%s%s", uri, r->args[0] ? "?" : "", r->args);
		error_answer(a, 301, r->keep_alive);
		a->location = absolute_location(r, at, path);
		a->header_only = !strcmp(r->method, "HEAD");
		filter_headers(a);
		return;
	}

	if(kind != NODE_FILE) {
		free(data);
		finish_error(r, a, 404);
		return;
	}

	if(post) {
		free(data);
		finish_error(r, a, 405);
		return;
	}

	a->status = 200;
	a->reason = xstrdup("OK");
	a->content_type = xstrdup(mime_for(uri));
	a->last_modified = mtime;
	a->body = (uint8_t *) data;
	a->blen = len;
	a->content_length = (long long) len;

	char etag[64];
	snprintf(etag, sizeof(etag), "\"%lx-%lx\"", (unsigned long) mtime, (unsigned long) len);
	list_add(a, "ETag", etag);

	filter_not_modified(r, a);

	if(a->status == 412) {
		filter_headers(a);
		filter_gzip(r, a);
		return;
	}

	filter_headers(a);
	filter_gzip(r, a);
	filter_range(r, a, true);

	if(a->header_only && a->status != 304) {
		a->blen = 0;
	}
}

/* ngx_http_header_filter + ngx_http_chunked_filter: nginx's field order --
   Server, Date, Content-Type, Content-Length, Last-Modified, Location,
   Transfer-Encoding, Connection, then the list. */
char *decoy_answer_http1(const decoy_answer_t *a, size_t *len) {
	if(a->http09) {
		char *out = xmalloc(a->blen + 1);
		memcpy(out, a->body, a->blen);
		*len = a->blen;
		return out;
	}

	char date[64], lm[64] = "";
	http_date(time(NULL), date, sizeof(date));

	if(a->last_modified && (a->status == 200 || a->status == 206 || a->status == 304)) {
		http_date(a->last_modified, lm, sizeof(lm));
	}

	size_t cap = 512 + (a->content_type ? strlen(a->content_type) : 0) + (a->location ? strlen(a->location) : 0) +
	             (a->reason ? strlen(a->reason) : 0);

	for(int i = 0; i < a->nlist; i++) {
		cap += strlen(a->list[i].name) + strlen(a->list[i].value) + 4;
	}

	bool body = !a->header_only;
	cap += body ? a->blen + 32 : 0;
	char *out = xmalloc(cap);
	size_t o = 0;

#define PUT(...) o += (size_t)snprintf(out + o, cap - o, __VA_ARGS__)
	PUT("HTTP/1.1 %d %s\r\nServer: nginx\r\nDate: %s\r\n", a->status, a->reason ? a->reason : "", date);

	if(a->content_type) {
		PUT("Content-Type: %s\r\n", a->content_type);
	}

	if(a->content_length >= 0) {
		PUT("Content-Length: %lld\r\n", a->content_length);
	}

	if(lm[0]) {
		PUT("Last-Modified: %s\r\n", lm);
	}

	if(a->location) {
		PUT("Location: %s\r\n", a->location);
	}

	if(a->chunked) {
		PUT("Transfer-Encoding: chunked\r\n");
	}

	PUT("Connection: %s\r\n", a->keep_alive ? "keep-alive" : "close");

	for(int i = 0; i < a->nlist; i++) {
		PUT("%s: %s\r\n", a->list[i].name, a->list[i].value);
	}

	PUT("\r\n");

	if(body && a->chunked) {
		if(a->blen) {
			PUT("%lx\r\n", (unsigned long) a->blen);
			memcpy(out + o, a->body, a->blen);
			o += a->blen;
			PUT("\r\n");
		}

		PUT("0\r\n\r\n");
	} else if(body && a->blen) {
		memcpy(out + o, a->body, a->blen);
		o += a->blen;
	}

#undef PUT
	*len = o;
	return out;
}

/* The framing decisions nginx takes last: a body of unknown length is
   chunked for HTTP/1.1 and ends the connection for HTTP/1.0; HTTP/3 needs
   neither. */
static void finish_framing(const decoy_request_t *r, const decoy_origin_t *at, decoy_answer_t *a) {
	a->chunked = false;

	if(a->content_length != -1 || a->status == 304 || a->status < 200 || !strcmp(r->method, "HEAD") || (at && at->h3)) {
		return;
	}

	if(r->version >= 1001) {
		a->chunked = true;
	} else {
		a->keep_alive = false;
	}
}

char *decoy_respond(const char *request, size_t reqlen, const decoy_origin_t *at, size_t *resplen) {
	decoy_request_t *r = xmalloc(sizeof(*r));
	decoy_answer_t a;
	decoy_parse_request(request, reqlen, r);
	decoy_answer(r, at, &a);
	finish_framing(r, at, &a);
	char *out = decoy_answer_http1(&a, resplen);
	decoy_answer_free(&a);
	free(r);
	return out;
}

char *decoy_respond_static(const char *request, size_t reqlen, size_t *resplen) {
	decoy_origin_t at = {.tls = true, .h3 = true, .port = h3_port ? h3_port : 443};
	return decoy_respond(request, reqlen, &at, resplen);
}

/* Plain HTTP on the TLS port: nginx's 497 page for a request, 400 for
   anything else; both close. */
static char *respond_plain_on_tls(const char *request, size_t reqlen, size_t *resplen) {
	decoy_request_t *r = xmalloc(sizeof(*r));
	decoy_parse_request(request, reqlen, r);
	decoy_request_t e;
	memset(&e, 0, sizeof(e));
	e.status = r->status || r->version == 9 ? 400 : 497;
	e.version = 1001;
	free(r);
	decoy_answer_t a;
	decoy_answer(&e, NULL, &a);
	char *out = decoy_answer_http1(&a, resplen);
	decoy_answer_free(&a);
	return out;
}

/* A request nginx answers as soon as it has its first line (or a bad
   header line): an unparsable request line, a bad version, HTTP/0.9. */
bool decoy_request_refused(const char *head, size_t len) {
	decoy_request_t *r = xmalloc(sizeof(*r));
	decoy_parse_request(head, len, r);
	bool refused = (r->status && !r->incomplete) || r->version == 9;
	free(r);
	return refused;
}

void decoy_origin_of(int fd, bool tls, decoy_origin_t *at) {
	memset(at, 0, sizeof(*at));
	at->tls = tls;
	at->port = tls ? 443 : 80;
	sockaddr_t sa;
	socklen_t salen = sizeof(sa);

	if(getsockname(fd, &sa.sa, &salen)) {
		return;
	}

	char host[NI_MAXHOST] = "";

	if(sa.sa.sa_family == AF_INET) {
		at->port = ntohs(sa.in.sin_port);
	} else if(sa.sa.sa_family == AF_INET6) {
		at->port = ntohs(sa.in6.sin6_port);
	} else {
		return;
	}

	if(getnameinfo(&sa.sa, salen, host, sizeof(host), NULL, 0, NI_NUMERICHOST)) {
		return;
	}

	snprintf(at->addr, sizeof(at->addr), sa.sa.sa_family == AF_INET6 ? "[%s]" : "%s", host);
}

/* ---- upstream proxy (event-driven) --------------------------------------- */

/* Rewrite the request head for the upstream as nginx's proxy_pass does
   with its defaults (proxy_http_version 1.0): the request line with
   HTTP/1.0, Host: the upstream authority, Connection: close (so the upstream
   ends the response with EOF), then the client's headers. Every header that
   can carry the tinc authenticator or betray the WebSocket upgrade shape is
   dropped (M5-10): Cookie, Upgrade, Sec-WebSocket-*, Authorization; and so
   are the ones nginx does not forward (Keep-Alive, TE, Expect). What the
   upstream sees is an ordinary request. The body bytes that arrived with the
   head follow it unchanged. */
static bool header_is(const char *line, size_t linelen, const char *name) {
	size_t n = strlen(name);
	return linelen >= n && !strncasecmp(line, name, n);
}

static char *rewrite_request(const char *request, size_t reqlen, const char *host, size_t *outlen) {
	const char *line = request;
	const char *req_end = request + reqlen;
	char *out = xmalloc(reqlen + strlen(host) + 64);
	size_t olen = 0;
	bool first = true;

	while(line < req_end) {
		const char *eol = memchr(line, '\n', (size_t)(req_end - line));
		size_t linelen = eol ? (size_t)(eol - line + 1) : (size_t)(req_end - line);

		if(first) {
			/* "HTTP/1.1" at the end of the request line becomes "HTTP/1.0" */
			size_t ll = linelen;

			while(ll && (line[ll - 1] == '\n' || line[ll - 1] == '\r')) {
				ll--;
			}

			memcpy(out + olen, line, ll);

			if(ll >= 8 && !strncmp(line + ll - 8, "HTTP/1.", 7)) {
				out[olen + ll - 1] = '0';
			}

			olen += ll;
			first = false;
			/* Our own headers right after the request line; duplicates from
			   the client are dropped below. */
			olen += (size_t) sprintf(out + olen, "\r\nHost: %s\r\nConnection: close\r\n", host);
		} else if(linelen <= 2 && (line[0] == '\r' || line[0] == '\n')) {
			/* the blank line, and then the body as it came */
			memcpy(out + olen, line, (size_t)(req_end - line));
			olen += (size_t)(req_end - line);
			break;
		} else if(header_is(line, linelen, "Host:") || header_is(line, linelen, "Connection:") ||
		          header_is(line, linelen, "Cookie:") || header_is(line, linelen, "Upgrade:") ||
		          header_is(line, linelen, "Sec-WebSocket-") || header_is(line, linelen, "Authorization:") ||
		          header_is(line, linelen, "Keep-Alive:") || header_is(line, linelen, "TE:") ||
		          header_is(line, linelen, "Expect:")) {
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
	*outlen = olen;
	return out;
}

/* A chunked body, de-chunked; what arrived of it if it was cut short. */
static size_t dechunk(uint8_t *b, size_t len) {
	size_t in = 0, out = 0;

	while(in < len) {
		char *e;
		unsigned long n = strtoul((char *)b + in, &e, 16);
		const uint8_t *nl = memchr(b + in, '\n', len - in);

		if(!nl || (uint8_t *)e == b + in || !n) {
			break;
		}

		in = (size_t)(nl - b) + 1;

		if(n > len - in) {
			n = len - in;
		}

		memmove(b + out, b + in, n);
		out += n;
		in += n;

		while(in < len && (b[in] == '\r' || b[in] == '\n')) {
			in++;
		}
	}

	return out;
}

/* The upstream's answer as nginx's proxy module relays it (proxy_pass with
   its defaults): the upstream's status line; nginx's own Server and Date
   (proxy_hide_header); Content-Type and Content-Length in nginx's fixed
   slots; the upstream's other headers in their order, without the
   hop-by-hop ones; a Location under the upstream's URL made relative
   (proxy_redirect default) and then absolute, a relative one as it came; then add_header and gzip as
   for any answer, but no 304 or ranges of nginx's own (a proxied response
   is not cacheable here). Its body is de-chunked; framing is redone for
   the client. False if `resp' is not an HTTP response. */
static bool answer_from_upstream(const decoy_request_t *r, const decoy_origin_t *at, const char *resp, size_t len,
                                 decoy_answer_t *a) {
	memset(a, 0, sizeof(*a));
	a->content_length = -1;
	a->keep_alive = r->keep_alive;
	const char *end = resp + len;
	const char *eol = memchr(resp, '\n', len);

	if(!eol || len < 12 || strncmp(resp, "HTTP/1.", 7) || resp[8] != ' ' || resp[9] < '1' || resp[9] > '9') {
		return false;
	}

	a->status = atoi(resp + 9);

	if(a->status < 200 || a->status > 999) {
		return false;
	}

	const char *reason = resp + 12;
	size_t rl = eol > reason ? (size_t)(eol - reason) : 0;

	while(rl && (reason[rl - 1] == '\r' || reason[rl - 1] == '\n')) {
		rl--;
	}

	while(rl && *reason == ' ') {
		reason++;
		rl--;
	}

	a->reason = xmalloc(rl + 1);
	memcpy(a->reason, reason, rl);
	a->reason[rl] = 0;

	bool chunked = false;
	long long clen = -1;
	const char *body = end;
	char prefix[300];
	snprintf(prefix, sizeof(prefix), "http://%s/", decoy_upstream ? decoy_upstream : "");

	for(const char *l = eol + 1; l < end;) {
		const char *le = memchr(l, '\n', (size_t)(end - l));

		if(!le) {
			break;
		}

		size_t ll = (size_t)(le - l);

		if(ll && l[ll - 1] == '\r') {
			ll--;
		}

		if(!ll) {
			body = le + 1;
			break;
		}

		const char *colon = memchr(l, ':', ll);

		if(colon && colon > l && (size_t)(colon - l) < 64) {
			char name[64], value[DECOY_FIELD_MAX];
			memcpy(name, l, (size_t)(colon - l));
			name[colon - l] = 0;
			copy_value(value, sizeof(value), colon + 1, ll - (size_t)(colon - l) - 1);

			if(!strcasecmp(name, "Server") || !strcasecmp(name, "Date") || !strcasecmp(name, "X-Pad") ||
			                !strncasecmp(name, "X-Accel-", 8) || !strcasecmp(name, "Connection") ||
			                !strcasecmp(name, "Keep-Alive")) {
				/* hidden, or hop-by-hop */
			} else if(!strcasecmp(name, "Transfer-Encoding")) {
				chunked = contains_ci(value, "chunked");
			} else if(!strcasecmp(name, "Content-Length")) {
				clen = strtoll(value, NULL, 10);
			} else if(!strcasecmp(name, "Content-Type")) {
				free(a->content_type);
				a->content_type = xstrdup(value);
			} else if(!strcasecmp(name, "Location") && !strncmp(value, prefix, strlen(prefix))) {
				/* proxy_redirect default: the upstream's URL becomes "/",
				   which the header filter then makes absolute. A relative
				   Location is left alone, in its place (measured). */
				free(a->location);
				a->location = absolute_location(r, at, value + strlen(prefix) - 1);
			} else {
				list_add(a, name, value);
			}
		}

		l = le + 1;
	}

	size_t blen = (size_t)(end - body);
	a->body = xmalloc(blen + 1);
	memcpy(a->body, body, blen);

	if(chunked) {
		blen = dechunk(a->body, blen);
	} else if(clen >= 0 && (size_t) clen < blen) {
		blen = (size_t) clen;
	}

	a->blen = blen;
	a->content_length = chunked ? -1 : clen;
	a->header_only = !strcmp(r->method, "HEAD") || a->status == 304 || a->status == 204;

	if(a->header_only) {
		a->blen = 0;
	}

	filter_headers(a);
	filter_gzip(r, a);
	return true;
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
	decoy_origin_t at;

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

/* Hand the result to the owner and free the handle. `f->resp` is consumed:
   it becomes nginx's relayed answer, or the static page if the upstream
   gave nothing usable. */
static void fetch_deliver(decoy_fetch_t *f) {
	char *resp = NULL;
	size_t len = 0;
	decoy_request_t *r = xmalloc(sizeof(*r));
	decoy_answer_t a;
	decoy_parse_request(f->orig, f->origlen, r);

	if(f->resp && f->rlen && answer_from_upstream(r, &f->at, f->resp, f->rlen, &a)) {
		finish_framing(r, &f->at, &a);
		resp = decoy_answer_http1(&a, &len);
		decoy_answer_free(&a);
	} else {
		logger(DEBUG_CONNECTIONS, LOG_INFO, "Decoy upstream %s gave no response; serving the static page", UPSTREAM_NAME);
		resp = decoy_respond(f->orig, f->origlen, &f->at, &len);
	}

	free(r);
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

decoy_fetch_t *decoy_fetch_start(const char *request, size_t reqlen, const decoy_origin_t *at, decoy_cb_t cb, void *data) {
	if(!decoy_upstream_ready) {
		return NULL;
	}

	/* A request nginx refuses by itself never reaches its upstream. */
	decoy_request_t *r = xmalloc(sizeof(*r));
	decoy_parse_request(request, request_span(request, reqlen), r);
	bool refused = r->status || r->version == 9;
	free(r);

	if(refused) {
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

	if(at) {
		f->at = *at;
	} else {
		f->at.tls = true;
		f->at.port = 443;
	}

	f->req = rewrite_request(request, reqlen, decoy_upstream_host, &f->reqlen);
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
		char *resp = respond_plain_on_tls(p->req, p->rlen, &len);
		plain_start_write(p, resp, len);
		return;
	}

	decoy_origin_t at;
	decoy_origin_of(p->c->socket, false, &at);
	p->state = PS_FETCHING;
	io_set(&p->c->io, 0); /* nothing to do on the client socket meanwhile */
	p->fetch = decoy_fetch_start(p->req, p->rlen, &at, plain_fetched, p);

	if(!p->fetch) {
		size_t len = 0;
		char *resp = decoy_respond(p->req, p->rlen, &at, &len);
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
			if(decoy_request_refused(p->req, p->rlen)) {
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
