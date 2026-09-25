#ifndef TINC_DECOY_H
#define TINC_DECOY_H

/*
    decoy.h -- the HTTPS/HTTP decoy served to anything that reaches the listen
               port without authenticating as a tinc peer.

    This is the active-probing resistance (REALITY-analogue, PLAN M5, decision
    1): a prober -- over plain HTTP, or inside a completed TLS handshake with
    the node's certificate but without a valid tinc authenticator -- is served
    a plausible web page, or is transparently proxied to a real upstream site.
    It never reveals that a VPN is here; no response path contains a tinc
    string. It needs no configuration to work (a default page ships).

    Config (docs/config-schema.md):
      HttpsDecoyRoot      static files served to probers (a default page if unset)
      HttpsDecoyUpstream  host:port -- transparently proxy probers here instead

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

/* Read HttpsDecoyRoot / HttpsDecoyUpstream from the config. Safe to call on
   every (re)load. */
void decoy_read_config(void);
void decoy_exit(void);

/* The UDP port this node serves HTTP/3 on (QuicPort), 0 for none. A site
   that serves HTTP/3 says so on its TCP answers, as nginx does with the
   usual `add_header Alt-Svc 'h3=":443"; ma=86400'`; the decoy then adds
   that header wherever nginx's add_header would. */
void decoy_set_h3_port(int port);

/* ---- the responder, independent of framing ---------------------------------

   The decoy is Debian 13's nginx 1.26.3 serving its stock page (docs/
   transports.md §8.5.1, measured by testing/transports/decoy-conformance-
   test.sh). A request is parsed into a decoy_request_t, answered as a
   decoy_answer_t -- nginx's own view of a response: status, the headers it
   keeps in fixed slots, the list of the others in order, and the body as it
   goes out (content coding applied) -- and only then framed. HTTP/1.1
   framing (status line, header order, chunked bodies) is
   decoy_answer_http1(); an h2 or HTTP/3 layer can frame the same answer
   itself: `list' holds no connection-specific field. */

/* Where a request arrived. nginx builds a redirect's Location from the Host
   header, else from the local address, and adds the port unless it is the
   scheme's default. */
typedef struct decoy_origin_t {
	bool tls;               /* https (else plain http) */
	bool h3;                /* framed as HTTP/3: no chunked bodies */
	int port;               /* local port */
	char addr[64];          /* local address, for a request without Host */
} decoy_origin_t;

/* Fill `at' for a connected socket. */
void decoy_origin_of(int fd, bool tls, decoy_origin_t *at);

#define DECOY_FIELD_MAX 1024    /* longest request field value kept */
#define DECOY_PATH_MAX 4096

typedef struct decoy_request_t {
	int status;             /* 0: parsed; else the error nginx answers (400, 414, 494, 505) */
	char method[24];
	char uri[DECOY_PATH_MAX];       /* decoded and normalised, starts with '/' */
	char args[DECOY_PATH_MAX];      /* after '?', raw */
	int version;            /* 9 (HTTP/0.9), 1000 (1.0), 1001 (1.1), ... */
	bool keep_alive;        /* after the version and Connection rules */
	bool has_host;
	char host[256];         /* Host (or the absolute URI's), without its port */
	bool has_via;
	bool has_content_length;
	char accept_encoding[DECOY_FIELD_MAX];
	char if_modified_since[128];
	char if_unmodified_since[128];
	char if_none_match[DECOY_FIELD_MAX];
	char if_match[DECOY_FIELD_MAX];
	char if_range[DECOY_FIELD_MAX];
	char range[DECOY_FIELD_MAX];
	bool has_ims, has_ius, has_inm, has_im, has_if_range, has_range;
	bool incomplete;        /* the head has no end yet (status 494) */
} decoy_request_t;

/* Parse an HTTP/1.x request head (up to and including the blank line). Always
   fills `r'; r->status says whether nginx would have answered it with an
   error before looking at the path. */
void decoy_parse_request(const char *head, size_t len, decoy_request_t *r);

#define DECOY_LIST_MAX 24

typedef struct decoy_answer_t {
	int status;
	char *reason;                   /* status line text after the code */
	char *content_type;             /* NULL: none */
	long long content_length;       /* -1: not known (chunked in HTTP/1.1) */
	time_t last_modified;           /* 0: none */
	char *location;                 /* NULL: none */
	struct {
		char *name;
		char *value;
	} list[DECOY_LIST_MAX];         /* the other headers, in nginx's order */
	int nlist;
	uint8_t *body;                  /* what goes on the wire, coded */
	size_t blen;
	bool header_only;               /* HEAD, 304: no body */
	bool keep_alive;
	bool chunked;                   /* HTTP/1.1 framing of an unknown length */
	bool http09;                    /* HTTP/0.9: the body alone */
} decoy_answer_t;

/* The static site's answer (HttpsDecoyRoot, or the built-in page). */
void decoy_answer(const decoy_request_t *r, const decoy_origin_t *at, decoy_answer_t *a);

/* HTTP/1.1 framing: a newly allocated response, head and body. */
char *decoy_answer_http1(const decoy_answer_t *a, size_t *len);

void decoy_answer_free(decoy_answer_t *a);

/* Parse + answer + frame: the static decoy response for a client whose
   request head (up to and including the blank line) is `request' (`reqlen'
   bytes). `at' may be NULL (TLS on 443). Never touches the network. */
char *decoy_respond(const char *request, size_t reqlen, const decoy_origin_t *at, size_t *resplen);
char *decoy_respond_static(const char *request, size_t reqlen, size_t *resplen);

/* Upstream proxy (HttpsDecoyUpstream), event-driven (review M5-1): the fetch
   runs on the daemon's event loop with a non-blocking connect, a total
   deadline and a size cap, so a slow, black-holed or malicious upstream never
   stalls the loop. The upstream address is resolved once, in
   decoy_read_config(). Headers that carry the tinc authenticator (Cookie,
   Upgrade, Sec-WebSocket-*) are stripped before forwarding (review M5-10).
   The upstream's answer is relayed as nginx's proxy_pass relays it: nginx's
   Server and Date, the upstream's other headers, the client connection
   kept alive.

   decoy_fetch_start() returns NULL when no upstream is configured or usable,
   or when nginx would answer the request itself (a request it cannot parse):
   the caller then serves decoy_respond() itself. Otherwise `cb` is
   called exactly once, later (never from inside decoy_fetch_start), with a
   newly-allocated response the caller owns -- the upstream's, or the static
   page if the upstream failed -- after which the handle is gone. A caller
   that goes away first must decoy_fetch_cancel() its handle. */
typedef struct decoy_fetch_t decoy_fetch_t;
typedef void (*decoy_cb_t)(void *data, char *resp, size_t resplen);
decoy_fetch_t *decoy_fetch_start(const char *request, size_t reqlen, const decoy_origin_t *at, decoy_cb_t cb, void *data);
void decoy_fetch_cancel(decoy_fetch_t *f);

/* Plain-HTTP path: take over a bare TCP connection the front classified as
   HTTP, read the request head, answer with the decoy and close -- all driven
   by the event loop (review M5-8: never a busy-wait on a client that does not
   read). The already-peeked bytes are still in the socket. The connection is
   reaped by the web front's timeouts if the exchange does not finish. */
struct connection_t;
void decoy_serve_plain(struct connection_t *c);

/* Plain bytes on the HttpsPort listener (a TLS-only port): answer as nginx
   answers plain HTTP on its TLS port -- 400 "The plain HTTP request was sent
   to HTTPS port" for a request, 400 Bad Request for anything else -- and
   close. */
void decoy_serve_plain_tls_port(struct connection_t *c);

/* After answering the request at the start of buf[0..len), move whatever
   follows it (a pipelined request) to the front. Returns its length. */
size_t decoy_next_request(char *buf, size_t len);

/* Whether a response keeps the connection open (its head says
   "Connection: keep-alive"): the caller then reads the next request. */
bool decoy_keeps_alive(const char *resp, size_t len);

/* Whether nginx answers `head' (a request so far, not necessarily ending
   in a blank line) already: an unparsable request line, a bad header line,
   HTTP/0.9. The caller then stops reading and answers. */
bool decoy_request_refused(const char *head, size_t len);

/* The longest request head read (nginx: large_client_header_buffers 4 8k).
   A head that does not end within it is answered as nginx answers it
   (400 "Request Header Or Cookie Too Large"). */
#define DECOY_HEAD_MAX 32768

/* How long a web front connection may sit without a complete request, and how
   long an idle keep-alive connection is kept: nginx's client_header_timeout
   and keepalive_timeout defaults (Debian's nginx.conf sets neither). */
#define DECOY_HEADER_TIMEOUT 60
#define DECOY_KEEPALIVE_TIMEOUT 75

/* A web server takes every connection until it runs out of them (nginx: 512
   worker_connections); it neither tarpits nor ignores a client that opened
   ten connections this second. The fronts (HttpsPort, QuicPort) use this
   cap instead of tinc's MaxConnectionBurst: past it, a new TCP connection is
   closed and a new QUIC Initial dropped. */
#define DECOY_MAX_WEB_CLIENTS 256

/* True when DECOY_MAX_WEB_CLIENTS unauthenticated front connections are open. */
bool decoy_front_full(void);

#endif /* TINC_DECOY_H */
