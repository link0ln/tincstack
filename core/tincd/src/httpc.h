#ifndef TINC_HTTPC_H
#define TINC_HTTPC_H

/*
    httpc.h -- blocking HTTPS requests for `tinc cert' (acme.c).

    Never call this from the daemon: it blocks. It exists for the CLI, which
    is a separate process and may take seconds to talk to a CA.

    This program is free software; see the GPL v2+ (same as the rest of tinc).
*/

#include "system.h"

typedef struct {
	int status;                 /* HTTP status code */
	char *headers;              /* raw header block, NUL-terminated */
	char *body;                 /* NUL-terminated (and dechunked) */
	size_t body_len;
} http_response_t;

typedef struct {
	const char *url;            /* https:// only */
	const char *method;         /* "GET", "POST", "DELETE" ... */
	const char *content_type;   /* optional */
	const char *const *headers; /* optional extra "Name: value" lines */
	size_t nheaders;
	const void *body;
	size_t body_len;
	const char *ca_file;        /* optional CA bundle; system store when NULL */
	int timeout_s;              /* per socket operation; 30 when 0 */
} httpc_request_t;

/* Perform the request. False on a transport-level failure (DNS, connect, TLS,
   malformed response), with a human-readable reason in `err`; an HTTP error
   status is a success here -- the caller decides what 4xx means. */
bool httpc_request(const httpc_request_t *req, http_response_t *res, char *err, size_t errlen);

/* The response half of httpc_request(), split out so it can be tested
   without a socket: `len' bytes of a raw HTTP/1.1 response (need not be
   NUL-terminated) into `res'. `head' says the request was a HEAD, whose
   answer has no body whatever its Content-Length says. False, with `res'
   freed and the reason in `err', on a malformed response, a chunked body
   without its last chunk, or a body shorter than its Content-Length. */
bool httpc_parse_response(const char *buf, size_t len, bool head, const char *host,
                          http_response_t *res, char *err, size_t errlen);

/* Header value by name, case-insensitive; caller frees. NULL when absent. */
char *httpc_header(const http_response_t *res, const char *name);

void httpc_free(http_response_t *res);

#endif
