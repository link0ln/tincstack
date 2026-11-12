#include "unittest.h"
#include "../../src/decoy.h"
#include "../../src/xalloc.h"

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

/* The decoy's responder against what Debian 13's nginx 1.26.3 answers
   (testing/transports/decoy-conformance-test.sh measures the same cases on
   the wire; these pin the parts that do not need a network). */

static char *answer(const char *req, size_t *len) {
	decoy_origin_t at = {.tls = true, .port = 443};
	strcpy(at.addr, "192.0.2.1");
	char *r = decoy_respond(req, strlen(req), &at, len);
	char *z = xmalloc(*len + 1);
	memcpy(z, r, *len);
	z[*len] = 0;
	free(r);
	return z;
}

static char *head_of(const char *resp) {
	const char *e = strstr(resp, "\r\n\r\n");
	size_t n = e ? (size_t)(e - resp) + 2 : strlen(resp);
	char *h = xmalloc(n + 1);
	memcpy(h, resp, n);
	h[n] = 0;
	return h;
}

/* The header names of a response, in order, one line each: "Server,Date,...". */
static char *names_of(const char *resp) {
	char *h = head_of(resp);
	char *out = xzalloc(strlen(h) + 1);
	char *line = strstr(h, "\r\n");

	while(line && line[2]) {
		char *colon = strchr(line + 2, ':');
		char *next = strstr(line + 2, "\r\n");

		if(!colon || !next || colon > next) {
			break;
		}

		if(*out) {
			strcat(out, ",");
		}

		strncat(out, line + 2, (size_t)(colon - line - 2));
		line = next;
	}

	free(h);
	return out;
}

static const char *body_of(const char *resp) {
	const char *e = strstr(resp, "\r\n\r\n");
	return e ? e + 4 : "";
}

#define ASSERT_ANSWER(req, status, names) do { \
		size_t _l; \
		char *_r = answer(req, &_l); \
		char *_n = names_of(_r); \
		assert_true(!strncmp(_r, status "\r\n", strlen(status "\r\n"))); \
		assert_string_equal(_n, names); \
		free(_n); \
		free(_r); \
	} while(0)

static void test_page(void **state) {
	(void)state;
	decoy_set_h3_port(0);
	size_t len;
	char *r = answer("GET / HTTP/1.1\r\nHost: a\r\n\r\n", &len);
	assert_true(!strncmp(r, "HTTP/1.1 200 OK\r\nServer: nginx\r\nDate: ", 38));
	assert_non_null(strstr(r, "\r\nContent-Type: text/html\r\nContent-Length: 615\r\n"
	                        "Last-Modified: Wed, 05 Feb 2025 11:07:30 GMT\r\nConnection: keep-alive\r\n"
	                        "ETag: \"67a34672-267\"\r\nAccept-Ranges: bytes\r\n\r\n<!DOCTYPE html>"));
	assert_int_equal(strlen(body_of(r)), 615);
	free(r);

	ASSERT_ANSWER("HEAD / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n", "HTTP/1.1 200 OK",
	              "Server,Date,Content-Type,Content-Length,Last-Modified,Connection,ETag,Accept-Ranges");
	r = answer("HEAD / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n", &len);
	assert_string_equal(body_of(r), "");
	free(r);

	/* The same file under other spellings of its path. */
	ASSERT_ANSWER("GET //index.html HTTP/1.1\r\nHost: a\r\n\r\n", "HTTP/1.1 200 OK",
	              "Server,Date,Content-Type,Content-Length,Last-Modified,Connection,ETag,Accept-Ranges");
	ASSERT_ANSWER("GET /a/../%69ndex.html?x=1 HTTP/1.1\r\nHost: a\r\n\r\n", "HTTP/1.1 200 OK",
	              "Server,Date,Content-Type,Content-Length,Last-Modified,Connection,ETag,Accept-Ranges");
	ASSERT_ANSWER("GET https://a/ HTTP/1.1\r\nHost: b\r\nConnection: close\r\n\r\n", "HTTP/1.1 200 OK",
	              "Server,Date,Content-Type,Content-Length,Last-Modified,Connection,ETag,Accept-Ranges");
}

static void test_errors(void **state) {
	(void)state;
	decoy_set_h3_port(0);
	ASSERT_ANSWER("GET /nope HTTP/1.1\r\nHost: a\r\n\r\n", "HTTP/1.1 404 Not Found",
	              "Server,Date,Content-Type,Content-Length,Connection");
	ASSERT_ANSWER("GET /index.html/ HTTP/1.1\r\nHost: a\r\n\r\n", "HTTP/1.1 404 Not Found",
	              "Server,Date,Content-Type,Content-Length,Connection");
	ASSERT_ANSWER("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n", "HTTP/1.1 405 Not Allowed",
	              "Server,Date,Content-Type,Content-Length,Connection");
	ASSERT_ANSWER("DELETE /nope HTTP/1.1\r\nHost: a\r\n\r\n", "HTTP/1.1 405 Not Allowed",
	              "Server,Date,Content-Type,Content-Length,Connection");
	ASSERT_ANSWER("POST /nope HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n", "HTTP/1.1 404 Not Found",
	              "Server,Date,Content-Type,Content-Length,Connection");
	ASSERT_ANSWER("XYZZY\r\n\r\n", "HTTP/1.1 400 Bad Request", "Server,Date,Content-Type,Content-Length,Connection");
	ASSERT_ANSWER("GET / HTTP/1.1\r\n\r\n", "HTTP/1.1 400 Bad Request", "Server,Date,Content-Type,Content-Length,Connection");
	ASSERT_ANSWER("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", "HTTP/1.1 400 Bad Request",
	              "Server,Date,Content-Type,Content-Length,Connection");
	ASSERT_ANSWER("GET /../x HTTP/1.1\r\nHost: a\r\n\r\n", "HTTP/1.1 400 Bad Request",
	              "Server,Date,Content-Type,Content-Length,Connection");
	ASSERT_ANSWER("GET / HTTP/2.0\r\nHost: a\r\n\r\n", "HTTP/1.1 505 HTTP Version Not Supported",
	              "Server,Date,Content-Type,Content-Length,Connection");

	size_t len;
	char *r = answer("get / HTTP/1.1\r\nHost: a\r\n\r\n", &len);
	assert_non_null(strstr(r, "\r\nConnection: close\r\n"));
	assert_string_equal(body_of(r), "<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body>\r\n"
	                    "<center><h1>400 Bad Request</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n");
	free(r);

	/* Longer than one of nginx's 8k header buffers. */
	char *big = xmalloc(20000);
	strcpy(big, "GET / HTTP/1.1\r\nHost: a\r\nX-A: ");
	size_t hl = strlen(big);
	memset(big + hl, 'a', 9000);
	strcpy(big + hl + 9000, "\r\n\r\n");
	r = answer(big, &len);
	assert_non_null(strstr(r, "<title>400 Request Header Or Cookie Too Large</title>"));
	free(r);
	strcpy(big, "GET /");
	memset(big + 5, 'a', 9000);
	strcpy(big + 9005, " HTTP/1.1\r\nHost: a\r\n\r\n");
	r = answer(big, &len);
	assert_true(!strncmp(r, "HTTP/1.1 414 Request-URI Too Large\r\n", 36));
	free(r);
	free(big);

	assert_true(decoy_request_refused("XYZZY\r\n", 7));
	assert_true(decoy_request_refused("GET /\r\n", 7));
	assert_false(decoy_request_refused("GET / HTTP/1.1\r\nHost: a\r\n", 25));
	/* a request line cut short waits, unless its method is already bad
	   or it has filled nginx's 8 KiB buffer (414) */
	assert_false(decoy_request_refused("GET /aaaa", 9));
	assert_true(decoy_request_refused("GE\x01", 3));
	char *line = xmalloc(8192);
	memcpy(line, "GET /", 5);
	memset(line + 5, 'a', 8192 - 5);
	assert_true(decoy_request_refused(line, 8192));
	assert_false(decoy_request_refused(line, 8191));
	free(line);
}

static void test_keep_alive(void **state) {
	(void)state;
	size_t len;
	char *r = answer("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n", &len);
	assert_true(decoy_keeps_alive(r, len));
	free(r);
	r = answer("GET / HTTP/1.0\r\n\r\n", &len);
	assert_false(decoy_keeps_alive(r, len));
	free(r);
	r = answer("GET /nope HTTP/1.1\r\nHost: a\r\n\r\n", &len);
	assert_true(decoy_keeps_alive(r, len));
	free(r);

	/* HTTP/0.9: the page alone. */
	r = answer("GET /\r\n", &len);
	assert_int_equal(len, 615);
	assert_true(!strncmp(r, "<!DOCTYPE html>", 15));
	free(r);
	/* ... and an error page alone for any other method */
	r = answer("HEAD /\r\n", &len);
	assert_true(!strncmp(r, "<html>\r\n<head><title>400 Bad Request</title>", 44));
	free(r);
}

static void test_conditional(void **state) {
	(void)state;
	decoy_set_h3_port(0);
	ASSERT_ANSWER("GET / HTTP/1.1\r\nHost: a\r\nIf-Modified-Since: Wed, 05 Feb 2025 11:07:30 GMT\r\n\r\n",
	              "HTTP/1.1 304 Not Modified", "Server,Date,Last-Modified,Connection,ETag");
	ASSERT_ANSWER("GET / HTTP/1.1\r\nHost: a\r\nIf-Modified-Since: Thu, 06 Feb 2025 11:07:30 GMT\r\n\r\n",
	              "HTTP/1.1 200 OK", "Server,Date,Content-Type,Content-Length,Last-Modified,Connection,ETag,Accept-Ranges");
	ASSERT_ANSWER("GET / HTTP/1.1\r\nHost: a\r\nIf-None-Match: \"x\", W/\"67a34672-267\"\r\n\r\n",
	              "HTTP/1.1 304 Not Modified", "Server,Date,Last-Modified,Connection,ETag");
	ASSERT_ANSWER("GET / HTTP/1.1\r\nHost: a\r\nIf-None-Match: \"x\"\r\nIf-Modified-Since: Wed, 05 Feb 2025 11:07:30 GMT\r\n\r\n",
	              "HTTP/1.1 200 OK", "Server,Date,Content-Type,Content-Length,Last-Modified,Connection,ETag,Accept-Ranges");
	ASSERT_ANSWER("GET / HTTP/1.1\r\nHost: a\r\nIf-Match: \"x\"\r\n\r\n",
	              "HTTP/1.1 412 Precondition Failed", "Server,Date,Content-Type,Content-Length,Connection");
	ASSERT_ANSWER("GET / HTTP/1.1\r\nHost: a\r\nIf-Unmodified-Since: Tue, 04 Feb 2025 11:07:30 GMT\r\n\r\n",
	              "HTTP/1.1 412 Precondition Failed", "Server,Date,Content-Type,Content-Length,Connection");
	/* the other two date formats nginx reads */
	ASSERT_ANSWER("GET / HTTP/1.1\r\nHost: a\r\nIf-Modified-Since: Wednesday, 05-Feb-25 11:07:30 GMT\r\n\r\n",
	              "HTTP/1.1 304 Not Modified", "Server,Date,Last-Modified,Connection,ETag");
	ASSERT_ANSWER("GET / HTTP/1.1\r\nHost: a\r\nIf-Modified-Since: Wed Feb  5 11:07:30 2025\r\n\r\n",
	              "HTTP/1.1 304 Not Modified", "Server,Date,Last-Modified,Connection,ETag");
}

static void test_ranges(void **state) {
	(void)state;
	decoy_set_h3_port(0);
	size_t len;
	char *r = answer("GET / HTTP/1.1\r\nHost: a\r\nRange: bytes=0-99\r\n\r\n", &len);
	assert_true(!strncmp(r, "HTTP/1.1 206 Partial Content\r\n", 30));
	assert_non_null(strstr(r, "\r\nContent-Length: 100\r\n"));
	assert_non_null(strstr(r, "\r\nContent-Range: bytes 0-99/615\r\n"));
	assert_int_equal(strlen(body_of(r)), 100);
	free(r);

	r = answer("GET / HTTP/1.1\r\nHost: a\r\nRange: bytes=-100\r\n\r\n", &len);
	assert_non_null(strstr(r, "\r\nContent-Range: bytes 515-614/615\r\n"));
	free(r);

	ASSERT_ANSWER("GET / HTTP/1.1\r\nHost: a\r\nRange: bytes=1000-2000\r\n\r\n",
	              "HTTP/1.1 416 Requested Range Not Satisfiable", "Server,Date,Content-Type,Content-Length,Connection,Content-Range");
	ASSERT_ANSWER("GET / HTTP/1.1\r\nHost: a\r\nRange: items=0-9\r\n\r\n",
	              "HTTP/1.1 200 OK", "Server,Date,Content-Type,Content-Length,Last-Modified,Connection,ETag,Accept-Ranges");
	ASSERT_ANSWER("GET / HTTP/1.1\r\nHost: a\r\nRange: bytes=0-9\r\nIf-Range: \"x\"\r\n\r\n",
	              "HTTP/1.1 200 OK", "Server,Date,Content-Type,Content-Length,Last-Modified,Connection,ETag,Accept-Ranges");

	r = answer("GET / HTTP/1.1\r\nHost: a\r\nRange: bytes=0-9,20-29\r\n\r\n", &len);
	assert_true(!strncmp(r, "HTTP/1.1 206 Partial Content\r\n", 30));
	assert_non_null(strstr(r, "\r\nContent-Type: multipart/byteranges; boundary="));
	assert_non_null(strstr(body_of(r), "\r\nContent-Type: text/html\r\nContent-Range: bytes 20-29/615\r\n\r\n"));
	free(r);
}

static void test_gzip(void **state) {
	(void)state;
	decoy_set_h3_port(0);
#ifdef HAVE_ZLIB
	size_t len;
	char *r = answer("GET / HTTP/1.1\r\nHost: a\r\nAccept-Encoding: gzip, deflate, br\r\n\r\n", &len);
	char *n = names_of(r);
	assert_string_equal(n, "Server,Date,Content-Type,Last-Modified,Transfer-Encoding,Connection,ETag,Content-Encoding");
	free(n);
	assert_non_null(strstr(r, "\r\nETag: W/\"67a34672-267\"\r\n"));

	/* one chunk, then the last */
	const char *b = body_of(r);
	char *e;
	unsigned long clen = strtoul(b, &e, 16);
	assert_true(!strncmp(e, "\r\n", 2));
	const uint8_t *gz = (const uint8_t *)e + 2;
	assert_int_equal(gz[0], 0x1f);
	assert_int_equal(gz[1], 0x8b);
	assert_true(!memcmp(gz + clen, "\r\n0\r\n\r\n", 7));

	uint8_t out[1024];
	z_stream z;
	memset(&z, 0, sizeof(z));
	assert_int_equal(inflateInit2(&z, 16 + 15), Z_OK);
	z.next_in = (uint8_t *)gz;
	z.avail_in = (uInt)clen;
	z.next_out = out;
	z.avail_out = sizeof(out);
	assert_int_equal(inflate(&z, Z_FINISH), Z_STREAM_END);
	assert_int_equal(z.total_out, 615);
	inflateEnd(&z);
	free(r);

	/* HEAD gets the coded answer's head, without a length or chunking */
	ASSERT_ANSWER("HEAD / HTTP/1.1\r\nHost: a\r\nAccept-Encoding: gzip\r\n\r\n", "HTTP/1.1 200 OK",
	              "Server,Date,Content-Type,Last-Modified,Connection,ETag,Content-Encoding");
	/* not for HTTP/1.0, q=0, a Via header */
	ASSERT_ANSWER("GET / HTTP/1.0\r\nAccept-Encoding: gzip\r\n\r\n", "HTTP/1.1 200 OK",
	              "Server,Date,Content-Type,Content-Length,Last-Modified,Connection,ETag,Accept-Ranges");
	ASSERT_ANSWER("GET / HTTP/1.1\r\nHost: a\r\nAccept-Encoding: gzip;q=0\r\n\r\n", "HTTP/1.1 200 OK",
	              "Server,Date,Content-Type,Content-Length,Last-Modified,Connection,ETag,Accept-Ranges");
	ASSERT_ANSWER("GET / HTTP/1.1\r\nHost: a\r\nAccept-Encoding: gzip\r\nVia: 1.1 p\r\n\r\n", "HTTP/1.1 200 OK",
	              "Server,Date,Content-Type,Content-Length,Last-Modified,Connection,ETag,Accept-Ranges");
	/* the 404 page is compressed, the 405 page is not */
	ASSERT_ANSWER("GET /nope HTTP/1.1\r\nHost: a\r\nAccept-Encoding: gzip\r\n\r\n", "HTTP/1.1 404 Not Found",
	              "Server,Date,Content-Type,Transfer-Encoding,Connection,Content-Encoding");
	ASSERT_ANSWER("POST / HTTP/1.1\r\nHost: a\r\nAccept-Encoding: gzip\r\n\r\n", "HTTP/1.1 405 Not Allowed",
	              "Server,Date,Content-Type,Content-Length,Connection");
#else
	skip();
#endif
}

static void test_alt_svc(void **state) {
	(void)state;
	decoy_set_h3_port(443);
	size_t len;
	char *r = answer("GET / HTTP/1.1\r\nHost: a\r\n\r\n", &len);
	assert_non_null(strstr(r, "\r\nAlt-Svc: h3=\":443\"; ma=86400\r\n"));
	free(r);
	/* add_header leaves error pages alone */
	r = answer("GET /nope HTTP/1.1\r\nHost: a\r\n\r\n", &len);
	assert_null(strstr(r, "Alt-Svc"));
	free(r);
	decoy_set_h3_port(0);
}

static void test_header_smuggling_and_content_length(void **state) {
	(void)state;
	decoy_set_h3_port(0);

	/* M-TR-04: whitespace before ':' in any header name must be 400 Bad Request (RFC 9112 §5.1). */
	ASSERT_ANSWER("GET / HTTP/1.1\r\nHost: a\r\nUpgrade : websocket\r\n\r\n",
	              "HTTP/1.1 400 Bad Request", "Server,Date,Content-Type,Content-Length,Connection");
	ASSERT_ANSWER("GET / HTTP/1.1\r\nHost: a\r\nCookie : session=1\r\n\r\n",
	              "HTTP/1.1 400 Bad Request", "Server,Date,Content-Type,Content-Length,Connection");
	ASSERT_ANSWER("GET / HTTP/1.1\r\nHost: a\r\nX-Forwarded-For\t: 127.0.0.1\r\n\r\n",
	              "HTTP/1.1 400 Bad Request", "Server,Date,Content-Type,Content-Length,Connection");
	ASSERT_ANSWER("GET / HTTP/1.1\r\nHost : a\r\n\r\n",
	              "HTTP/1.1 400 Bad Request", "Server,Date,Content-Type,Content-Length,Connection");

	/* M-TR-04: malformed, negative, duplicate, or TE-conflicting Content-Length -> 400 Bad Request. */
	ASSERT_ANSWER("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\n",
	              "HTTP/1.1 400 Bad Request", "Server,Date,Content-Type,Content-Length,Connection");
	ASSERT_ANSWER("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 12abc\r\n\r\n",
	              "HTTP/1.1 400 Bad Request", "Server,Date,Content-Type,Content-Length,Connection");
	ASSERT_ANSWER("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: \r\n\r\n",
	              "HTTP/1.1 400 Bad Request", "Server,Date,Content-Type,Content-Length,Connection");
	ASSERT_ANSWER("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\nContent-Length: 5\r\n\r\n",
	              "HTTP/1.1 400 Bad Request", "Server,Date,Content-Type,Content-Length,Connection");
	ASSERT_ANSWER("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
	              "HTTP/1.1 400 Bad Request", "Server,Date,Content-Type,Content-Length,Connection");
	ASSERT_ANSWER("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n",
	              "HTTP/1.1 400 Bad Request", "Server,Date,Content-Type,Content-Length,Connection");
}

static void test_upstream_ipv6_and_keepalive_body(void **state) {
	(void)state;
	char host[128], port[16], hosthdr[160];

	/* L-TR-02: bracketed IPv6 upstream parsing. */
	assert_true(decoy_parse_upstream_hostport("[2001:db8::1]:8443", host, sizeof(host), port, sizeof(port), hosthdr, sizeof(hosthdr)));
	assert_string_equal(host, "2001:db8::1");
	assert_string_equal(port, "8443");
	assert_string_equal(hosthdr, "[2001:db8::1]:8443");

	assert_true(decoy_parse_upstream_hostport("[::1]", host, sizeof(host), port, sizeof(port), hosthdr, sizeof(hosthdr)));
	assert_string_equal(host, "::1");
	assert_string_equal(port, "80");
	assert_string_equal(hosthdr, "[::1]");

	assert_true(decoy_parse_upstream_hostport("[::1]:80", host, sizeof(host), port, sizeof(port), hosthdr, sizeof(hosthdr)));
	assert_string_equal(host, "::1");
	assert_string_equal(port, "80");
	assert_string_equal(hosthdr, "[::1]");

	assert_true(decoy_parse_upstream_hostport("upstream.example.com:8080", host, sizeof(host), port, sizeof(port), hosthdr, sizeof(hosthdr)));
	assert_string_equal(host, "upstream.example.com");
	assert_string_equal(port, "8080");
	assert_string_equal(hosthdr, "upstream.example.com:8080");

	assert_false(decoy_parse_upstream_hostport("[2001:db8::1", host, sizeof(host), port, sizeof(port), hosthdr, sizeof(hosthdr)));
	assert_false(decoy_parse_upstream_hostport("[not-an-ipv6]:8080", host, sizeof(host), port, sizeof(port), hosthdr, sizeof(hosthdr)));
	assert_false(decoy_parse_upstream_hostport("upstream.example.com:0", host, sizeof(host), port, sizeof(port), hosthdr, sizeof(hosthdr)));
	assert_false(decoy_parse_upstream_hostport("upstream.example.com:70000", host, sizeof(host), port, sizeof(port), hosthdr, sizeof(hosthdr)));

	/* L-TR-02: Content-Length body consumption across keep-alive / pipelining. */
	const char *partial = "GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nab";
	assert_false(decoy_request_ready(partial, strlen(partial), DECOY_HEAD_MAX));

	char pipebuf[256];
	strcpy(pipebuf, "GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhelloGET /nope HTTP/1.1\r\nHost: a\r\n\r\n");
	size_t pipelen = strlen(pipebuf);
	assert_true(decoy_request_ready(pipebuf, pipelen, DECOY_HEAD_MAX));
	size_t rem = decoy_next_request(pipebuf, pipelen);
	assert_int_equal(rem, strlen("GET /nope HTTP/1.1\r\nHost: a\r\n\r\n"));
	assert_int_equal(0, memcmp(pipebuf, "GET /nope HTTP/1.1\r\nHost: a\r\n\r\n", rem));

	/* Unbuffered large Content-Length body forces Connection: close so body bytes cannot smuggle a request. */
	size_t rlen = 0;
	char *r = answer("GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 100000\r\n\r\n", &rlen);
	assert_false(decoy_keeps_alive(r, rlen));
	free(r);

	/* M-TR-05: 4 MiB file cap and global 32 MiB decoy response budget -> 503 when saturated. */
	assert_int_equal(DECOY_MAX_FILE_SIZE, 4 * 1024 * 1024);
	assert_true(decoy_budget_acquire(DECOY_MAX_RESP_BUDGET));
	assert_false(decoy_budget_acquire(1));
	r = answer("GET / HTTP/1.1\r\nHost: a\r\n\r\n", &rlen);
	assert_true(!strncmp(r, "HTTP/1.1 503 Service Temporarily Unavailable\r\n", 46));
	free(r);
	decoy_budget_release(DECOY_MAX_RESP_BUDGET);
	assert_int_equal(decoy_budget_used(), 0);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_page),
		cmocka_unit_test(test_errors),
		cmocka_unit_test(test_keep_alive),
		cmocka_unit_test(test_conditional),
		cmocka_unit_test(test_ranges),
		cmocka_unit_test(test_gzip),
		cmocka_unit_test(test_alt_svc),
		cmocka_unit_test(test_header_smuggling_and_content_length),
		cmocka_unit_test(test_upstream_ipv6_and_keepalive_body),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
