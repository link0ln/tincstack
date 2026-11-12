#include "unittest.h"
#include "../../src/httpc.h"

/* The response parser of httpc_request(), without a socket. Inputs are copied
   into exactly-sized heap buffers (no NUL after them), so a read past `len'
   shows up under ASan. */
static bool parse(const char *raw, size_t len, bool head, http_response_t *res, char *err, size_t errlen) {
	char *buf = malloc(len ? len : 1);
	assert_non_null(buf);
	memcpy(buf, raw, len);
	bool ok = httpc_parse_response(buf, len, head, "ca.test", res, err, errlen);
	free(buf);
	return ok;
}

#define PARSE(raw, head, res, err) parse((raw), strlen(raw), (head), (res), (err), sizeof(err))

static void test_content_length_exact(void **state) {
	(void)state;
	http_response_t res;
	char err[256] = "";
	assert_true(PARSE("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", false, &res, err));
	assert_int_equal(res.status, 200);
	assert_int_equal(res.body_len, 5);
	assert_string_equal(res.body, "hello");
	httpc_free(&res);
}

static void test_content_length_short_body_is_an_error(void **state) {
	(void)state;
	http_response_t res;
	char err[256] = "";
	assert_false(PARSE("HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n{\"status\":", false, &res, err));
	assert_non_null(strstr(err, "truncated"));
	assert_non_null(strstr(err, "Content-Length 50"));
	assert_null(res.body);
	assert_null(res.headers);

	/* No body at all. */
	assert_false(PARSE("HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\n", false, &res, err));
	assert_non_null(strstr(err, "truncated"));
}

static void test_content_length_longer_body_is_cut(void **state) {
	(void)state;
	http_response_t res;
	char err[256] = "";
	assert_true(PARSE("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nabcdef", false, &res, err));
	assert_int_equal(res.body_len, 2);
	assert_string_equal(res.body, "ab");
	httpc_free(&res);
}

static void test_content_length_malformed(void **state) {
	(void)state;
	http_response_t res;
	char err[256] = "";
	assert_false(PARSE("HTTP/1.1 200 OK\r\nContent-Length: 2x\r\n\r\nab", false, &res, err));
	assert_non_null(strstr(err, "Content-Length"));
	assert_false(PARSE("HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\nab", false, &res, err));
	assert_false(PARSE("HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999\r\n\r\nab", false, &res, err));
}

static void test_head_and_bodiless_statuses(void **state) {
	(void)state;
	http_response_t res;
	char err[256] = "";
	/* ACME newNonce is a HEAD: Content-Length describes a body not sent. */
	assert_true(PARSE("HTTP/1.1 200 OK\r\nReplay-Nonce: abc\r\nContent-Length: 120\r\n\r\n", true, &res, err));
	assert_int_equal(res.body_len, 0);
	char *nonce = httpc_header(&res, "replay-nonce");
	assert_string_equal(nonce, "abc");
	free(nonce);
	httpc_free(&res);

	assert_true(PARSE("HTTP/1.1 304 Not Modified\r\nContent-Length: 10\r\n\r\n", false, &res, err));
	httpc_free(&res);
	assert_true(PARSE("HTTP/1.1 204 No Content\r\nContent-Length: 10\r\n\r\n", false, &res, err));
	httpc_free(&res);
}

static void test_close_delimited(void **state) {
	(void)state;
	http_response_t res;
	char err[256] = "";
	assert_true(PARSE("HTTP/1.0 200 OK\n\nbody", false, &res, err));
	assert_string_equal(res.body, "body");
	httpc_free(&res);
}

static void test_chunked(void **state) {
	(void)state;
	http_response_t res;
	char err[256] = "";
	assert_true(PARSE("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
	                  "5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\n\r\n", false, &res, err));
	assert_int_equal(res.body_len, 11);
	assert_string_equal(res.body, "hello world");
	httpc_free(&res);
}

static void test_chunked_truncated(void **state) {
	(void)state;
	http_response_t res;
	char err[256] = "";
	const char *cases[] = {
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nhello\r\n0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX0\r\n\r\n",
	};

	for(size_t i = 0; i < sizeof(cases) / sizeof(*cases); i++) {
		err[0] = 0;
		assert_false(PARSE(cases[i], false, &res, err));
		assert_non_null(strstr(err, "chunked"));
	}
}

static void test_chunk_size_cannot_wrap(void **state) {
	(void)state;
	http_response_t res;
	char err[256] = "";
	/* PLAN.md: ffffffffffffffff wrapped `in + chunk' and reached memmove()
	   with SIZE_MAX (ASan negative-size-param). */
	assert_false(PARSE("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
	                   "ffffffffffffffff\r\nx\r\n0\r\n\r\n", false, &res, err));
	assert_false(PARSE("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
	                   "fffffffffffffffffffff\r\nx\r\n0\r\n\r\n", false, &res, err));
}

static void test_malformed(void **state) {
	(void)state;
	http_response_t res;
	char err[256] = "";
	assert_false(PARSE("HTTP/1.1\r\n\r\n", false, &res, err));
	assert_non_null(strstr(err, "malformed"));
	assert_false(PARSE("HTTP/1.1 2x0 OK\r\n\r\n", false, &res, err));
	assert_false(PARSE("SMTP 220 hi\r\n\r\n", false, &res, err));
	assert_false(PARSE("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n", false, &res, err));
	assert_false(parse("", 0, false, &res, err, sizeof(err)));
	/* An unterminated header block ending exactly at len. */
	assert_false(PARSE("HTTP/1.1 200 OK\r\n\r", false, &res, err));
}

static void test_split_url_and_ipv6(void **state) {
	(void)state;
	char host[256], port[8], path[256];

	assert_true(httpc_split_url("https://acme-v02.api.letsencrypt.org/directory",
	                            host, sizeof(host), port, sizeof(port), path, sizeof(path)));
	assert_string_equal(host, "acme-v02.api.letsencrypt.org");
	assert_string_equal(port, "443");
	assert_string_equal(path, "/directory");

	assert_true(httpc_split_url("https://[2001:db8::1]:14000/dir",
	                            host, sizeof(host), port, sizeof(port), path, sizeof(path)));
	assert_string_equal(host, "2001:db8::1");
	assert_string_equal(port, "14000");
	assert_string_equal(path, "/dir");

	assert_true(httpc_split_url("https://[::1]",
	                            host, sizeof(host), port, sizeof(port), path, sizeof(path)));
	assert_string_equal(host, "::1");
	assert_string_equal(port, "443");
	assert_string_equal(path, "/");

	/* M-TR-06: control chars, CRLF, spaces, non-https, malformed IPv6/port rejected. */
	assert_false(httpc_split_url("https://ca.test/dir\r\nX-Injected: 1",
	                             host, sizeof(host), port, sizeof(port), path, sizeof(path)));
	assert_false(httpc_split_url("https://ca.test/dir with space",
	                             host, sizeof(host), port, sizeof(port), path, sizeof(path)));
	assert_false(httpc_split_url("https://ca.test/\x7f",
	                             host, sizeof(host), port, sizeof(port), path, sizeof(path)));
	assert_false(httpc_split_url("http://ca.test/dir",
	                             host, sizeof(host), port, sizeof(port), path, sizeof(path)));
	assert_false(httpc_split_url("https://2001:db8::1/dir",
	                             host, sizeof(host), port, sizeof(port), path, sizeof(path)));
	assert_false(httpc_split_url("https://[2001:db8::1/dir",
	                             host, sizeof(host), port, sizeof(port), path, sizeof(path)));
	assert_false(httpc_split_url("https://[not-ipv6]:443/dir",
	                             host, sizeof(host), port, sizeof(port), path, sizeof(path)));
	assert_false(httpc_split_url("https://ca.test:0/dir",
	                             host, sizeof(host), port, sizeof(port), path, sizeof(path)));
	assert_false(httpc_split_url("https://ca.test:70000/dir",
	                             host, sizeof(host), port, sizeof(port), path, sizeof(path)));
}

static void test_interim_1xx_and_clean_eof(void **state) {
	(void)state;
	http_response_t res;
	char err[256] = "";

	/* M-TR-06: 100 Continue interim block skipped before final 200 OK. */
	assert_true(PARSE("HTTP/1.1 100 Continue\r\n\r\n"
	                  "HTTP/1.1 200 OK\r\nReplay-Nonce: n2\r\nContent-Length: 5\r\n\r\nhello",
	                  false, &res, err));
	assert_int_equal(res.status, 200);
	assert_int_equal(res.body_len, 5);
	assert_string_equal(res.body, "hello");
	httpc_free(&res);

	/* Truncated right after 100 Continue must fail instead of returning status 100. */
	assert_false(PARSE("HTTP/1.1 100 Continue\r\n\r\n", false, &res, err));

	/* Unframed response without clean TLS close_notify (clean_eof = false) must fail. */
	const char *unframed = "HTTP/1.1 200 OK\r\nContent-Type: application/pem-certificate-chain\r\n\r\n"
	                       "-----BEGIN CERTIFICATE-----\nMIIB";
	assert_false(httpc_parse_response_ex(unframed, strlen(unframed), false, false, "ca.test", &res, err, sizeof(err)));
	assert_non_null(strstr(err, "close_notify"));
	assert_true(httpc_parse_response_ex(unframed, strlen(unframed), false, true, "ca.test", &res, err, sizeof(err)));
	httpc_free(&res);

	/* Chunked missing final CRLF after 0\r\n must fail. */
	assert_false(PARSE("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n",
	                   false, &res, err));

	/* Conflicting Transfer-Encoding + Content-Length or duplicate Content-Length must fail. */
	assert_false(PARSE("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n"
	                   "5\r\nhello\r\n0\r\n\r\n", false, &res, err));
	assert_false(PARSE("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
	                   false, &res, err));
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_content_length_exact),
		cmocka_unit_test(test_content_length_short_body_is_an_error),
		cmocka_unit_test(test_content_length_longer_body_is_cut),
		cmocka_unit_test(test_content_length_malformed),
		cmocka_unit_test(test_head_and_bodiless_statuses),
		cmocka_unit_test(test_close_delimited),
		cmocka_unit_test(test_chunked),
		cmocka_unit_test(test_chunked_truncated),
		cmocka_unit_test(test_chunk_size_cannot_wrap),
		cmocka_unit_test(test_malformed),
		cmocka_unit_test(test_split_url_and_ipv6),
		cmocka_unit_test(test_interim_1xx_and_clean_eof),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
