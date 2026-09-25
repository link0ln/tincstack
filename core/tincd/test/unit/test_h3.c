#include "unittest.h"
#include "../../src/h3.h"

/* A field section: the two-byte prefix (Required Insert Count 0, Base 0),
   then the field lines. */
static bool decode(const uint8_t *fs, size_t len, h3_req_fields_t *f) {
	uint64_t ric;
	return h3_decode_request(NULL, fs, len, f, &ric) == H3_DECODE_OK;
}

/* RFC 7541 C.4.1's Huffman string for www.example.com, as the value of a
   literal with a static name reference (:authority), plus indexed GET and
   indexed :path "/". */
static void test_decode_huffman_authority(void **state) {
	(void)state;
	static const uint8_t fs[] = {
		0x00, 0x00,
		0x50, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
		0xd1, 0xc1,
	};
	h3_req_fields_t f;
	assert_true(decode(fs, sizeof(fs), &f));
	assert_string_equal(f.method, "GET");
	assert_string_equal(f.path, "/");
	assert_string_equal(f.authority, "www.example.com");
}

/* Literal names, one plain and one Huffman-coded value (RFC 7541 C.4.2's
   "no-cache" is 0xa8eb10649cbf). */
static void test_decode_literal_names(void **state) {
	(void)state;
	static const uint8_t fs[] = {
		0x00, 0x00,
		0x25, ':', 'p', 'a', 't', 'h', 0x05, '/', 'n', 'o', 'p', 'e',
		0x27, 0x00, ':', 'm', 'e', 't', 'h', 'o', 'd', 0x86, 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf,
		0xd2,   /* indexed HEAD: the later line wins */
	};
	h3_req_fields_t f;
	assert_true(decode(fs, sizeof(fs), &f));
	assert_string_equal(f.path, "/nope");
	assert_string_equal(f.method, "HEAD");
	assert_string_equal(f.authority, "");
}

static void test_decode_rejects(void **state) {
	(void)state;
	h3_req_fields_t f;

	static const uint8_t ric[] = {0x01, 0x00, 0xd1};
	assert_false(decode(ric, sizeof(ric), &f));

	/* Without a dynamic table, references into one fail. */
	static const uint8_t dynamic[] = {0x00, 0x00, 0x80};
	assert_false(decode(dynamic, sizeof(dynamic), &f));

	static const uint8_t postbase[] = {0x00, 0x00, 0x10};
	assert_false(decode(postbase, sizeof(postbase), &f));

	/* '0' (00000) then three zero bits: padding must be ones. */
	static const uint8_t pad0[] = {0x00, 0x00, 0x51, 0x81, 0x00};
	assert_false(decode(pad0, sizeof(pad0), &f));

	/* Eight bits of padding. */
	static const uint8_t pad8[] = {0x00, 0x00, 0x51, 0x81, 0xff};
	assert_false(decode(pad8, sizeof(pad8), &f));

	/* A string longer than the section. */
	static const uint8_t trunc[] = {0x00, 0x00, 0x51, 0x05, '/', 'x'};
	assert_false(decode(trunc, sizeof(trunc), &f));
}

/* The dialler's own request decodes to what it says. */
static void test_decode_own_request(void **state) {
	(void)state;
	size_t len;
	uint8_t *frame = h3_request("example.org", "/api/v1", "sid=abc-_", &len);
	uint64_t type, flen;
	size_t n1 = h3_varint_get(frame, len, &type);
	size_t n2 = h3_varint_get(frame + n1, len - n1, &flen);
	assert_int_equal(type, H3_FRAME_HEADERS);
	assert_int_equal(n1 + n2 + flen, len);

	h3_req_fields_t f;
	assert_true(decode(frame + n1 + n2, flen, &f));
	assert_string_equal(f.method, "POST");
	assert_string_equal(f.path, "/api/v1");
	assert_string_equal(f.authority, "example.org");
	assert_string_equal(f.cookie, "sid=abc-_");
	free(frame);

	frame = h3_request("example.org", "/", NULL, &len);
	n1 = h3_varint_get(frame, len, &type);
	n2 = h3_varint_get(frame + n1, len - n1, &flen);
	assert_true(decode(frame + n1 + n2, flen, &f));
	assert_string_equal(f.path, "/");
	assert_string_equal(f.cookie, "");
	free(frame);
}

/* Cookie field lines a client split (RFC 9114 4.2.1) come back joined. */
static void test_decode_split_cookie(void **state) {
	(void)state;
	static const uint8_t fs[] = {
		0x00, 0x00,
		0xd1,
		0x55, 0x03, 'a', '=', '1',
		0x55, 0x03, 'b', '=', '2',
	};
	h3_req_fields_t f;
	assert_true(decode(fs, sizeof(fs), &f));
	assert_string_equal(f.method, "GET");
	assert_string_equal(f.cookie, "a=1; b=2");
	assert_string_equal(f.headers, "cookie: a=1\r\ncookie: b=2\r\n");
}

/* Regular fields come out as HTTP/1.1 header lines, in order, for the
   decoy; `host' is kept apart; a name that is not a lowercase token or a
   value with CR, LF or NUL fails the decode. */
static void test_decode_regular_fields(void **state) {
	(void)state;
	static const uint8_t fs[] = {
		0x00, 0x00,
		0xd1,
		0x5f, 0x10, 0x04, 'g', 'z', 'i', 'p',           /* accept-encoding (static 31) */
		0x5f, 0x28, 0x08, 'b', 'y', 't', 'e', 's', '=', '0', '-',       /* range (static 55) */
		0x24, 'h', 'o', 's', 't', 0x01, 'h',
		0x24, 'x', '-', 'a', 'b', 0x01, 'v',
	};
	h3_req_fields_t f;
	assert_true(decode(fs, sizeof(fs), &f));
	assert_string_equal(f.headers, "accept-encoding: gzip\r\nrange: bytes=0-\r\nx-ab: v\r\n");
	assert_string_equal(f.host, "h");
	assert_int_equal(f.headers_len, strlen(f.headers));

	static const uint8_t upper[] = {0x00, 0x00, 0xd1, 0x23, 'X', '-', 'a', 0x01, 'v'};
	assert_false(decode(upper, sizeof(upper), &f));

	static const uint8_t cr[] = {0x00, 0x00, 0xd1, 0x23, 'x', '-', 'a', 0x02, 'v', '\r'};
	assert_false(decode(cr, sizeof(cr), &f));

	static const uint8_t nul[] = {0x00, 0x00, 0xd1, 0x23, 'x', '-', 'a', 0x02, 'v', 0};
	assert_false(decode(nul, sizeof(nul), &f));
}

/* RFC 9204 Appendix B.1/B.2-style exchange: the encoder sets the capacity,
   inserts :authority and :path, and the request references both. */
static void test_dynamic_table(void **state) {
	(void)state;
	h3_qpack_t *q = h3_qpack_new(H3_QPACK_CAPACITY);
	h3_req_fields_t f;
	uint64_t ric;
	uint8_t out[16];

	/* Set Dynamic Table Capacity 220; Insert With Name Reference static 0
	   (:authority) "www.example.com"; static 1 (:path) "/sample/path". */
	static const uint8_t enc[] = {
		0x3f, 0xbd, 0x01,
		0xc0, 0x0f, 'w', 'w', 'w', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
		0xc1, 0x0c, '/', 's', 'a', 'm', 'p', 'l', 'e', '/', 'p', 'a', 't', 'h',
	};

	/* Required Insert Count 2 (encoded 3), Base 2; indexed dynamic
	   relative 1 (:authority) and 0 (:path); indexed static GET. */
	static const uint8_t fs[] = {0x03, 0x00, 0x81, 0x80, 0xd1};

	/* Before the encoder stream: blocked. */
	assert_int_equal(h3_decode_request(q, fs, sizeof(fs), &f, &ric), H3_DECODE_BLOCKED);

	/* Split mid-instruction: the decoder waits for the rest. */
	assert_true(h3_qpack_encoder_data(q, enc, 10));
	assert_int_equal(h3_qpack_inserts(q), 0);
	assert_true(h3_qpack_encoder_data(q, enc + 10, sizeof(enc) - 10));
	assert_int_equal(h3_qpack_inserts(q), 2);

	assert_int_equal(h3_decode_request(q, fs, sizeof(fs), &f, &ric), H3_DECODE_OK);
	assert_int_equal(ric, 2);
	assert_string_equal(f.authority, "www.example.com");
	assert_string_equal(f.path, "/sample/path");
	assert_string_equal(f.method, "GET");

	/* Section Acknowledgment for stream 4, and then nothing left to tell. */
	assert_int_equal(h3_qpack_section_ack(q, ric, 4, out), 1);
	assert_int_equal(out[0], 0x84);
	assert_int_equal(h3_qpack_increment(q, out), 0);

	/* Post-base: Base 0 with Required Insert Count 2 (sign bit, delta 1),
	   post-base index 0 and 1; plus a Duplicate that bumps the count. */
	static const uint8_t fs2[] = {0x03, 0x81, 0x10, 0x11};
	assert_int_equal(h3_decode_request(q, fs2, sizeof(fs2), &f, &ric), H3_DECODE_OK);
	assert_string_equal(f.authority, "www.example.com");
	assert_string_equal(f.path, "/sample/path");

	static const uint8_t dup[] = {0x01};
	assert_true(h3_qpack_encoder_data(q, dup, sizeof(dup)));
	assert_int_equal(h3_qpack_inserts(q), 3);
	assert_int_equal(h3_qpack_increment(q, out), 1);
	assert_int_equal(out[0], 0x01);

	/* A reference past the table, a capacity over ours, an insert that does
	   not fit: errors. */
	static const uint8_t past[] = {0x03, 0x00, 0x82};
	assert_int_equal(h3_decode_request(q, past, sizeof(past), &f, &ric), H3_DECODE_ERROR);
	static const uint8_t cap[] = {0x3f, 0xe2, 0x1f};       /* 4097 */
	assert_false(h3_qpack_encoder_data(q, cap, sizeof(cap)));
	h3_qpack_free(q);

	q = h3_qpack_new(H3_QPACK_CAPACITY);
	static const uint8_t small[] = {0x20 | 30, 0xc0, 0x01, 'x'};  /* capacity 30 < 32 + 11 */
	assert_false(h3_qpack_encoder_data(q, small, sizeof(small)));
	h3_qpack_free(q);

	assert_int_equal(h3_qpack_stream_cancel(8, out), 1);
	assert_int_equal(out[0], 0x48);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_decode_huffman_authority),
		cmocka_unit_test(test_decode_literal_names),
		cmocka_unit_test(test_decode_rejects),
		cmocka_unit_test(test_decode_own_request),
		cmocka_unit_test(test_decode_split_cookie),
		cmocka_unit_test(test_decode_regular_fields),
		cmocka_unit_test(test_dynamic_table),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
