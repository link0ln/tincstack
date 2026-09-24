#include "unittest.h"
#include "../../src/h3.h"

/* A field section: the two-byte prefix (Required Insert Count 0, Base 0),
   then the field lines. */
static bool decode(const uint8_t *fs, size_t len, h3_req_fields_t *f) {
	return h3_decode_request(fs, len, f);
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
	uint8_t *frame = h3_request("example.org", "/api/v1", &len);
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
	free(frame);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_decode_huffman_authority),
		cmocka_unit_test(test_decode_literal_names),
		cmocka_unit_test(test_decode_rejects),
		cmocka_unit_test(test_decode_own_request),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
