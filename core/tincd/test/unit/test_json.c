#include "unittest.h"
#include "../../src/json.h"

/* Every input is copied into a heap buffer of exactly its length, with no NUL
   after it, so a read past `len' is a heap-buffer-overflow under ASan rather
   than a silent read of whatever follows a string literal. */
static json_t *parse_exact(const char *text, size_t len) {
	char *buf = malloc(len ? len : 1);
	assert_non_null(buf);
	memcpy(buf, text, len);
	json_t *v = json_parse(buf, len);
	free(buf);
	return v;
}

static json_t *parse(const char *text) {
	return parse_exact(text, strlen(text));
}

static void test_number_at_end_of_unterminated_buffer(void **state) {
	(void)state;
	json_t *v = parse("12345");
	assert_non_null(v);
	assert_true(json_number(v, -1) == 12345.0);
	json_free(v);

	v = parse("-0.5E-1");
	assert_non_null(v);
	assert_true(json_number(v, 0) == -0.05);
	json_free(v);

	v = parse("[1,2e3]");
	assert_non_null(v);
	assert_true(json_number(json_index(v, 1), 0) == 2000.0);
	json_free(v);
}

static void test_number_stops_at_len(void **state) {
	(void)state;
	/* The bytes after `len' are digits in the same buffer: they must be
	   neither read nor part of the number. The old strtod() read them, saw
	   the number end past `len' and refused a valid document. */
	const char buf[] = "12345";
	json_t *v = json_parse(buf, 3);
	assert_non_null(v);
	assert_true(json_number(v, -1) == 123.0);
	json_free(v);

	v = json_parse("[7]8", 3);
	assert_non_null(v);
	json_free(v);
}

static void test_number_incomplete_at_len(void **state) {
	(void)state;
	assert_null(parse("-"));
	assert_null(parse("1."));
	assert_null(parse("1e"));
	assert_null(parse("1e+"));
	assert_null(parse("[1."));
	assert_null(parse("{\"a\":-"));
}

static void test_number_not_json(void **state) {
	(void)state;
	assert_null(parse("+1"));
	assert_null(parse("inf"));
	assert_null(parse("nan"));
	assert_null(parse("0x10"));
	assert_null(parse(".5"));
	assert_null(parse("01"));
	assert_null(parse("1.e5"));
}

static void test_number_too_long(void **state) {
	(void)state;
	char big[100];
	memset(big, '7', sizeof(big));
	assert_null(parse_exact(big, sizeof(big)));

	json_t *v = parse_exact(big, 20);
	assert_non_null(v);
	json_free(v);
}

static void test_trailing_garbage(void **state) {
	(void)state;
	assert_null(parse("{\"a\":1}x"));
	assert_null(parse("{\"a\":1} {}"));
	assert_null(parse("[] ]"));
	assert_null(parse("true false"));
	assert_null(parse("\"s\"\""));
	assert_null(parse("1 2"));

	json_t *v = parse(" {\"a\":1} \r\n\t");
	assert_non_null(v);
	assert_true(json_number(json_member(v, "a"), 0) == 1.0);
	json_free(v);
}

static void test_truncated_values(void **state) {
	(void)state;
	assert_null(parse(""));
	assert_null(parse("   "));
	assert_null(parse("{"));
	assert_null(parse("{\"a\""));
	assert_null(parse("{\"a\":"));
	assert_null(parse("[1,"));
	assert_null(parse("\"abc"));
	assert_null(parse("\"\\u12"));
	assert_null(parse("tru"));
	assert_null(parse("nul"));
}

static void test_ordinary_document(void **state) {
	(void)state;
	const char *doc = "{\"status\":\"valid\",\"n\":3,\"ok\":true,\"list\":[\"x\",\"y\"],"
	                  "\"u\":\"\\u00e9\",\"z\":null}";
	json_t *v = parse(doc);
	assert_non_null(v);
	assert_string_equal(json_member_string(v, "status"), "valid");
	assert_true(json_number(json_member(v, "n"), 0) == 3.0);
	assert_true(json_is_true(json_member(v, "ok")));
	assert_int_equal(json_count(json_member(v, "list")), 2);
	assert_string_equal(json_string(json_index(json_member(v, "list"), 1)), "y");
	assert_string_equal(json_member_string(v, "u"), "\xc3\xa9");
	json_free(v);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_number_at_end_of_unterminated_buffer),
		cmocka_unit_test(test_number_stops_at_len),
		cmocka_unit_test(test_number_incomplete_at_len),
		cmocka_unit_test(test_number_not_json),
		cmocka_unit_test(test_number_too_long),
		cmocka_unit_test(test_trailing_garbage),
		cmocka_unit_test(test_truncated_values),
		cmocka_unit_test(test_ordinary_document),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
