#include "unittest.h"
#include "../../src/netutl.h"
#include "../../src/xalloc.h"

static void test_service_to_port_invalid(void **state) {
	(void)state;

	assert_int_equal(0, service_to_port(NULL));
	assert_int_equal(0, service_to_port(""));
	assert_int_equal(0, service_to_port("-1"));
	assert_int_equal(0, service_to_port("foobar"));
}

static void test_service_to_port_valid(void **state) {
	(void)state;

	assert_int_equal(22, service_to_port("ssh"));
	assert_int_equal(80, service_to_port("http"));
	assert_int_equal(443, service_to_port("https"));
	assert_int_equal(1234, service_to_port("1234"));
}

static void test_is_local_connection_ipv4(void **state) {
	(void)state;

	sockaddr_t sa;

	assert_true(inet_pton(AF_INET, "127.0.0.0", &sa.in.sin_addr));
	sa.sa.sa_family = AF_INET;
	assert_true(is_local_connection(&sa));

	assert_true(inet_pton(AF_INET, "127.42.13.5", &sa.in.sin_addr));
	sa.sa.sa_family = AF_INET;
	assert_true(is_local_connection(&sa));

	assert_true(inet_pton(AF_INET, "127.255.255.255", &sa.in.sin_addr));
	sa.sa.sa_family = AF_INET;
	assert_true(is_local_connection(&sa));

	assert_true(inet_pton(AF_INET, "128.0.0.1", &sa.in.sin_addr));
	sa.sa.sa_family = AF_INET;
	assert_false(is_local_connection(&sa));
}

static void test_is_local_connection_ipv6(void **state) {
	(void)state;

	sockaddr_t sa;

	assert_true(inet_pton(AF_INET6, "::1", &sa.in6.sin6_addr));
	sa.sa.sa_family = AF_INET6;
	assert_true(is_local_connection(&sa));

	assert_true(inet_pton(AF_INET6, "::1:1", &sa.in6.sin6_addr));
	sa.sa.sa_family = AF_INET6;
	assert_false(is_local_connection(&sa));

	assert_true(inet_pton(AF_INET6, "fe80::", &sa.in6.sin6_addr));
	sa.sa.sa_family = AF_INET6;
	assert_false(is_local_connection(&sa));
}

static void test_is_local_connection_unix(void **state) {
	(void)state;

	sockaddr_t sa = {.sa.sa_family = AF_UNIX};
	assert_true(is_local_connection(&sa));
}

static void test_sockaddrcpy_and_free_af_unknown(void **state) {
	(void)state;

	sockaddr_t src = {0};
	src.sa.sa_family = AF_UNKNOWN;
	src.unknown.address = xstrdup("vpn.example.org");
	src.unknown.port = xstrdup("655");

	sockaddr_t dst = {0};
	sockaddrcpy(&dst, &src);

	assert_int_equal(AF_UNKNOWN, dst.sa.sa_family);
	assert_non_null(dst.unknown.address);
	assert_non_null(dst.unknown.port);
	assert_ptr_not_equal(src.unknown.address, dst.unknown.address);
	assert_ptr_not_equal(src.unknown.port, dst.unknown.port);
	assert_string_equal("vpn.example.org", dst.unknown.address);
	assert_string_equal("655", dst.unknown.port);
	assert_int_equal(0, sockaddrcmp(&src, &dst));

	/* Freeing source must leave deep-copied destination intact and be idempotent */
	sockaddrfree(&src);
	assert_int_equal(AF_UNSPEC, src.sa.sa_family);
	assert_null(src.unknown.address);
	assert_null(src.unknown.port);
	sockaddrfree(&src);

	assert_string_equal("vpn.example.org", dst.unknown.address);
	assert_string_equal("655", dst.unknown.port);

	/* Self-copy and port update on AF_UNKNOWN must not leak or UAF */
	sockaddrcpy(&dst, &dst);
	sockaddr_setport(&dst, "8443");
	assert_string_equal("vpn.example.org", dst.unknown.address);
	assert_string_equal("8443", dst.unknown.port);

	char *addrstr = NULL, *portstr = NULL;
	sockaddr2str(&dst, &addrstr, &portstr);
	assert_string_equal("vpn.example.org", addrstr);
	assert_string_equal("8443", portstr);
	free(addrstr);
	free(portstr);

	sockaddrfree(&dst);
	assert_int_equal(AF_UNSPEC, dst.sa.sa_family);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_service_to_port_invalid),
		cmocka_unit_test(test_service_to_port_valid),
		cmocka_unit_test(test_is_local_connection_ipv4),
		cmocka_unit_test(test_is_local_connection_ipv6),
		cmocka_unit_test(test_is_local_connection_unix),
		cmocka_unit_test(test_sockaddrcpy_and_free_af_unknown),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
