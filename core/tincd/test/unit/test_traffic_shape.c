#include "unittest.h"
#include "../../src/connection.h"
#include "../../src/net.h"
#define TINC_TRANSPORT_DAEMON
#include "../../src/transport.h"

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#endif

typedef enum https_state_t {
	HS_TCP_CONNECTING,
	HS_TLS_HANDSHAKE,
	HS_CLIENT_WRITE_REQ,
	HS_CLIENT_READ_RESP,
	HS_SERVER_READ_REQ,
	HS_SERVER_FETCH_DECOY,
	HS_SERVER_WRITE,
	HS_SERVER_WRITE_DECOY,
	HS_ESTABLISHED,
	HS_DYING,
} https_state_t;

typedef struct https_session_t {
	connection_t *c;
	void *ssl;
	https_state_t state;
	bool is_server;
	char *sni;
	char *host;
	char *wbuf;
	size_t wlen, woff;
	char *rbuf;
	size_t rlen, rcap;
	uint8_t server_fp[32];
	char server_fp_hex[65];
	bool pin_pending;
	bool established_after_write;
	bool decoy_keep_alive;
	void *fetch;
	size_t pad_budget;
} https_session_t;

static void test_is_tls_client_hello_null_and_short(void **state) {
	(void)state;
	uint8_t buf[32] = {0};

	assert_false(is_tls_client_hello(NULL, 0));
	assert_false(is_tls_client_hello(NULL, 100));
	assert_false(is_tls_client_hello(buf, 0));
	assert_false(is_tls_client_hello(buf, 10));
	assert_false(is_tls_client_hello(buf, 19));
}

static void test_is_tls_client_hello_ipv4_non_tcp(void **state) {
	(void)state;
	/* IPv4 header, 20 bytes, protocol UDP (17) */
	uint8_t pkt[48] = {
		0x45, 0x00, 0x00, 0x30, 0x12, 0x34, 0x00, 0x00,
		0x40, 0x11, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x01,
		0x7f, 0x00, 0x00, 0x01,
	};
	assert_false(is_tls_client_hello(pkt, sizeof(pkt)));

	/* Protocol ICMP (1) */
	pkt[9] = 0x01;
	assert_false(is_tls_client_hello(pkt, sizeof(pkt)));
}

static void test_is_tls_client_hello_ipv4_tcp_no_tls(void **state) {
	(void)state;
	/* IPv4 TCP packet without TLS (e.g. plain SYN or HTTP) */
	uint8_t pkt[60] = {
		0x45, 0x00, 0x00, 0x3c, 0x00, 0x01, 0x00, 0x00,
		0x40, 0x06, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
		0x0a, 0x00, 0x00, 0x02,
		/* TCP header (20 bytes, data offset = 5) */
		0x1f, 0x90, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x72, 0x10,
		0x00, 0x00, 0x00, 0x00,
		/* Payload: "GET / HTTP/1.1\r\n" */
		'G', 'E', 'T', ' ', '/', ' ', 'H', 'T', 'T', 'P', '/', '1', '.', '1', '\r', '\n'
	};
	assert_false(is_tls_client_hello(pkt, sizeof(pkt)));

	/* Truncated TCP header (less than 20 bytes) */
	assert_false(is_tls_client_hello(pkt, 25));

	/* Truncated payload (< 6 bytes of TLS) */
	assert_false(is_tls_client_hello(pkt, 42));
}

static void test_is_tls_client_hello_ipv4_non_client_hello_tls(void **state) {
	(void)state;
	uint8_t pkt[60] = {
		0x45, 0x00, 0x00, 0x3c, 0x00, 0x01, 0x00, 0x00,
		0x40, 0x06, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
		0x0a, 0x00, 0x00, 0x02,
		0x01, 0xbb, 0x1f, 0x90, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x50, 0x18, 0x72, 0x10,
		0x00, 0x00, 0x00, 0x00,
		/* TLS record header: Handshake (0x16), TLS 1.2 (0x03, 0x03), length, but HandshakeType = 0x02 (ServerHello) */
		0x16, 0x03, 0x03, 0x00, 0x10, 0x02, 0x00, 0x00, 0x0c
	};
	assert_false(is_tls_client_hello(pkt, sizeof(pkt)));

	/* TLS record header: ApplicationData (0x17) */
	pkt[40] = 0x17;
	assert_false(is_tls_client_hello(pkt, sizeof(pkt)));
}

static void test_is_tls_client_hello_ipv4_valid(void **state) {
	(void)state;
	/* IPv4 TCP packet carrying TLS ClientHello */
	uint8_t pkt[60] = {
		0x45, 0x00, 0x00, 0x3c, 0x00, 0x01, 0x00, 0x00,
		0x40, 0x06, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
		0x0a, 0x00, 0x00, 0x02,
		/* TCP header (20 bytes) */
		0x1f, 0x90, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x50, 0x18, 0x72, 0x10,
		0x00, 0x00, 0x00, 0x00,
		/* TLS record header: Handshake (0x16), TLS 1.0 (0x03, 0x01), length 16, HandshakeType = 0x01 (ClientHello) */
		0x16, 0x03, 0x01, 0x00, 0x10, 0x01, 0x00, 0x00, 0x0c
	};
	assert_true(is_tls_client_hello(pkt, sizeof(pkt)));

	/* TLS 1.2 legacy version (0x03, 0x03) */
	pkt[42] = 0x03;
	assert_true(is_tls_client_hello(pkt, sizeof(pkt)));
}

static void test_is_tls_client_hello_ipv4_with_options(void **state) {
	(void)state;
	/* IPv4 (IHL = 6 -> 24 bytes) + TCP (Data Offset = 6 -> 24 bytes) */
	uint8_t pkt[64] = {
		0x46, 0x00, 0x00, 0x40, 0x00, 0x01, 0x00, 0x00,
		0x40, 0x06, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
		0x0a, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, /* 4 bytes IP opt */
		0x1f, 0x90, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x60, 0x18, 0x72, 0x10, /* offset 6 */
		0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, /* 4 bytes TCP opt */
		0x16, 0x03, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x06
	};
	assert_true(is_tls_client_hello(pkt, sizeof(pkt)));
}

static void test_is_tls_client_hello_ipv6_valid(void **state) {
	(void)state;
	/* IPv6 header (40 bytes) + TCP (20 bytes) + TLS ClientHello */
	uint8_t pkt[70] = {
		0x60, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x06, 0x40,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		/* TCP header (20 bytes) */
		0x1f, 0x90, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x50, 0x18, 0x72, 0x10,
		0x00, 0x00, 0x00, 0x00,
		/* TLS ClientHello */
		0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00
	};
	assert_true(is_tls_client_hello(pkt, sizeof(pkt)));

	/* Non-TCP IPv6 (Next Header UDP = 17) */
	pkt[6] = 0x11;
	assert_false(is_tls_client_hello(pkt, sizeof(pkt)));
}

static void test_https_record_padding_cb(void **state) {
	(void)state;
#ifdef HAVE_OPENSSL
	https_session_t s;
	memset(&s, 0, sizeof(s));

	/* Null session */
	assert_int_equal(0, https_record_padding_cb(NULL, 23, 100, NULL));

	/* Non-application data record (e.g. handshake = 22) must not be padded */
	s.pad_budget = 1500;
	assert_int_equal(0, https_record_padding_cb(NULL, 22, 100, &s));
	assert_int_equal(s.pad_budget, 1500);

	/* Application data (23) returns pad_budget and consumes it */
	assert_int_equal(1500, https_record_padding_cb(NULL, 23, 100, &s));
	assert_int_equal(s.pad_budget, 0);

	/* Subsequent call returns 0 */
	assert_int_equal(0, https_record_padding_cb(NULL, 23, 100, &s));

	/* Capped at 16384 total plaintext length */
	s.pad_budget = 1000;
	assert_int_equal(384, https_record_padding_cb(NULL, 23, 16000, &s));
	assert_int_equal(s.pad_budget, 0);
#endif
}

static void test_https_pad_next_burst(void **state) {
	(void)state;
#ifdef HAVE_OPENSSL
	connection_t c;
	memset(&c, 0, sizeof(c));
	https_session_t s;
	memset(&s, 0, sizeof(s));

	c.transport = transport_get(TRANSPORT_HTTPS);
	c.transport_data = &s;

	/* If not established, pad_budget remains 0 */
	s.state = HS_TLS_HANDSHAKE;
	https_pad_next_burst(&c, 1350, 1650);
	assert_int_equal(0, s.pad_budget);

	/* Established: pad_budget randomized between min and max */
	s.state = HS_ESTABLISHED;
	https_pad_next_burst(&c, 1350, 1650);
	assert_true(s.pad_budget >= 1350 && s.pad_budget <= 1650);

	/* Fixed budget when min == max */
	https_pad_next_burst(&c, 1500, 1500);
	assert_int_equal(1500, s.pad_budget);
#endif
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_is_tls_client_hello_null_and_short),
		cmocka_unit_test(test_is_tls_client_hello_ipv4_non_tcp),
		cmocka_unit_test(test_is_tls_client_hello_ipv4_tcp_no_tls),
		cmocka_unit_test(test_is_tls_client_hello_ipv4_non_client_hello_tls),
		cmocka_unit_test(test_is_tls_client_hello_ipv4_valid),
		cmocka_unit_test(test_is_tls_client_hello_ipv4_with_options),
		cmocka_unit_test(test_is_tls_client_hello_ipv6_valid),
		cmocka_unit_test(test_https_record_padding_cb),
		cmocka_unit_test(test_https_pad_next_burst),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
