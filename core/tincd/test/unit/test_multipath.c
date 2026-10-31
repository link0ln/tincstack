#include "unittest.h"
#include "../../src/xalloc.h"
#include "../../src/connection.h"
#include "../../src/node.h"
#include "../../src/multipath.h"

static void test_multipath_mode_parse_and_name(void **state) {
	(void)state;
	multipath_mode_t m = MULTIPATH_OFF;

	assert_true(multipath_parse_mode("off", &m) && m == MULTIPATH_OFF);
	assert_true(multipath_parse_mode("failover", &m) && m == MULTIPATH_FAILOVER);
	assert_true(multipath_parse_mode("flowhash", &m) && m == MULTIPATH_FLOWHASH);
	assert_true(multipath_parse_mode("ecmp", &m) && m == MULTIPATH_FLOWHASH);
	assert_true(multipath_parse_mode("redundant", &m) && m == MULTIPATH_REDUNDANT);
	assert_true(multipath_parse_mode("split", &m) && m == MULTIPATH_SPLIT);
	assert_true(multipath_parse_mode("strip", &m) && m == MULTIPATH_SPLIT);
	assert_false(multipath_parse_mode("invalid_xyz", &m));

	assert_string_equal("off", multipath_mode_name(MULTIPATH_OFF));
	assert_string_equal("failover", multipath_mode_name(MULTIPATH_FAILOVER));
	assert_string_equal("flowhash", multipath_mode_name(MULTIPATH_FLOWHASH));
	assert_string_equal("redundant", multipath_mode_name(MULTIPATH_REDUNDANT));
	assert_string_equal("split", multipath_mode_name(MULTIPATH_SPLIT));
}

static void test_multipath_flow_hash_deterministic(void **state) {
	(void)state;
	vpn_packet_t pkt1 = {0}, pkt2 = {0};
	/* Synthetic IPv4 TCP packet (src 10.0.0.1:12345 -> dst 10.0.0.2:443) */
	uint8_t raw[40] = {
		0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00,
		0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1,
		10, 0, 0, 2,
		0x30, 0x39, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x02, 0x50, 0x10, 0x10, 0x00,
		0x00, 0x00, 0x00, 0x00
	};
	memcpy(DATA(&pkt1), raw, sizeof(raw));
	pkt1.len = sizeof(raw);

	/* Same 5-tuple, different TCP seq number -> must produce identical flow hash */
	memcpy(DATA(&pkt2), raw, sizeof(raw));
	pkt2.len = sizeof(raw);
	DATA(&pkt2)[27] = 0x99;

	uint32_t h1 = multipath_flow_hash(&pkt1);
	uint32_t h2 = multipath_flow_hash(&pkt2);
	assert_int_equal(h1, h2);

	/* Different source port -> different flow hash */
	DATA(&pkt2)[20] = 0x40;
	uint32_t h3 = multipath_flow_hash(&pkt2);
	assert_int_not_equal(h1, h3);
}

static void test_multipath_connection_pooling_and_failover(void **state) {
	(void)state;
	node_t *n = new_node("peer1");

	connection_t *c1 = new_connection();
	c1->name = xstrdup("peer1");
	c1->node = n;
	c1->status.active = true;
	n->connection = c1;
	multipath_node_add_connection(n, c1);

	connection_t *c2 = new_connection();
	c2->name = xstrdup("peer1");
	c2->node = n;
	c2->status.active = true;

	multipath_mode = MULTIPATH_FLOWHASH;
	multipath_target_connections = 2;

	/* Pool c2 as a secondary active connection */
	assert_true(multipath_accept_secondary(n, c2));
	assert_int_equal(2, n->connections.count);
	assert_true(c2->status.multipath_sub);
	assert_ptr_equal(c1, n->connection);

	/* Test scheduling modes */
	connection_t *out[2];

	multipath_mode = MULTIPATH_FAILOVER;
	int cnt = multipath_select_connections(n, NULL, out);
	assert_int_equal(1, cnt);
	assert_ptr_equal(c1, out[0]);

	multipath_mode = MULTIPATH_REDUNDANT;
	cnt = multipath_select_connections(n, NULL, out);
	assert_int_equal(2, cnt);

	multipath_mode = MULTIPATH_SPLIT;
	cnt = multipath_select_connections(n, NULL, out);
	assert_int_equal(1, cnt);
	connection_t *first_pick = out[0];
	/* Advance burst past SPLIT_BURST_PACKETS (16) to verify round-robin rotation */
	for(int i = 0; i < 16; i++) {
		multipath_select_connections(n, NULL, out);
	}
	assert_ptr_not_equal(first_pick, out[0]);

	/* Promote survivor when primary c1 fails (0-ms make-before-break) */
	assert_true(multipath_promote_survivor(n, c1));
	assert_ptr_equal(c2, n->connection);
	assert_false(c2->status.multipath_sub);
	assert_int_equal(1, n->connections.count);

	multipath_node_del_connection(n, c2);
	n->connection = NULL;
	free_connection(c1);
	free_connection(c2);
	free_node(n);
	multipath_mode = MULTIPATH_FAILOVER;
	multipath_target_connections = 1;
}

static void test_multipath_udp_paths_scheduling(void **state) {
	(void)state;
	node_t *n = new_node("peer_udp");
	n->status.udp_confirmed = true;

	sockaddr_t sa1 = {0}, sa2 = {0};
	sa1.in.sin_family = AF_INET;
	sa1.in.sin_addr.s_addr = htonl(0x0a000001);
	sa1.in.sin_port = htons(655);

	sa2.in.sin_family = AF_INET;
	sa2.in.sin_addr.s_addr = htonl(0x0a000002);
	sa2.in.sin_port = htons(655);

	n->address = sa1;
	multipath_record_udp_rx(n, -1, 0, &sa1, 100);
	multipath_record_udp_rx(n, -1, 0, &sa2, 100);

	node_path_t *paths[2];

	multipath_mode = MULTIPATH_REDUNDANT;
	int cnt = multipath_select_udp_paths(n, NULL, paths);
	assert_int_equal(2, cnt);

	multipath_mode = MULTIPATH_FAILOVER;
	cnt = multipath_select_udp_paths(n, NULL, paths);
	assert_int_equal(1, cnt);

	free_node(n);
	multipath_mode = MULTIPATH_FAILOVER;
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_multipath_mode_parse_and_name),
		cmocka_unit_test(test_multipath_flow_hash_deterministic),
		cmocka_unit_test(test_multipath_connection_pooling_and_failover),
		cmocka_unit_test(test_multipath_udp_paths_scheduling),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
