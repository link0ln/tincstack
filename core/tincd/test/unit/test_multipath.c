#include "unittest.h"
#include "../../src/autoif.h"
#include "../../src/xalloc.h"
#include "../../src/connection.h"
#include "../../src/edge.h"
#include "../../src/netutl.h"
#include "../../src/node.h"
#include "../../src/multipath.h"
#define TINC_TRANSPORT_DAEMON
#include "../../src/transport.h"

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
	/* Synthetic 14-byte Ethernet/pseudo-Ethernet header + IPv4 TCP packet
	   (src 10.0.0.1:12345 -> dst 10.0.0.2:443). Every vpn_packet_t in tincd
	   carries a 14-byte header at DATA(pkt)[0..13] in both RMODE_ROUTER and
	   RMODE_SWITCH. */
	uint8_t raw[14 + 40] = {
		/* 14-byte L2 / pseudo-L2 header */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x08, 0x00,
		/* 40-byte IPv4 + TCP header */
		0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00,
		0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1,
		10, 0, 0, 2,
		0x30, 0x39, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x02, 0x50, 0x10, 0x10, 0x00,
		0x00, 0x00, 0x00, 0x00
	};
	memcpy(DATA(&pkt1), raw, sizeof(raw));
	pkt1.len = sizeof(raw);

	/* Same 5-tuple, different TCP seq number AND different uninitialized L2 MAC
	   bytes -> must produce identical flow hash in RMODE_ROUTER! */
	memcpy(DATA(&pkt2), raw, sizeof(raw));
	pkt2.len = sizeof(raw);
	DATA(&pkt2)[0] = 0xde;
	DATA(&pkt2)[5] = 0xad;
	DATA(&pkt2)[14 + 27] = 0x99;

	uint32_t h1 = multipath_flow_hash(&pkt1);
	uint32_t h2 = multipath_flow_hash(&pkt2);
	assert_int_equal(h1, h2);

	/* Different TCP source port -> different flow hash */
	DATA(&pkt2)[14 + 20] = 0x40;
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

static void test_multipath_promote_survivor_teardown_and_af_unknown(void **state) {
	(void)state;
	node_t *from_node = new_node("self_mp");
	node_t *n = new_node("peer_mp");

	outgoing_t out = {0};
	out.node = n;
	out.timeout = -1; /* Intentional teardown (e.g. dnsrefresh_apply / removed ConnectTo) */

	connection_t *c1 = new_connection();
	c1->name = xstrdup("peer_mp");
	c1->hostname = xstrdup("peer_mp.example");
	c1->node = n;
	c1->status.active = true;
	c1->outgoing = &out;

	edge_t *e = new_edge();
	e->from = from_node;
	e->to = n;
	e->connection = c1;
	c1->edge = e;

	connection_t *c2 = new_connection();
	c2->name = xstrdup("peer_mp");
	c2->hostname = xstrdup("peer_mp.example");
	c2->node = n;
	c2->status.active = true;
	c2->address.sa.sa_family = AF_UNKNOWN;
	c2->address.unknown.address = xstrdup("standby.example.org");
	c2->address.unknown.port = xstrdup("655");

	n->connection = c1;
	multipath_node_add_connection(n, c1);
	multipath_mode = MULTIPATH_FAILOVER;
	assert_true(multipath_accept_secondary(n, c2));

	assert_true(multipath_promote_survivor(n, c1));
	assert_ptr_equal(c2, n->connection);
	/* H-DP-04: outgoing with timeout == -1 must NOT be hijacked by survivor */
	assert_null(c2->outgoing);
	assert_ptr_equal(&out, c1->outgoing);

	/* C-DP-01: AF_UNKNOWN address on transferred edge must be deep-copied */
	assert_int_equal(AF_UNKNOWN, e->address.sa.sa_family);
	assert_non_null(e->address.unknown.address);
	assert_ptr_not_equal(c2->address.unknown.address, e->address.unknown.address);
	assert_string_equal("standby.example.org", e->address.unknown.address);
	assert_string_equal("655", e->address.unknown.port);

	c1->outgoing = NULL;
	c2->edge = NULL;
	multipath_node_del_connection(n, c2);
	n->connection = NULL;
	free_connection(c1);
	free_connection(c2);
	/* Verify e->address remains valid after c2's AF_UNKNOWN strings were freed! */
	assert_string_equal("standby.example.org", e->address.unknown.address);
	free_edge(e);
	free_node(n);
	free_node(from_node);
}

static void test_multipath_flowhash_slot_consistency_and_degraded_redirect(void **state) {
	(void)state;
	node_t *n = new_node("peer_slots");
	connection_t *conns[4];

	for(int i = 0; i < 4; i++) {
		conns[i] = new_connection();
		conns[i]->name = xstrdup("peer_slots");
		conns[i]->node = n;
		conns[i]->status.active = true;
		conns[i]->socket = -1;
		conns[i]->tcp_min_rtt_us = 40000;
		conns[i]->tcp_diag_at = now.tv_sec;
		multipath_node_add_connection(n, conns[i]);
		assert_int_equal((uint32_t)i, conns[i]->relay_slot);
	}

	n->connection = conns[0];
	multipath_mode = MULTIPATH_FLOWHASH;
	multipath_target_connections = 4;

	vpn_packet_t pkts[64];
	connection_t *chosen_before[64];
	int hits[4] = {0, 0, 0, 0};

	for(int i = 0; i < 64; i++) {
		memset(&pkts[i], 0, sizeof(pkts[i]));
		uint8_t raw[14 + 40] = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x08, 0x00,
			0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00,
			0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1,
			10, 0, 0, 2,
			0x00, 0x00, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x02, 0x50, 0x10, 0x10, 0x00,
			0x00, 0x00, 0x00, 0x00
		};
		uint16_t sport = (uint16_t)(10000 + i);
		raw[14 + 20] = (uint8_t)(sport >> 8);
		raw[14 + 21] = (uint8_t)(sport & 0xff);
		memcpy(DATA(&pkts[i]), raw, sizeof(raw));
		pkts[i].len = sizeof(raw);

		connection_t *out[2] = {NULL, NULL};
		assert_int_equal(1, multipath_select_connections(n, &pkts[i], out));
		chosen_before[i] = out[0];

		for(int c = 0; c < 4; c++) {
			if(out[0] == conns[c]) {
				hits[c]++;
			}
		}
	}

	for(int c = 0; c < 4; c++) {
		assert_true(hits[c] > 0);
	}

	/* Degrading slot 2 must redirect slot-2 flows cleanly WITHOUT shifting any
	   healthy flow on slots 0, 1, or 3 (zero intra-flow reordering). */
	conns[2]->tcp_degraded = true;

	for(int i = 0; i < 64; i++) {
		connection_t *out[2] = {NULL, NULL};
		assert_int_equal(1, multipath_select_connections(n, &pkts[i], out));

		if(chosen_before[i] == conns[2]) {
			assert_ptr_not_equal(conns[2], out[0]);
		} else {
			assert_ptr_equal(chosen_before[i], out[0]);
		}
	}

	/* Deleting slot 2 from n->connections must likewise preserve slots 0, 1, and 3 */
	multipath_node_del_connection(n, conns[2]);

	for(int i = 0; i < 64; i++) {
		connection_t *out[2] = {NULL, NULL};
		assert_int_equal(1, multipath_select_connections(n, &pkts[i], out));

		if(chosen_before[i] != conns[2]) {
			assert_ptr_equal(chosen_before[i], out[0]);
		}
	}

	/* Re-adding a replacement connection must reuse lowest free slot 2 and preserve others */
	connection_t *c2_new = new_connection();
	c2_new->name = xstrdup("peer_slots");
	c2_new->node = n;
	c2_new->status.active = true;
	c2_new->socket = -1;
	c2_new->tcp_min_rtt_us = 40000;
	c2_new->tcp_diag_at = now.tv_sec;
	multipath_node_add_connection(n, c2_new);
	assert_int_equal(2, c2_new->relay_slot);

	for(int i = 0; i < 64; i++) {
		connection_t *out[2] = {NULL, NULL};
		assert_int_equal(1, multipath_select_connections(n, &pkts[i], out));

		if(chosen_before[i] == conns[2]) {
			assert_ptr_equal(c2_new, out[0]);
		} else {
			assert_ptr_equal(chosen_before[i], out[0]);
		}
	}

	multipath_node_del_connection(n, c2_new);
	multipath_node_del_connection(n, conns[0]);
	multipath_node_del_connection(n, conns[1]);
	multipath_node_del_connection(n, conns[3]);
	n->connection = NULL;
	free_connection(c2_new);

	for(int i = 0; i < 4; i++) {
		free_connection(conns[i]);
	}

	free_node(n);
	multipath_mode = MULTIPATH_FAILOVER;
	multipath_target_connections = 1;
}

static void test_multipath_tspu_policed_leg_exclusion_and_sticky_latch(void **state) {
	(void)state;
	node_t *n = new_node("peer_tspu");
	connection_t *conns[6];

	for(int i = 0; i < 6; i++) {
		conns[i] = new_connection();
		conns[i]->name = xstrdup("peer_tspu");
		conns[i]->node = n;
		conns[i]->status.active = true;
		conns[i]->socket = -1;
		conns[i]->tcp_min_rtt_us = 39000;
		conns[i]->tcp_diag_at = now.tv_sec;
		multipath_node_add_connection(n, conns[i]);
	}

	conns[0]->tcp_segs_out = 41000;
	conns[0]->tcp_total_retrans = 2600;
	conns[0]->tcp_cwnd = 14;
	conns[0]->tcp_pacing_bps = 950000ULL;

	conns[1]->tcp_segs_out = 90000;
	conns[1]->tcp_total_retrans = 2700;
	conns[1]->tcp_cwnd = 674;
	conns[1]->tcp_pacing_bps = 109000000ULL;

	conns[2]->tcp_segs_out = 15000;
	conns[2]->tcp_total_retrans = 1060;
	conns[2]->tcp_cwnd = 50;
	conns[2]->tcp_pacing_bps = 5470000ULL;

	conns[3]->tcp_segs_out = 10500;
	conns[3]->tcp_total_retrans = 1380;
	conns[3]->tcp_cwnd = 18;
	conns[3]->tcp_pacing_bps = 1260000ULL;

	/* Low-loss app_limited healthy leg must stay enabled */
	conns[4]->tcp_segs_out = 2000;
	conns[4]->tcp_total_retrans = 0;
	conns[4]->tcp_cwnd = 18;
	conns[4]->tcp_pacing_bps = 8400000ULL;

	conns[5]->tcp_segs_out = 5000;
	conns[5]->tcp_total_retrans = 100;
	conns[5]->tcp_cwnd = 180;
	conns[5]->tcp_pacing_bps = 46500000ULL;

	n->connection = conns[0];
	multipath_mode = MULTIPATH_FLOWHASH;
	multipath_target_connections = 6;

	for(int i = 0; i < 64; i++) {
		vpn_packet_t pkt = {0};
		uint8_t raw[14 + 40] = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x08, 0x00,
			0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00,
			0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1,
			10, 0, 0, 2,
			0x00, 0x00, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x02, 0x50, 0x10, 0x10, 0x00,
			0x00, 0x00, 0x00, 0x00
		};
		uint16_t sport = (uint16_t)(20000 + i);
		raw[14 + 20] = (uint8_t)(sport >> 8);
		raw[14 + 21] = (uint8_t)(sport & 0xff);
		memcpy(DATA(&pkt), raw, sizeof(raw));
		pkt.len = sizeof(raw);

		connection_t *out[2] = {NULL, NULL};
		assert_int_equal(1, multipath_select_connections(n, &pkt, out));
		assert_true(out[0] == conns[1] || out[0] == conns[4] || out[0] == conns[5]);
	}

	assert_true(conns[0]->tcp_degraded);
	assert_false(conns[1]->tcp_degraded);
	assert_true(conns[2]->tcp_degraded);
	assert_true(conns[3]->tcp_degraded);
	assert_false(conns[4]->tcp_degraded);
	assert_false(conns[5]->tcp_degraded);

	/* Sticky zero-flap latch: even if fast siblings dip to 20 Mbps, conns[2] stays degraded */
	conns[1]->tcp_pacing_bps = 20000000ULL;
	conns[5]->tcp_pacing_bps = 20000000ULL;

	vpn_packet_t pkt_chk = {0};
	uint8_t raw_chk[14 + 40] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x08, 0x00,
		0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00,
		0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1,
		10, 0, 0, 2,
		0x4e, 0x22, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x02, 0x50, 0x10, 0x10, 0x00,
		0x00, 0x00, 0x00, 0x00
	};
	memcpy(DATA(&pkt_chk), raw_chk, sizeof(raw_chk));
	pkt_chk.len = sizeof(raw_chk);

	for(int i = 0; i < 64; i++) {
		uint16_t sport = (uint16_t)(30000 + i);
		DATA(&pkt_chk)[14 + 20] = (uint8_t)(sport >> 8);
		DATA(&pkt_chk)[14 + 21] = (uint8_t)(sport & 0xff);
		connection_t *out[2] = {NULL, NULL};
		assert_int_equal(1, multipath_select_connections(n, &pkt_chk, out));
		assert_true(out[0] == conns[1] || out[0] == conns[4] || out[0] == conns[5]);
	}

	assert_true(conns[2]->tcp_degraded);

	for(int i = 0; i < 6; i++) {
		multipath_node_del_connection(n, conns[i]);
	}

	n->connection = NULL;

	for(int i = 0; i < 6; i++) {
		free_connection(conns[i]);
	}

	free_node(n);
	multipath_mode = MULTIPATH_FAILOVER;
	multipath_target_connections = 1;
}

static void test_multipath_bbr_lt_bw_and_all_degraded_fallback(void **state) {
	(void)state;
	node_t *n = new_node("peer_ltbw");
	connection_t *conns[3];

	for(int i = 0; i < 3; i++) {
		conns[i] = new_connection();
		conns[i]->name = xstrdup("peer_ltbw");
		conns[i]->node = n;
		conns[i]->status.active = true;
		conns[i]->socket = -1;
		conns[i]->tcp_min_rtt_us = 42000;
		conns[i]->tcp_diag_at = now.tv_sec;
		multipath_node_add_connection(n, conns[i]);
	}

	/* conns[0]: BBRv1 lt_bw lockup (1% retrans >= 0.5%, cwnd=12 <= 24, pacing=0.8 Mbps < 2 Mbps) */
	conns[0]->tcp_segs_out = 2000;
	conns[0]->tcp_total_retrans = 20;
	conns[0]->tcp_cwnd = 12;
	conns[0]->tcp_pacing_bps = 800000ULL;

	/* conns[1]: proven fast sibling (>= 30 Mbps) */
	conns[1]->tcp_segs_out = 5000;
	conns[1]->tcp_total_retrans = 5;
	conns[1]->tcp_cwnd = 220;
	conns[1]->tcp_pacing_bps = 45000000ULL;

	/* conns[2]: zero-retrans app_limited sibling must remain healthy */
	conns[2]->tcp_segs_out = 2000;
	conns[2]->tcp_total_retrans = 0;
	conns[2]->tcp_cwnd = 18;
	conns[2]->tcp_pacing_bps = 8400000ULL;

	n->connection = conns[0];
	multipath_mode = MULTIPATH_FLOWHASH;
	multipath_target_connections = 3;

	for(int i = 0; i < 32; i++) {
		vpn_packet_t pkt = {0};
		uint8_t raw[14 + 40] = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x08, 0x00,
			0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00,
			0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1,
			10, 0, 0, 2,
			0x00, 0x00, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x02, 0x50, 0x10, 0x10, 0x00,
			0x00, 0x00, 0x00, 0x00
		};
		uint16_t sport = (uint16_t)(40000 + i);
		raw[14 + 20] = (uint8_t)(sport >> 8);
		raw[14 + 21] = (uint8_t)(sport & 0xff);
		memcpy(DATA(&pkt), raw, sizeof(raw));
		pkt.len = sizeof(raw);

		connection_t *out[2] = {NULL, NULL};
		assert_int_equal(1, multipath_select_connections(n, &pkt, out));
		assert_true(out[0] == conns[1] || out[0] == conns[2]);
	}

	assert_true(conns[0]->tcp_degraded);
	assert_false(conns[1]->tcp_degraded);
	assert_false(conns[2]->tcp_degraded);

	/* When ALL connections are degraded, selector must fall back cleanly to usable[] */
	conns[1]->tcp_degraded = true;
	conns[2]->tcp_degraded = true;

	vpn_packet_t pkt_all = {0};
	uint8_t raw_all[14 + 40] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x08, 0x00,
		0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00,
		0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1,
		10, 0, 0, 2,
		0x9c, 0x41, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x02, 0x50, 0x10, 0x10, 0x00,
		0x00, 0x00, 0x00, 0x00
	};
	memcpy(DATA(&pkt_all), raw_all, sizeof(raw_all));
	pkt_all.len = sizeof(raw_all);

	connection_t *out_all[2] = {NULL, NULL};
	assert_int_equal(1, multipath_select_connections(n, &pkt_all, out_all));
	assert_non_null(out_all[0]);

	for(int i = 0; i < 3; i++) {
		multipath_node_del_connection(n, conns[i]);
	}

	n->connection = NULL;

	for(int i = 0; i < 3; i++) {
		free_connection(conns[i]);
	}

	free_node(n);
	multipath_mode = MULTIPATH_FAILOVER;
	multipath_target_connections = 1;
}

static void test_multipath_dynamic_tcp_pacing_and_high_loss_ecmp(void **state) {
	(void)state;

	assert_int_equal(0U, multipath_calc_socket_pacing_rate(0, 4, 1));
	assert_int_equal(4500000U, multipath_calc_socket_pacing_rate(4500000U, 1, 1));
	assert_int_equal(3000000U, multipath_calc_socket_pacing_rate(4500000U, 4, 1));
	assert_int_equal(2250000U, multipath_calc_socket_pacing_rate(4500000U, 4, 2));
	assert_int_equal(1500000U, multipath_calc_socket_pacing_rate(4500000U, 4, 3));
	assert_int_equal(1125000U, multipath_calc_socket_pacing_rate(4500000U, 4, 4));

	time_t saved_sec = now.tv_sec;
	now.tv_sec = 1000;

	node_t *n = new_node("peer_paced");
	n->tcp_max_pacing_rate = 4500000U;
	connection_t *conns[4];

	for(int i = 0; i < 4; i++) {
		conns[i] = new_connection();
		conns[i]->name = xstrdup("peer_paced");
		conns[i]->node = n;
		conns[i]->status.active = true;
		conns[i]->socket = -1;
		conns[i]->tcp_min_rtt_us = 40000;
		conns[i]->tcp_diag_at = now.tv_sec;
		conns[i]->tcp_segs_out = 2000;
		conns[i]->tcp_total_retrans = 120; /* 6% baseline cross-border loss */
		conns[i]->tcp_cwnd = 60;
		conns[i]->tcp_pacing_bps = 9000000ULL;
		multipath_node_add_connection(n, conns[i]);
	}

	n->connection = conns[0];
	multipath_mode = MULTIPATH_FLOWHASH;
	multipath_target_connections = 4;

	vpn_packet_t pkts[64];
	int seen_slots[4] = {0, 0, 0, 0};
	vpn_packet_t *pkt_for_slot[4] = {NULL, NULL, NULL, NULL};

	for(int i = 0; i < 64; i++) {
		memset(&pkts[i], 0, sizeof(pkts[i]));
		uint8_t raw[14 + 40] = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x08, 0x00,
			0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00,
			0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1,
			10, 0, 0, 2,
			0x00, 0x00, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x02, 0x50, 0x10, 0x10, 0x00,
			0x00, 0x00, 0x00, 0x00
		};
		uint16_t sport = (uint16_t)(50000 + i);
		raw[14 + 20] = (uint8_t)(sport >> 8);
		raw[14 + 21] = (uint8_t)(sport & 0xff);
		memcpy(DATA(&pkts[i]), raw, sizeof(raw));
		pkts[i].len = sizeof(raw);

		uint32_t s = multipath_flow_hash(&pkts[i]) % 4U;

		if(!pkt_for_slot[s]) {
			pkt_for_slot[s] = &pkts[i];
		}

		seen_slots[s]++;
	}

	for(int s = 0; s < 4; s++) {
		assert_true(seen_slots[s] > 0);
		assert_non_null(pkt_for_slot[s]);
	}

	/* Light chatter (4 KB/s) + medium TV-like background streams (180 KB/s) with
	   no heavy bulk flows must leave all legs at single_cap (3.0 MB/s). */
	connection_t *out[2] = {NULL, NULL};

	for(int s = 0; s < 4; s++) {
		assert_int_equal(1, multipath_select_connections(n, pkt_for_slot[s], out));
		multipath_apply_node_tcp_pacing(n, out[0], 4000);
	}

	for(int s = 0; s < 4; s++) {
		assert_int_equal(3000000U, conns[s]->target_pacing_rate);
	}

	/* 1 heavy bulk flow (800 KB/s on slot 0) + TV-like background (180 KB/s on slots 1,2)
	   + chatter (4 KB/s on slot 3) -> heavy flow keeps single_cap (3.0 MB/s), light gets 1.5 MB/s */
	now.tv_sec += 2;
	assert_int_equal(1, multipath_select_connections(n, pkt_for_slot[1], out));
	assert_ptr_equal(conns[1], out[0]);
	multipath_apply_node_tcp_pacing(n, out[0], 180000);
	assert_int_equal(1, multipath_select_connections(n, pkt_for_slot[2], out));
	assert_ptr_equal(conns[2], out[0]);
	multipath_apply_node_tcp_pacing(n, out[0], 180000);
	assert_int_equal(1, multipath_select_connections(n, pkt_for_slot[3], out));
	assert_ptr_equal(conns[3], out[0]);
	multipath_apply_node_tcp_pacing(n, out[0], 4000);
	assert_int_equal(1, multipath_select_connections(n, pkt_for_slot[0], out));
	assert_ptr_equal(conns[0], out[0]);
	multipath_apply_node_tcp_pacing(n, out[0], 800000);
	assert_int_equal(3000000U, conns[0]->target_pacing_rate);
	assert_int_equal(1500000U, conns[1]->target_pacing_rate);
	assert_int_equal(1500000U, conns[2]->target_pacing_rate);
	assert_int_equal(1500000U, conns[3]->target_pacing_rate);

	/* 2 simultaneous heavy bulk flows (800 KB/s on slots 0,1) -> 4.5 MB/s / 2 = 2.25 MB/s (18 Mbps) */
	now.tv_sec += 2;
	assert_int_equal(1, multipath_select_connections(n, pkt_for_slot[0], out));
	multipath_apply_node_tcp_pacing(n, out[0], 800000);
	assert_int_equal(1, multipath_select_connections(n, pkt_for_slot[1], out));
	multipath_apply_node_tcp_pacing(n, out[0], 800000);
	assert_int_equal(2250000U, conns[0]->target_pacing_rate);
	assert_int_equal(2250000U, conns[1]->target_pacing_rate);

	/* Third + fourth simultaneous heavy bulk flows -> 1.125 MB/s (9 Mbps) */
	assert_int_equal(1, multipath_select_connections(n, pkt_for_slot[2], out));
	multipath_apply_node_tcp_pacing(n, out[0], 800000);
	assert_int_equal(1, multipath_select_connections(n, pkt_for_slot[3], out));
	multipath_apply_node_tcp_pacing(n, out[0], 800000);
	assert_int_equal(1125000U, conns[0]->target_pacing_rate);
	assert_int_equal(1125000U, conns[3]->target_pacing_rate);

	/* Advancing +1s holds 1.125 MB/s smoothly via prev_tx_bytes without boundary jitter */
	now.tv_sec += 1;
	multipath_apply_node_tcp_pacing(n, conns[0], 1400);
	assert_int_equal(1125000U, conns[0]->target_pacing_rate);

	/* Advancing +2s with TV/chatter on conns[1..3] and bulk on conns[0] decays back to 3.0 MB/s */
	now.tv_sec += 2;
	multipath_apply_node_tcp_pacing(n, conns[1], 180000);
	multipath_apply_node_tcp_pacing(n, conns[2], 4000);
	multipath_apply_node_tcp_pacing(n, conns[3], 4000);
	multipath_apply_node_tcp_pacing(n, conns[0], 800000);
	assert_int_equal(3000000U, conns[0]->target_pacing_rate);

	/* Condition D: high-loss (> 12%) ECMP tuple lagging healthy sibling under TcpMaxPacingRate */
	conns[3]->tcp_segs_out = 2000;
	conns[3]->tcp_total_retrans = 310; /* 15.5% > 12% */
	conns[3]->tcp_cwnd = 35;
	conns[3]->tcp_pacing_bps = 5200000ULL; /* 5.2 Mbps < 2/3 of 9.0 Mbps */

	for(int i = 0; i < 64; i++) {
		assert_int_equal(1, multipath_select_connections(n, &pkts[i], out));
		assert_ptr_not_equal(conns[3], out[0]);
	}

	assert_true(conns[3]->tcp_degraded);
	assert_false(conns[0]->tcp_degraded);
	assert_false(conns[1]->tcp_degraded);
	assert_false(conns[2]->tcp_degraded);

	/* Metro WAN (1.8 ms vs 25.3 ms hair-pin): adaptive 15 ms tolerance excludes skewed WAN leg */
	for(int i = 0; i < 4; i++) {
		conns[i]->tcp_degraded = false;
		conns[i]->tcp_segs_out = 2000;
		conns[i]->tcp_total_retrans = 10;
		conns[i]->tcp_cwnd = 120;
		conns[i]->tcp_pacing_bps = 40000000ULL;
		conns[i]->address.sa.sa_family = AF_INET;
		conns[i]->address.in.sin_addr.s_addr = htonl(0x5057c827U); /* 80.87.200.39 */
		conns[i]->tcp_min_rtt_us = (i == 3) ? 25300U : 1800U;
	}

	for(int i = 0; i < 64; i++) {
		assert_int_equal(1, multipath_select_connections(n, &pkts[i], out));
		assert_ptr_not_equal(conns[3], out[0]);
	}

	/* Loopback sockets (127.0.0.1, e.g. Angie local proxy) must NEVER be excluded or latched degraded */
	for(int i = 0; i < 4; i++) {
		conns[i]->tcp_degraded = false;
		conns[i]->address.sa.sa_family = AF_INET;
		conns[i]->address.in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		conns[i]->tcp_min_rtt_us = (i == 3) ? 25300U : 100U;
	}

	assert_int_equal(1, multipath_select_connections(n, pkt_for_slot[3], out));
	assert_ptr_equal(conns[3], out[0]);
	assert_false(conns[3]->tcp_degraded);

	/* Late-life BBRv1 lt_bw lockup under TcpMaxPacingRate (23.2 Mbps sibling, 0.085% retrans) */
	for(int i = 0; i < 4; i++) {
		conns[i]->tcp_degraded = false;
		conns[i]->address.sa.sa_family = AF_INET;
		conns[i]->address.in.sin_addr.s_addr = htonl(0x5057c827U);
		conns[i]->tcp_min_rtt_us = 40000U;
		conns[i]->tcp_segs_out = 2000;
		conns[i]->tcp_total_retrans = 5;
		conns[i]->tcp_cwnd = 120;
		conns[i]->tcp_pacing_bps = 23200000ULL;
	}

	conns[1]->tcp_total_retrans = 0;
	conns[1]->tcp_cwnd = 18;
	conns[1]->tcp_pacing_bps = 8400000ULL;

	conns[2]->tcp_segs_out = 75000;
	conns[2]->tcp_total_retrans = 64; /* 0.085%, >= 8 retrans */
	conns[2]->tcp_cwnd = 20;
	conns[2]->tcp_pacing_bps = 1790000ULL;

	for(int i = 0; i < 64; i++) {
		assert_int_equal(1, multipath_select_connections(n, &pkts[i], out));
		assert_ptr_not_equal(conns[2], out[0]);
	}

	assert_true(conns[2]->tcp_degraded);
	assert_false(conns[1]->tcp_degraded);

	for(int i = 0; i < 4; i++) {
		multipath_node_del_connection(n, conns[i]);
	}

	n->connection = NULL;

	for(int i = 0; i < 4; i++) {
		free_connection(conns[i]);
	}

	free_node(n);
	multipath_mode = MULTIPATH_FAILOVER;
	multipath_target_connections = 1;
	now.tv_sec = saved_sec;
}

static void test_multipath_health_score_and_latency_sensitivity(void **state) {
	(void)state;
	vpn_packet_t pkt = {0};

	/* IPv4 UDP packet -> latency sensitive */
	memset(DATA(&pkt), 0, 14 + 28);
	DATA(&pkt)[12] = 0x08;
	DATA(&pkt)[13] = 0x00;
	DATA(&pkt)[14] = 0x45;
	DATA(&pkt)[14 + 9] = 17; /* UDP */
	pkt.len = 14 + 28;
	assert_true(multipath_pkt_is_latency_sensitive(&pkt));

	/* Small interactive TCP (SYN / SSH, 64B <= 320B) -> latency sensitive */
	DATA(&pkt)[14 + 9] = 6; /* TCP */
	pkt.len = 64;
	assert_true(multipath_pkt_is_latency_sensitive(&pkt));

	/* Bulk TCP segment (1000B > 320B) -> bulk, not latency sensitive */
	pkt.len = 1000;
	assert_false(multipath_pkt_is_latency_sensitive(&pkt));

	/* Mixed https + quic pool: latency-sensitive UDP steers onto healthy quic leg */
	static transport_t mock_quic = {
		.id = TRANSPORT_QUIC,
		.name = "quic",
		.send_datagram = (bool (*)(struct connection_t *, const void *, size_t, size_t *))1,
	};
	static transport_t mock_https = {
		.id = TRANSPORT_HTTPS,
		.name = "https",
	};

	node_t *n = new_node("peer_het");
	connection_t *c_https = new_connection();
	c_https->name = xstrdup("peer_het");
	c_https->node = n;
	c_https->status.active = true;
	c_https->socket = -1;
	c_https->transport = &mock_https;
	c_https->address.sa.sa_family = AF_INET;
	c_https->address.in.sin_addr.s_addr = htonl(0x5057c827U);
	c_https->tcp_min_rtt_us = 35000U;
	c_https->tcp_pacing_bps = 25000000ULL;
	c_https->relay_slot = 0;

	connection_t *c_quic = new_connection();
	c_quic->name = xstrdup("peer_het");
	c_quic->node = n;
	c_quic->status.active = true;
	c_quic->socket = -1;
	c_quic->transport = &mock_quic;
	c_quic->address.sa.sa_family = AF_INET;
	c_quic->address.in.sin_addr.s_addr = htonl(0x5057c827U);
	c_quic->tcp_min_rtt_us = 35000U;
	c_quic->tcp_pacing_bps = 25000000ULL;
	c_quic->relay_slot = 1;

	n->connection = c_https;
	multipath_node_add_connection(n, c_https);
	multipath_node_add_connection(n, c_quic);
	multipath_mode = MULTIPATH_FLOWHASH;

	uint8_t s_https = multipath_conn_health_score(n, c_https, 35000U);
	uint8_t s_quic = multipath_conn_health_score(n, c_quic, 35000U);
	assert_int_equal(100, s_https);
	assert_int_equal(100, s_quic);

	DATA(&pkt)[14 + 9] = 17; /* UDP */
	pkt.len = 200;
	connection_t *out[2] = {NULL, NULL};

	for(int i = 0; i < 16; i++) {
		DATA(&pkt)[14 + 20] = (uint8_t)i; /* Vary port to test all 5-tuple hashes */
		assert_int_equal(1, multipath_select_connections(n, &pkt, out));
		assert_ptr_equal(c_quic, out[0]);
	}

	/* Degraded leg score drops significantly */
	c_https->tcp_degraded = true;
	assert_true(multipath_conn_health_score(n, c_https, 35000U) <= 50);

	multipath_node_del_connection(n, c_quic);

	/* Homogeneous stream pool: latency-sensitive traffic bypasses congested outbuf > 64 KB
	   while bulk TCP (> 320B) keeps its consistent flowhash slot. */
	c_https->tcp_degraded = false;
	c_https->outbuf.offset = 0;
	c_https->outbuf.len = 200000;

	connection_t *c_https2 = new_connection();
	c_https2->name = xstrdup("peer_het");
	c_https2->node = n;
	c_https2->status.active = true;
	c_https2->socket = -1;
	c_https2->transport = &mock_https;
	c_https2->address.sa.sa_family = AF_INET;
	c_https2->address.in.sin_addr.s_addr = htonl(0x5057c827U);
	c_https2->tcp_min_rtt_us = 35000U;
	c_https2->tcp_pacing_bps = 25000000ULL;
	c_https2->relay_slot = 1;
	multipath_node_add_connection(n, c_https2);

	vpn_packet_t bypass_pkt = {0};
	memset(DATA(&bypass_pkt), 0, 1000);
	DATA(&bypass_pkt)[12] = 0x08;
	DATA(&bypass_pkt)[13] = 0x00;
	DATA(&bypass_pkt)[14] = 0x45;
	DATA(&bypass_pkt)[14 + 9] = 6; /* TCP */
	int slot0_port = -1;

	for(int i = 0; i < 64; i++) {
		DATA(&bypass_pkt)[14 + 20] = (uint8_t)i;
		bypass_pkt.len = 1000; /* Bulk TCP -> uses slot assignment directly */
		assert_int_equal(1, multipath_select_connections(n, &bypass_pkt, out));

		if(out[0] == c_https) {
			slot0_port = i;
			break;
		}
	}

	assert_true(slot0_port >= 0);
	DATA(&bypass_pkt)[14 + 20] = (uint8_t)slot0_port;
	bypass_pkt.len = 64; /* Small interactive TCP on exact same 5-tuple bypasses congested c_https */
	assert_int_equal(1, multipath_select_connections(n, &bypass_pkt, out));
	assert_ptr_equal(c_https2, out[0]);

	bypass_pkt.len = 1000; /* Bulk TCP stays pinned on slot 0 (c_https) */
	assert_int_equal(1, multipath_select_connections(n, &bypass_pkt, out));
	assert_ptr_equal(c_https, out[0]);

	c_https->outbuf.len = 0;
	multipath_node_del_connection(n, c_https2);
	multipath_node_del_connection(n, c_https);
	n->connection = NULL;
	free_connection(c_https2);
	free_connection(c_quic);
	free_connection(c_https);
	free_node(n);
	multipath_mode = MULTIPATH_FAILOVER;
}

static void test_multipath_auto_pacing_aimd_and_canary(void **state) {
	(void)state;
	time_t saved_sec = now.tv_sec;
	now.tv_sec = 1000;

	bool saved_auto = multipath_tcp_auto_pacing;
	uint32_t saved_cap = multipath_tcp_max_pacing_rate;
	multipath_tcp_auto_pacing = true;
	multipath_tcp_max_pacing_rate = 0;
	multipath_mode = MULTIPATH_FLOWHASH;
	multipath_target_connections = 4;

	node_t *n = new_node("peer_aimd");
	connection_t *conns[4];

	for(int i = 0; i < 4; i++) {
		conns[i] = new_connection();
		conns[i]->name = xstrdup("peer_aimd");
		conns[i]->node = n;
		conns[i]->status.active = true;
		conns[i]->socket = -1;
		conns[i]->address.sa.sa_family = AF_INET;
		conns[i]->address.in.sin_addr.s_addr = htonl(0x5057c827U);
		conns[i]->tcp_min_rtt_us = 35000U;
		conns[i]->tcp_cwnd = 100;
		conns[i]->tcp_pacing_bps = 24000000ULL;
		multipath_node_add_connection(n, conns[i]);
	}

	n->connection = conns[0];

	/* 1) Light burst (< 1.25 MB/s) must never trigger self-throttling backoff */
	now.tv_sec = 900;
	multipath_apply_node_tcp_pacing(n, conns[1], 420000U);
	now.tv_sec = 901;
	multipath_apply_node_tcp_pacing(n, conns[1], 1500U);
	conns[1]->tcp_degraded = true;
	multipath_handle_conn_degraded(n, conns[1]);
	assert_int_equal(0U, n->auto_pacing_budget_Bps);
	conns[1]->tcp_degraded = false;
	conns[1]->peak_tx_Bps = 0;
	conns[1]->peak_tx_at = 0;

	/* 2) Explicit TcpMaxPacingRate disables auto-pacing unless TcpAutoPacing=yes override is set */
	n->tcp_max_pacing_rate = 4350000U;
	n->tcp_auto_pacing_override = 0;
	assert_false(multipath_node_auto_pacing_enabled(n));
	now.tv_sec = 910;
	multipath_apply_node_tcp_pacing(n, conns[2], 3000000U);
	now.tv_sec = 911;
	multipath_apply_node_tcp_pacing(n, conns[2], 1500U);
	conns[2]->tcp_degraded = true;
	multipath_handle_conn_degraded(n, conns[2]);
	assert_int_equal(0U, n->auto_pacing_budget_Bps);

	n->tcp_auto_pacing_override = 1;
	assert_true(multipath_node_auto_pacing_enabled(n));
	multipath_handle_conn_degraded(n, conns[2]);
	assert_int_equal(3825000U, n->auto_pacing_budget_Bps);

	/* Reset before standard AIMD + canary probe sequence */
	n->tcp_max_pacing_rate = 0;
	n->tcp_auto_pacing_override = 0;
	n->auto_pacing_budget_Bps = 0;
	n->auto_pacing_policer_Bps = 0;
	n->auto_pacing_last_backoff_at = 0;
	n->auto_pacing_next_probe_at = 0;
	conns[2]->tcp_degraded = false;
	conns[2]->peak_tx_Bps = 0;
	conns[2]->peak_tx_at = 0;

	/* Measure 3.0 MB/s (24 Mbps) peak TX on conns[0] */
	now.tv_sec = 1000;
	multipath_apply_node_tcp_pacing(n, conns[0], 3000000U);
	now.tv_sec = 1001;
	multipath_apply_node_tcp_pacing(n, conns[0], 1500U);
	assert_true(conns[0]->peak_tx_Bps >= 3000000U);

	/* Trigger policer collapse on conns[0]: backoff to 0.85 * R -> budget = 3,825,000 B/s */
	conns[0]->tcp_degraded = true;
	multipath_handle_conn_degraded(n, conns[0]);
	assert_int_equal(3000000U, n->auto_pacing_policer_Bps);
	assert_int_equal(3825000U, n->auto_pacing_budget_Bps);
	assert_int_equal(1901, (int)n->auto_pacing_next_probe_at);

	/* Advance 15m (900s): canary probe activates +10% on ONE secondary leg */
	now.tv_sec = 1901;
	conns[0]->tcp_degraded = false;
	multipath_step_auto_pacing(n);
	assert_non_null(n->auto_pacing_canary);
	connection_t *can = n->auto_pacing_canary;
	assert_ptr_not_equal(n->connection, can);
	assert_true(can->is_canary);
	assert_true(can->target_pacing_rate > conns[0]->target_pacing_rate);

	/* Feed load onto canary and finish clean 30s window -> +10% promotion to 4,207,500 B/s */
	now.tv_sec = 1910;
	multipath_apply_node_tcp_pacing(n, can, 400000U);
	now.tv_sec = 1932;
	multipath_step_auto_pacing(n);
	assert_null(n->auto_pacing_canary);
	assert_false(can->is_canary);
	assert_int_equal(4207500U, n->auto_pacing_budget_Bps);
	assert_int_equal(1932 + 900, (int)n->auto_pacing_next_probe_at);

	/* Next probe window triggers canary, which hits policer -> keeps budget intact, 20m cooldown */
	now.tv_sec = 2900;
	multipath_step_auto_pacing(n);
	assert_non_null(n->auto_pacing_canary);
	can = n->auto_pacing_canary;
	can->tcp_degraded = true;
	multipath_step_auto_pacing(n);
	assert_null(n->auto_pacing_canary);
	assert_false(can->is_canary);
	assert_int_equal(4207500U, n->auto_pacing_budget_Bps);
	assert_int_equal(2900 + 1200, (int)n->auto_pacing_next_probe_at);

	for(int i = 0; i < 4; i++) {
		multipath_node_del_connection(n, conns[i]);
	}

	n->connection = NULL;

	for(int i = 0; i < 4; i++) {
		free_connection(conns[i]);
	}

	free_node(n);
	multipath_tcp_auto_pacing = saved_auto;
	multipath_tcp_max_pacing_rate = saved_cap;
	multipath_mode = MULTIPATH_FAILOVER;
	multipath_target_connections = 1;
	now.tv_sec = saved_sec;
}

static void test_autoif_build_route_cmd_policy_tables(void **state) {
	(void)state;
	char cmd[512];

	assert_true(autoif_build_route_cmd("10.11.0.0/24", "tincstack", cmd, sizeof(cmd)));
	assert_string_equal("ip route replace 10.11.0.0/24 dev tincstack", cmd);

	assert_true(autoif_build_route_cmd("192.168.1.0/24 10.11.0.1", "tincstack", cmd, sizeof(cmd)));
	assert_string_equal("ip route replace 192.168.1.0/24 via 10.11.0.1 dev tincstack", cmd);

	assert_true(autoif_build_route_cmd("0.0.0.0/0 via 10.11.0.1 table 240 mtu 1280 metric 100", "tincstack", cmd, sizeof(cmd)));
	assert_string_equal("ip route replace 0.0.0.0/0 via 10.11.0.1 dev tincstack table 240 metric 100 mtu 1280", cmd);

	assert_true(autoif_build_route_cmd("default table main advmss 1200 scope link", "tun0", cmd, sizeof(cmd)));
	assert_string_equal("ip route replace default dev tun0 table main advmss 1200 scope link", cmd);

	assert_true(autoif_build_route_cmd("unreachable default table 200 metric 4096", "tincstack", cmd, sizeof(cmd)));
	assert_string_equal("ip route replace unreachable default table 200 metric 4096", cmd);

	assert_true(autoif_build_route_cmd("blackhole 10.99.0.0/16 metric 2000", "tincstack", cmd, sizeof(cmd)));
	assert_string_equal("ip route replace blackhole 10.99.0.0/16 metric 2000", cmd);

	assert_true(autoif_build_route_cmd("prohibit 8.8.8.8/32", "tincstack", cmd, sizeof(cmd)));
	assert_string_equal("ip route replace prohibit 8.8.8.8/32", cmd);

	/* Reject shell injection, bad options, out-of-range MTU, foreign dev */
	assert_false(autoif_build_route_cmd("0.0.0.0/0;reboot", "tincstack", cmd, sizeof(cmd)));
	assert_false(autoif_build_route_cmd("default via -bad", "tincstack", cmd, sizeof(cmd)));
	assert_false(autoif_build_route_cmd("default table 240 mtu 100", "tincstack", cmd, sizeof(cmd)));
	assert_false(autoif_build_route_cmd("default dev eth0", "tincstack", cmd, sizeof(cmd)));
	assert_false(autoif_build_route_cmd("default bogus_kw 1", "tincstack", cmd, sizeof(cmd)));
	assert_false(autoif_build_route_cmd("unreachable default via 10.11.0.1", "tincstack", cmd, sizeof(cmd)));
	assert_false(autoif_build_route_cmd("unreachable default dev tincstack", "tincstack", cmd, sizeof(cmd)));
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_multipath_mode_parse_and_name),
		cmocka_unit_test(test_multipath_flow_hash_deterministic),
		cmocka_unit_test(test_multipath_connection_pooling_and_failover),
		cmocka_unit_test(test_multipath_udp_paths_scheduling),
		cmocka_unit_test(test_multipath_promote_survivor_teardown_and_af_unknown),
		cmocka_unit_test(test_multipath_flowhash_slot_consistency_and_degraded_redirect),
		cmocka_unit_test(test_multipath_tspu_policed_leg_exclusion_and_sticky_latch),
		cmocka_unit_test(test_multipath_bbr_lt_bw_and_all_degraded_fallback),
		cmocka_unit_test(test_multipath_dynamic_tcp_pacing_and_high_loss_ecmp),
		cmocka_unit_test(test_multipath_health_score_and_latency_sensitivity),
		cmocka_unit_test(test_multipath_auto_pacing_aimd_and_canary),
		cmocka_unit_test(test_autoif_build_route_cmd_policy_tables),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
