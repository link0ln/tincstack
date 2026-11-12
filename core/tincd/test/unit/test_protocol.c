#include "unittest.h"
#include "../../src/connection.h"
#include "../../src/edge.h"
#include "../../src/event.h"
#include "../../src/logger.h"
#include "../../src/meta.h"
#include "../../src/net.h"
#include "../../src/node.h"
#include "../../src/protocol.h"
#include "../../src/subnet.h"
#include "../../src/xalloc.h"

static void test_get_invalid_request(void **state) {
	(void)state;

	assert_null(get_request_entry(ALL));
	assert_null(get_request_entry(LAST));
}

static void test_get_valid_request_returns_nonnull(void **state) {
	(void)state;

	for(request_t req = ID; req < LAST; ++req) {
		const request_entry_t *ent = get_request_entry(req);
		assert_non_null(ent);
		assert_non_null(ent->name);
	}
}

static void test_seen_request_cap_and_fifo_eviction(void **state) {
	(void)state;
	debug_level = DEBUG_NOTHING;
	gettimeofday(&now, NULL);

	/* H-DP-09: past_request_tree is capped at 65536 entries with FIFO eviction */
	char req[64];

	for(unsigned int i = 0; i < 65600U; i++) {
		snprintf(req, sizeof(req), "10 peer_%u 10.0.0.1/32", i);
		assert_false(seen_request(req));
	}

	/* The first 64 entries (0..63) must have been evicted, while 64..65599 remain seen */
	assert_true(seen_request("10 peer_65599 10.0.0.1/32"));
	assert_true(seen_request("10 peer_64 10.0.0.1/32"));
	assert_false(seen_request("10 peer_0 10.0.0.1/32"));

	exit_requests();
	timeout_del(&(timeout_t) {
		0
	});
	while(timeout_tree.head) {
		timeout_t *t = timeout_tree.head->data;
		timeout_del(t);
	}
}

typedef struct rearm_ctx_t {
	timeout_t timer;
	int calls;
} rearm_ctx_t;

static void rearm_zero_cb(void *data) {
	rearm_ctx_t *ctx = data;
	ctx->calls++;

	if(ctx->calls < 3) {
		/* H-DP-06: re-arming with {0, 0} inside callback must NOT be deleted
		   after cb() returns, and must defer to the next timeout_execute() tick */
		timeout_set(&ctx->timer, &(struct timeval) {
			0, 0
		});
	}
}

static void test_event_timeout_rearm_inside_callback(void **state) {
	(void)state;
	gettimeofday(&now, NULL);

	rearm_ctx_t ctx;
	memset(&ctx, 0, sizeof(ctx));

	timeout_add(&ctx.timer, rearm_zero_cb, &ctx, &(struct timeval) {
		0, 0
	});

	/* Tick 1: fires once, re-arms for next tick (not deleted, not infinite loop) */
	struct timeval wait1 = timeout_execute();
	assert_int_equal(1, ctx.calls);
	assert_true(timerisset(&ctx.timer.tv));
	assert_int_equal(0, wait1.tv_sec);
	assert_int_equal(0, wait1.tv_usec);

	/* Tick 2: fires second time, re-arms once more */
	timeout_execute();
	assert_int_equal(2, ctx.calls);
	assert_true(timerisset(&ctx.timer.tv));

	/* Tick 3: fires third time and leaves timer disarmed */
	timeout_execute();
	assert_int_equal(3, ctx.calls);
	assert_false(timerisset(&ctx.timer.tv));
}

static void test_edge_weight_clamping_and_subnetcheck(void **state) {
	(void)state;
	debug_level = DEBUG_NOTHING;
	gettimeofday(&now, NULL);
	init_connections();

	myself = new_node("self");
	myself->hostname = xstrdup("MYSELF");
	myself->connection = new_connection();
	myself->connection->socket = -1;
	node_add(myself);

	connection_t *peer_c = new_connection();
	peer_c->socket = -1;
	peer_c->name = xstrdup("peerA");
	peer_c->hostname = xstrdup("198.51.100.1 port 655");
	peer_c->status.active = true;
	node_t *peerA = new_node("peerA");
	peerA->hostname = xstrdup("198.51.100.1 port 655");
	peerA->connection = peer_c;
	peer_c->node = peerA;
	node_add(peerA);

	/* C-DP-02: extreme ADD_EDGE weight is clamped to [-100000000, 100000000] */
	assert_true(add_edge_h(peer_c, "12 peerA peerB 198.51.100.2 655 0 999999999"));
	node_t *peerB = lookup_node("peerB");
	assert_non_null(peerB);
	edge_t *e = lookup_edge(peerA, peerB);
	assert_non_null(e);
	assert_int_equal(100000000, e->weight);

	assert_true(add_edge_h(peer_c, "12 peerB peerA 198.51.100.1 655 0 -999999999"));
	edge_t *er = lookup_edge(peerB, peerA);
	assert_non_null(er);
	assert_int_equal(-100000000, er->weight);

	/* M-DP-08: ADD_SUBNET rejects non-canonical CIDR host bits (10.0.0.5/24) */
	assert_int_equal(0, peerA->subnet_tree.count);
	assert_false(add_subnet_h(peer_c, "10 peerA 10.0.0.5/24#10"));
	assert_int_equal(0, peerA->subnet_tree.count);

	/* Canonical CIDR with extreme weight is accepted and clamped to 100000000 */
	assert_true(add_subnet_h(peer_c, "10 peerA 10.0.0.0/24#999999999"));
	assert_int_equal(1, peerA->subnet_tree.count);
	subnet_t *sub = peerA->subnet_tree.head->data;
	assert_int_equal(100000000, sub->weight);

	/* H-DP-05 & H-DP-09: connection_can_buffer checks combined header+payload atomically */
	uint32_t saved_max = maxoutbufsize;
	maxoutbufsize = 1024;
	assert_true(connection_can_buffer(peer_c, 900));
	assert_false(connection_can_buffer(peer_c, 1200));

	connection_t *ctl_c = new_connection();
	ctl_c->socket = -1;
	ctl_c->status.control = true;
	assert_true(connection_can_buffer(ctl_c, 1024 * 1024));
	assert_false(connection_can_buffer(ctl_c, 17U * 1024U * 1024U));
	ctl_c->status.pcap = true;
	assert_false(connection_can_buffer(ctl_c, 5U * 1024U * 1024U));
	free_connection(ctl_c);
	maxoutbufsize = saved_max;

	peerA->connection = NULL;
	free_connection(peer_c);
	free_connection(myself->connection);
	myself->connection = NULL;
	exit_edges();
	exit_subnets();
	exit_connections();
	exit_nodes();
	exit_requests();
	while(timeout_tree.head) {
		timeout_t *t = timeout_tree.head->data;
		timeout_del(t);
	}
	myself = NULL;
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_get_invalid_request),
		cmocka_unit_test(test_get_valid_request_returns_nonnull),
		cmocka_unit_test(test_seen_request_cap_and_fifo_eviction),
		cmocka_unit_test(test_event_timeout_rearm_inside_callback),
		cmocka_unit_test(test_edge_weight_clamping_and_subnetcheck),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
