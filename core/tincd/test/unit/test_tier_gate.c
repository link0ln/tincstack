#include "unittest.h"

#include <stdarg.h>
#include <stdio.h>

#include "../../src/autoconnect.h"
#include "../../src/conf.h"
#include "../../src/connection.h"
#include "../../src/edge.h"
#include "../../src/event.h"
#include "../../src/net.h"
#include "../../src/node.h"
#include "../../src/tier_gate.h"
#include "../../src/xalloc.h"

static char last_req_buf[512];
static unsigned int send_req_calls = 0;
static unsigned int send_ping_calls = 0;
static unsigned int term_conn_calls = 0;
static unsigned int term_conn_reported = 0;

bool __wrap_send_request(connection_t *c, const char *format, ...);
bool __wrap_send_ping(connection_t *c);
void __wrap_terminate_connection(connection_t *c, bool report);

bool __wrap_send_request(connection_t *c, const char *format, ...) {
	(void)c;
	send_req_calls++;
	va_list ap;
	va_start(ap, format);
	vsnprintf(last_req_buf, sizeof(last_req_buf), format, ap);
	va_end(ap);
	return true;
}

bool __wrap_send_ping(connection_t *c) {
	(void)c;
	send_ping_calls++;
	return true;
}

void __wrap_terminate_connection(connection_t *c, bool report) {
	term_conn_calls++;

	if(report) {
		term_conn_reported++;
	}

	if(c && c->node && c->node->connection == c) {
		c->node->connection = NULL;
	}

	if(c) {
		c->edge = NULL;
		c->status.active = false;
	}
}

static void reset_counters(void) {
	last_req_buf[0] = '\0';
	send_req_calls = 0;
	send_ping_calls = 0;
	term_conn_calls = 0;
	term_conn_reported = 0;
}

static void set_config_opt(const char *key, const char *val) {
	config_t *cfg = new_config();
	cfg->variable = xstrdup(key);
	cfg->value = xstrdup(val);
	config_add(&config_tree, cfg);
}

static void init_test_env(const char *self_name) {
	now.tv_sec = 1000;
	now.tv_usec = 0;
	init_configuration(&config_tree);
	init_connections();
	myself = new_node(self_name);
	node_add(myself);
	tier_gate_exit();
	fallback_exit();
	reset_counters();
}

static void exit_test_env(void) {
	fallback_exit();
	tier_gate_exit();
	exit_edges();
	exit_connections();
	exit_nodes();
	splay_empty_tree(&config_tree);
	myself = NULL;
}

static void test_required_hold_backoff(void **state) {
	(void)state;

	assert_int_equal(0, tier_gate_required_hold_sec(0, 45));
	assert_int_equal(45, tier_gate_required_hold_sec(1, 45));
	assert_int_equal(90, tier_gate_required_hold_sec(2, 45));
	assert_int_equal(180, tier_gate_required_hold_sec(3, 45));
	assert_int_equal(300, tier_gate_required_hold_sec(4, 45));
	assert_int_equal(300, tier_gate_required_hold_sec(10, 45));

	/* Clamping of base_sec [5..600] */
	assert_int_equal(5, tier_gate_required_hold_sec(1, 1));
	assert_int_equal(300, tier_gate_required_hold_sec(1, 900));
}

static void test_drop_penalty_and_decay(void **state) {
	(void)state;

	assert_int_equal(1200, tier_gate_drop_penalty_delta(1));
	assert_int_equal(1600, tier_gate_drop_penalty_delta(2));
	assert_int_equal(2000, tier_gate_drop_penalty_delta(3));
	assert_int_equal(2400, tier_gate_drop_penalty_delta(4));
	assert_int_equal(2800, tier_gate_drop_penalty_delta(5));
	assert_int_equal(2800, tier_gate_drop_penalty_delta(8));

	/* Online decays at 15/sec; offline at 4/sec; clamped >= 0 */
	assert_int_equal(1050, tier_gate_decay_penalty(1200, 10, true));
	assert_int_equal(1160, tier_gate_decay_penalty(1200, 10, false));
	assert_int_equal(0, tier_gate_decay_penalty(100, 20, true));
	assert_int_equal(500, tier_gate_decay_penalty(500, 0, true));
}

static void test_rtt_anomaly_detection(void **state) {
	(void)state;

	assert_false(tier_gate_is_rtt_anomaly(-1, 50));
	assert_false(tier_gate_is_rtt_anomaly(30, 80));
	assert_false(tier_gate_is_rtt_anomaly(30, 300));
	assert_true(tier_gate_is_rtt_anomaly(30, 301));
	assert_true(tier_gate_is_rtt_anomaly(100, 401));
	assert_false(tier_gate_is_rtt_anomaly(100, 400));
	assert_true(tier_gate_is_rtt_anomaly(-1, 1501));
	assert_false(tier_gate_is_rtt_anomaly(-1, -1));
}

static void test_quarantine_clear_threshold(void **state) {
	(void)state;

	assert_false(tier_gate_can_clear_quarantine(501, 45, 1, 45));
	assert_false(tier_gate_can_clear_quarantine(500, 44, 1, 45));
	assert_true(tier_gate_can_clear_quarantine(500, 45, 1, 45));
	assert_false(tier_gate_can_clear_quarantine(200, 89, 2, 45));
	assert_true(tier_gate_can_clear_quarantine(200, 90, 2, 45));
}

static void test_fallback_rank_and_cooldown(void **state) {
	(void)state;
	init_test_env("client");

	set_config_opt("FallbackConnectTo", "euvds hub_backup");
	tier_gate_reload();

	assert_true(tier_gate_has_fallback_connect_to());
	assert_int_equal(1, tier_gate_fallback_rank("euvds"));
	assert_int_equal(2, tier_gate_fallback_rank("hub_backup"));
	assert_int_equal(0, tier_gate_fallback_rank("ruvds3"));
	assert_string_equal("euvds", tier_gate_fallback_name_at(0));
	assert_string_equal("hub_backup", tier_gate_fallback_name_at(1));
	assert_null(tier_gate_fallback_name_at(2));

	node_t *peer = new_node("peer_x");
	peer->peer_tier = 1;
	node_add(peer);

	tier_gate_note_peer_rejected(peer);
	assert_true(tier_gate_peer_in_cooldown(peer));
	assert_int_equal(1001, (int)tier_gate_peer_retry_after(peer));

	now.tv_sec = 1001;
	assert_false(tier_gate_peer_in_cooldown(peer));

	tier_gate_note_peer_rejected(peer);
	assert_int_equal(1003, (int)tier_gate_peer_retry_after(peer));
	tier_gate_clear_all_cooldowns();
	assert_false(tier_gate_peer_in_cooldown(peer));

	exit_test_env();
}

static void test_admission_and_probation_state_machine(void **state) {
	(void)state;
	init_test_env("euvds");

	set_config_opt("TierGate", "yes");
	set_config_opt("TierHoldBase", "20");

	node_t *ruvds = new_node("ruvds3");
	ruvds->peer_tier = 2;
	node_add(ruvds);

	node_t *client = new_node("router");
	client->peer_tier = 1;
	node_add(client);

	connection_t *rc = new_connection();
	rc->name = xstrdup("ruvds3");
	rc->node = ruvds;
	rc->edge = new_edge();
	rc->status.active = true;
	rc->activated_at = now.tv_sec;
	ruvds->connection = rc;
	connection_add(rc);

	tier_gate_reload();
	assert_true(tier_gate_is_enabled());
	assert_int_equal(2, tier_gate_active_tier());
	assert_int_equal(2, tier_gate_max_tier());
	assert_string_equal("normal", tier_gate_state_name());

	/* Tier-1 peer must be refused with TERMREQ tier_gate while Tier-2 is healthy */
	connection_t *cc = new_connection();
	cc->name = xstrdup("router");
	cc->node = client;
	cc->status.active = true;
	reset_counters();
	assert_false(tier_gate_check_admission(cc, client, false));
	assert_int_equal(1, (int)tier_gate_rejects_count());
	assert_non_null(strstr(last_req_buf, "tier_gate"));
	free_connection(cc);

	/* Drop Tier-2 peer -> immediate fallback to active_tier=1 */
	ruvds->connection = NULL;
	free_edge(rc->edge);
	rc->edge = NULL;
	rc->status.active = false;
	tier_gate_on_peer_disconnected(ruvds);

	assert_true(ruvds->tier_quarantined);
	assert_int_equal(1, ruvds->tier_flap_count);
	assert_int_equal(1200, ruvds->tier_penalty);
	assert_int_equal(1, tier_gate_active_tier());
	assert_string_equal("fallback", tier_gate_state_name());

	/* Tier-1 peer is now admitted */
	connection_t *cc2 = new_connection();
	cc2->name = xstrdup("router");
	cc2->node = client;
	edge_t *ce = new_edge();
	cc2->edge = ce;
	cc2->status.active = true;
	client->connection = cc2;
	connection_add(cc2);
	assert_true(tier_gate_check_admission(cc2, client, false));
	tier_gate_on_connection_activated(cc2, client);

	/* Reconnect Tier-2 -> enters probation, active_tier remains 1 */
	now.tv_sec += 5;
	edge_t *re = new_edge();
	rc->edge = re;
	rc->status.active = true;
	ruvds->connection = rc;
	tier_gate_on_connection_activated(rc, ruvds);

	assert_true(ruvds->tier_quarantined);
	assert_int_equal(1, tier_gate_active_tier());
	assert_string_equal("probation", tier_gate_state_name());

	/* Step probation ticks with valid PONG RTTs until penalty<=500 and stable>=20s */
	for(int i = 0; i < 60 && ruvds->tier_quarantined; i++) {
		now.tv_sec += 1;

		if(ruvds->tier_probe_inflight) {
			ruvds->tier_last_rtt_ms = 25;
			tier_gate_on_pong(rc);
		}

		tier_gate_step_second();
	}

	assert_false(ruvds->tier_quarantined);
	assert_int_equal(2, tier_gate_active_tier());
	assert_string_equal("normal", tier_gate_state_name());
	/* Redirect was started with grace period because no higher-tier edge graph exists in unit mock */
	assert_true(client->tier_redirect_grace_until > 0);
	assert_int_equal(0, (int)tier_gate_redirects_count());

	/* Advancing past 10s grace triggers make-before-break timeout redirect */
	for(int i = 0; i < 10; i++) {
		now.tv_sec += 1;
		tier_gate_step_second();
	}

	assert_int_equal(1, (int)tier_gate_redirects_count());
	assert_int_equal(0, (int)client->tier_redirect_grace_until);
	assert_null(client->connection);

	cc2->edge = NULL;
	free_edge(ce);
	rc->edge = NULL;
	free_edge(re);
	exit_test_env();
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_required_hold_backoff),
		cmocka_unit_test(test_drop_penalty_and_decay),
		cmocka_unit_test(test_rtt_anomaly_detection),
		cmocka_unit_test(test_quarantine_clear_threshold),
		cmocka_unit_test(test_fallback_rank_and_cooldown),
		cmocka_unit_test(test_admission_and_probation_state_machine),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
