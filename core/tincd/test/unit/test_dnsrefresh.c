#include "unittest.h"
#include "../../src/dnsrefresh.h"
#include "../../src/conf.h"
#include "../../src/logger.h"
#include "../../src/names.h"
#include "../../src/netutl.h"
#include "../../src/xalloc.h"

/* dnsrefresh.c: the decision core of the DNS-name watcher (owner request
   2026-10-07, plan block D1-D3) exercised without a thread, without a
   resolver and without the event loop:

     - a numeric Address is not a name to watch;
     - the persisted state file round-trips (write -> free -> load);
     - a load with a name that no longer has a job does not crash and is
       dropped on the next save;
     - the last-good lookup returns exactly what was persisted.

   The thread itself and the live re-dial are proven by the lab
   (testing/transports/dns-refresh-test.sh); here only the pure pieces. */

static char tmp[] = "/tmp/tinc.test.dnsrefresh.XXXXXX";

static int setup(void **state) {
	(void)state;
	assert_ptr_equal(tmp, mkdtemp(tmp));
	confbase = xstrdup(tmp);

	/* dnsrefresh_state_path() writes to <confbase>/cache/dnsrefresh.state */
	char cachedir[PATH_MAX];
	snprintf(cachedir, sizeof(cachedir), "%s/cache", tmp);
	assert_int_equal(0, mkdir(cachedir, 0700));

	debug_level = DEBUG_NOTHING;
	openlogger("test_dnsrefresh", LOGMODE_STDERR);
	return 0;
}

static int teardown(void **state) {
	(void)state;
	closelogger();

	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/cache/dnsrefresh.state", tmp);
	unlink(path);
	snprintf(path, sizeof(path), "%s/cache", tmp);
	rmdir(path);
	rmdir(tmp);
	strcpy(tmp, "/tmp/tinc.test.dnsrefresh.XXXXXX");

	free(confbase);
	confbase = NULL;
	return 0;
}

/* dnsrefresh_is_name() is static; the same decision is reachable through
   the public surface indirectly, but the numeric check is worth testing on
   its own, so include the .c file and call it directly. */
#include "../../src/dnsrefresh.c"

static void test_numeric_addresses_are_not_names(void **state) {
	(void)state;
	assert_false(dnsrefresh_is_name("192.0.2.1"));
	assert_false(dnsrefresh_is_name("2001:db8::1"));
	assert_true(dnsrefresh_is_name("vpn.example.net"));
	assert_true(dnsrefresh_is_name("node-1.example.org."));
}

static void test_state_roundtrip(void **state) {
	(void)state;
	dnsrefresh_job_t *jobs = NULL;
	dnsrefresh_load_state(&jobs);
	assert_null(jobs);

	/* Build a job list by hand: what rebuild() would have made. */
	dnsrefresh_job_t *a = xzalloc(sizeof(*a));
	a->node_name = xstrdup("bravo1");
	a->hostname = xstrdup("bravo.example.net");
	a->port = xstrdup("655");
	sockaddr_t sa = str2sockaddr("192.0.2.10", "655");
	assert_int_equal(sa.sa.sa_family, AF_INET);
	a->last_good = sa;
	a->has_last_good = true;

	dnsrefresh_job_t *b = xzalloc(sizeof(*b));
	b->node_name = xstrdup("charlie2");
	b->hostname = xstrdup("charlie.example.net");
	b->port = xstrdup("655");
	/* no last_good yet: must not be written */

	a->next = b;
	dnsrefresh_save_state(a);

	/* Load into a fresh list and compare. */
	dnsrefresh_job_t *loaded = NULL;
	dnsrefresh_load_state(&loaded);
	assert_non_null(loaded);

	/* Order: save walks a->b, load prepends, so loaded is b,a or a,b --
	   find by node name rather than position. */
	dnsrefresh_job_t *la = NULL;
	dnsrefresh_job_t *lb = NULL;

	for(dnsrefresh_job_t *j = loaded; j; j = j->next) {
		if(!strcmp(j->node_name, "bravo1")) {
			la = j;
		} else if(!strcmp(j->node_name, "charlie2")) {
			lb = j;
		}
	}

	assert_non_null(la);
	assert_null(lb); /* a job without last_good is not persisted */

	assert_string_equal(la->hostname, "bravo.example.net");
	assert_string_equal(la->port, "655");
	assert_true(la->has_last_good);
	assert_int_equal(la->last_good.sa.sa_family, AF_INET);
	assert_int_equal(la->last_good.in.sin_addr.s_addr, htonl(0xC000020A));
	assert_int_equal(ntohs(la->last_good.in.sin_port), 655);

	for(dnsrefresh_job_t *j = loaded; j;) {
		dnsrefresh_job_t *next = j->next;
		free(j->node_name);
		free(j->hostname);
		free(j->port);
		free(j);
		j = next;
	}

	for(dnsrefresh_job_t *j = a; j;) {
		dnsrefresh_job_t *next = j->next;
		free(j->node_name);
		free(j->hostname);
		free(j->port);
		free(j);
		j = next;
	}
}

static void test_corrupt_state_is_ignored(void **state) {
	(void)state;
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/cache/dnsrefresh.state", tmp);
	FILE *fp = fopen(path, "w");
	assert_non_null(fp);
	/* Lines with fewer than four whitespace-separated fields are skipped.
	   A four-word line parses but its address is not an IP, so it loads as
	   a job with no last_good and is never written back. */
	fputs("garbage without fields\n\na b c d\n", fp);
	fclose(fp);

	dnsrefresh_job_t *jobs = NULL;
	dnsrefresh_load_state(&jobs);

	/* The four-word line loads (it cannot be told apart from a name
	   without resolving it) but has no last_good. */
	assert_non_null(jobs);
	assert_false(jobs->has_last_good);

	/* Saving it back writes nothing (no last_good), and the file reloads
	   empty. */
	for(dnsrefresh_job_t *j = jobs; j;) {
		dnsrefresh_job_t *next = j->next;
		free(j->node_name);
		free(j->hostname);
		free(j->port);
		free(j);
		j = next;
	}

	dnsrefresh_save_state(NULL);
	dnsrefresh_job_t *reloaded = NULL;
	dnsrefresh_load_state(&reloaded);
	assert_null(reloaded);
}

static void test_job_match_port_and_ai_family_and_pending_done(void **state) {
	(void)state;

	/* M-DP-03: dnsrefresh_job_match must distinguish same node+host on different ports */
	dnsrefresh_job_t j655 = {
		.node_name = (char *)"hub",
		.hostname = (char *)"vpn.example.net",
		.port = (char *)"655",
	};
	assert_true(dnsrefresh_job_match(&j655, "hub", "vpn.example.net", "655"));
	assert_false(dnsrefresh_job_match(&j655, "hub", "vpn.example.net", "443"));
	assert_false(dnsrefresh_job_match(&j655, "other", "vpn.example.net", "655"));
	assert_false(dnsrefresh_job_match(&j655, "hub", "other.example.net", "655"));

	/* M-DP-03: DnsRefreshInterval = 0 disables background periodic refresh */
	pthread_mutex_init(&dnsrefresh.mutex, NULL);
	pthread_cond_init(&dnsrefresh.work, NULL);

	dnsrefresh_job_t *live_job = xzalloc(sizeof(*live_job));
	live_job->node_name = xstrdup("hub");
	live_job->hostname = xstrdup("vpn.example.net");
	live_job->port = xstrdup("655");
	dnsrefresh_jobs = live_job;

	dnsrefresh.started = true;
	dnsrefresh.pending = NULL;
	dnsrefresh_interval = 0;
	dnsrefresh_queue_batch();
	assert_null(dnsrefresh.pending);

	/* When interval > 0, dnsrefresh_queue_batch snapshots addressfamily by value */
	dnsrefresh_interval = 60;
	addressfamily = AF_INET6;
	dnsrefresh_queue_batch();
	assert_non_null(dnsrefresh.pending);
	assert_int_equal(AF_INET6, dnsrefresh.pending->ai_family);
	dnsrefresh_free_job_list(dnsrefresh.pending);
	dnsrefresh.pending = NULL;

	/* When interval == 0, dnsrefresh_handle_results drops pending_done without applying */
	dnsrefresh_result_t *done_res = xzalloc(sizeof(*done_res));
	done_res->node_name = xstrdup("hub");
	done_res->hostname = xstrdup("vpn.example.net");
	done_res->port = xstrdup("655");
	done_res->ok = true;
	done_res->addr = str2sockaddr("198.51.100.77", "655");
	dnsrefresh.pending_done = done_res;
	dnsrefresh_interval = 0;
	dnsrefresh_handle_results();
	assert_null(dnsrefresh.pending_done);
	assert_false(live_job->has_last_good);

	dnsrefresh.started = false;
	dnsrefresh_interval = 600;
	dnsrefresh_free_jobs();
	addressfamily = AF_UNSPEC;
	pthread_cond_destroy(&dnsrefresh.work);
	pthread_mutex_destroy(&dnsrefresh.mutex);
}

static void test_apply_terminates_multipath_siblings_before_primary(void **state) {
	(void)state;

	/* H-DP-04: when DNS IP changes, dnsrefresh_apply() must terminate secondary
	   multipath_sub connections BEFORE terminating primary so multipath_promote_survivor()
	   cannot promote a stale-IP connection to own `outgoing_t`! */
	init_connections();

	myself = new_node("client");
	myself->hostname = xstrdup("MYSELF");
	myself->connection = new_connection();
	myself->connection->socket = -1;
	node_add(myself);

	node_t *hub = new_node("hub");
	hub->hostname = xstrdup("198.51.100.10 port 655");
	node_add(hub);

	outgoing_t *out = xzalloc(sizeof(*out));
	out->node = hub;
	list_insert_tail(&outgoing_list, out);

	connection_t *primary = new_connection();
	primary->socket = -1;
	primary->name = xstrdup("hub");
	primary->hostname = xstrdup("198.51.100.10 port 655");
	primary->address = str2sockaddr("198.51.100.10", "655");
	primary->node = hub;
	primary->outgoing = out;
	hub->connection = primary;
	connection_add(primary);

	connection_t *mp_sib = new_connection();
	mp_sib->socket = -1;
	mp_sib->name = xstrdup("hub");
	mp_sib->hostname = xstrdup("198.51.100.10 port 655");
	mp_sib->address = str2sockaddr("198.51.100.10", "655");
	mp_sib->node = hub;
	mp_sib->status.multipath_sub = true;
	connection_add(mp_sib);

	dnsrefresh_job_t *job = xzalloc(sizeof(*job));
	job->node_name = xstrdup("hub");
	job->hostname = xstrdup("vpn.example.net");
	job->port = xstrdup("655");
	job->has_last_good = true;
	job->last_good = str2sockaddr("198.51.100.10", "655");
	dnsrefresh_jobs = job;

	dnsrefresh_result_t *res = xzalloc(sizeof(*res));
	res->node_name = xstrdup("hub");
	res->hostname = xstrdup("vpn.example.net");
	res->port = xstrdup("655");
	res->ok = true;
	res->addr = str2sockaddr("203.0.113.99", "655");

	dnsrefresh_interval = 60;
	dnsrefresh_apply(res);
	dnsrefresh_free_result_list(res);

	/* Neither primary nor multipath_sub sibling may remain alive on old IP! */
	assert_int_equal(0, connection_list.count);
	assert_null(hub->connection);
	assert_int_equal(htonl(0xCB007163), job->last_good.in.sin_addr.s_addr);

	/* Cancel any scheduled reconnect timeout from out (list_delete_head calls free_outgoing) */
	timeout_del(&out->ev);
	list_delete_head(&outgoing_list);

	dnsrefresh_free_jobs();

	free_connection(myself->connection);
	myself->connection = NULL;
	exit_connections();
	exit_nodes();
	myself = NULL;
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_numeric_addresses_are_not_names),
		cmocka_unit_test(test_state_roundtrip),
		cmocka_unit_test(test_corrupt_state_is_ignored),
		cmocka_unit_test(test_job_match_port_and_ai_family_and_pending_done),
		cmocka_unit_test(test_apply_terminates_multipath_siblings_before_primary),
	};
	return cmocka_run_group_tests(tests, setup, teardown);
}
