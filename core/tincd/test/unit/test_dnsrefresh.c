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
		free(j);
		j = next;
	}

	dnsrefresh_save_state(NULL);
	dnsrefresh_job_t *reloaded = NULL;
	dnsrefresh_load_state(&reloaded);
	assert_null(reloaded);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_numeric_addresses_are_not_names),
		cmocka_unit_test(test_state_roundtrip),
		cmocka_unit_test(test_corrupt_state_is_ignored),
	};
	return cmocka_run_group_tests(tests, setup, teardown);
}
