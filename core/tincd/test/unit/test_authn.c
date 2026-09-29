#include "unittest.h"
#include "../../src/authn.h"
#include "../../src/conf.h"
#include "../../src/connection.h"
#include "../../src/ecdsa.h"
#include "../../src/ecdsagen.h"
#include "../../src/event.h"
#include "../../src/logger.h"
#include "../../src/names.h"
#include "../../src/node.h"
#include "../../src/random.h"
#include "../../src/xalloc.h"
#include "../../src/yamlconf.h"

/* The carrier authenticator (authn.c): what it accepts, and that a rejection
   costs the same whether or not the claimed node exists (review M5-9, a
   timing oracle for node-name enumeration; masking-hardening plan T3).
   Everything runs twice: with host records as files and with a tinc.yaml. */

#define ME "alpha1"
#define PEER "bravo1"
#define STRANGER "zulu99" /* same length as PEER: the name length is public */

typedef enum {
	STORE_FILES,
	STORE_YAML,
} store_t;

static char tmp[] = "/tmp/tinc.test.authn.XXXXXX";
static char hostsdir[PATH_MAX];
static char logpath[PATH_MAX];
static ecdsa_t *me_key;
static ecdsa_t *peer_key;
static const uint8_t server_fp[AUTHN_FP_LEN] = {1, 2, 3};
static const uint8_t exporter[AUTHN_EXPORTER_LEN] = {4, 5, 6};
static const uint8_t other_exporter[AUTHN_EXPORTER_LEN] = {7, 8, 9};

/* Both records have the same shape, so parsing ours (the unknown-name path)
   costs what parsing the peer's does. */
static char *host_text(ecdsa_t *key, int octet) {
	char *b64 = ecdsa_get_base64_public_key(key);
	char *text;
	xasprintf(&text, "Address = 192.0.2.%d\nPort = 655\nSubnet = 10.0.0.%d/32\nEd25519PublicKey = %s\n", octet, octet, b64);
	free(b64);
	return text;
}

static void write_file(const char *name, const char *text) {
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/%s", hostsdir, name);
	FILE *f = fopen(path, "w");
	assert_non_null(f);
	assert_true(fputs(text, f) >= 0);
	assert_int_equal(0, fclose(f));
}

static int setup(store_t store) {
	assert_ptr_equal(tmp, mkdtemp(tmp));
	confbase = xstrdup(tmp);
	snprintf(hostsdir, sizeof(hostsdir), "%s/hosts", tmp);
	assert_int_equal(0, mkdir(hostsdir, 0700));

	me_key = ecdsa_generate();
	peer_key = ecdsa_generate();
	assert_non_null(me_key);
	assert_non_null(peer_key);

	char *me_text = host_text(me_key, 1);
	char *peer_text = host_text(peer_key, 2);

	if(store == STORE_FILES) {
		write_file(ME, me_text);
		write_file(PEER, peer_text);
	} else {
		netname = xstrdup("t3");
		yamlconf_global = yamlconf_new();
		yamlconf_host_set_text(yamlconf_global, netname, ME, me_text);
		yamlconf_host_set_text(yamlconf_global, netname, PEER, peer_text);
	}

	free(me_text);
	free(peer_text);

	myself = new_node(ME);
	myself->connection = new_connection();
	myself->connection->ecdsa = me_key;

	/* What the daemon logs at its default level goes here. */
	snprintf(logpath, sizeof(logpath), "%s/tinc.log", tmp);
	logfilename = xstrdup(logpath);
	debug_level = DEBUG_NOTHING;
	openlogger("test_authn", LOGMODE_FILE);

	gettimeofday(&now, NULL);
	return 0;
}

static int setup_files(void **state) {
	(void)state;
	return setup(STORE_FILES);
}

static int setup_yaml(void **state) {
	(void)state;
	return setup(STORE_YAML);
}

static int teardown(void **state) {
	(void)state;
	closelogger();

	char path[PATH_MAX];
	const char *names[] = {ME, PEER};

	for(size_t i = 0; i < sizeof(names) / sizeof(*names); i++) {
		snprintf(path, sizeof(path), "%s/%s", hostsdir, names[i]);
		unlink(path);
	}

	unlink(logpath);
	rmdir(hostsdir);
	rmdir(tmp);
	strcpy(tmp, "/tmp/tinc.test.authn.XXXXXX");

	if(yamlconf_global) {
		yamlconf_free(yamlconf_global);
		yamlconf_global = NULL;
	}

	free(netname);
	netname = NULL;
	free(logfilename);
	logfilename = NULL;
	free(confbase);
	confbase = NULL;

	myself->connection->ecdsa = NULL;
	free(myself->connection);
	myself->connection = NULL;
	free_node(myself);
	myself = NULL;
	ecdsa_free(me_key);
	ecdsa_free(peer_key);
	return 0;
}

/* An authenticator `name' signs with `key' at time `ts' for `exp'. */
static size_t build_as(const char *name, ecdsa_t *key, time_t ts, const uint8_t *exp, uint8_t *out) {
	char *saved_name = myself->name;
	ecdsa_t *saved_key = myself->connection->ecdsa;
	time_t saved_now = now.tv_sec;

	myself->name = (char *) name;
	myself->connection->ecdsa = key;
	now.tv_sec = ts;
	size_t len = authn_build(server_fp, exp, out, AUTHN_MAX_LEN);
	now.tv_sec = saved_now;
	myself->connection->ecdsa = saved_key;
	myself->name = saved_name;

	assert_int_not_equal(0, len);
	return len;
}

static bool verify(const uint8_t *payload, size_t len, const uint8_t *exp) {
	char *name = NULL;
	bool ok = authn_verify(payload, len, server_fp, exp, "test", "prober", &name);
	free(name);
	return ok;
}

static size_t log_lines(void) {
	FILE *f = fopen(logpath, "r");

	if(!f) {
		return 0;
	}

	size_t n = 0;

	for(int c; (c = fgetc(f)) != EOF;) {
		n += c == '\n';
	}

	fclose(f);
	return n;
}

static void test_accepts_a_fresh_authenticator_once(void **state) {
	(void)state;
	uint8_t p[AUTHN_MAX_LEN];
	size_t len = build_as(PEER, peer_key, now.tv_sec, exporter, p);

	char *name = NULL;
	assert_true(authn_verify(p, len, server_fp, exporter, "test", "prober", &name));
	assert_string_equal(PEER, name);
	free(name);

	assert_false(verify(p, len, exporter)); /* the same nonce again */
}

static void test_rejects(void **state) {
	(void)state;
	uint8_t p[AUTHN_MAX_LEN];
	size_t len = build_as(PEER, peer_key, now.tv_sec, exporter, p);

	assert_false(verify(p, len, other_exporter));   /* another session */
	assert_false(verify(p, len - 1, exporter));     /* truncated */

	uint8_t q[AUTHN_MAX_LEN];
	memcpy(q, p, len);
	memcpy(q + AUTHN_HDR_LEN, STRANGER, strlen(STRANGER));
	assert_false(verify(q, len, exporter));         /* unknown node */

	memcpy(q, p, len);
	q[0] = AUTHN_VERSION - 1;
	assert_false(verify(q, len, exporter));         /* old version */

	len = build_as(PEER, peer_key, now.tv_sec - 10 * AUTHN_TS_SKEW, exporter, p);
	assert_false(verify(p, len, exporter));         /* stale */

	len = build_as(ME, me_key, now.tv_sec, exporter, p);
	assert_false(verify(p, len, exporter));         /* ourselves */
}

/* A prober can name any node it likes; what that makes the daemon write at
   its default log level must not depend on whether the node exists. A
   known name with a bad signature writes nothing, so neither may this. */
static void test_unknown_name_writes_no_log_line(void **state) {
	(void)state;
	uint8_t p[AUTHN_MAX_LEN];
	size_t len = build_as(PEER, peer_key, now.tv_sec, exporter, p);

	size_t before = log_lines();
	assert_false(verify(p, len, other_exporter));
	assert_int_equal(before, log_lines());

	memcpy(p + AUTHN_HDR_LEN, STRANGER, strlen(STRANGER));
	assert_false(verify(p, len, exporter));
	assert_int_equal(before, log_lines());
}

/* The timing test. Every rejection a prober can cause is timed against the
   one it cannot tell apart by construction -- a known node whose signature
   fails -- in interleaved, shuffled rounds so drift hits every case alike.
   A second copy of the baseline measures the noise floor (an A/A test). Two
   positive controls add a known small cost to the baseline -- one log line,
   one lookup of an absent host record -- and show what a real difference of
   that size looks like; the log line must clear the budget, or the test
   could not have seen the defect it was written for. The statistic is the
   mean, over a case's pool, of each authenticator's fastest verification:
   the minimum drops what a busy host adds, the mean over the pool what the
   variable-time signature check adds. */

typedef enum {
	EXTRA_NONE,
	EXTRA_LOG_LINE,
	EXTRA_ABSENT_LOOKUP,
} extra_t;

/* Ed25519 verification is variable-time in the (public) signature, so each
   case cycles through its own pool of distinct authenticators; comparing two
   single signatures would measure the signatures, not the code path. */
#define POOL 100 /* the replay pool must fit the 256-slot replay cache, twice */

typedef struct {
	uint8_t payload[AUTHN_MAX_LEN];
	size_t len;
} authn_t;

typedef struct {
	const char *label;
	authn_t *pool;
	const uint8_t *exp;
	extra_t extra;
	uint64_t *ns;
} probe_t;

static uint64_t ns_now(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t) ts.tv_sec * 1000000000u + (uint64_t) ts.tv_nsec;
}

static uint64_t time_once(const probe_t *pr, size_t round) {
	const authn_t *a = &pr->pool[round % POOL];
	uint64_t t0 = ns_now();
	bool ok = verify(a->payload, a->len, pr->exp);

	if(pr->extra == EXTRA_LOG_LINE) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Cannot open config file %s/%s: No such file or directory", hostsdir, STRANGER);
	} else if(pr->extra == EXTRA_ABSENT_LOOKUP) {
		splay_tree_t *tree = create_configuration();
		assert_false(read_host_config(tree, STRANGER, false));
		exit_configuration(tree);
	}

	uint64_t t1 = ns_now();
	assert_false(ok);
	return t1 - t0;
}

static int cmp_u64(const void *a, const void *b) {
	uint64_t x = *(const uint64_t *) a, y = *(const uint64_t *) b;
	return (x > y) - (x < y);
}

static double quantile(const uint64_t *sorted, size_t n, double q) {
	return (double) sorted[(size_t)(q * (double)(n - 1))];
}

/* Mean over the pool of each authenticator's fastest time; sample k was
   taken in round k + warmup. */
static double mean_of_minima(const uint64_t *ns, size_t rounds, size_t warmup) {
	uint64_t best[POOL];

	for(size_t i = 0; i < POOL; i++) {
		best[i] = UINT64_MAX;
	}

	for(size_t k = 0; k < rounds; k++) {
		size_t i = (k + warmup) % POOL;

		if(ns[k] < best[i]) {
			best[i] = ns[k];
		}
	}

	double sum = 0;

	for(size_t i = 0; i < POOL; i++) {
		sum += (double) best[i];
	}

	return sum / POOL;
}

static void test_rejection_cost_is_name_independent(void **state) {
	(void)state;
	const char *env = getenv("TINC_AUTHN_ROUNDS");
	size_t rounds = env ? (size_t) atol(env) : 2000;
	const size_t warmup = 100;

	/* Each case has a pool of its own: a pool that two cases shared ran its
	   signatures twice as often and came out ~0.7 us faster (warm caches
	   and branch history), which the A/A copy exposed. */
	enum { BASE, BASE_AA, UNKNOWN, STALE, REPLAY, LOG_LINE, ABSENT, NCASES };
	probe_t pr[NCASES] = {
		[BASE] = {"known name, signature fails (baseline)", NULL, other_exporter, EXTRA_NONE, NULL},
		[BASE_AA] = {"the same, other signatures (A/A: noise)", NULL, other_exporter, EXTRA_NONE, NULL},
		[UNKNOWN] = {"unknown name", NULL, exporter, EXTRA_NONE, NULL},
		[STALE] = {"stale timestamp, valid signature", NULL, exporter, EXTRA_NONE, NULL},
		[REPLAY] = {"replayed nonce, valid signature", NULL, exporter, EXTRA_NONE, NULL},
		[LOG_LINE] = {"control: baseline + one log line", NULL, other_exporter, EXTRA_LOG_LINE, NULL},
		[ABSENT] = {"control: baseline + one absent-record lookup", NULL, other_exporter, EXTRA_ABSENT_LOOKUP, NULL},
	};

	for(size_t c = 0; c < NCASES; c++) {
		authn_t *pool = xzalloc(POOL * sizeof(*pool));
		time_t ts = c == STALE ? now.tv_sec - 10 * AUTHN_TS_SKEW : now.tv_sec;

		for(size_t i = 0; i < POOL; i++) {
			pool[i].len = build_as(PEER, peer_key, ts, exporter, pool[i].payload);

			if(c == UNKNOWN) {
				memcpy(pool[i].payload + AUTHN_HDR_LEN, STRANGER, strlen(STRANGER));
			} else if(c == REPLAY) {
				/* Accepted once, so that from here on it is a replay. */
				assert_true(verify(pool[i].payload, pool[i].len, exporter));
			}
		}

		pr[c].pool = pool;
	}

	for(size_t c = 0; c < NCASES; c++) {
		pr[c].ns = xzalloc(rounds * sizeof(uint64_t));
	}

	srand(0x7433);
	size_t order[NCASES];

	for(size_t r = 0; r < warmup + rounds; r++) {
		for(size_t c = 0; c < NCASES; c++) {
			order[c] = c;
		}

		for(size_t c = NCASES - 1; c > 0; c--) {
			size_t j = (size_t) rand() % (c + 1);
			size_t t = order[c];
			order[c] = order[j];
			order[j] = t;
		}

		for(size_t c = 0; c < NCASES; c++) {
			uint64_t ns = time_once(&pr[order[c]], r);

			if(r >= warmup) {
				pr[order[c]].ns[r - warmup] = ns;
			}
		}
	}

	double mm[NCASES], med[NCASES];

	for(size_t c = 0; c < NCASES; c++) {
		mm[c] = mean_of_minima(pr[c].ns, rounds, warmup);
		qsort(pr[c].ns, rounds, sizeof(uint64_t), cmp_u64);
		med[c] = quantile(pr[c].ns, rounds, 0.5);
	}

	print_message("# %zu rounds over pools of %d, ns per verification; mm = mean of per-authenticator minima\n",
	              rounds, POOL);
	print_message("# %-46s %8s %8s %8s %8s\n", "case", "mm", "median", "d(mm)", "d(med)");

	for(size_t c = 0; c < NCASES; c++) {
		print_message("# %-46s %8.0f %8.0f %+8.0f %+8.0f\n", pr[c].label, mm[c], med[c],
		              mm[c] - mm[BASE], med[c] - med[BASE]);
	}

	/* The budget: 1% of the baseline, or four times the A/A difference on a
	   host too noisy for that. */
	double aa = fabs(mm[BASE_AA] - mm[BASE]);
	double budget = mm[BASE] / 100;

	if(budget < 4 * aa) {
		budget = 4 * aa;
	}

	print_message("# budget: %.0f ns\n", budget);

	if(!getenv("TINC_AUTHN_REPORT_ONLY")) {
		if(mm[LOG_LINE] - mm[BASE] <= budget) {
			fail_msg("the method cannot see one log line (%+.0f ns, budget %.0f ns): host too noisy",
			         mm[LOG_LINE] - mm[BASE], budget);
		}

		for(size_t c = UNKNOWN; c <= REPLAY; c++) {
			if(fabs(mm[c] - mm[BASE]) > budget) {
				fail_msg("%s: %+.0f ns against the baseline, budget %.0f ns", pr[c].label, mm[c] - mm[BASE], budget);
			}
		}
	}

	for(size_t c = 0; c < NCASES; c++) {
		free(pr[c].ns);
		free(pr[c].pool);
	}
}

int main(void) {
	random_init();

	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_accepts_a_fresh_authenticator_once, setup_files, teardown),
		cmocka_unit_test_setup_teardown(test_rejects, setup_files, teardown),
		cmocka_unit_test_setup_teardown(test_unknown_name_writes_no_log_line, setup_files, teardown),
		cmocka_unit_test_setup_teardown(test_rejection_cost_is_name_independent, setup_files, teardown),
		cmocka_unit_test_setup_teardown(test_accepts_a_fresh_authenticator_once, setup_yaml, teardown),
		cmocka_unit_test_setup_teardown(test_unknown_name_writes_no_log_line, setup_yaml, teardown),
		cmocka_unit_test_setup_teardown(test_rejection_cost_is_name_independent, setup_yaml, teardown),
	};

	int rc = cmocka_run_group_tests(tests, NULL, NULL);
	random_exit();
	return rc;
}
