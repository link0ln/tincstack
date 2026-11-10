#include "unittest.h"
#include "../../src/conf.h"
#include "../../src/connection.h"
#include "../../src/ecdsa.h"
#include "../../src/ecdsagen.h"
#include "../../src/edge.h"
#include "../../src/event.h"
#include "../../src/logger.h"
#include "../../src/names.h"
#include "../../src/node.h"
#include "../../src/protocol.h"
#include "../../src/random.h"
#include "../../src/transport.h"
#include "../../src/utils.h"
#include "../../src/xalloc.h"
#include "../../src/yamlconf.h"

#define KEY_QUORUM_REQ      100
#define KEY_QUORUM_ANS      101
#define KEY_QUORUM_FLAG_HAS_KEY     0x01
#define KEY_QUORUM_FLAG_DIRECT_EDGE 0x02

typedef struct captured_req_t {
	connection_t *conn;
	char line[2048];
} captured_req_t;

static captured_req_t g_captured[32];
static size_t g_captured_count = 0;

bool __wrap_send_request(connection_t *c, const char *format, ...);
bool __wrap_send_request(connection_t *c, const char *format, ...) {
	va_list ap;
	va_start(ap, format);

	if(g_captured_count < 32) {
		g_captured[g_captured_count].conn = c;
		vsnprintf(g_captured[g_captured_count].line,
		          sizeof(g_captured[g_captured_count].line), format, ap);
		g_captured_count++;
	}

	va_end(ap);
	return true;
}

bool __wrap_send_req_key(node_t *to);
bool __wrap_send_req_key(node_t *to) {
	(void)to;
	return true;
}

static void sign_quorum_vote(ecdsa_t *voter_priv, const char *voter_name,
                             const char *requester_name, const char *target_name,
                             const char *nonce, const char *voted_pk, int flags,
                             char *out_sig_b64, size_t out_size) {
	char msg[2048];
	int mlen = snprintf(msg, sizeof(msg), "tinc-key-quorum-v1 %s %s %s %s %s %d",
	                    voter_name, requester_name, target_name, nonce, voted_pk, flags);
	assert_true(mlen > 0 && (size_t)mlen < sizeof(msg));

	size_t siglen = ecdsa_size(voter_priv);
	assert_true(siglen > 0 && siglen <= 128);
	uint8_t raw_sig[128];
	assert_true(ecdsa_sign(voter_priv, msg, (size_t)mlen, raw_sig));
	assert_true(B64_SIZE(siglen) <= out_size);
	b64encode_tinc(raw_sig, out_sig_b64, siglen);
}

static node_t *make_mesh_peer(const char *name, ecdsa_t *priv, connection_t *via_conn) {
	node_t *n = new_node(name);
	n->hostname = xstrdup("192.0.2.1 port 655");
	char *pub = ecdsa_get_base64_public_key(priv);
	n->ecdsa = ecdsa_set_base64_public_key(pub);
	assert_non_null(n->ecdsa);
	free(pub);
	n->status.reachable = true;
	n->nexthop = via_conn->node ? via_conn->node : n;
	node_add(n);
	return n;
}

static void test_strict_ed25519_key_quorum_and_replay_and_veto(void **state) {
	(void)state;
	char tmp[] = "/tmp/tinc.test.quorum.XXXXXX";
	assert_ptr_equal(tmp, mkdtemp(tmp));

	char ypath[PATH_MAX];
	snprintf(ypath, sizeof(ypath), "%s/tinc.yaml", tmp);
	netname = xstrdup("mesh");
	yamlconf_path = xstrdup(ypath);
	yamlconf_global = yamlconf_new();
	debug_level = DEBUG_NOTHING;
	gettimeofday(&now, NULL);
	now.tv_sec = 100000;

	ecdsa_t *me_priv = ecdsa_generate();
	ecdsa_t *relay_priv = ecdsa_generate();
	ecdsa_t *v1_priv = ecdsa_generate();
	ecdsa_t *v2_priv = ecdsa_generate();
	ecdsa_t *target_old_priv = ecdsa_generate();
	ecdsa_t *target_new_priv = ecdsa_generate();
	ecdsa_t *target2_old_priv = ecdsa_generate();
	ecdsa_t *target2_new_priv = ecdsa_generate();

	char *old_pub = ecdsa_get_base64_public_key(target_old_priv);
	char *new_pub = ecdsa_get_base64_public_key(target_new_priv);
	char *t2_old_pub = ecdsa_get_base64_public_key(target2_old_priv);
	char *t2_new_pub = ecdsa_get_base64_public_key(target2_new_priv);

	char host_buf[512];
	snprintf(host_buf, sizeof(host_buf), "Ed25519PublicKey = %s\nTransports = quic\n", old_pub);
	yamlconf_host_set_text(yamlconf_global, netname, "target1", host_buf);
	snprintf(host_buf, sizeof(host_buf), "Ed25519PublicKey = %s\n", t2_old_pub);
	yamlconf_host_set_text(yamlconf_global, netname, "target2", host_buf);
	assert_true(yamlconf_save(yamlconf_global, ypath));

	myself = new_node("alpha");
	myself->hostname = xstrdup("MYSELF");
	myself->connection = new_connection();
	myself->connection->ecdsa = me_priv;
	node_add(myself);

	/* Direct neighbor relay_conn */
	connection_t *relay_conn = new_connection();
	relay_conn->name = xstrdup("relay");
	relay_conn->hostname = xstrdup("198.51.100.1 port 655");
	relay_conn->status.active = true;
	node_t *relay = new_node("relay");
	relay->hostname = xstrdup("198.51.100.1 port 655");
	char *rpub = ecdsa_get_base64_public_key(relay_priv);
	relay->ecdsa = ecdsa_set_base64_public_key(rpub);
	free(rpub);
	relay->status.reachable = true;
	relay->connection = relay_conn;
	relay->nexthop = relay;
	relay_conn->node = relay;
	node_add(relay);

	node_t *voter1 = make_mesh_peer("voter1", v1_priv, relay_conn);
	node_t *voter2 = make_mesh_peer("voter2", v2_priv, relay_conn);
	node_t *target = make_mesh_peer("target1", target_old_priv, relay_conn);
	target->transports = TRANSPORT_BIT(TRANSPORT_QUIC);
	node_t *target2 = make_mesh_peer("target2", target2_old_priv, relay_conn);

	/* 1. ANS_PUBKEY with a mismatched key must NOT mutate transports or YAML,
	      and must start a nonce-bound quorum round querying relay, voter1, voter2, target2. */
	g_captured_count = 0;
	char req[2048];
	snprintf(req, sizeof(req), "%d target1 alpha %d %s https", REQ_KEY, ANS_PUBKEY, new_pub);
	assert_true(req_key_h(relay_conn, req));
	assert_int_equal(TRANSPORT_BIT(TRANSPORT_QUIC), target->transports);
	assert_non_null(target->pending_pubkey);
	assert_string_equal(new_pub, target->pending_pubkey);
	assert_int_equal(32, strlen(target->quorum_nonce));
	assert_int_equal(4, target->quorum_asked_peers); /* relay, voter1, voter2, target2 */

	/* 2. Unsigned legacy 3-field KEY_QUORUM_ANS must be strictly rejected */
	snprintf(req, sizeof(req), "%d voter1 alpha %d target1 %s %d",
	         REQ_KEY, KEY_QUORUM_ANS, new_pub, KEY_QUORUM_FLAG_HAS_KEY);
	assert_true(req_key_h(relay_conn, req));
	assert_int_equal(0, target->quorum_votes_new);

	/* 3. Signed vote with wrong nonce must be strictly rejected */
	char sig[256];
	sign_quorum_vote(v1_priv, "voter1", "alpha", "target1",
	                 "00112233445566778899aabbccddeeff", new_pub,
	                 KEY_QUORUM_FLAG_HAS_KEY, sig, sizeof(sig));
	snprintf(req, sizeof(req), "%d voter1 alpha %d target1 %s %d %s %s",
	         REQ_KEY, KEY_QUORUM_ANS, new_pub, KEY_QUORUM_FLAG_HAS_KEY,
	         "00112233445566778899aabbccddeeff", sig);
	assert_true(req_key_h(relay_conn, req));
	assert_int_equal(0, target->quorum_votes_new);

	/* 4. Vote forged by compromised relay claiming to be voter1 must be rejected */
	sign_quorum_vote(relay_priv, "voter1", "alpha", "target1",
	                 target->quorum_nonce, new_pub,
	                 KEY_QUORUM_FLAG_HAS_KEY, sig, sizeof(sig));
	snprintf(req, sizeof(req), "%d voter1 alpha %d target1 %s %d %s %s",
	         REQ_KEY, KEY_QUORUM_ANS, new_pub, KEY_QUORUM_FLAG_HAS_KEY,
	         target->quorum_nonce, sig);
	assert_true(req_key_h(relay_conn, req));
	assert_int_equal(0, target->quorum_votes_new);

	/* 5. Valid Ed25519-signed vote from voter1 accepted (votes_new == 1) */
	char v1_sig[256];
	sign_quorum_vote(v1_priv, "voter1", "alpha", "target1",
	                 target->quorum_nonce, new_pub,
	                 KEY_QUORUM_FLAG_HAS_KEY, v1_sig, sizeof(v1_sig));
	snprintf(req, sizeof(req), "%d voter1 alpha %d target1 %s %d %s %s",
	         REQ_KEY, KEY_QUORUM_ANS, new_pub, KEY_QUORUM_FLAG_HAS_KEY,
	         target->quorum_nonce, v1_sig);
	assert_true(req_key_h(relay_conn, req));
	assert_int_equal(1, target->quorum_votes_new);
	assert_non_null(target->pending_pubkey); /* 1 of 4 is not majority yet */

	/* 6. Concurrent round on target2 + replay of voter1's valid signed vote on target1
	      MUST be deduplicated (votes_new stays 1, NOT 2)! */
	snprintf(req, sizeof(req), "%d target2 alpha %d %s", REQ_KEY, ANS_PUBKEY, t2_new_pub);
	assert_true(req_key_h(relay_conn, req));
	assert_non_null(target2->pending_pubkey);

	char v1_t2_sig[256];
	sign_quorum_vote(v1_priv, "voter1", "alpha", "target2",
	                 target2->quorum_nonce, t2_new_pub,
	                 KEY_QUORUM_FLAG_HAS_KEY, v1_t2_sig, sizeof(v1_t2_sig));
	snprintf(req, sizeof(req), "%d voter1 alpha %d target2 %s %d %s %s",
	         REQ_KEY, KEY_QUORUM_ANS, t2_new_pub, KEY_QUORUM_FLAG_HAS_KEY,
	         target2->quorum_nonce, v1_t2_sig);
	assert_true(req_key_h(relay_conn, req));
	assert_int_equal(1, target2->quorum_votes_new);

	/* Now replay voter1's exact signed vote for target1: must NOT increment votes_new! */
	snprintf(req, sizeof(req), "%d voter1 alpha %d target1 %s %d %s %s",
	         REQ_KEY, KEY_QUORUM_ANS, new_pub, KEY_QUORUM_FLAG_HAS_KEY,
	         target->quorum_nonce, v1_sig);
	assert_true(req_key_h(relay_conn, req));
	assert_int_equal(1, target->quorum_votes_new);

	/* 7. Valid signed vote from voter2 (votes_new == 2), then abstention ("-") from
	      relay & target2 reduces asked_peers from 4 -> 2 and triggers approval! */
	char v2_sig[256];
	sign_quorum_vote(v2_priv, "voter2", "alpha", "target1",
	                 target->quorum_nonce, new_pub,
	                 KEY_QUORUM_FLAG_HAS_KEY, v2_sig, sizeof(v2_sig));
	snprintf(req, sizeof(req), "%d voter2 alpha %d target1 %s %d %s %s",
	         REQ_KEY, KEY_QUORUM_ANS, new_pub, KEY_QUORUM_FLAG_HAS_KEY,
	         target->quorum_nonce, v2_sig);
	assert_true(req_key_h(relay_conn, req));
	assert_int_equal(2, target->quorum_votes_new);
	assert_non_null(target->pending_pubkey); /* 2 of 4 still needs abstentions or 3rd vote */

	char abstain_sig[256];
	sign_quorum_vote(relay_priv, "relay", "alpha", "target1",
	                 target->quorum_nonce, "-", 0, abstain_sig, sizeof(abstain_sig));
	snprintf(req, sizeof(req), "%d relay alpha %d target1 - 0 %s %s",
	         REQ_KEY, KEY_QUORUM_ANS, target->quorum_nonce, abstain_sig);
	assert_true(req_key_h(relay_conn, req));
	/* 2 votes > asked_peers/2 (asked_peers became 3, 2*2 > 3) -> APPROVED! */
	assert_null(target->pending_pubkey);
	char *updated_pk = ecdsa_get_base64_public_key(target->ecdsa);
	assert_string_equal(new_pub, updated_pk);
	free(updated_pk);

	/* 8. Local veto: when target2->status.validkey is true, start_key_quorum / evaluate_key_quorum
	      refuses key replacement! */
	target2->status.validkey = true;
	char v2_t2_sig[256];
	sign_quorum_vote(v2_priv, "voter2", "alpha", "target2",
	                 target2->quorum_nonce, t2_new_pub,
	                 KEY_QUORUM_FLAG_HAS_KEY, v2_t2_sig, sizeof(v2_t2_sig));
	snprintf(req, sizeof(req), "%d voter2 alpha %d target2 %s %d %s %s",
	         REQ_KEY, KEY_QUORUM_ANS, t2_new_pub, KEY_QUORUM_FLAG_HAS_KEY,
	         target2->quorum_nonce, v2_t2_sig);
	assert_true(req_key_h(relay_conn, req));
	assert_null(target2->pending_pubkey);
	char *t2_cur_pk = ecdsa_get_base64_public_key(target2->ecdsa);
	assert_string_equal(t2_old_pub, t2_cur_pk); /* Kept OLD key due to local veto! */
	free(t2_cur_pk);

	/* 9. Responder signing check: KEY_QUORUM_REQ causes myself to emit a 5-field signed KEY_QUORUM_ANS */
	g_captured_count = 0;
	snprintf(req, sizeof(req), "%d voter1 alpha %d target1 aabbccddeeff00112233445566778899",
	         REQ_KEY, KEY_QUORUM_REQ);
	assert_true(req_key_h(relay_conn, req));
	assert_true(g_captured_count >= 1);
	const char *ans_line = NULL;
	for(size_t i = 0; i < g_captured_count; i++) {
		int reqno = 0, subcmd = 0;
		if(sscanf(g_captured[i].line, "%d %*s %*s %d", &reqno, &subcmd) == 2 &&
		                reqno == REQ_KEY && subcmd == KEY_QUORUM_ANS) {
			ans_line = g_captured[i].line;
			break;
		}
	}
	assert_non_null(ans_line);
	char ans_target[64], ans_pk[256], ans_nonce[128], ans_sig[256];
	int ans_flags = -1;
	assert_int_equal(5, sscanf(ans_line, "%*d %*s %*s %*d %63s %255s %d %127s %255s",
	                           ans_target, ans_pk, &ans_flags, ans_nonce, ans_sig));
	assert_string_equal("target1", ans_target);
	assert_string_equal(new_pub, ans_pk);
	assert_string_equal("aabbccddeeff00112233445566778899", ans_nonce);
	char expected_sig[256];
	sign_quorum_vote(me_priv, "alpha", "voter1", "target1",
	                 "aabbccddeeff00112233445566778899", new_pub,
	                 ans_flags, expected_sig, sizeof(expected_sig));
	assert_string_equal(expected_sig, ans_sig);

	(void)voter1;
	(void)voter2;

	free(old_pub);
	free(new_pub);
	free(t2_old_pub);
	free(t2_new_pub);
	ecdsa_free(relay_priv);
	ecdsa_free(v1_priv);
	ecdsa_free(v2_priv);
	ecdsa_free(target_old_priv);
	ecdsa_free(target_new_priv);
	ecdsa_free(target2_old_priv);
	ecdsa_free(target2_new_priv);

	relay->connection = NULL;
	free_connection(relay_conn);
	free_connection(myself->connection);
	myself->connection = NULL;
	exit_nodes();
	myself = NULL;

	yamlconf_free(yamlconf_global);
	yamlconf_global = NULL;
	unlink(ypath);
	char lockpath[PATH_MAX + 16];
	snprintf(lockpath, sizeof(lockpath), "%s.lock", ypath);
	unlink(lockpath);
	free(yamlconf_path);
	yamlconf_path = NULL;
	free(netname);
	netname = NULL;
	rmdir(tmp);
}

static void test_conf_whitespace_underflow_and_indented_comments(void **state) {
	(void)state;
	char tmp[] = "/tmp/tinc.test.conf.XXXXXX";
	assert_ptr_equal(tmp, mkdtemp(tmp));
	char cpath[PATH_MAX];
	snprintf(cpath, sizeof(cpath), "%s/tinc.conf", tmp);

	FILE *f = fopen(cpath, "w");
	assert_non_null(f);
	/* Pure whitespace lines ("   \t  \n") previously underflowed line[-1], and
	   indented "# comment" lines previously failed read_config_file()! */
	fputs("   \t   \n"
	      "  # indented comment\n"
	      "\t# tab-indented comment\n"
	      "Name = alpha   \t \n"
	      "Port = 655\n", f);
	fclose(f);

	splay_tree_t cfg;
	init_configuration(&cfg);
	assert_true(read_config_file(&cfg, cpath, false));

	char *name_val = NULL;
	int port_val = 0;
	assert_true(get_config_string(lookup_config(&cfg, "Name"), &name_val));
	assert_string_equal("alpha", name_val);
	free(name_val);
	assert_true(get_config_int(lookup_config(&cfg, "Port"), &port_val));
	assert_int_equal(655, port_val);

	splay_empty_tree(&cfg);
	unlink(cpath);
	rmdir(tmp);
}

static void test_yamlconf_comments_flowseq_singlequote_and_nul(void **state) {
	(void)state;
	char doc[] =
	        "networks: # top-level inline comment\n"
	        "  'my''net': # single-quoted key with escaped quote\n"
	        "    options: # mapping header comment\n"
	        "      Name: alpha # inline comment\n"
	        "      ConnectTo: [\"peer,one\", 'peer,two', peer3] # flow seq with commas in quotes\n"
	        "    hosts:\n"
	        "      alpha: | # block header comment\n"
	        "        Subnet = 10.0.0.1/32#10\n"
	        "        Ed25519PublicKey = AAAA\n";

	yamlconf_t *yc = yamlconf_parse(doc);
	assert_non_null(yc);
	assert_true(yamlconf_has_network(yc, "my'net"));
	assert_string_equal("alpha", yamlconf_get_option(yc, "my'net", "Name"));

	const char **ct = yamlconf_option_values(yc, "my'net", "ConnectTo");
	assert_non_null(ct);
	assert_string_equal("peer,one", ct[0]);
	assert_string_equal("peer,two", ct[1]);
	assert_string_equal("peer3", ct[2]);
	assert_null(ct[3]);
	free(ct);

	char *htext = yamlconf_host_text(yc, "my'net", "alpha");
	assert_non_null(htext);
	assert_non_null(strstr(htext, "Subnet = 10.0.0.1/32#10"));
	free(htext);
	yamlconf_free(yc);

	/* Embedded NUL byte in file on disk must be rejected by yamlconf_load() */
	char tmp[] = "/tmp/tinc.test.yaml.XXXXXX";
	assert_ptr_equal(tmp, mkdtemp(tmp));
	char ypath[PATH_MAX];
	snprintf(ypath, sizeof(ypath), "%s/bad.yaml", tmp);
	FILE *f = fopen(ypath, "wb");
	assert_non_null(f);
	const char bad_bytes[] = "networks:\n  demo:\n\0    options:\n      Name: evil\n";
	fwrite(bad_bytes, 1, sizeof(bad_bytes) - 1, f);
	fclose(f);
	assert_null(yamlconf_load(ypath));
	unlink(ypath);
	rmdir(tmp);
}

int main(void) {
	random_init();
	crypto_init();

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_strict_ed25519_key_quorum_and_replay_and_veto),
		cmocka_unit_test(test_conf_whitespace_underflow_and_indented_comments),
		cmocka_unit_test(test_yamlconf_comments_flowseq_singlequote_and_nul),
	};
	int rc = cmocka_run_group_tests(tests, NULL, NULL);
	random_exit();
	return rc;
}
