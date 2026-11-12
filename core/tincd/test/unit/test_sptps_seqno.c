#include "unittest.h"
#include "../../src/crypto.h"
#include "../../src/ecdsa.h"
#include "../../src/ecdsagen.h"
#include "../../src/random.h"
#include "../../src/sptps.h"
#include "../../src/xalloc.h"

typedef struct queued_pkt_t {
	bool to_b;
	uint8_t buf[256];
	size_t len;
} queued_pkt_t;

typedef struct test_pair_t {
	sptps_t a;
	sptps_t b;
	queued_pkt_t q[16];
	size_t q_head;
	size_t q_tail;
	uint8_t last_buf[256];
	size_t last_len;
	int rx_count;
} test_pair_t;

static bool send_from_a(void *handle, uint8_t type, const void *data, size_t len) {
	test_pair_t *p = handle;
	assert_true(len <= sizeof(p->last_buf));
	memcpy(p->last_buf, data, len);
	p->last_len = len;

	if(!p->a.outstate || type >= SPTPS_HANDSHAKE) {
		assert_true(p->q_tail < 16);
		p->q[p->q_tail].to_b = true;
		memcpy(p->q[p->q_tail].buf, data, len);
		p->q[p->q_tail].len = len;
		p->q_tail++;
	}

	return true;
}

static bool send_from_b(void *handle, uint8_t type, const void *data, size_t len) {
	test_pair_t *p = handle;
	assert_true(len <= sizeof(p->last_buf));
	memcpy(p->last_buf, data, len);
	p->last_len = len;

	if(!p->b.outstate || type >= SPTPS_HANDSHAKE) {
		assert_true(p->q_tail < 16);
		p->q[p->q_tail].to_b = false;
		memcpy(p->q[p->q_tail].buf, data, len);
		p->q[p->q_tail].len = len;
		p->q_tail++;
	}

	return true;
}

static void drain_handshake_queue(test_pair_t *p) {
	while(p->q_head < p->q_tail) {
		queued_pkt_t pkt = p->q[p->q_head++];
		sptps_t *dst = pkt.to_b ? &p->b : &p->a;
		assert_true(sptps_receive_data(dst, pkt.buf, pkt.len) != 0);
	}
}

static bool on_record_rx(void *handle, uint8_t type, const void *data, uint16_t len) {
	(void)data;
	(void)len;
	test_pair_t *p = handle;

	if(type < SPTPS_HANDSHAKE) {
		p->rx_count++;
	}

	return true;
}

static void test_sptps_wraparound_and_non_pow2_window(void **state) {
	(void)state;
	sptps_log = sptps_log_quiet;
	/* Deliberately use a non-power-of-two ReplayWindow (3 bytes = 24 packets)
	   to prove that 0xFFFFFFFF -> 0 wraparound has zero bitmap aliasing! */
	unsigned int saved_win = sptps_replaywin;
	sptps_replaywin = 3;

	ecdsa_t *ka = ecdsa_generate();
	ecdsa_t *kb = ecdsa_generate();
	assert_non_null(ka);
	assert_non_null(kb);

	char *pub_a = ecdsa_get_base64_public_key(ka);
	char *pub_b = ecdsa_get_base64_public_key(kb);
	ecdsa_t *ka_pub = ecdsa_set_base64_public_key(pub_a);
	ecdsa_t *kb_pub = ecdsa_set_base64_public_key(pub_b);
	free(pub_a);
	free(pub_b);

	test_pair_t pair;
	memset(&pair, 0, sizeof(pair));

	assert_true(sptps_start(&pair.a, &pair, true, true, ka, kb_pub, "test-sptps", 10,
	                        send_from_a, on_record_rx));
	assert_true(sptps_start(&pair.b, &pair, false, true, kb, ka_pub, "test-sptps", 10,
	                        send_from_b, on_record_rx));
	drain_handshake_queue(&pair);
	assert_true(pair.a.outstate && pair.a.instate);
	assert_true(pair.b.outstate && pair.b.instate);

	/* 1. Early negative wrap before session advanced must NOT be accepted,
	      even with a valid AEAD ciphertext encrypted at seqno 0xFFFFFFFE! */
	uint32_t saved_seq = pair.a.outseqno;
	pair.a.outseqno = 0xFFFFFFFEU;
	assert_true(sptps_send_record(&pair.a, 0, "early", 5));
	assert_false(sptps_verify_datagram(&pair.b, pair.last_buf, pair.last_len));
	assert_true(sptps_receive_data(&pair.b, pair.last_buf, pair.last_len) != 0);
	assert_int_equal(0, pair.rx_count);
	pair.a.outseqno = saved_seq;
	pair.a.out_key_packets = 0;

	/* 2. Fast-forward sender & receiver just before 32-bit wraparound (0xFFFFFFFD),
	      keeping out_key_packets / in_key_packets small (simulating post-rekey session) */
	pair.a.outseqno = 0xFFFFFFFDU;
	pair.b.inseqno = 0xFFFFFFFDU;
	pair.b.inseq_abs = 0xFFFFFFFDULL;

	/* Send 0xFFFFFFFD (delivered), 0xFFFFFFFE (saved out-of-order), 0xFFFFFFFF (LOST!), 0x00000000 (delivered), 0x00000001 (delivered) */
	assert_true(sptps_send_record(&pair.a, 0, "pkt-fd", 6));
	assert_true(sptps_receive_data(&pair.b, pair.last_buf, pair.last_len) != 0);
	assert_int_equal(1, pair.rx_count);

	uint8_t pkt_fe[256];
	assert_true(sptps_send_record(&pair.a, 0, "pkt-fe", 6));
	size_t pkt_fe_len = pair.last_len;
	memcpy(pkt_fe, pair.last_buf, pkt_fe_len);

	uint8_t pkt_ff[256];
	assert_true(sptps_send_record(&pair.a, 0, "pkt-ff", 6)); /* seqno 0xFFFFFFFF */
	size_t pkt_ff_len = pair.last_len;
	memcpy(pkt_ff, pair.last_buf, pkt_ff_len);

	/* Packet 0x00000000 arrives while BOTH 0xFFFFFFFE and 0xFFFFFFFF are missing! */
	assert_true(sptps_send_record(&pair.a, 0, "pkt-00", 6)); /* seqno 0 */
	uint8_t pkt_00[256];
	size_t pkt_00_len = pair.last_len;
	memcpy(pkt_00, pair.last_buf, pkt_00_len);
	assert_true(sptps_verify_datagram(&pair.b, pkt_00, pkt_00_len));
	assert_true(sptps_receive_data(&pair.b, pkt_00, pkt_00_len) != 0);
	assert_int_equal(2, pair.rx_count);
	assert_int_equal(1U, pair.b.inseqno);

	/* Packet 0x00000001 arrives */
	assert_true(sptps_send_record(&pair.a, 0, "pkt-01", 6)); /* seqno 1 */
	assert_true(sptps_receive_data(&pair.b, pair.last_buf, pair.last_len) != 0);
	assert_int_equal(3, pair.rx_count);
	assert_int_equal(2U, pair.b.inseqno);

	/* Delayed packets 0xFFFFFFFF and 0xFFFFFFFE arrive AFTER wraparound -> MUST be accepted! */
	assert_true(sptps_verify_datagram(&pair.b, pkt_ff, pkt_ff_len));
	assert_true(sptps_receive_data(&pair.b, pkt_ff, pkt_ff_len) != 0);
	assert_int_equal(4, pair.rx_count);

	assert_true(sptps_verify_datagram(&pair.b, pkt_fe, pkt_fe_len));
	assert_true(sptps_receive_data(&pair.b, pkt_fe, pkt_fe_len) != 0);
	assert_int_equal(5, pair.rx_count);

	/* Replaying 0xFFFFFFFF, 0xFFFFFFFE, or 0x00000000 MUST be rejected by sptps_verify_datagram and ignored by sptps_receive_data! */
	assert_false(sptps_verify_datagram(&pair.b, pkt_ff, pkt_ff_len));
	assert_false(sptps_verify_datagram(&pair.b, pkt_fe, pkt_fe_len));
	assert_false(sptps_verify_datagram(&pair.b, pkt_00, pkt_00_len));
	assert_true(sptps_receive_data(&pair.b, pkt_ff, pkt_ff_len) != 0);
	assert_int_equal(5, pair.rx_count); /* duplicate ignored without error or double delivery */

	/* 3. Nonce-reuse refusal when out_key_packets reaches UINT32_MAX without key rotation */
	pair.a.out_key_packets = UINT32_MAX;
	assert_false(sptps_send_record(&pair.a, 0, "overflow", 8));

	sptps_stop(&pair.a);
	sptps_stop(&pair.b);
	ecdsa_free(ka);
	ecdsa_free(kb);
	ecdsa_free(ka_pub);
	ecdsa_free(kb_pub);
	sptps_replaywin = saved_win;
}

static void test_sptps_secondary_rekey_prev_seqno_isolation_and_timeout(void **state) {
	(void)state;
	sptps_log = sptps_log_quiet;

	ecdsa_t *ka = ecdsa_generate();
	ecdsa_t *kb = ecdsa_generate();
	assert_non_null(ka);
	assert_non_null(kb);

	char *pub_a = ecdsa_get_base64_public_key(ka);
	char *pub_b = ecdsa_get_base64_public_key(kb);
	ecdsa_t *ka_pub = ecdsa_set_base64_public_key(pub_a);
	ecdsa_t *kb_pub = ecdsa_set_base64_public_key(pub_b);
	free(pub_a);
	free(pub_b);

	test_pair_t pair;
	memset(&pair, 0, sizeof(pair));

	assert_true(sptps_start(&pair.a, &pair, true, true, ka, kb_pub, "test-rekey", 10,
	                        send_from_a, on_record_rx));
	assert_true(sptps_start(&pair.b, &pair, false, true, kb, ka_pub, "test-rekey", 10,
	                        send_from_b, on_record_rx));
	drain_handshake_queue(&pair);
	assert_true(pair.a.outstate && pair.a.instate);
	assert_true(pair.b.outstate && pair.b.instate);

	/* Advance epoch 1 to seqno 500000 and capture an in-flight epoch-1 packet (seqno 500001) */
	pair.a.outseqno = 500000U;
	pair.b.inseqno = 500000U;
	pair.b.inseq_abs = 500000ULL;

	assert_true(sptps_send_record(&pair.a, 0, "ep1-500000", 10));
	assert_true(sptps_receive_data(&pair.b, pair.last_buf, pair.last_len) != 0);
	assert_int_equal(1, pair.rx_count);
	assert_int_equal(500001U, pair.b.inseqno);

	uint8_t late_ep1[256];
	assert_true(sptps_send_record(&pair.a, 0, "ep1-500001", 10));
	size_t late_ep1_len = pair.last_len;
	memcpy(late_ep1, pair.last_buf, late_ep1_len);

	/* Initiate secondary rekey from A and step until B has processed A's SIG
	   (B has sent B's SIG + ACK, which have NOT reached A yet, and A has NOT sent ACK yet) */
	pair.q_head = pair.q_tail = 0;
	assert_true(sptps_force_kex(&pair.a));
	assert_int_equal(SPTPS_KEX, (int)pair.a.state);
	assert_true(pair.a.kex_started != 0);

	/* Step 1: A's KEX -> B (B replies with B's KEX) */
	assert_int_equal(1, (int)(pair.q_tail - pair.q_head));
	queued_pkt_t p1 = pair.q[pair.q_head++];
	assert_true(sptps_receive_data(&pair.b, p1.buf, p1.len) != 0);

	/* Step 2: B's KEX -> A (A replies with A's SIG) */
	queued_pkt_t p2 = pair.q[pair.q_head++];
	assert_true(sptps_receive_data(&pair.a, p2.buf, p2.len) != 0);

	/* Step 3: A's SIG -> B (B queues B's SIG and B's ACK, NOT yet delivered to A!) */
	queued_pkt_t p3 = pair.q[pair.q_head++];
	assert_true(sptps_receive_data(&pair.b, p3.buf, p3.len) != 0);

	/* H-DP-01(1): Responder B sends a data datagram BEFORE A receives B's SIG/ACK
	   and BEFORE B receives A's ACK. Because B has NOT prematurely rotated outcipher,
	   A MUST decrypt it cleanly with 0 packet loss! */
	assert_true(sptps_send_record(&pair.b, 0, "b-mid-rekey", 11));
	assert_true(sptps_verify_datagram(&pair.a, pair.last_buf, pair.last_len));
	assert_true(sptps_receive_data(&pair.a, pair.last_buf, pair.last_len) != 0);
	assert_int_equal(2, pair.rx_count);

	/* Complete secondary handshake (B's SIG + ACK -> A, A's ACK -> B).
	   A sent KEX(500002), SIG(500003), ACK(500004), so B's inseqno/prev_inseqno is 500005
	   with 500001 still marked late in prev_late. */
	drain_handshake_queue(&pair);
	assert_int_equal(SPTPS_SECONDARY_KEX, (int)pair.a.state);
	assert_int_equal(SPTPS_SECONDARY_KEX, (int)pair.b.state);
	assert_int_equal(0, (int)pair.a.kex_started);
	assert_int_equal(0, (int)pair.b.kex_started);
	assert_int_equal(500005U, pair.b.prev_inseqno);

	/* Send two epoch-2 packets from A (seqno 500005 and 500006) */
	assert_true(sptps_send_record(&pair.a, 0, "ep2-1", 5));
	assert_true(sptps_receive_data(&pair.b, pair.last_buf, pair.last_len) != 0);
	assert_true(sptps_send_record(&pair.a, 0, "ep2-2", 5));
	assert_true(sptps_receive_data(&pair.b, pair.last_buf, pair.last_len) != 0);
	assert_int_equal(4, pair.rx_count);
	assert_int_equal(500007U, pair.b.inseqno);

	/* H-DP-01(3): Late epoch-1 packet (seqno 500001) arrives now!
	   Must be accepted once via prev_incipher + prev_late, rejected on replay,
	   and MUST NOT mutate pair.b.inseqno of epoch 2! */
	assert_true(sptps_verify_datagram(&pair.b, late_ep1, late_ep1_len));
	assert_true(sptps_receive_data(&pair.b, late_ep1, late_ep1_len) != 0);
	assert_int_equal(5, pair.rx_count);
	assert_int_equal(500007U, pair.b.inseqno);
	assert_int_equal(500005U, pair.b.prev_inseqno);

	/* Replay of late epoch-1 packet must fail verification and be ignored */
	assert_false(sptps_verify_datagram(&pair.b, late_ep1, late_ep1_len));
	assert_true(sptps_receive_data(&pair.b, late_ep1, late_ep1_len) != 0);
	assert_int_equal(5, pair.rx_count);

	/* Subsequent epoch-2 packets (seqno 500007, 500008) MUST continue to succeed! */
	assert_true(sptps_send_record(&pair.a, 0, "ep2-3", 5));
	assert_true(sptps_verify_datagram(&pair.b, pair.last_buf, pair.last_len));
	assert_true(sptps_receive_data(&pair.b, pair.last_buf, pair.last_len) != 0);
	assert_true(sptps_send_record(&pair.a, 0, "ep2-4", 5));
	assert_true(sptps_verify_datagram(&pair.b, pair.last_buf, pair.last_len));
	assert_true(sptps_receive_data(&pair.b, pair.last_buf, pair.last_len) != 0);
	assert_int_equal(7, pair.rx_count);
	assert_int_equal(500009U, pair.b.inseqno);

	/* H-DP-01(2): Simulate a lost secondary KEX packet and verify 30s timeout recovery */
	pair.q_head = pair.q_tail = 0;
	assert_true(sptps_force_kex(&pair.a));
	assert_int_equal(SPTPS_KEX, (int)pair.a.state);
	pair.q_head = pair.q_tail = 0; /* drop KEX packet */
	pair.a.kex_started -= 31;
	assert_true(sptps_send_record(&pair.a, 0, "unstick", 7));
	assert_int_equal(SPTPS_SECONDARY_KEX, (int)pair.a.state);
	assert_int_equal(0, (int)pair.a.kex_started);

	/* Verify a fresh rekey succeeds after timeout abort */
	assert_true(sptps_force_kex(&pair.a));
	drain_handshake_queue(&pair);
	assert_int_equal(SPTPS_SECONDARY_KEX, (int)pair.a.state);
	assert_int_equal(SPTPS_SECONDARY_KEX, (int)pair.b.state);

	sptps_stop(&pair.a);
	sptps_stop(&pair.b);
	ecdsa_free(ka);
	ecdsa_free(kb);
	ecdsa_free(ka_pub);
	ecdsa_free(kb_pub);
}

int main(void) {
	random_init();
	crypto_init();
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_sptps_wraparound_and_non_pow2_window),
		cmocka_unit_test(test_sptps_secondary_rekey_prev_seqno_isolation_and_timeout),
	};
	int rc = cmocka_run_group_tests(tests, NULL, NULL);
	random_exit();
	return rc;
}
