#include "unittest.h"
#include "../../src/quic_txq.h"

/* What a stream's bytes are, by offset: a pattern that shows a byte moved. */
static uint8_t at(uint64_t off) {
	return (uint8_t)(off * 131 + (off >> 8));
}

static void append_pattern(quic_txq_t *q, size_t len) {
	uint8_t buf[9000];
	assert_true(len <= sizeof(buf));

	for(size_t i = 0; i < len; i++) {
		buf[i] = at(q->end + i);
	}

	quic_txq_append(q, buf, len);
}

/* Hand out everything pending, as ngtcp2 would take it: packets of at most
   `mtu' bytes. Every piece is remembered, to be read again later (a
   retransmission). */
typedef struct handed_t {
	quic_txq_vec_t v;
	uint64_t off;
} handed_t;

static size_t hand_out(quic_txq_t *q, handed_t *h, size_t nh, size_t mtu) {
	size_t n = 0;

	while(quic_txq_unsent(q) && n < nh) {
		quic_txq_vec_t v[4];
		size_t cnt = quic_txq_pending(q, v, 4, mtu);
		assert_true(cnt > 0);
		size_t took = 0;

		for(size_t i = 0; i < cnt && n < nh; i++) {
			h[n].v = v[i];
			h[n].off = q->sent + took;
			took += v[i].len;
			n++;
		}

		quic_txq_sent(q, took);
	}

	return n;
}

static void check_handed(const handed_t *h, size_t n, uint64_t acked) {
	for(size_t i = 0; i < n; i++) {
		for(size_t j = 0; j < h[i].v.len; j++) {
			if(h[i].off + j >= acked) {
				assert_int_equal(h[i].v.base[j], at(h[i].off + j));
			}
		}
	}
}

/* The defect this replaced: bytes in flight moved when more were appended
   (realloc) or when a prefix was acknowledged (memmove). Here every byte
   handed out and not acknowledged is still where it was, with its value,
   across appends that outgrow any chunk and partial acknowledgments; ASan
   would flag a read of a freed chunk. */
static void test_in_flight_bytes_never_move(void **state) {
	(void)state;
	quic_txq_t q = {0};
	static handed_t h[4096];
	size_t n = 0;

	append_pattern(&q, 10);
	n += hand_out(&q, h + n, 4096 - n, 1200);

	for(int round = 0; round < 40; round++) {
		append_pattern(&q, (size_t)(round * 211 % 8999) + 1);
		n += hand_out(&q, h + n, 4096 - n, 1200);
		check_handed(h, n, q.acked);

		/* Acknowledge a prefix that ends inside a chunk. */
		quic_txq_ack(&q, q.acked + (q.sent - q.acked) / 3);
		check_handed(h, n, q.acked);
	}

	quic_txq_ack(&q, q.end);
	assert_int_equal(quic_txq_chunks(&q), 0);
	assert_int_equal(q.acked, q.end);

	/* Appending after everything was acknowledged starts a new chunk at the
	   right offset. */
	uint64_t off = q.end;
	append_pattern(&q, 5);
	quic_txq_vec_t v;
	assert_int_equal(quic_txq_pending(&q, &v, 1, 100), 1);
	assert_int_equal(v.len, 5);

	for(size_t i = 0; i < 5; i++) {
		assert_int_equal(v.base[i], at(off + i));
	}

	quic_txq_free(&q);
}

/* Small appends share a chunk; the chunk goes only when all of it is
   acknowledged. */
static void test_chunks_freed_by_ack(void **state) {
	(void)state;
	quic_txq_t q = {0};

	for(int i = 0; i < 3 * QUIC_TXQ_CHUNK / 100; i++) {
		append_pattern(&q, 100);
	}

	assert_int_equal(quic_txq_chunks(&q), 3);
	quic_txq_vec_t v[8];
	assert_int_equal(quic_txq_pending(&q, v, 8, SIZE_MAX), 3);
	assert_int_equal(v[0].len, QUIC_TXQ_CHUNK);
	quic_txq_sent(&q, (size_t)q.end);

	quic_txq_ack(&q, QUIC_TXQ_CHUNK - 1);
	assert_int_equal(quic_txq_chunks(&q), 3);
	quic_txq_ack(&q, QUIC_TXQ_CHUNK);
	assert_int_equal(quic_txq_chunks(&q), 2);
	assert_int_equal(q.base, QUIC_TXQ_CHUNK);

	/* An old or repeated acknowledgment changes nothing. */
	quic_txq_ack(&q, 10);
	assert_int_equal(q.acked, QUIC_TXQ_CHUNK);

	quic_txq_free(&q);
	assert_null(q.head);
}

/* `max' and `nvec' bound what is handed out; the pieces continue exactly
   where the last hand-out ended. */
static void test_pending_limits(void **state) {
	(void)state;
	quic_txq_t q = {0};
	append_pattern(&q, QUIC_TXQ_CHUNK + 50);        /* one chunk of its own size */
	append_pattern(&q, 30);
	quic_txq_vec_t v[2];

	assert_int_equal(quic_txq_pending(&q, v, 2, 1), 1);
	assert_int_equal(v[0].len, 1);
	quic_txq_sent(&q, 1);

	assert_int_equal(quic_txq_pending(&q, v, 1, SIZE_MAX), 1);
	assert_int_equal(v[0].len, QUIC_TXQ_CHUNK + 49);
	assert_int_equal(v[0].base[0], at(1));

	assert_int_equal(quic_txq_pending(&q, v, 2, SIZE_MAX), 2);
	assert_int_equal(v[1].len, 30);
	assert_int_equal(v[1].base[0], at(QUIC_TXQ_CHUNK + 50));

	quic_txq_sent(&q, QUIC_TXQ_CHUNK + 79);
	assert_int_equal(quic_txq_unsent(&q), 0);
	assert_int_equal(quic_txq_pending(&q, v, 2, SIZE_MAX), 0);
	quic_txq_free(&q);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_in_flight_bytes_never_move),
		cmocka_unit_test(test_chunks_freed_by_ack),
		cmocka_unit_test(test_pending_limits),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
