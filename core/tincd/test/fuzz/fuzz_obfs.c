/*
    fuzz_obfs.c -- libFuzzer harness for the obfs unseal path
    (obfs.c: obfs_udp_try() via transport_udp_dispatch()), i.e. what any
    Internet host can send to the UDP port, plus deterministic unit-style
    self-tests for the review-R hardening that run once at startup (so
    `run.sh check', which executes the harness with -runs=0, still asserts
    them):

      (M5-3) nonce uniqueness: encoding a flood of frames on one link yields
             a strictly unique 8-byte wire nonce every time (the per-direction
             counter never repeats), even with a magic header configured (the
             magic is a separate prefix and steals no nonce entropy);
      (M5-5) direction separation / reflection: a frame WE encode (our tx
             direction) never verifies when fed back into our own receive path,
             because the receive key is the peer->us direction key;
      (v3)   header protection and random padding (wire audit 2026-09-26): over
             a flood of frames no wire field is the length, bytes 0-5 never
             repeat between consecutive frames, sizes vary, the tail stays in
             its bounds; frames the PEER seals (a second link built from the
             peer's point of view) round-trip in v3 and in v2, the receiver
             answers a v2-only peer in v2 and returns to v3, a tampered
             sample or a replay is not delivered, and the shortest frame
             (empty inner) round-trips.

    The fuzzed input then drives obfs_udp_try() with two node keys installed, so
    the fast path, cold-start key scan and replay window are all exercised on
    attacker-controlled bytes. Connections the SF inject path may create are
    torn down after every input.

    Wrapped edges (-Wl,--wrap): sendto (no socket), receive_meta_bytes,
    terminate_connection, finish_connecting (as in fuzz_sf), and
    handle_incoming_vpn_packet_decap (keep the SPTPS data path out of the
    unseal test -- the obfs layer is what is under test here).

    This program is free software; see the GPL v2+ (same as the rest of tinc).
*/

#include "system.h"
#include "buffer.h"
#include "connection.h"
#include "ecdsa.h"
#include "ecdsagen.h"
#include "event.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"

#define TINC_TRANSPORT_DAEMON
#include "transport.h"
#include "obfs.h"

bool __wrap_receive_meta_bytes(connection_t *c, char *buf, ssize_t len);
void __wrap_terminate_connection(connection_t *c, bool report);
ssize_t __wrap_sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *to, socklen_t tolen);
void __wrap_finish_connecting(connection_t *c);
void __wrap_handle_incoming_vpn_packet_decap(listen_socket_t *ls, const uint8_t *buf, size_t len, const sockaddr_t *addr);

bool __wrap_receive_meta_bytes(connection_t *c, char *buf, ssize_t len) {
	if(len > 0 && (uint8_t)buf[0] == 0xff) {
		return false;
	}

	if(len > 0 && c->outbuf.len < 65536) {
		buffer_add(&c->outbuf, buf, (uint32_t)len);
		transport_meta_flush(c);
	}

	return true;
}

void __wrap_terminate_connection(connection_t *c, bool report) {
	(void)report;
	transport_connection_close(c);
	connection_del(c);
}

ssize_t __wrap_sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *to, socklen_t tolen) {
	(void)fd;
	(void)buf;
	(void)flags;
	(void)to;
	(void)tolen;
	return (ssize_t)len;
}

void __wrap_finish_connecting(connection_t *c) {
	(void)c;
}

static unsigned decap_count;     /* inner datagrams delivered to the SPTPS path */
static size_t decap_len;
static uint8_t decap_buf[2048];

void __wrap_handle_incoming_vpn_packet_decap(listen_socket_t *ls, const uint8_t *buf, size_t len, const sockaddr_t *addr) {
	(void)ls;
	(void)addr;
	decap_count++;
	decap_len = len;

	if(len <= sizeof(decap_buf)) {
		memcpy(decap_buf, buf, len);
	}
}

static sockaddr_t peers[2];
static node_t *peer;

static uint64_t nonce_u64(const uint8_t *p) {
	uint64_t v = 0;

	for(int i = 0; i < 8; i++) {
		v = (v << 8) | p[i];
	}

	return v;
}

static int cmp_u64(const void *a, const void *b) {
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
	return (x > y) - (x < y);
}

/* (M5-3) A flood of encodes on one link must never reuse a wire nonce. */
static void selftest_nonce_unique(obfs_link_t *l) {
	enum { N = 100000 };
	uint64_t *seen = xmalloc(sizeof(uint64_t) * N);
	uint8_t payload[64];
	uint8_t frame[512];
	memset(payload, 0x5a, sizeof(payload));

	for(int i = 0; i < N; i++) {
		size_t flen = obfs_encode(l, payload, sizeof(payload), frame, sizeof(frame), false);

		if(flen < OBFS_MIN_FRAME) {
			fprintf(stderr, "SELFTEST: obfs_encode failed at %d\n", i);
			abort();
		}

		seen[i] = nonce_u64(frame); /* no magic here: nonce is at offset 0 */
	}

	qsort(seen, N, sizeof(uint64_t), cmp_u64);

	for(int i = 1; i < N; i++) {
		if(seen[i] == seen[i - 1]) {
			fprintf(stderr, "SELFTEST: obfs wire nonce repeated (%016llx)\n", (unsigned long long)seen[i]);
			abort();
		}
	}

	free(seen);
}

/* (M5-3) A configured magic header does not consume nonce entropy: it is a
   4-byte prefix and the 8 nonce bytes after it still vary per frame. */
static void selftest_magic_prefix(obfs_link_t *l) {
	extern uint32_t obfs_transport_magic;
	uint32_t saved = obfs_transport_magic;
	obfs_transport_magic = 0x17030300u;

	uint8_t payload[16];
	uint8_t f1[128], f2[128];
	memset(payload, 0x11, sizeof(payload));

	size_t n1 = obfs_encode(l, payload, sizeof(payload), f1, sizeof(f1), false);
	size_t n2 = obfs_encode(l, payload, sizeof(payload), f2, sizeof(f2), false);

	if(n1 < OBFS_MAGIC_LEN + OBFS_MIN_FRAME || n2 < OBFS_MAGIC_LEN + OBFS_MIN_FRAME) {
		fprintf(stderr, "SELFTEST: obfs_encode with magic failed\n");
		abort();
	}

	/* magic bytes present as a plaintext prefix */
	if(f1[0] != 0x17 || f1[1] != 0x03 || f1[2] != 0x03 || f1[3] != 0x00) {
		fprintf(stderr, "SELFTEST: magic prefix not on the wire\n");
		abort();
	}

	/* nonce region (after the 4-byte magic) differs between the two frames */
	if(!memcmp(f1 + OBFS_MAGIC_LEN, f2 + OBFS_MAGIC_LEN, OBFS_NONCE_LEN)) {
		fprintf(stderr, "SELFTEST: nonce did not advance under a magic header\n");
		abort();
	}

	obfs_transport_magic = saved;
}

/* (M5-5) A frame we encoded (our tx direction) must not verify on our own
   receive path -- direction-separated keys defeat reflection. */
static void selftest_reflection(obfs_link_t *l) {
	uint8_t payload[32];
	uint8_t frame[128];
	memset(payload, 0x77, sizeof(payload));
	size_t flen = obfs_encode(l, payload, sizeof(payload), frame, sizeof(frame), false);

	if(flen < OBFS_MIN_FRAME) {
		abort();
	}

	/* Feed our own (tx-direction) frame into the receive path. It uses the
	   rx = peer->us key, so it must NOT unseal. obfs_udp_try returns false
	   (nothing claimed it). */
	if(obfs_udp_try(&listen_socket[0], frame, flen, &peers[0])) {
		fprintf(stderr, "SELFTEST: a reflected obfs frame verified (direction keys not separated)\n");
		abort();
	}
}

/* (M5-2 residual) Closing a SUPERSEDED sibling connection must not wipe the
   session key the surviving connection holds. Reproduces the exact
   terminate_connection() ordering: node->connection is cleared BEFORE the
   carrier close hook runs, so at obfs_close() time node->connection is NULL
   while a replacement connection is already on the connection_list. obfs_close
   must decide "another connection survives" from that list, not from
   node->connection -- otherwise it drops the link back to the mesh-wide
   bootstrap key. On the pre-fix code (node->connection check) this aborts. */
/* The peer's own link toward us: its keys are ours mirrored (tx <-> rx), so
   what it seals is what our receive path must open. Built by pretending, for
   the duration of obfs_link_for_node(), that `myself' is the peer. The node
   it points at is NOT in node_tree, so our cold scan never tries it. */
static obfs_link_t *peer_view;
static node_t *as_peer;   /* kept reachable: it lives as long as the process */

static obfs_link_t *build_peer_view(void) {
	node_t *saved = myself;
	as_peer = new_node("peer-self");
	as_peer->connection = new_connection();
	as_peer->connection->name = xstrdup("peer-self");
	as_peer->connection->ecdsa = peer->ecdsa;
	node_t *me_remote = new_node("me-remote");
	me_remote->ecdsa = saved->connection->ecdsa;

	myself = as_peer;
	obfs_link_t *pl = obfs_link_for_node(me_remote);
	myself = saved;

	if(!pl) {
		fprintf(stderr, "SELFTEST: could not build the peer's view of the link\n");
		abort();
	}

	return pl;
}

static void fail(const char *what) {
	fprintf(stderr, "SELFTEST: %s\n", what);
	abort();
}

/* Hand a frame to the receive path from the peer's address; the cold scan
   budget is per second, so step the clock for every datagram. */
static bool deliver(const uint8_t *frame, size_t len) {
	now.tv_sec++;
	return obfs_udp_try(&listen_socket[0], frame, len, &peers[0]);
}

/* (v3) What an observer of our frames can count: the length field, a
   constant prefix, a small size set. Bounds are loose on purpose (the
   expected counts for random bytes are well under 1); the old v2 wire failed
   each of them on every single frame. */
static void selftest_wire_random(obfs_link_t *l) {
	enum { N = 20000 };
	static const size_t inner_sizes[2] = { 125, 1061 };
	uint8_t payload[1100];
	uint8_t frame[1600];
	uint8_t prev[6] = { 0 };
	unsigned len_rule = 0, same6 = 0;
	unsigned seen[2][OBFS_PAD_DATA + 1];
	memset(seen, 0, sizeof(seen));
	memset(payload, 0x42, sizeof(payload));

	for(int i = 0; i < N; i++) {
		size_t in = inner_sizes[i & 1];
		size_t flen = obfs_encode(l, payload, in, frame, sizeof(frame), false);
		size_t min = OBFS_MIN_FRAME + in;

		if(flen < min || flen > min + OBFS_PAD_DATA) {
			fail("steady-state frame outside [inner + seal, inner + seal + OBFS_PAD_DATA]");
		}

		seen[i & 1][flen - min]++;
		len_rule += (size_t)((frame[8] << 8) | frame[9]) == flen - OBFS_HDR_LEN;
		len_rule += (size_t)((frame[8] << 8) | frame[9]) == in + OBFS_TAG_LEN;

		if(i && !memcmp(prev, frame, 6)) {
			same6++;
		}

		memcpy(prev, frame, 6);
	}

	if(len_rule > 10) {
		fprintf(stderr, "SELFTEST: bytes 8-9 carry the length in %u of %d frames\n", len_rule, N);
		abort();
	}

	if(same6) {
		fprintf(stderr, "SELFTEST: %u consecutive frames share bytes 0-5\n", same6);
		abort();
	}

	for(int k = 0; k < 2; k++) {
		unsigned distinct = 0;

		for(int t = 0; t <= OBFS_PAD_DATA; t++) {
			distinct += seen[k][t] != 0;
		}

		if(distinct < OBFS_PAD_DATA) {
			fprintf(stderr, "SELFTEST: only %u distinct tail lengths for one inner size\n", distinct);
			abort();
		}
	}

	/* Handshake-phase frames get the larger floor. */
	unsigned init_max = 0;

	for(int i = 0; i < 2000; i++) {
		size_t flen = obfs_encode(l, payload, 36, frame, sizeof(frame), true);

		if(flen < OBFS_MIN_FRAME + 36 || flen > OBFS_MIN_FRAME + 36 + OBFS_PAD_INIT) {
			fail("handshake frame outside its padding bounds");
		}

		if(flen - OBFS_MIN_FRAME - 36 > init_max) {
			init_max = (unsigned)(flen - OBFS_MIN_FRAME - 36);
		}
	}

	if(init_max < OBFS_PAD_INIT / 2) {
		fail("handshake frames are not padded over the handshake range");
	}
}

/* (v3) Frames sealed by the peer, in v3 and in v2, open on our side; we
   answer a v2-only peer in v2 and go back to v3 when it does. */
static void selftest_roundtrip(obfs_link_t *l) {
	uint8_t payload[200];
	uint8_t frame[1600];

	for(size_t i = 0; i < sizeof(payload); i++) {
		payload[i] = (uint8_t)(i * 7 + 1);   /* not the SF magic: SPTPS path */
	}

	/* v3, including the empty inner (the frame is exactly the seal, and the
	   sample is the bare tag). */
	static const size_t sizes[3] = { 0, 1, sizeof(payload) };

	for(int i = 0; i < 3; i++) {
		unsigned before = decap_count;
		size_t flen = obfs_encode(peer_view, payload, sizes[i], frame, sizeof(frame), false);

		if(!deliver(frame, flen) || decap_count != before + 1 || decap_len != sizes[i] || memcmp(decap_buf, payload, sizes[i])) {
			fail("a v3 frame from the peer did not round-trip");
		}

		if(obfs_link_frame_version(l) != OBFS_FRAME_V3) {
			fail("a v3 peer moved our sealing off v3");
		}

		/* The same datagram again is a replay: claimed, not delivered. */
		if(!deliver(frame, flen) || decap_count != before + 1) {
			fail("a replayed v3 frame was delivered");
		}
	}

	/* A flipped bit in the sample changes the mask and the tag input: the
	   frame no longer opens under any key or version. */
	{
		unsigned before = decap_count;
		size_t flen = obfs_encode(peer_view, payload, 64, frame, sizeof(frame), false);
		frame[OBFS_HDR_LEN + 3] ^= 0x10;
		deliver(frame, flen);

		if(decap_count != before) {
			fail("a frame with a tampered sample was delivered");
		}
	}

	/* The peer turns into an older build: v2 frames, header in the clear. */
	obfs_link_force_v2_for_test(peer_view, true);
	{
		unsigned before = decap_count;
		size_t flen = obfs_encode(peer_view, payload, 64, frame, sizeof(frame), false);

		if((size_t)((frame[8] << 8) | frame[9]) != 64 + OBFS_TAG_LEN) {
			fail("a v2 frame does not carry clen in the clear");
		}

		if(!deliver(frame, flen) || decap_count != before + 1 || decap_len != 64) {
			fail("a v2 frame from an older peer did not open");
		}

		if(obfs_link_frame_version(l) != OBFS_FRAME_V2) {
			fail("we do not answer a v2-only peer in v2");
		}

		/* ...and our v2 answer is what an older peer reads: clen in clear. */
		flen = obfs_encode(l, payload, 64, frame, sizeof(frame), false);

		if((size_t)((frame[8] << 8) | frame[9]) != 64 + OBFS_TAG_LEN) {
			fail("our answer to a v2 peer is not a v2 frame");
		}
	}

	/* The peer is upgraded again: its first v3 frame moves us back. */
	obfs_link_force_v2_for_test(peer_view, false);
	{
		size_t flen = obfs_encode(peer_view, payload, 64, frame, sizeof(frame), false);

		if(!deliver(frame, flen) || obfs_link_frame_version(l) != OBFS_FRAME_V3) {
			fail("a v3 frame did not move a v2 link back to v3");
		}
	}

	/* A magic prefix still works in front of a protected header. */
	{
		extern uint32_t obfs_transport_magic;
		uint32_t saved = obfs_transport_magic;
		obfs_transport_magic = 0x17030300u;
		unsigned before = decap_count;
		size_t flen = obfs_encode(peer_view, payload, 64, frame, sizeof(frame), false);
		bool ok = frame[0] == 0x17 && deliver(frame, flen) && decap_count == before + 1;
		obfs_transport_magic = saved;

		if(!ok) {
			fail("a v3 frame behind a magic prefix did not round-trip");
		}
	}
}

static void selftest_close_preserves_session(void) {
	/* Owner connection over the obfs carrier, dialled so it owns an sf session
	   whose ->obfs points at the shared link (obfs_close finds it that way). */
	connection_t *c1 = new_connection();
	c1->name = xstrdup("peer");
	c1->hostname = xstrdup("peer");
	c1->address = peers[0];
	c1->protocol_minor = 0;    /* legacy meta path: no SPTPS state to set up */

	if(!obfs_dial(c1)) {       /* creates the sf session and adds c1 to the list */
		fprintf(stderr, "SELFTEST: obfs_dial failed\n");
		abort();
	}

	c1->node = peer;
	peer->connection = c1;
	c1->allow_request = ALL;
	c1->transport = transport_get(TRANSPORT_OBFS);

	/* Drive the OBFS_KEY seed exchange to a promoted session key: our offer,
	   then the peer's offer (flag 0) and the peer's ack (flag 1). */
	obfs_session_start(c1);

	uint8_t seed[OBFS_SEED_LEN];
	memset(seed, 0x33, sizeof(seed));
	char b64[OBFS_SEED_LEN * 2];
	b64encode_tinc(seed, b64, OBFS_SEED_LEN);

	char req[128];
	snprintf(req, sizeof(req), "%d 0 %s", OBFS_KEY, b64);
	obfs_key_h(c1, req);
	snprintf(req, sizeof(req), "%d 1 %s", OBFS_KEY, b64);
	obfs_key_h(c1, req);

	if(!obfs_link_has_session(peer)) {
		fprintf(stderr, "SELFTEST: could not establish an obfs session key for the test\n");
		abort();
	}

	/* A second, surviving connection to the same node (the winner of a
	   simultaneous dial): on the connection_list, but its node->connection
	   link is not yet what obfs_close would see. */
	connection_t *c2 = new_connection();
	c2->name = xstrdup("peer");
	c2->hostname = xstrdup("peer");
	c2->node = peer;
	connection_add(c2);

	/* terminate_connection() clears node->connection when closing the owner,
	   BEFORE the carrier close hook. Reproduce that, then close c1. */
	peer->connection = NULL;
	obfs_close(c1);

	if(!obfs_link_has_session(peer)) {
		fprintf(stderr, "SELFTEST: obfs_close wiped the session a surviving connection still held (M5-2 residual)\n");
		abort();
	}

	/* Tidy up and leave the shared link exactly as freshly created, so the
	   fuzzed body below starts from the same state as before this self-test. */
	connection_del(c1);   /* frees c1 (list .delete = free_connection) */
	__wrap_terminate_connection(c2, false);
	peer->connection = NULL;
	obfs_link_reset_for_test(peer);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
	(void)argc;
	(void)argv;
	openlogger("fuzz_obfs", LOGMODE_NULL);
	debug_level = DEBUG_NOTHING;
	init_connections();

	myself = new_node("me");
	myself->connection = new_connection();
	myself->connection->name = xstrdup("me");
	myself->connection->ecdsa = ecdsa_generate();
	node_add(myself);

	peer = new_node("peer");
	peer->ecdsa = ecdsa_generate();
	node_add(peer);

	now.tv_sec = 1000;
	max_connection_burst = 100;
	transport_accept_mask = TRANSPORT_BIT(TRANSPORT_PLAIN) | TRANSPORT_BIT(TRANSPORT_SF) | TRANSPORT_BIT(TRANSPORT_OBFS);
	listen_sockets = 1;
	listen_socket[0].udp.fd = -1;
	listen_socket[0].tcp.fd = -1;
	listen_socket[0].sa.in.sin_family = AF_INET;

	for(int i = 0; i < 2; i++) {
		peers[i].in.sin_family = AF_INET;
		peers[i].in.sin_port = htons(10000 + i);
		peers[i].in.sin_addr.s_addr = htonl(0x0a000001 + i);
	}

	obfs_link_t *l = obfs_link_for_node(peer);

	if(!l) {
		fprintf(stderr, "SELFTEST: could not build an obfs link\n");
		abort();
	}

	selftest_nonce_unique(l);
	selftest_magic_prefix(l);
	selftest_reflection(l);
	selftest_wire_random(l);

	peer_view = build_peer_view();
	selftest_roundtrip(l);
	obfs_link_reset_for_test(peer);
	obfs_link_force_v2_for_test(peer_view, false);

	selftest_close_preserves_session();
	decap_count = 0;
	return 0;
}

static void teardown(void) {
	for list_each(connection_t, c, &connection_list) {
		if(c != myself->connection) {
			__wrap_terminate_connection(c, false);
		}
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	size_t pos = 0;

	while(pos + 3 <= size) {
		uint8_t flags = data[pos];
		size_t len = ((size_t)data[pos + 1] << 8) | data[pos + 2];
		pos += 3;

		if(len > size - pos) {
			len = size - pos;
		}

		if(flags & 2) {
			now.tv_sec++;
		}

		uint8_t *frame = xmalloc(len ? len : 1);
		memcpy(frame, data + pos, len);
		obfs_udp_try(&listen_socket[0], frame, len, &peers[flags & 1]);
		free(frame);
		pos += len;
	}

	teardown();
	return 0;
}
