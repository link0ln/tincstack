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
             because the receive key is the peer->us direction key.

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

void __wrap_handle_incoming_vpn_packet_decap(listen_socket_t *ls, const uint8_t *buf, size_t len, const sockaddr_t *addr) {
	(void)ls;
	(void)buf;
	(void)len;
	(void)addr;
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
