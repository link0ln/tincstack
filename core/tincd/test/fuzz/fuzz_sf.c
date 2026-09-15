/*
    fuzz_sf.c -- libFuzzer harness for the single-flow frame parser
    (transport_sf.c: sf_udp_receive() via transport_udp_dispatch()), i.e. what
    any Internet host can send to the UDP port before any authentication.

    The harness is stateful within one input: the input is a sequence of
    records [flags][len:2 BE][frame], each frame delivered as one datagram.
    flags bit0 selects one of two source addresses (so address-mismatch and
    session hijack paths are reached), bit1 advances the clock by a second
    (rate limiter). Sessions and connections are torn down after every input.

    Wrapped edges (-Wl,--wrap): sendto() (no socket), receive_meta_bytes()
    (echoes the bytes back into the connection's outbuf so the acceptor
    accumulates in-flight segments and the ACK/window logic runs; a payload
    starting with 0xff makes it fail, exercising the teardown path),
    terminate_connection() (carrier close + connection_del without the rest
    of the daemon), finish_connecting() (never dialled here).

    This program is free software; see the GPL v2+ (same as the rest of tinc).
*/

#include "system.h"
#include "buffer.h"
#include "connection.h"
#include "event.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "xalloc.h"

#define TINC_TRANSPORT_DAEMON
#include "transport.h"

bool __wrap_receive_meta_bytes(connection_t *c, char *buf, ssize_t len);
void __wrap_terminate_connection(connection_t *c, bool report);
ssize_t __wrap_sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *to, socklen_t tolen);
void __wrap_finish_connecting(connection_t *c);

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

static sockaddr_t peers[2];

int LLVMFuzzerInitialize(int *argc, char ***argv) {
	(void)argc;
	(void)argv;
	openlogger("fuzz_sf", LOGMODE_NULL);
	debug_level = DEBUG_NOTHING;
	init_connections();
	myself = new_node("me");
	myself->connection = new_connection();
	myself->connection->name = xstrdup("me");
	node_add(myself);
	now.tv_sec = 1000;
	max_connection_burst = 100;
	transport_accept_mask = TRANSPORT_BIT(TRANSPORT_PLAIN) | TRANSPORT_BIT(TRANSPORT_SF);
	listen_sockets = 1;
	listen_socket[0].udp.fd = -1;
	listen_socket[0].tcp.fd = -1;
	listen_socket[0].sa.in.sin_family = AF_INET;

	for(int i = 0; i < 2; i++) {
		peers[i].in.sin_family = AF_INET;
		peers[i].in.sin_port = htons(10000 + i);
		peers[i].in.sin_addr.s_addr = htonl(0x0a000001 + i);
	}

	return 0;
}

static void teardown(void) {
	for list_each(connection_t, c, &connection_list) {
		if(c != myself->connection) {
			__wrap_terminate_connection(c, false);
		}
	}

	sf_exit();
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
		transport_udp_dispatch(&listen_socket[0], frame, len, &peers[flags & 1]);
		free(frame);
		pos += len;
	}

	teardown();
	return 0;
}
