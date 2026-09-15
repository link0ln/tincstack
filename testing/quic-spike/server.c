/*
    server.c -- stream-Q spike: QUIC server on one UDP socket.

    Accepts exactly one connection (cold start from the first Initial packet,
    the way the tincd front classifier would hand it over), reports the
    negotiated ALPN/SNI, echoes datagrams and stream bytes back with a
    role-swapped prefix, logs every path validation (that is what a NAT
    rebind or a client migration triggers on this side), and exits when the
    peer closes.

    Usage: spike-server <bind-host> <port> <cert.pem> <key.pem> <alpn>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <gnutls/crypto.h>

#include "common.h"

static uint8_t static_secret[32];       /* for stateless reset tokens */

static void on_handshake(spike_conn_t *sc) {
	spike_report_tls(sc, "server");
}

static void on_datagram(spike_conn_t *sc, const uint8_t *data, size_t len) {
	char reply[SPIKE_MAX_DGRAM];
	int n = snprintf(reply, sizeof(reply), "s2c:%.*s", (int)len, (const char *)data);
	fprintf(stderr, "server DATAGRAM recv %zu bytes '%.*s'\n", len, (int)len, (const char *)data);
	spike_dgram_send(sc, reply, (size_t)n);
}

static void on_stream_data(spike_conn_t *sc, const uint8_t *data, size_t len) {
	char reply[512];
	int n = snprintf(reply, sizeof(reply), "server-ack:%.*s", (int)len, (const char *)data);
	fprintf(stderr, "server STREAM recv %zu bytes on stream %lld '%.*s'\n", len, (long long)sc->stream_id, (int)len, (const char *)data);
	spike_stream_send(sc, reply, (size_t)n);
}

static void on_path_validation(spike_conn_t *sc, const ngtcp2_path *path, ngtcp2_path_validation_result res) {
	(void)sc;
	char a[64];
	fprintf(stderr, "server PATH_VALIDATION %s remote=%s\n",
	        res == NGTCP2_PATH_VALIDATION_RESULT_SUCCESS ? "success" : res == NGTCP2_PATH_VALIDATION_RESULT_FAILURE ? "failure" : "aborted",
	        spike_addr_str(path->remote.addr, path->remote.addrlen, a, sizeof(a)));
}

static bool closed(spike_conn_t *sc) {
	return sc->closed;
}

/* Wait for the first packet, decide whether it is a QUIC Initial we can
   accept, and create the connection from it. This is exactly the decision
   the M4 UDP classifier makes before calling the carrier's udp_receive. */
static int accept_first(spike_conn_t *sc, const char *cert, const char *key, const char *alpn) {
	uint8_t buf[65536];
	struct sockaddr_storage from;
	socklen_t fromlen = sizeof(from);
	ssize_t n = recvfrom(sc->fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);

	if(n < 0) {
		fprintf(stderr, "recvfrom: %s\n", strerror(errno));
		return -1;
	}

	ngtcp2_version_cid vc;
	int rv = ngtcp2_pkt_decode_version_cid(&vc, buf, (size_t)n, SPIKE_SCIDLEN);

	if(rv) {
		fprintf(stderr, "server not a QUIC packet we understand: %s\n", ngtcp2_strerror(rv));
		return -1;
	}

	ngtcp2_pkt_hd hd;

	if(ngtcp2_accept(&hd, buf, (size_t)n)) {
		fprintf(stderr, "server first packet is not an acceptable Initial\n");
		return -1;
	}

	char a[64];
	fprintf(stderr, "server ACCEPT initial from %s len=%zd first_byte=0x%02x version=0x%08x dcidlen=%zu scidlen=%zu tokenlen=%zu\n",
	        spike_addr_str((struct sockaddr *)&from, fromlen, a, sizeof(a)), n, buf[0], hd.version,
	        hd.dcid.datalen, hd.scid.datalen, hd.tokenlen);

	if(spike_tls_init(sc, true, cert, key, NULL, alpn, NULL)) {
		return -1;
	}

	ngtcp2_callbacks cb;
	ngtcp2_settings settings;
	ngtcp2_transport_params params;
	spike_callbacks(&cb, true);
	spike_settings(&settings, &params);

	params.original_dcid = hd.dcid;
	params.original_dcid_present = 1;

	ngtcp2_cid scid = {.datalen = SPIKE_SCIDLEN};
	gnutls_rnd(GNUTLS_RND_RANDOM, scid.data, scid.datalen);

	if(ngtcp2_crypto_generate_stateless_reset_token(params.stateless_reset_token, static_secret, sizeof(static_secret), &scid)) {
		return -1;
	}

	params.stateless_reset_token_present = 1;

	ngtcp2_path path = {
		.local = {(struct sockaddr *)&sc->local, sc->locallen},
		.remote = {(struct sockaddr *)&from, fromlen},
	};

	rv = ngtcp2_conn_server_new(&sc->conn, &hd.scid, &scid, &path, hd.version, &cb, &settings, &params, NULL, sc);

	if(rv) {
		fprintf(stderr, "ngtcp2_conn_server_new: %s\n", ngtcp2_strerror(rv));
		return -1;
	}

	ngtcp2_conn_set_tls_native_handle(sc->conn, sc->session);

	ngtcp2_pkt_info pi = {0};
	rv = ngtcp2_conn_read_pkt(sc->conn, &path, &pi, buf, (size_t)n, spike_now());

	if(rv) {
		fprintf(stderr, "ngtcp2_conn_read_pkt(initial): %s\n", ngtcp2_strerror(rv));
		return -1;
	}

	return 0;
}

int main(int argc, char **argv) {
	if(argc != 6) {
		fprintf(stderr, "usage: %s <bind-host> <port> <cert.pem> <key.pem> <alpn>\n", argv[0]);
		return 2;
	}

	gnutls_global_init();
	gnutls_rnd(GNUTLS_RND_RANDOM, static_secret, sizeof(static_secret));

	spike_conn_t sc = {.stream_id = -1};
	ngtcp2_ccerr_default(&sc.last_error);
	sc.on_handshake = on_handshake;
	sc.on_datagram = on_datagram;
	sc.on_stream_data = on_stream_data;
	sc.on_path_validation = on_path_validation;

	if(spike_bind(&sc, argv[1], argv[2])) {
		return 1;
	}

	char a[64];
	fprintf(stderr, "server LISTEN %s\n", spike_addr_str((struct sockaddr *)&sc.local, sc.locallen, a, sizeof(a)));

	if(accept_first(&sc, argv[3], argv[4], argv[5])) {
		return 1;
	}

	int rv = spike_run_until(&sc, closed, 60000);

	if(rv < 0) {
		fprintf(stderr, "server FAIL connection error\n");
		spike_close(&sc);
		return 1;
	}

	if(rv == 1) {
		fprintf(stderr, "server FAIL timed out waiting for the client to close\n");
		spike_close(&sc);
		return 1;
	}

	fprintf(stderr, "server DONE pkts_sent=%zu\n", sc.pkts_sent);
	return 0;
}
