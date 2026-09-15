/*
    client.c -- stream-Q spike: QUIC client exercising the carrier primitives.

    Phases, each printed as "RESULT PASS|FAIL <name>":
      handshake   TLS 1.3 inside QUIC, server cert checked by SHA-256 pin only
      stream      bytes both ways on one bidirectional stream (the meta path)
      datagram    unreliable DATAGRAM frames both ways (the SPTPS data path)
      rebind      the UDP source port changes under the session without the
                  client telling ngtcp2 anything but its new local address
                  (NAT rebinding as the server sees it); stream+datagrams
                  still flow
      migrate     explicit connection migration to a third port with a fresh
                  connection id (ngtcp2_conn_initiate_immediate_migration);
                  stream+datagrams still flow
      close       CONNECTION_CLOSE sent

    Usage: spike-client <host> <port> <sha256-pin> <alpn> <sni>
    Exit status 0 only if every phase passed.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <gnutls/crypto.h>

#include "common.h"

#define DGRAMS_PER_ROUND 5

static struct {
	int dgram_echoes;           /* s2c datagrams received in the current round */
	int stream_acks;            /* server-ack lines received in the current round */
	char last_stream[512];
	int failures;
	int path_ok;                /* client-side path validation successes (migrate) */
} st;

static void result(bool ok, const char *name, const char *detail) {
	fprintf(stderr, "RESULT %s %s%s%s\n", ok ? "PASS" : "FAIL", name, detail ? " -- " : "", detail ? detail : "");

	if(!ok) {
		st.failures++;
	}
}

static void on_handshake(spike_conn_t *sc) {
	spike_report_tls(sc, "client");
}

static void on_datagram(spike_conn_t *sc, const uint8_t *data, size_t len) {
	(void)sc;
	fprintf(stderr, "client DATAGRAM recv %zu bytes '%.*s'\n", len, (int)len, (const char *)data);

	if(len >= 4 && !memcmp(data, "s2c:", 4)) {
		st.dgram_echoes++;
	}
}

static void on_stream_data(spike_conn_t *sc, const uint8_t *data, size_t len) {
	(void)sc;
	fprintf(stderr, "client STREAM recv %zu bytes '%.*s'\n", len, (int)len, (const char *)data);

	/* The server echoes each message with a server-ack: prefix; count them
	   (a burst can arrive coalesced, so count prefixes, not callbacks). */
	for(size_t i = 0; i + 11 <= len; i++) {
		if(!memcmp(data + i, "server-ack:", 11)) {
			st.stream_acks++;
		}
	}

	snprintf(st.last_stream, sizeof(st.last_stream), "%.*s", (int)len, (const char *)data);
}

static void on_path_validation(spike_conn_t *sc, const ngtcp2_path *path, ngtcp2_path_validation_result res) {
	(void)sc;
	char a[64], b[64];
	fprintf(stderr, "client PATH_VALIDATION %s local=%s remote=%s\n",
	        res == NGTCP2_PATH_VALIDATION_RESULT_SUCCESS ? "success" : res == NGTCP2_PATH_VALIDATION_RESULT_FAILURE ? "failure" : "aborted",
	        spike_addr_str(path->local.addr, path->local.addrlen, a, sizeof(a)),
	        spike_addr_str(path->remote.addr, path->remote.addrlen, b, sizeof(b)));

	if(res == NGTCP2_PATH_VALIDATION_RESULT_SUCCESS) {
		st.path_ok++;
	}
}

/* The bytes the M4 UDP classifier keys on: long header form bit, fixed bit,
   and the 4-byte version word right behind the first byte. */
static void on_first_packet(spike_conn_t *sc, const uint8_t *pkt, size_t len) {
	(void)sc;
	uint32_t version = len >= 5 ? ((uint32_t)pkt[1] << 24 | (uint32_t)pkt[2] << 16 | (uint32_t)pkt[3] << 8 | pkt[4]) : 0;
	fprintf(stderr, "client FIRST_PKT len=%zu bytes[0..5]=%02x %02x %02x %02x %02x %02x form=%s fixed=%u type=%s version=0x%08x dcidlen=%u\n",
	        len, pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5],
	        (pkt[0] & 0x80) ? "long" : "short", (pkt[0] >> 6) & 1,
	        ((pkt[0] >> 4) & 3) == 0 ? "Initial" : "other", version, pkt[5]);
}

static bool handshake_done(spike_conn_t *sc) {
	return sc->handshake_done;
}

static int want_stream_acks;
static bool stream_round_done(spike_conn_t *sc) {
	(void)sc;
	return st.stream_acks >= want_stream_acks;
}

static int want_dgrams;
static bool dgram_round_done(spike_conn_t *sc) {
	(void)sc;
	return st.dgram_echoes >= want_dgrams;
}

/* One round of application traffic: a stream message, then a burst of
   datagrams, each side must answer. Returns true if both came back. */
static bool traffic_round(spike_conn_t *sc, const char *tag) {
	char msg[128];
	int n = snprintf(msg, sizeof(msg), "meta:%s\n", tag);
	want_stream_acks = st.stream_acks + 1;

	if(spike_stream_send(sc, msg, (size_t)n)) {
		return false;
	}

	int rv = spike_run_until(sc, stream_round_done, 3000);
	bool stream_ok = rv == 0 && strstr(st.last_stream, tag);

	want_dgrams = st.dgram_echoes;

	for(int i = 1; i <= DGRAMS_PER_ROUND; i++) {
		n = snprintf(msg, sizeof(msg), "%s-%d", tag, i);

		if(spike_dgram_send(sc, msg, (size_t)n)) {
			return false;
		}

		want_dgrams++;
	}

	rv = spike_run_until(sc, dgram_round_done, 3000);
	bool dgram_ok = rv == 0;

	fprintf(stderr, "client ROUND %s stream=%s datagrams=%d/%d\n", tag, stream_ok ? "ok" : "FAILED",
	        DGRAMS_PER_ROUND - (want_dgrams - st.dgram_echoes), DGRAMS_PER_ROUND);
	return stream_ok && dgram_ok;
}

/* Replace the UDP socket with a fresh one on a different ephemeral port.
   nat_rebind: only tell ngtcp2 the new local address (as if a NAT had
   changed the mapping; the server sees a new source port under the same
   connection id). Otherwise: explicit migration with a new connection id. */
static int rebind(spike_conn_t *sc, const char *host, bool nat_rebind, const struct sockaddr *remote, socklen_t remotelen) {
	int old_port = spike_addr_port((struct sockaddr *)&sc->local);
	int old_fd = sc->fd;

	for(int attempt = 0; attempt < 10; attempt++) {
		if(spike_bind(sc, host, "0")) {
			return -1;
		}

		if(spike_addr_port((struct sockaddr *)&sc->local) != old_port) {
			break;
		}

		close(sc->fd);
	}

	close(old_fd);

	char a[64];
	fprintf(stderr, "client REBIND %s: local port %d -> %s\n", nat_rebind ? "nat-rebind" : "migrate", old_port,
	        spike_addr_str((struct sockaddr *)&sc->local, sc->locallen, a, sizeof(a)));

	ngtcp2_addr local = {(struct sockaddr *)&sc->local, sc->locallen};

	if(nat_rebind) {
		ngtcp2_conn_set_local_addr(sc->conn, &local);
		return 0;
	}

	ngtcp2_path path = {.local = local, .remote = {(struct sockaddr *)remote, remotelen}};
	int rv = ngtcp2_conn_initiate_immediate_migration(sc->conn, &path, spike_now());

	if(rv) {
		fprintf(stderr, "ngtcp2_conn_initiate_immediate_migration: %s\n", ngtcp2_strerror(rv));
		return -1;
	}

	return 0;
}

int main(int argc, char **argv) {
	if(argc != 6) {
		fprintf(stderr, "usage: %s <host> <port> <sha256-pin> <alpn> <sni>\n", argv[0]);
		return 2;
	}

	const char *host = argv[1], *port = argv[2], *pin = argv[3], *alpn = argv[4], *sni = argv[5];

	gnutls_global_init();

	struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_DGRAM};
	struct addrinfo *res;
	int rv = getaddrinfo(host, port, &hints, &res);

	if(rv) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	struct sockaddr_storage remote;
	socklen_t remotelen = res->ai_addrlen;
	memcpy(&remote, res->ai_addr, remotelen);
	freeaddrinfo(res);

	spike_conn_t sc = {.stream_id = -1};
	ngtcp2_ccerr_default(&sc.last_error);
	sc.on_handshake = on_handshake;
	sc.on_datagram = on_datagram;
	sc.on_stream_data = on_stream_data;
	sc.on_path_validation = on_path_validation;
	sc.on_first_packet = on_first_packet;

	const char *bind_host = remote.ss_family == AF_INET6 ? "::" : "0.0.0.0";

	if(spike_bind(&sc, bind_host, "0") || spike_tls_init(&sc, false, NULL, NULL, pin, alpn, sni)) {
		return 1;
	}

	ngtcp2_callbacks cb;
	ngtcp2_settings settings;
	ngtcp2_transport_params params;
	spike_callbacks(&cb, false);
	spike_settings(&settings, &params);

	ngtcp2_cid dcid = {.datalen = NGTCP2_MIN_INITIAL_DCIDLEN}, scid = {.datalen = SPIKE_SCIDLEN};
	gnutls_rnd(GNUTLS_RND_RANDOM, dcid.data, dcid.datalen);
	gnutls_rnd(GNUTLS_RND_RANDOM, scid.data, scid.datalen);

	ngtcp2_path path = {
		.local = {(struct sockaddr *)&sc.local, sc.locallen},
		.remote = {(struct sockaddr *)&remote, remotelen},
	};

	rv = ngtcp2_conn_client_new(&sc.conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1, &cb, &settings, &params, NULL, &sc);

	if(rv) {
		fprintf(stderr, "ngtcp2_conn_client_new: %s\n", ngtcp2_strerror(rv));
		return 1;
	}

	ngtcp2_conn_set_tls_native_handle(sc.conn, sc.session);

	/* (a) handshake */
	rv = spike_run_until(&sc, handshake_done, 5000);
	result(rv == 0, "handshake", rv == 1 ? "timed out" : rv < 0 ? "connection error" : NULL);

	if(rv) {
		spike_close(&sc);
		return 1;
	}

	const ngtcp2_transport_params *peer = ngtcp2_conn_get_remote_transport_params(sc.conn);
	fprintf(stderr, "client PEER_PARAMS max_datagram_frame_size=%llu max_idle_timeout=%llums active_cid_limit=%llu disable_active_migration=%u\n",
	        (unsigned long long)peer->max_datagram_frame_size, (unsigned long long)(peer->max_idle_timeout / NGTCP2_MILLISECONDS),
	        (unsigned long long)peer->active_connection_id_limit, peer->disable_active_migration);

	/* (c) one bidirectional stream, (b) datagrams */
	int64_t sid;
	rv = ngtcp2_conn_open_bidi_stream(sc.conn, &sid, NULL);

	if(rv) {
		fprintf(stderr, "ngtcp2_conn_open_bidi_stream: %s\n", ngtcp2_strerror(rv));
		result(false, "stream", "could not open");
		result(false, "datagram", "skipped");
	} else {
		sc.stream_id = sid;
		fprintf(stderr, "client STREAM opened id=%lld\n", (long long)sid);
		int acks0 = st.stream_acks, dg0 = st.dgram_echoes;
		bool ok = traffic_round(&sc, "round1");
		result(st.stream_acks > acks0 && strstr(st.last_stream, "round1") != NULL, "stream", ok ? NULL : "see ROUND line");
		result(st.dgram_echoes - dg0 == DGRAMS_PER_ROUND, "datagram", ok ? NULL : "see ROUND line");
	}

	/* (d1) NAT rebind: new source port, same connection id */
	if(rebind(&sc, bind_host, true, (struct sockaddr *)&remote, remotelen) == 0) {
		result(traffic_round(&sc, "after-rebind"), "rebind", NULL);
	} else {
		result(false, "rebind", "could not rebind the socket");
	}

	/* (d2) explicit migration: new port and a fresh connection id */
	if(peer->disable_active_migration) {
		result(false, "migrate", "peer disables active migration");
	} else if(rebind(&sc, bind_host, false, (struct sockaddr *)&remote, remotelen) == 0) {
		bool ok = traffic_round(&sc, "after-migrate");
		result(ok && st.path_ok > 0, "migrate", ok ? (st.path_ok ? NULL : "traffic ok but no client-side path validation") : "traffic failed");
	} else {
		result(false, "migrate", "initiate_immediate_migration failed");
	}

	/* close */
	spike_close(&sc);
	result(sc.closed, "close", NULL);

	fprintf(stderr, "client DONE pkts_sent=%zu failures=%d\n", sc.pkts_sent, st.failures);
	return st.failures ? 1 : 0;
}
