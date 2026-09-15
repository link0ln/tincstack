/*
    common.h -- shared QUIC endpoint for the stream-Q spike (ngtcp2 + GnuTLS).

    One ngtcp2 connection driven from a single-threaded poll() loop over one
    unconnected UDP socket, the way the tincd event loop would drive it: the
    library never touches the socket, every packet in and out passes through
    this file. Both the server and the client are built on this.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#ifndef SPIKE_COMMON_H
#define SPIKE_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include <gnutls/gnutls.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#define SPIKE_SCIDLEN 8                 /* connection id length this endpoint issues */
#define SPIKE_MAX_DGRAM 1200            /* one SPTPS data record fits (MTU-sized) */
#define SPIKE_DGRAM_QUEUE 32
#define SPIKE_STREAM_BUF 8192           /* append-only TX buffer; enough for the spike */
#define SPIKE_PKT_BUF 1452

typedef struct spike_conn_t {
	ngtcp2_crypto_conn_ref conn_ref;    /* what ngtcp2_crypto uses to find the conn from the TLS session */
	ngtcp2_conn *conn;
	gnutls_session_t session;
	gnutls_certificate_credentials_t cred;
	bool server;

	int fd;
	struct sockaddr_storage local;
	socklen_t locallen;

	bool handshake_done;
	bool closed;                        /* peer closed (draining) or we closed */
	ngtcp2_ccerr last_error;

	/* Meta path: one bidirectional stream. TX is an append-only buffer
	   because ngtcp2 needs the bytes to stay valid until acknowledged. */
	int64_t stream_id;
	uint8_t stream_buf[SPIKE_STREAM_BUF];
	size_t stream_len;                  /* bytes appended by the application */
	size_t stream_off;                  /* bytes already handed to ngtcp2 */
	bool stream_blocked;

	/* Data path: unreliable datagrams. ngtcp2 copies the payload into the
	   packet when it accepts one, so a small ring is enough. */
	struct {
		uint8_t data[SPIKE_MAX_DGRAM];
		size_t len;
	} dgram[SPIKE_DGRAM_QUEUE];
	size_t dgram_head;
	size_t dgram_n;
	uint64_t dgram_id;

	/* Application hooks. */
	void (*on_handshake)(struct spike_conn_t *sc);
	void (*on_stream_data)(struct spike_conn_t *sc, const uint8_t *data, size_t len);
	void (*on_datagram)(struct spike_conn_t *sc, const uint8_t *data, size_t len);
	void (*on_path_validation)(struct spike_conn_t *sc, const ngtcp2_path *path, ngtcp2_path_validation_result res);
	void (*on_first_packet)(struct spike_conn_t *sc, const uint8_t *pkt, size_t len);
	void *user;

	size_t pkts_sent;
} spike_conn_t;

ngtcp2_tstamp spike_now(void);
const char *spike_addr_str(const struct sockaddr *sa, socklen_t len, char *buf, size_t buflen);
int spike_addr_port(const struct sockaddr *sa);

/* Socket bound to host:port (port 0 = ephemeral); fills sc->local. */
int spike_bind(spike_conn_t *sc, const char *host, const char *port);

/* TLS session bound to sc. Server: cert+key PEM files. Client: pin is the
   expected SHA-256 fingerprint of the server certificate (hex, any case,
   colons allowed) and sni the name to send. alpn is sent by both. */
int spike_tls_init(spike_conn_t *sc, bool server, const char *cert_pem, const char *key_pem,
                   const char *pin, const char *alpn, const char *sni);

/* Fill the callback table and default settings / transport parameters shared
   by both roles (datagrams on, one bidi stream, idle timeout). */
void spike_callbacks(ngtcp2_callbacks *cb, bool server);
void spike_settings(ngtcp2_settings *settings, ngtcp2_transport_params *params);

/* Queue application data. */
int spike_stream_send(spike_conn_t *sc, const void *data, size_t len);
int spike_dgram_send(spike_conn_t *sc, const void *data, size_t len);

/* Drive the connection: write everything ngtcp2 has to send, read what is
   on the socket, handle timers. spike_run_until returns 0 when pred(sc)
   became true, 1 on the deadline, -1 on a connection error. */
int spike_flush(spike_conn_t *sc);
int spike_read(spike_conn_t *sc);
int spike_run_until(spike_conn_t *sc, bool (*pred)(spike_conn_t *sc), int timeout_ms);

/* Send CONNECTION_CLOSE and mark closed. */
void spike_close(spike_conn_t *sc);

/* Report what the TLS layer negotiated. */
void spike_report_tls(spike_conn_t *sc, const char *who);

#endif
