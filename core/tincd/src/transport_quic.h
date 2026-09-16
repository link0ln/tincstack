#ifndef TINC_TRANSPORT_QUIC_H
#define TINC_TRANSPORT_QUIC_H

/*
    transport_quic.h -- the `quic' carrier (M5, stream G3).

    QUIC (ngtcp2 + GnuTLS) carries the tinc meta channel on one bidirectional
    stream and the SPTPS data records in DATAGRAM frames, over tinc's existing
    UDP listen socket. SPTPS is never touched: QUIC is an outer carrier
    (principle 1). Design and rationale: docs/transports.md §9.

    Compiled only when HAVE_QUIC (meson -Dquic, ngtcp2 + libngtcp2_crypto_gnutls
    + gnutls found). transport_quic.c holds the carrier and the event-loop glue;
    transport_quic_tls.c holds the ~60 GnuTLS-specific lines so another TLS
    backend can replace it per platform (§9.10).

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
*/

#include "system.h"

#ifdef HAVE_QUIC

#include "net.h"
#include "connection.h"

/* ---- carrier hooks (registered in transport.c under HAVE_QUIC) ----------- */

bool quic_init(void);
void quic_exit(void);
bool quic_read_config(void);            /* on reload: re-serve a replaced certificate */
bool quic_dial(struct connection_t *c);
bool quic_send(struct connection_t *c);
void quic_close(struct connection_t *c);
bool quic_local_address(struct connection_t *c, sockaddr_t *sa);
void quic_udp_receive(listen_socket_t *ls, const uint8_t *buf, size_t len, const sockaddr_t *addr);

/* Dispatcher entry: true if the datagram was a QUIC packet for a live session
   or a valid Initial that opened one; false lets it fall through to the obfs
   keyed check and the SPTPS path (a long-header lookalike is never eaten). */
bool quic_udp_try(listen_socket_t *ls, const uint8_t *buf, size_t len, const sockaddr_t *addr);

/* Data path (net_packet.c send_sptps_data): frame one SPTPS datagram as a
   QUIC DATAGRAM. Returns false when it does not fit the connection's current
   datagram ceiling, so the caller treats it exactly like EMSGSIZE and lets
   tinc's MTU probing converge (docs/transports.md §9.5). */
bool quic_send_datagram(struct connection_t *c, const void *buf, size_t len);

/* Classifier hook: short-header 1-RTT packets carry a destination connection
   id we issued and no version word, so the pure classifier cannot key on them.
   quic_init() registers its CID lookup with transport_set_quic_cid_matcher()
   (transport.h); transport_classify_udp() calls it for a short-header packet
   before falling through to SPTPS (docs/transports.md §9.5). */

#endif /* HAVE_QUIC */

#endif /* TINC_TRANSPORT_QUIC_H */
