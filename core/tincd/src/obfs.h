#ifndef TINC_OBFS_H
#define TINC_OBFS_H

/*
    obfs.h -- obfuscated-UDP carrier (M5, redesign of tinc-obfs).

    obfs is an outer wrapper around the UDP datagram flow. Every datagram it
    carries -- the single-flow meta frames and the SPTPS data datagrams -- is
    sealed with an authenticated frame keyed from material both peers already
    share (their Ed25519 public keys), so:

      * the junk/real discriminator is a Poly1305 tag, not a cleartext flag
        byte: an attacker without the key can neither forge a "real" datagram
        nor tell junk from real;
      * junk is emitted only around the handshake (ObfsJunkPacket*), never per
        data packet;
      * the receiver classifies the first datagram of a cold session with a
        keyed check (like try_harder() for SPTPS), so a cold tunnel comes up;
      * a relay strips the frame on receive and re-applies it per hop, so a
        relayed SPTPS record is never double-wrapped.

    SPTPS is never touched: obfs seals the bytes SPTPS already produced. See
    docs/transports.md, "Obfuscated UDP (obfs)".

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

#include "net.h"
#include "connection.h"
#include "node.h"

typedef struct obfs_link_t obfs_link_t;

/* ---- wire geometry ------------------------------------------------------- */

/* nonce(8) + clen(2) + Poly1305 tag(16): the smallest possible real frame
   wraps a zero-length inner payload. */
#define OBFS_NONCE_LEN 8
#define OBFS_CLEN_LEN  2
#define OBFS_TAG_LEN   16
#define OBFS_HDR_LEN   (OBFS_NONCE_LEN + OBFS_CLEN_LEN)
#define OBFS_MIN_FRAME (OBFS_HDR_LEN + OBFS_TAG_LEN)
#define OBFS_MAX_JUNK  1400

/* ---- configuration (parsed from the YAML/config tree) -------------------- */

extern int obfs_junk_count;        /* ObfsJunkPacketCount: junk datagrams around the handshake */
extern int obfs_junk_min;          /* ObfsJunkPacketMinSize */
extern int obfs_junk_max;          /* ObfsJunkPacketMaxSize */
extern int obfs_init_header_junk;  /* ObfsInitHeaderJunkSize: tail padding on handshake frames */
extern int obfs_transport_header_junk; /* ObfsTransportHeaderJunkSize: tail padding on steady frames */
extern uint32_t obfs_init_magic;   /* ObfsInitMagicHeader: shape the leading bytes of handshake frames */
extern uint32_t obfs_transport_magic;  /* ObfsTransportMagicHeader */

/* Parse the Obfs* options from config_tree. Never fails hard: bad values are
   clamped and warned about, so a running tunnel is never taken down by them. */
bool obfs_read_config(void);

/* One-time init after the listen sockets exist, and teardown. */
bool obfs_init(void);
void obfs_exit(void);

/* ---- carrier hooks (registered in transport.c) --------------------------- */

bool obfs_dial(connection_t *c);
void obfs_close(connection_t *c);

/* ---- per-link key material ----------------------------------------------- */

/* Get (creating if needed) the obfs link for a node. Returns NULL when the
   node has no Ed25519 public key yet (nothing to derive a key from). */
obfs_link_t *obfs_link_for_node(node_t *n);

/* Mark a link active and remember the peer's current UDP address, so inbound
   datagrams from it take the single-key fast path instead of a cold scan. */
void obfs_link_activate(obfs_link_t *l, const sockaddr_t *addr);

/* ---- framing ------------------------------------------------------------- */

/* Seal `inlen' bytes into `out' (capacity `outcap'); returns the framed
   length, or 0 on error. `init' selects handshake-phase shaping (magic +
   header junk) over steady-state shaping. */
size_t obfs_encode(obfs_link_t *l, const void *in, size_t inlen, uint8_t *out, size_t outcap, bool init);

/* SPTPS data path: if `to' is an active obfs link, seal `buf' and send it on
   listen_socket[sock], returning true. Returns false when `to' is not an obfs
   link, so the caller sends the datagram unchanged (byte-identical to plain
   tinc when obfs is not in use). */
bool obfs_wrap_send(size_t sock, const sockaddr_t *sa, const void *buf, size_t len, node_t *to);

/* ---- inbound ------------------------------------------------------------- */

/* Try to claim one inbound datagram: a keyed check unseals it and re-injects
   the inner datagram (a single-flow meta frame or an SPTPS record) into the
   normal receive path. Returns true if the datagram was an obfs frame (real
   or, after failing every key, silently dropped as junk from a known peer). */
bool obfs_udp_try(listen_socket_t *ls, const uint8_t *buf, size_t len, const sockaddr_t *addr);

/* Emit ObfsJunkPacketCount junk datagrams toward a peer (around a handshake).
   Junk carries no valid tag, so the peer drops it after the keyed check. */
void obfs_send_junk(size_t sock, const sockaddr_t *addr);

#endif /* TINC_OBFS_H */
