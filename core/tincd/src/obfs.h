#ifndef TINC_OBFS_H
#define TINC_OBFS_H

/*
    obfs.h -- obfuscated-UDP carrier (M5, redesign of tinc-obfs; hardened for
    security review R, findings M5-2..M5-6).

    obfs is an outer wrapper around the UDP datagram flow. Every datagram it
    carries -- the single-flow meta frames and the SPTPS data datagrams -- is
    sealed with an authenticated frame. The seal is the junk/real discriminator
    (a Poly1305 tag, not a cleartext flag) and hides tinc's fingerprint; SPTPS
    inside still provides identity and confidentiality and is never touched.

    Key schedule (frame format "v2"):

      * a per-direction BOOTSTRAP key is derived from the two nodes' Ed25519
        public keys. Both peers already hold those, so it is available before
        any handshake, which is what makes cold-start classification possible.
        Because every mesh member holds every public key, the bootstrap key is
        NOT a per-link secret: it is used only for the first datagrams, until a
        session key exists (finding M5-2).

      * a per-link SESSION key is derived from two fresh 32-byte seeds the peers
        exchange over the authenticated SPTPS meta channel (request OBFS_KEY)
        once the connection is up. Only the two endpoints know it; a third mesh
        member cannot derive it, so it can neither classify nor forge steady
        traffic. It is re-negotiated periodically (aligned with KeyExpire),
        which also bounds the per-key nonce space (M5-2, rekey).

      * keys are DIRECTION-SEPARATED (lo->hi and hi->lo labels), so a datagram
        reflected back to its sender never verifies (finding M5-5).

      * the ChaCha20-Poly1305 nonce is a strict per-direction 64-bit COUNTER
        (whitened on the wire by XOR with a key-derived mask), so it never
        repeats -> no keystream reuse or Poly1305 forgery. A configured magic
        header is a separate plaintext prefix that costs no nonce entropy
        (finding M5-3).

      * a sliding replay window on the counter rejects replayed datagrams, and
        the remembered peer address is moved only AFTER a datagram both
        verifies and is fresh (finding M5-4).

    Junk is emitted only around a handshake (ObfsJunkPacket*), never per data
    packet. On a relay the frame is stripped on receive and re-applied per hop,
    so a relayed SPTPS record is never double-wrapped.

    See docs/transports.md, "Obfuscated UDP (obfs)".

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

/* magic(0 or 4) | nonce(8) | clen(2) | ChaCha20-Poly1305(inner) | tail-junk.
   The nonce is the whitened counter; clen is the ciphertext length (network
   order). The smallest real frame wraps a zero-length inner payload. */
#define OBFS_MAGIC_LEN 4
#define OBFS_NONCE_LEN 8
#define OBFS_CLEN_LEN  2
#define OBFS_TAG_LEN   16
#define OBFS_HDR_LEN   (OBFS_NONCE_LEN + OBFS_CLEN_LEN)
#define OBFS_MIN_FRAME (OBFS_HDR_LEN + OBFS_TAG_LEN)
#define OBFS_MAX_OVERHEAD (OBFS_MAGIC_LEN + OBFS_HDR_LEN + OBFS_TAG_LEN)
#define OBFS_MAX_JUNK  1400

/* ---- path budget ---------------------------------------------------------

   tinc sets IP_MTU_DISCOVER (DF) on its UDP sockets, so a datagram larger than
   the path MTU is not fragmented: the kernel refuses it with EMSGSIZE. obfs
   adds OBFS_MAX_OVERHEAD plus up to OBFS_MAX_JUNK bytes of tail padding on TOP
   of a frame tinc already sized to the path, so every shaping option could push
   a datagram over the path MTU. Sizes are therefore computed against a per-link
   budget -- the UDP payload the path toward that peer can carry -- and never
   against a constant. See docs/transports.md, "obfs and the path MTU".

   OBFS_SAFE_MTU is what we assume when the kernel cannot tell us the route MTU
   (no IP_MTU/IPV6_MTU, or the query fails): the IPv6 minimum link MTU, the
   largest value that is safe everywhere. OBFS_INNER_FLOOR is the smallest inner
   payload we will squeeze a link down to before we start cutting junk instead:
   below it the meta stream would be chunked into uselessly small segments. */
#define OBFS_SAFE_MTU     1280
#define OBFS_PATH_TTL     10   /* seconds a cached per-link path budget is kept */
#define OBFS_INNER_FLOOR  256

/* Length of the per-link seed exchanged over the meta channel for the session
   key, and of the base64 that carries it on the wire. */
#define OBFS_SEED_LEN 32

/* ---- configuration (parsed from the YAML/config tree) -------------------- */

extern int obfs_junk_count;        /* ObfsJunkPacketCount: junk datagrams around the handshake */
extern int obfs_junk_min;          /* ObfsJunkPacketMinSize */
extern int obfs_junk_max;          /* ObfsJunkPacketMaxSize */
extern int obfs_init_header_junk;  /* ObfsInitHeaderJunkSize: tail padding on handshake frames */
extern int obfs_transport_header_junk; /* ObfsTransportHeaderJunkSize: tail padding on steady frames */
extern uint32_t obfs_init_magic;   /* ObfsInitMagicHeader: plaintext prefix on handshake frames */
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
   datagrams from it take the single-key fast path instead of a cold scan.
   Called only after a datagram has verified and passed the replay window. */
void obfs_link_activate(obfs_link_t *l, const sockaddr_t *addr);

/* True when the node's obfs link currently seals outbound traffic with a
   per-link session key rather than the mesh-wide bootstrap key (review R
   M5-2). Introspection for tests and diagnostics. */
bool obfs_link_has_session(node_t *n);

/* Restore a node's link to its freshly-created state (bootstrap key only).
   Test-only helper (see fuzz_obfs.c). */
void obfs_link_reset_for_test(node_t *n);

/* ---- session key handshake (over the authenticated meta channel) --------- */

/* After a connection over an obfs link activates, kick off the OBFS_KEY seed
   exchange that establishes the per-link session key. No-op for non-obfs
   connections, so ack_h can call it unconditionally. */
void obfs_session_start(connection_t *c);

/* Handle an OBFS_KEY request (declared as a request handler in protocol.h). */

/* ---- framing ------------------------------------------------------------- */

/* Seal `inlen' bytes into `out' (capacity `outcap'); returns the framed
   length, or 0 on error. `init' selects handshake-phase shaping (magic +
   header junk) over steady-state shaping. Uses the session key once it is
   ready, else the bootstrap key. */
size_t obfs_encode(obfs_link_t *l, const void *in, size_t inlen, uint8_t *out, size_t outcap, bool init);

/* Largest inner payload this link can seal without the sealed datagram
   exceeding the path MTU, with the configured tail junk still on it. The
   single-flow carrier chunks the meta stream against this, so shaping never
   costs a datagram: the stream simply takes one more segment. `init' selects
   handshake shaping (init magic + ObfsInitHeaderJunkSize) over steady-state. */
size_t obfs_max_inner(obfs_link_t *l, bool init);

/* SPTPS data path: if `to' is an active obfs link, seal `buf' and send it on
   listen_socket[sock]. See obfs_send_t; on OBFS_SEND_TOOBIG *excess holds how
   many bytes over the path budget the sealed datagram would have been, so the
   caller can hand the exact overshoot to tinc's PMTU machinery. */
typedef enum obfs_send_t {
	/* `to' is not an obfs link: the caller sends the datagram unchanged, so the
	   wire is byte-identical to plain tinc when obfs is not in use. */
	OBFS_SEND_PLAIN = 0,
	/* Sealed and handed to the socket. */
	OBFS_SEND_OK,
	/* Does not fit the path; the caller treats it exactly like EMSGSIZE. */
	OBFS_SEND_TOOBIG,
} obfs_send_t;

obfs_send_t obfs_wrap_send(size_t sock, const sockaddr_t *sa, const void *buf, size_t len, node_t *to, size_t *excess);

/* ---- inbound ------------------------------------------------------------- */

/* Try to claim one inbound datagram: a keyed check unseals it (session key
   first, then bootstrap), the replay window checks freshness, and on success
   the inner datagram (a single-flow meta frame or an SPTPS record) is
   re-injected into the normal receive path. Returns true if the datagram was
   an obfs frame (real, or a replay/junk from a known peer that is dropped). */
bool obfs_udp_try(listen_socket_t *ls, const uint8_t *buf, size_t len, const sockaddr_t *addr);

/* Emit ObfsJunkPacketCount junk datagrams toward a peer (around a handshake).
   Junk carries no valid tag, so the peer drops it after the keyed check. */
void obfs_send_junk(size_t sock, const sockaddr_t *addr);

#endif /* TINC_OBFS_H */
