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

    Key schedule (frame format "v2", header protection added in "v3"):

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

      * frame v3 protects the header as QUIC does (RFC 9001 5.4): nonce and
        clen are XORed with a ChaCha20 block keyed by a separate per-direction
        header key over a 16-byte sample of the ciphertext, and the tail
        padding length is drawn from the same block. Nothing on the wire is
        then constant or a length (wire audit 2026-09-26). The receiver also
        accepts v2 and answers a v2-only peer in v2; there is no version
        field on the wire.

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
   order). The smallest real frame wraps a zero-length inner payload. In frame
   v3 the ten header bytes are masked (see OBFS_HP_SAMPLE_LEN); the ciphertext
   is always at least OBFS_TAG_LEN bytes, so the sample exists for the
   smallest frame too. */
#define OBFS_MAGIC_LEN 4
#define OBFS_NONCE_LEN 8
#define OBFS_CLEN_LEN  2
#define OBFS_TAG_LEN   16
#define OBFS_HDR_LEN   (OBFS_NONCE_LEN + OBFS_CLEN_LEN)
#define OBFS_MIN_FRAME (OBFS_HDR_LEN + OBFS_TAG_LEN)
#define OBFS_MAX_OVERHEAD (OBFS_MAGIC_LEN + OBFS_HDR_LEN + OBFS_TAG_LEN)
#define OBFS_MAX_JUNK  1400

/* Frame versions. v2: header in the clear. v3: header protection. What we
   send to a peer is v3 unless that peer has only ever spoken v2 to us (an
   older tincstack); what we accept is both. */
#define OBFS_FRAME_V2      2
#define OBFS_FRAME_V3      3
#define OBFS_FRAME_VERSION OBFS_FRAME_V3

/* Header protection sample: the first 16 ciphertext bytes, i.e. the bytes
   right after the (masked) header. */
#define OBFS_HP_SAMPLE_LEN 16

/* Per-datagram random tail padding (wire audit 2026-09-26: sizes were the
   inner sizes plus a constant). Every frame gets a tail of a length drawn
   uniformly from [0, max(configured header junk, floor)], never beyond the
   path budget. The floor is larger for handshake-phase frames: there are few
   of them and their inner sizes are the most characteristic. */
#define OBFS_PAD_INIT 256
#define OBFS_PAD_DATA 64

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
extern int obfs_init_header_junk;  /* ObfsInitHeaderJunkSize: max tail padding on handshake frames (reserved in the MTU) */
extern int obfs_transport_header_junk; /* ObfsTransportHeaderJunkSize: max tail padding on steady frames (reserved in the MTU) */
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

/* Pick the dedicated ObfsPort UDP socket fd for `sa', or -1 if none */
int obfs_pick_socket(const sockaddr_t *sa);

/* Burst-aware padding for inner ClientHellos (displace bursts from nDPI centroids) */
void obfs_pad_next_burst(node_t *n);

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

/* Frame version this link currently seals with (OBFS_FRAME_V2 or _V3), and a
   test-only override that makes it seal as a v2-only (older) peer would. */
int obfs_link_frame_version(const obfs_link_t *l);
void obfs_link_force_v2_for_test(obfs_link_t *l, bool v2);

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

/* ---- direct seal (DirectSeal, stream N2 2026-09-26) ------------------------

   The direct peer-to-peer UDP path (SPTPS data datagrams, UDP probes, probe
   replies) used to be cleartext tinc whatever carrier hid the meta
   connection: six zero bytes, the sender's node id, 51-byte probes
   (docs/nat.md §5.3). A node that runs a masking carrier now seals every such
   datagram in an obfs frame v3 -- the obfs link of that peer, i.e. the same
   keys, counters, replay window and random tails as the obfs carrier -- from
   the very first probe.

   Keys: until a session exists, the pair's bootstrap key (derived from the
   two Ed25519 public keys, as obfs). The session key is negotiated end to end
   by DSEAL_KEX: a signed ephemeral X25519 exchange carried as a REQ_KEY
   extension through the meta graph, signed with each node's Ed25519 key, so
   a relay forwards it but can neither read nor forge the key. SPTPS is not
   touched and not weakened: the seal is an outer layer, SPTPS inside it is
   unchanged.

   Who seals (DirectSeal = auto, the default): a node whose
   PreferredTransports lists obfs, https or quic, or that refuses cleartext
   meta (AllowPlainMeta = no). `yes' always seals, `no' never. A node that
   does not seal itself still seals towards a peer that asks for it (the
   peer's `wants' flag) and answers a peer that sealed to it in kind, so a
   masking node's direct path is sealed in both directions; between two
   nodes that do not seal the wire is upstream tinc's, byte for byte.

   Capability travels as one trailing token, `dseal=<hex flags>', on ACK and
   ANS_PUBKEY; older parsers stop before it. A peer without the token is an
   older tincstack (it reads a sealed datagram iff it accepts obfs: its
   cold-scan classifier unseals bootstrap-key frames) or upstream tinc (it
   reads none). A sealing node sends no direct UDP at all to a peer that
   cannot read it -- the pair stays on the relay, and the log says why. The
   one peer that cannot be told apart in advance is a tincstack from before
   obfs frame v3 (reads v2 only): it gets sealed probes it drops, the direct
   path never confirms, the pair stays on the relay, and after
   DSEAL_UNREAD_NOTE seconds the log says so. */

#define DSEAL_READS 0x01  /* reads sealed direct datagrams */
#define DSEAL_WANTS 0x02  /* seals its own and wants ours sealed */
#define DSEAL_KEX   0x04  /* speaks DSEAL_KEX (end-to-end session key) */
#define DSEAL_PUNCH 0x08  /* coordinated hole punch (net_packet.c, PUNCH_REQ);
                             not a seal property, but the same capability token */
#define DSEAL_OLD   0x40  /* learned without a token: older tincstack or upstream */
#define DSEAL_KNOWN 0x80  /* learned at all (token, or a definitive answer without one) */

/* REQ_KEY extension number of the direct-seal key exchange. Outside the
   request_t range; only ever sent to a peer that advertised DSEAL_KEX, and
   forwarded verbatim by any relay (upstream included). */
#define DSEAL_KEX_REQ 97

typedef enum dseal_verdict_t {
	DSEAL_SEND_PLAIN,          /* neither side seals: upstream format */
	DSEAL_SEND_PLAIN_UNKNOWN,  /* we do not seal and do not know the peer yet */
	DSEAL_SEND_SEAL,           /* seal it */
	DSEAL_SEND_HOLD,           /* we seal, the peer is not known yet: send nothing direct */
	DSEAL_SEND_BLOCK,          /* we seal, the peer cannot read it: send nothing direct */
} dseal_verdict_t;

bool dseal_self_wants(void);
bool dseal_self_reads(void);

/* The capability token for ACK / ANS_PUBKEY (`dseal=<hex>'). */
const char *dseal_token(char *buf, size_t len);

/* Learn a peer's capability from its token (NULL or not a dseal token: the
   peer sent none, which is itself an answer). Call after n->transports. */
void dseal_learn(node_t *n, const char *token);

/* What to do with a datagram for next hop `n' on the plain UDP socket (not
   for a carrier datagram path, not for an active obfs link: those are sealed
   or carried anyway). */
dseal_verdict_t dseal_verdict(node_t *n);

/* Log once per minute per node why no direct UDP goes to it. */
void dseal_log_hold(node_t *n, dseal_verdict_t v);

/* True when an obfs link to `n' is up (its datagrams are sealed anyway). */
bool obfs_link_is_active(const node_t *n);

/* Seal one SPTPS datagram for `to' with its obfs link, creating the link if
   needed (DSEAL_SEND_SEAL). Same contract as obfs_wrap_send, except that it
   never returns OBFS_SEND_PLAIN: a datagram that cannot be sealed is dropped,
   never sent in the clear. */
obfs_send_t obfs_seal_send(size_t sock, const sockaddr_t *sa, const void *buf, size_t len, node_t *to, size_t *excess);

/* One probe round to an unconfirmed peer: log once when an older peer
   (no capability token) never answers sealed datagrams. */
void dseal_note_probe(node_t *to);

/* REQ_KEY DSEAL_KEX addressed to us. */
bool dseal_kex_h(node_t *from, const char *request);

#endif /* TINC_OBFS_H */
