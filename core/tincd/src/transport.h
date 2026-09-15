#ifndef TINC_TRANSPORT_H
#define TINC_TRANSPORT_H

/*
    transport.h -- transport (carrier) registry, negotiation and front dispatch.

    A carrier is an outer wrapper around the tinc protocol. SPTPS (identity,
    authentication, encryption) is never touched by a carrier: a carrier only
    decides on which flow the already-authenticated SPTPS records travel and
    what the bytes on the wire look like around them. See docs/transports.md.

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

/* ---- carrier identities (stable order, used as bit positions) ----------- */

typedef enum transport_id_t {
	TRANSPORT_PLAIN = 0,    /* upstream tinc shape: TCP meta connection + UDP data flow */
	TRANSPORT_SF,           /* single-flow plain UDP: meta and data share one UDP flow */
	TRANSPORT_OBFS,         /* obfuscated UDP (M5) */
	TRANSPORT_HTTPS,        /* TLS front carrier (M5) */
	TRANSPORT_QUIC,         /* QUIC carrier (M5) */
	TRANSPORT_TEST,         /* stub carrier, only with -Dtransport_test=true; always fails to dial */
	TRANSPORT_MAX
} transport_id_t;

#define TRANSPORT_BIT(id) (1u << (id))
#define TRANSPORT_MASK_PLAIN TRANSPORT_BIT(TRANSPORT_PLAIN)

/* Longest string transport_mask_to_string() can produce, NUL included. */
#define TRANSPORT_LIST_MAX 64

/* ---- pure table & classifier (transport_table.c; no daemon dependencies) -- */

/* Name of a carrier, or NULL for an out-of-range id. */
const char *transport_name(transport_id_t id);

/* Look a name up (case-insensitive). Returns TRANSPORT_MAX if unknown. */
transport_id_t transport_lookup(const char *name);

/* True if the carrier's code is part of this build. */
bool transport_is_compiled(transport_id_t id);

/* Bitmask of every compiled carrier: the default accept list. */
uint32_t transport_compiled_mask(void);

/* Parse "a, b c" (commas and/or whitespace) into a bitmask, keeping the
   order of first appearance in `order` (may be NULL). Unknown names make
   the call return false; the offending token is copied into `bad` (may be
   NULL, size TRANSPORT_LIST_MAX). Known-but-not-compiled names are accepted
   (their bit is set) so a newer peer's list does not break parsing. */
bool transport_parse_list(const char *list, uint32_t *mask, transport_id_t *order, int *count, char *bad);

/* Render a mask as "plain,sf" in id order. `buf` is TRANSPORT_LIST_MAX bytes. */
const char *transport_mask_to_string(uint32_t mask, char *buf);

/* TCP front classification: what the first bytes of an inbound TCP
   connection look like. See the decision table in docs/transports.md. */
typedef enum transport_tcp_class_t {
	TCP_CLASS_NEED_MORE = -1, /* fewer bytes than needed to decide */
	TCP_CLASS_UNKNOWN = 0,    /* nothing we serve: close (and tarpit) */
	TCP_CLASS_TINC,           /* tinc ID line: "0 <name|^cookie|?key> ..." */
	TCP_CLASS_TLS,            /* TLS record header 0x16 0x03 0x00..0x04: https carrier / decoy */
	TCP_CLASS_HTTP,           /* plaintext HTTP request line: decoy */
	TCP_CLASS_OBFS,           /* reserved first-byte range for the obfs carrier */
} transport_tcp_class_t;

/* Bytes the TCP classifier wants to see before it can always decide. */
#define TRANSPORT_TCP_PEEK 8

transport_tcp_class_t transport_classify_tcp(const uint8_t *buf, size_t len);

/* UDP classification of one datagram. `accept_mask` limits which carriers
   may claim a packet: a carrier that is not accepted never wins, so the
   datagram falls through to the SPTPS data path (where it is dropped if it
   does not authenticate, exactly as today). */
typedef enum transport_udp_class_t {
	UDP_CLASS_SPTPS = 0,      /* the existing tinc data path (SPTPS datagram / legacy) */
	UDP_CLASS_SF,             /* single-flow meta frame */
	UDP_CLASS_QUIC,           /* QUIC long header (version negotiation / initial / handshake) */
	UDP_CLASS_OBFS,           /* reserved: the obfs carrier's keyed classifier claims it */
} transport_udp_class_t;

transport_udp_class_t transport_classify_udp(const uint8_t *buf, size_t len, uint32_t accept_mask);

/* ---- single-flow frame layout (shared by the classifier and transport_sf.c) */

#define SF_MAGIC_LEN 6
extern const uint8_t sf_magic[SF_MAGIC_LEN];

#define SF_HDR_LEN 24
#define SF_MAX_PAYLOAD 1200

#define SF_TYPE_DATA  0x01
#define SF_TYPE_ACK   0x02
#define SF_TYPE_CLOSE 0x03
#define SF_TYPE_RESET 0x04

#define SF_FLAG_SYN 0x01

#endif /* TINC_TRANSPORT_H */

/* ---- daemon-side registry (transport.c) ----------------------------------
   Kept outside the main include guard: net.h pulls in the pure part above
   for outgoing_t, and daemon sources include this header again after
   net.h/connection.h with TINC_TRANSPORT_DAEMON defined. */

#if defined(TINC_TRANSPORT_DAEMON) && !defined(TINC_TRANSPORT_DAEMON_H)
#define TINC_TRANSPORT_DAEMON_H

#include "net.h"
#include "connection.h"
#include "node.h"

typedef struct transport_t {
	transport_id_t id;
	const char *name;
	unsigned int caps;

	/* Hooks. Every hook is optional; a carrier without `dial` cannot be
	   dialled and is skipped by the selector. See docs/transports.md
	   "Carrier contract". */
	bool (*init)(void);
	void (*exit)(void);
	bool (*dial)(struct connection_t *c);
	bool (*accept)(struct connection_t *c, const uint8_t *peek, size_t len);
	bool (*send)(struct connection_t *c);
	void (*close)(struct connection_t *c);
	bool (*local_address)(struct connection_t *c, sockaddr_t *sa);
	void (*udp_receive)(listen_socket_t *ls, const uint8_t *buf, size_t len, const sockaddr_t *addr);
} transport_t;

#define TRANSPORT_CAP_META_TCP     0x01 /* meta channel is a TCP stream on the front port */
#define TRANSPORT_CAP_SINGLE_FLOW  0x02 /* meta and data share one flow: no tinc-shaped TCP */
#define TRANSPORT_CAP_DATA_UDP     0x04 /* data path is the SPTPS datagram flow on the UDP port */

extern uint32_t transport_accept_mask;             /* Transports (effective) */
extern transport_id_t transport_pref[TRANSPORT_MAX]; /* PreferredTransports (effective) */
extern int transport_pref_count;
extern bool single_flow;                           /* SingleFlow option */

const transport_t *transport_get(transport_id_t id);

/* Option parsing; called from setup_myself_reloadable(). Returns false on an
   invalid list (the error names the option). */
bool transport_read_config(void);

/* One-time init after the listen sockets exist; and teardown. */
bool transport_init(void);
void transport_exit(void);

/* Accept list a node advertised (host record or ACK), PLAIN if unknown. */
uint32_t transport_node_mask(const struct node_t *n);

/* Read a "Transports" line from a host config tree into n->transports. */
void transport_node_read_config(struct node_t *n, splay_tree_t *config_tree);

/* Own accept list as sent in ACK. */
const char *transport_accept_string(char *buf);

/* Outbound selection: carrier to use for this attempt, advancing through
   the preference list across attempts. transport_next_candidate() returns
   false when the candidate list is exhausted (the caller backs off and the
   next cycle starts from the top again). */
const transport_t *transport_current(struct outgoing_t *outgoing);
bool transport_next_candidate(struct outgoing_t *outgoing);
void transport_reset_candidates(struct outgoing_t *outgoing);

/* Meta-channel plumbing. */
void transport_meta_flush(struct connection_t *c);           /* c->outbuf has new bytes */
void transport_connection_close(struct connection_t *c);     /* before connection_del() */
bool transport_local_address(struct connection_t *c, sockaddr_t *sa);

/* Inbound TCP front: peek, classify, route. Returns true if the connection
   is now a tinc connection and the caller may go on reading meta data. */
bool transport_front_dispatch(struct connection_t *c);

/* Inbound UDP: true if the datagram was consumed by a carrier. */
bool transport_udp_dispatch(listen_socket_t *ls, const uint8_t *buf, size_t len, const sockaddr_t *addr);

/* plain carrier's dial (net_socket.c): socket + connect + io_add. */
bool transport_plain_dial(struct connection_t *c);

/* https carrier (https.c): TLS front, meta+data in one TLS flow, decoy for
   anything that does not authenticate. Compiled only with OpenSSL. */
bool https_init(void);
void https_exit(void);
bool https_dial(struct connection_t *c);
bool https_accept(struct connection_t *c, const uint8_t *peek, size_t len);
bool https_send(struct connection_t *c);
void https_close(struct connection_t *c);

/* single-flow carrier (transport_sf.c) */
bool sf_dial(struct connection_t *c);
bool sf_send(struct connection_t *c);
void sf_close(struct connection_t *c);
bool sf_local_address(struct connection_t *c, sockaddr_t *sa);
void sf_udp_receive(listen_socket_t *ls, const uint8_t *buf, size_t len, const sockaddr_t *addr);
void sf_exit(void);

#endif /* TINC_TRANSPORT_DAEMON */
