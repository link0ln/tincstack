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
	UDP_CLASS_QUIC,           /* QUIC (long header, or a short header on a CID we issued) */
	UDP_CLASS_OBFS,           /* reserved: the obfs carrier's keyed classifier claims it */
} transport_udp_class_t;

transport_udp_class_t transport_classify_udp(const uint8_t *buf, size_t len, uint32_t accept_mask);

/* Connection-id length the quic carrier issues and the classifier keys on for
   1-RTT short-header packets (docs/transports.md §9.6). 20 bytes, nginx's:
   the listener's ids are in every long header, in the clear (8 until
   2026-09-25). */
#define TRANSPORT_QUIC_CIDLEN 20

/* Register a keyed lookup for QUIC short-header packets: given the 20-byte
   destination connection id, return true if it belongs to one of our live
   QUIC sessions. transport_quic.c sets a real one; the classifier unit test
   sets a fake. NULL (the default) means no short-header packet is ever
   claimed as QUIC, so a build without the carrier behaves like plain tinc. */
void transport_set_quic_cid_matcher(bool (*matcher)(const uint8_t *dcid));

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
	/* Data path (M5 quic): frame one SPTPS datagram (the exact bytes
	   send_sptps_data() would put on the wire) on the carrier's flow instead
	   of the plain UDP socket. false = does not fit the carrier's ceiling; the
	   caller treats it like EMSGSIZE, and *excess (when not 0) says by how many
	   bytes it was over. NULL = data rides the plain UDP path. */
	bool (*send_datagram)(struct connection_t *c, const void *buf, size_t len, size_t *excess);
} transport_t;

#define TRANSPORT_CAP_META_TCP     0x01 /* meta channel is a TCP stream on the front port */
#define TRANSPORT_CAP_SINGLE_FLOW  0x02 /* meta and data share one flow: no tinc-shaped TCP */
#define TRANSPORT_CAP_DATA_UDP     0x04 /* data path is the SPTPS datagram flow on the UDP port */

extern uint32_t transport_accept_mask;             /* Transports (effective) */
extern transport_id_t transport_pref[TRANSPORT_MAX]; /* PreferredTransports (effective) */
extern int transport_pref_count;
extern bool single_flow;                           /* SingleFlow option */
extern bool allow_plain_meta;                      /* AllowPlainMeta option (default yes) */
extern bool udp_meta_fallback;                     /* UdpMetaFallback option (default yes) */

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
   the preference list across attempts. transport_next_candidate() is called
   after a failure *before activation*; it returns true when it moved on to
   another candidate that can be dialled right away, false when the same
   candidate is to be retried after the normal backoff (it is the carrier
   that last activated and has not yet failed TRANSPORT_STICKY_FAILURES
   times in a row) or when the list is exhausted (the next cycle starts
   from the top of the preference list again). transport_candidate_activated()
   is called when a connection is activated (ACK): it resets the walk so the
   next reconnect starts from the operator's first preference and records the
   carrier if this connection was the one we dialled. An activated link that
   drops never advances the walk (net.c terminate_connection). */
#define TRANSPORT_STICKY_FAILURES 3
const transport_t *transport_current(struct outgoing_t *outgoing);
bool transport_next_candidate(struct outgoing_t *outgoing);
void transport_candidate_activated(struct outgoing_t *outgoing, const struct connection_t *c);

/* Acceptor-side rule (review row L-2 residual, docs/transports.md §2 "When the
   peer dials first"): true when `c' -- a link the *peer* opened towards us --
   runs on a carrier that ranks below the candidate this outgoing_t would dial
   next, so our dial should go ahead instead of being suppressed by "Already
   connected". The ranking is the transport_id_t order, which both ends compile
   identically, so only one of the two nodes can ever want to re-dial and the
   surviving link only ever moves *up* the order: the rule terminates. */
bool transport_outranks_connection(struct outgoing_t *outgoing, const struct connection_t *c);

/* Defect E. True when every address we know for this peer has just refused a
   meta connection AND the data path to it is a confirmed *direct* UDP flow:
   then `sa' is filled with the address that flow uses and the meta connection
   is dialled there over the single-flow carrier. Two nodes behind one NAT are
   the case this exists for -- the NAT hairpins UDP but not TCP, so the short
   path is reachable for data and unreachable for the meta connection, and the
   pair stays relayed through a third node for ever.

   Conditions, all of them: the option is on; `sf' is compiled, dialable and in
   OUR accept list (an operator who removed it does not want it dialled); the
   PEER's advertised accept list contains it (never a guess); the peer is
   reachable, its UDP path is confirmed and goes to the peer itself rather than
   through a relay. Once per dial cycle: retry_outgoing() re-arms it.

   Nothing about authentication changes -- the sf carrier hands the same ID
   exchange and the same SPTPS session to the same code -- and the acceptor
   still enforces its own Transports/AllowPlainMeta. */
bool transport_udp_meta_fallback(struct outgoing_t *outgoing, sockaddr_t *sa);

/* Meta-channel plumbing. */
void transport_meta_flush(struct connection_t *c);           /* c->outbuf has new bytes */
void transport_connection_close(struct connection_t *c);     /* before connection_del() */
bool transport_local_address(struct connection_t *c, sockaddr_t *sa);

/* Inbound TCP front: peek, classify, route. Returns true if the connection
   is now a tinc connection and the caller may go on reading meta data. */
bool transport_front_dispatch(struct connection_t *c);

/* Front ports (docs/transports.md §3.1). The https and quic fronts listen on
   443 by default -- a separate listener next to the tinc port, which keeps
   plain and obfs -- on a node that accepts inbound connections (Port is not
   0). `option' is "HttpsPort" or "QuicPort": set by the operator it wins, 0
   turning the extra listener off. Returns the port to try, or 0. */
int transport_front_port(const char *option, bool *configured);

/* Write `key = port' into this node's own host record (drop the line when
   port is 0), only if it changed, so invitations tell peers where the front
   listens. A listening front advertises `<key>Public' instead of the bound
   port when the operator set it (a port forward to another external port). */
void transport_advertise_port(const char *key, int port);

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

/* obfs carrier reuses the single-flow engine, sealing every frame
   (transport_sf.c hooks; the seal itself lives in obfs.c). */
struct obfs_link_t;
bool sf_dial_obfs(struct connection_t *c, struct obfs_link_t *obfs);
void sf_udp_receive_obfs(listen_socket_t *ls, const uint8_t *buf, size_t len, const sockaddr_t *addr, struct obfs_link_t *obfs);
struct obfs_link_t *sf_connection_obfs(struct connection_t *c);

#endif /* TINC_TRANSPORT_DAEMON */
