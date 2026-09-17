/*
    transport_sf.c -- single-flow carrier: the meta channel on the UDP data flow.

    The meta channel is an ordered byte stream (tinc requests, and the
    SPTPS stream records once the connection is authenticated). This carrier
    moves that stream over the node's UDP data socket, so a link between two
    nodes is one UDP flow: no tinc-shaped TCP connection exists. SPTPS is
    untouched; this file only provides an ordered, reliable byte stream
    where a TCP socket used to be.

    Wire format (docs/transports.md, "Single-flow framing"):

        0   6   magic  9f 74 73 66 6c 77   (a reserved node id, never QUIC/TLS)
        6   1   type   1 DATA, 2 ACK, 3 CLOSE, 4 RESET
        7   1   flags  bit0 SYN (first segment of a new session)
        8   8   cid    session id chosen at random by the initiator
        16  4   seq    stream offset of the first payload byte (DATA)
        20  4   ack    next stream offset the sender expects from the peer
        24  ..  payload (DATA only, at most SF_MAX_PAYLOAD bytes)

    Reliability: go-back-N, SF_WINDOW segments in flight, cumulative ACKs,
    exponential retransmission timer, fast retransmit on three duplicate
    ACKs. The 64-bit random cid is what an off-path attacker would have to
    guess to inject into a session; on-path attackers can only cause what a
    TCP RST would (the connection is torn down and re-dialled), because the
    SPTPS records inside authenticate everything else.

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

#include "connection.h"
#include "list.h"
#include "logger.h"
#include "meta.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "random.h"
#include "utils.h"
#include "xalloc.h"

#define TINC_TRANSPORT_DAEMON
#include "transport.h"
#include "obfs.h"

#define SF_CID_LEN 8
#define SF_WINDOW 32            /* segments in flight */
#define SF_RTO_INITIAL_MS 500
#define SF_RTO_MAX_MS 4000
#define SF_SYN_RETRIES 3        /* dial: 0.5 + 1 + 2 s before falling back to the next carrier */
#define SF_MAX_RETRIES 8        /* established: ~24 s of silence before the link is declared dead */

/* Silence and refusal are not the same thing. A retransmission budget exists
   because a path can be lossy, and 24 s of it is the right answer to "we heard
   nothing back". It is the wrong answer to "the kernel returned EPERM on every
   one of those sends": that is the local stack saying, synchronously, that
   these bytes never left the machine. Burning the whole budget then keeps a
   dead edge in the graph -- measured in singleflow-test.sh PART 2, where a
   severed A<->B link held its sf meta connection for 27 s while REQ_KEY after
   REQ_KEY went into it, instead of rerouting through the relay that was up the
   whole time.

   So: count CONSECUTIVE hard send errors and give up after this many, which at
   the initial RTO is about 3.5 s. Consecutive, because a route flap that
   clears must be forgiven -- any send the kernel accepts, and any frame that
   arrives, resets the count to zero. */
#define SF_MAX_HARD_ERRORS 3

/* What the kernel did with a frame we handed it. */
typedef enum {
	SF_SEND_OK = 0,        /* accepted, or failed in a way that may be transient */
	SF_SEND_TOOBIG,        /* EMSGSIZE: these bytes can never fit this path */
	SF_SEND_UNREACHABLE,   /* refused for this destination right now (see above) */
} sf_send_t;

typedef struct sf_segment_t {
	uint32_t seq;
	uint16_t len;
	uint8_t data[SF_MAX_PAYLOAD];
} sf_segment_t;

typedef struct sf_session_t {
	connection_t *c;
	uint8_t cid[SF_CID_LEN];
	sockaddr_t peer;
	size_t sock;            /* index into listen_socket[] whose UDP socket carries this flow */
	obfs_link_t *obfs;      /* non-NULL: every frame of this flow is sealed by the obfs carrier */
	bool initiator;
	bool established;       /* the peer has acknowledged something (or, as acceptor, sent the SYN) */
	bool dead;              /* failed; waiting for the reaper to terminate the connection */
	bool close_sent;

	uint32_t snd_una;       /* oldest unacknowledged stream offset */
	uint32_t snd_nxt;       /* next stream offset to send */
	uint32_t rcv_nxt;       /* next stream offset expected from the peer */

	list_t inflight;        /* sf_segment_t, oldest first */
	timeout_t rto;
	int rto_ms;
	int retries;
	int dupacks;
	int hard_errors;        /* consecutive SF_SEND_UNREACHABLE sends (see SF_MAX_HARD_ERRORS) */
} sf_session_t;

static void free_session(sf_session_t *s) {
	timeout_del(&s->rto);
	list_empty_list(&s->inflight);
	free(s);
}

static list_t sf_sessions = {
	.head = NULL,
	.tail = NULL,
	.count = 0,
	.delete = (list_action_t)free_session,
};

static timeout_t sf_reaper;

/* ---- frame helpers ------------------------------------------------------- */

static void put32(uint8_t *p, uint32_t v) {
	v = htonl(v);
	memcpy(p, &v, 4);
}

static uint32_t get32(const uint8_t *p) {
	uint32_t v;
	memcpy(&v, p, 4);
	return ntohl(v);
}

/* Returns false ONLY when the datagram could not be put on the wire because it
   does not fit the path (EMSGSIZE). Every other outcome -- sent, would block,
   any other socket error -- is true, so the caller only reacts to the one case
   retransmission can never fix. */
static sf_send_t sf_send_raw(size_t sock, const sockaddr_t *peer, const uint8_t *cid, uint8_t type, uint8_t flags, uint32_t seq, uint32_t ack, const void *payload, size_t len, obfs_link_t *obfs, bool init) {
	uint8_t frame[SF_HDR_LEN + SF_MAX_PAYLOAD];

	memcpy(frame, sf_magic, SF_MAGIC_LEN);
	frame[6] = type;
	frame[7] = flags;
	memcpy(frame + 8, cid, SF_CID_LEN);
	put32(frame + 16, seq);
	put32(frame + 20, ack);

	if(len) {
		memcpy(frame + SF_HDR_LEN, payload, len);
	}

	const void *out = frame;
	size_t outlen = SF_HDR_LEN + len;

	/* obfs carrier: seal the whole single-flow frame so the SF magic and the
	   fixed header never appear on the wire. */
	uint8_t sealed[OBFS_MAX_OVERHEAD + SF_HDR_LEN + SF_MAX_PAYLOAD + OBFS_MAX_JUNK];

	if(obfs) {
		size_t slen = obfs_encode(obfs, frame, outlen, sealed, sizeof(sealed), init);

		if(!slen) {
			logger(DEBUG_TRAFFIC, LOG_WARNING, "Could not obfs-seal a single-flow frame");
			return SF_SEND_OK;
		}

		out = sealed;
		outlen = slen;
	}

	if(sendto(listen_socket[sock].udp.fd, (void *)out, outlen, 0, &peer->sa, SALEN(peer->sa)) < 0 && !sockwouldblock(sockerrno)) {
		if(sockmsgsize(sockerrno)) {
			/* Larger than the path MTU, and tinc sets DF: retransmitting the
			   same bytes can only fail the same way. Say so with the size, at a
			   level that is visible without -d5 -- the old line was a bare
			   "Message too long" behind DEBUG_TRAFFIC, which is why a dial that
			   died here looked like a hang. */
			logger(DEBUG_ALWAYS, LOG_WARNING, "Single-flow frame of %zu bytes does not fit the path: %s", outlen, sockstrerror(sockerrno));
			return SF_SEND_TOOBIG;
		}

		if(sockunreachable(sockerrno)) {
			logger(DEBUG_TRAFFIC, LOG_WARNING, "The kernel refused a single-flow frame towards this path: %s", sockstrerror(sockerrno));
			return SF_SEND_UNREACHABLE;
		}

		logger(DEBUG_TRAFFIC, LOG_WARNING, "Error sending single-flow frame: %s", sockstrerror(sockerrno));
	}

	return SF_SEND_OK;
}

static void sf_schedule_reap(void);

static void sf_send_frame(sf_session_t *s, uint8_t type, uint8_t flags, uint32_t seq, const void *payload, size_t len) {
	sf_send_t r = sf_send_raw(s->sock, &s->peer, s->cid, type, flags, seq, s->rcv_nxt, payload, len, s->obfs, !s->established);

	/* A refusal is evidence about the path and is remembered; anything the
	   kernel accepted clears it, so only an unbroken run of refusals counts
	   (sf_rto_handler acts on the count). */
	if(r == SF_SEND_UNREACHABLE) {
		if(s->hard_errors < SF_MAX_HARD_ERRORS) {
			s->hard_errors++;
		}
	} else {
		s->hard_errors = 0;
	}

	if(r != SF_SEND_TOOBIG) {
		return;
	}

	/* The frame does not fit the path. Fail the session NOW instead of letting
	   the retransmission timer resend the identical bytes until SF_SYN_RETRIES
	   runs out: on a dial that is 3.5 s of apparent hang before the carrier
	   selector moves on, and the retries cannot succeed. Declaring the session
	   dead is the defined degradation -- the reaper terminates the connection
	   and the next carrier in PreferredTransports is tried at once. */
	if(!s->dead) {
		logger(DEBUG_CONNECTIONS, LOG_WARNING, "Single-flow %s to %s (%s) cannot fit the path MTU; failing the carrier over",
		       s->established ? "link" : "dial", s->c->name, s->c->hostname);
		s->dead = true;
		sf_schedule_reap();
	}
}

static struct timeval ms_to_tv(int ms) {
	return (struct timeval) {
		ms / 1000, (ms % 1000) * 1000
	};
}

static sf_session_t *sf_lookup(const uint8_t *cid) {
	for list_each(sf_session_t, s, &sf_sessions) {
		if(!memcmp(s->cid, cid, SF_CID_LEN)) {
			return s;
		}
	}

	return NULL;
}

/* ---- retransmission ------------------------------------------------------ */

static void sf_retransmit_head(sf_session_t *s) {
	sf_segment_t *seg = list_get_head(&s->inflight);

	if(!seg) {
		return;
	}

	uint8_t flags = (seg->seq == 0 && s->initiator) ? SF_FLAG_SYN : 0;
	sf_send_frame(s, SF_TYPE_DATA, flags, seg->seq, seg->data, seg->len);
}

static void sf_rto_handler(void *data) {
	sf_session_t *s = data;

	if(s->dead || !s->inflight.count) {
		return; /* not re-armed: the event loop drops the expired timer */
	}

	/* The kernel has refused every one of the last SF_MAX_HARD_ERRORS sends on
	   this flow. The remaining retransmissions would hand it the same bytes for
	   the same destination and get the same answer, while the graph goes on
	   believing this edge exists and routes REQ_KEY into it. Stop now. */
	if(s->hard_errors >= SF_MAX_HARD_ERRORS) {
		logger(DEBUG_CONNECTIONS, LOG_WARNING, "Single-flow %s to %s (%s): the kernel refused the last %d sends, so the path is gone; not waiting out the retransmission budget",
		       s->established ? "link" : "dial", s->c->name, s->c->hostname, s->hard_errors);
		s->dead = true;
		sf_schedule_reap();
		return;
	}

	int limit = s->established ? SF_MAX_RETRIES : SF_SYN_RETRIES;

	if(s->retries >= limit) {
		logger(DEBUG_CONNECTIONS, LOG_WARNING, "Single-flow %s to %s (%s): no acknowledgement after %d retransmissions",
		       s->established ? "link" : "dial", s->c->name, s->c->hostname, s->retries);
		s->dead = true;
		sf_schedule_reap();
		return;
	}

	s->retries++;
	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Single-flow retransmit #%d to %s (%s), rto %d ms", s->retries, s->c->name, s->c->hostname, s->rto_ms);
	sf_retransmit_head(s);
	s->rto_ms *= 2;

	if(s->rto_ms > SF_RTO_MAX_MS) {
		s->rto_ms = SF_RTO_MAX_MS;
	}

	struct timeval tv = ms_to_tv(s->rto_ms);
	timeout_set(&s->rto, &tv);
}

static void sf_arm_rto(sf_session_t *s) {
	struct timeval tv = ms_to_tv(s->rto_ms);

	if(s->rto.cb) {
		timeout_set(&s->rto, &tv);
	} else {
		timeout_add(&s->rto, sf_rto_handler, s, &tv);
	}
}

/* Failed sessions are torn down from a separate timer: terminate_connection()
   frees the session, and the event loop still touches a timer after its
   callback returned, so a session must never free itself inside its own
   RTO callback. */
static void sf_reap(void *data) {
	(void)data;

	for list_each(sf_session_t, s, &sf_sessions) {
		if(s->dead) {
			connection_t *c = s->c;
			terminate_connection(c, c->edge);
		}
	}
}

static void sf_schedule_reap(void) {
	struct timeval tv = {0, 0};

	if(sf_reaper.cb) {
		timeout_set(&sf_reaper, &tv);
	} else {
		timeout_add(&sf_reaper, sf_reap, NULL, &tv);
	}
}

/* ---- sending ------------------------------------------------------------- */

/* How many payload bytes may go into one segment. SF_MAX_PAYLOAD for a plain
   flow; for an obfs flow, the largest inner payload the seal (magic + header +
   tag + the configured tail junk) still leaves inside the path MTU. Chunking
   against the path is what makes the shaping options free: the meta stream
   simply takes one more segment instead of producing a datagram the kernel
   refuses. Re-evaluated per segment, so a path MTU that changes mid-stream is
   picked up on the next one. */
static uint32_t sf_payload_limit(sf_session_t *s) {
	uint32_t max = SF_MAX_PAYLOAD;

	if(s->obfs) {
		size_t inner = obfs_max_inner(s->obfs, !s->established);
		size_t room = inner > SF_HDR_LEN ? inner - SF_HDR_LEN : 1;

		if(room < max) {
			max = (uint32_t)room;
		}
	}

	return max;
}

bool sf_send(connection_t *c) {
	sf_session_t *s = c->transport_data;

	if(!s || s->dead) {
		return false;
	}

	while(c->outbuf.len > c->outbuf.offset && s->inflight.count < SF_WINDOW && !s->dead) {
		uint32_t limit = sf_payload_limit(s);
		uint32_t avail = c->outbuf.len - c->outbuf.offset;
		uint32_t n = avail < limit ? avail : limit;
		char *p = buffer_read(&c->outbuf, n);

		sf_segment_t *seg = xmalloc(sizeof(*seg));
		seg->seq = s->snd_nxt;
		seg->len = (uint16_t)n;
		memcpy(seg->data, p, n);
		list_insert_tail(&s->inflight, seg);

		uint8_t flags = (seg->seq == 0 && s->initiator) ? SF_FLAG_SYN : 0;
		sf_send_frame(s, SF_TYPE_DATA, flags, seg->seq, seg->data, n);
		s->snd_nxt += n;
	}

	if(s->inflight.count && !s->rto.cb) {
		sf_arm_rto(s);
	}

	return true;
}

static void sf_process_ack(sf_session_t *s, uint32_t ack) {
	int32_t adv = (int32_t)(ack - s->snd_una);

	if(adv > 0 && (int32_t)(ack - s->snd_nxt) <= 0) {
		s->snd_una = ack;
		s->established = true;
		s->retries = 0;
		s->dupacks = 0;
		s->rto_ms = SF_RTO_INITIAL_MS;
		s->hard_errors = 0;   /* the peer answered: whatever the kernel said, this path works */

		while(s->inflight.head) {
			sf_segment_t *seg = s->inflight.head->data;

			if((int32_t)(seg->seq + seg->len - ack) > 0) {
				break;
			}

			list_delete_head(&s->inflight);
		}

		if(s->inflight.count) {
			sf_arm_rto(s);
		} else {
			timeout_del(&s->rto);
		}

		/* The window opened: push whatever is still queued. */
		sf_send(s->c);
	} else if(adv == 0 && s->inflight.count) {
		if(++s->dupacks >= 3) {
			s->dupacks = 0;
			logger(DEBUG_TRAFFIC, LOG_DEBUG, "Single-flow fast retransmit to %s (%s)", s->c->name, s->c->hostname);
			sf_retransmit_head(s);
		}
	}
}

/* ---- session setup ------------------------------------------------------- */

static int sf_pick_socket(const sockaddr_t *peer) {
	for(int i = 0; i < listen_sockets; i++) {
		if(listen_socket[i].sa.sa.sa_family == peer->sa.sa_family) {
			return i;
		}
	}

	return -1;
}

static sf_session_t *new_session(connection_t *c, size_t sock, const sockaddr_t *peer, bool initiator) {
	sf_session_t *s = xzalloc(sizeof(*s));
	s->c = c;
	s->sock = sock;
	s->peer = *peer;
	s->initiator = initiator;
	s->rto_ms = SF_RTO_INITIAL_MS;
	s->inflight.delete = (list_action_t)free;
	c->transport_data = s;
	c->socket = -1;
	list_insert_tail(&sf_sessions, s);
	return s;
}

static bool sf_dial_generic(connection_t *c, obfs_link_t *obfs) {
	int sock = sf_pick_socket(&c->address);

	if(sock < 0) {
		logger(DEBUG_CONNECTIONS, LOG_ERR, "No UDP socket with the address family of %s (%s) for a single-flow dial", c->name, c->hostname);
		return false;
	}

	sf_session_t *s = new_session(c, (size_t)sock, &c->address, true);
	s->obfs = obfs;
	randomize(s->cid, SF_CID_LEN);

	c->status.connecting = false;
	connection_add(c);

	logger(DEBUG_CONNECTIONS, LOG_INFO, "Dialling %s (%s) via %s UDP", c->name, c->hostname, obfs ? "obfuscated single-flow" : "single-flow");

	/* Sends the ID line, which becomes the SYN segment. */
	finish_connecting(c);
	return true;
}

bool sf_dial(connection_t *c) {
	return sf_dial_generic(c, NULL);
}

/* obfs carrier entry point: a single-flow dial whose frames are obfs-sealed. */
bool sf_dial_obfs(connection_t *c, obfs_link_t *obfs) {
	return sf_dial_generic(c, obfs);
}

/* obfs carrier's close hook needs the link so it can be deactivated. */
obfs_link_t *sf_connection_obfs(connection_t *c) {
	sf_session_t *s = c->transport_data;
	return s ? s->obfs : NULL;
}

static sf_session_t *sf_accept(listen_socket_t *ls, const uint8_t *cid, const sockaddr_t *addr, obfs_link_t *obfs) {
	/* Cheap admission control, in the spirit of check_tarpit(): at most
	   MaxConnectionBurst new sessions per second. */
	static time_t burst_time;
	static int burst;

	if(now.tv_sec != burst_time) {
		burst_time = now.tv_sec;
		burst = 0;
	}

	if(++burst > max_connection_burst) {
		logger(DEBUG_CONNECTIONS, LOG_WARNING, "Too many new single-flow sessions, dropping one");
		return NULL;
	}

	connection_t *c = new_connection();
	c->name = xstrdup("<unknown>");
	c->outmaclength = myself->connection->outmaclength;
	c->address = *addr;
	c->hostname = sockaddr2hostname(addr);
	c->last_ping_time = now.tv_sec;
	c->transport = transport_get(obfs ? TRANSPORT_OBFS : TRANSPORT_SF);
	c->allow_request = ID;

	sf_session_t *s = new_session(c, (size_t)(ls - listen_socket), addr, false);
	memcpy(s->cid, cid, SF_CID_LEN);
	s->obfs = obfs;
	s->established = true;

	connection_add(c);

	if(obfs) {
		/* Answer with junk of our own around the handshake, then continue
		   over the obfs-sealed flow. */
		obfs_send_junk((size_t)(ls - listen_socket), addr);
	}

	logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Connection from %s (%s UDP)", c->hostname, obfs ? "obfuscated single-flow" : "single-flow");
	return s;
}

void sf_close(connection_t *c) {
	sf_session_t *s = c->transport_data;

	if(!s) {
		return;
	}

	if(s->established && !s->dead && !s->close_sent) {
		s->close_sent = true;
		sf_send_frame(s, SF_TYPE_CLOSE, 0, s->snd_nxt, NULL, 0);
	}

	c->transport_data = NULL;
	list_delete(&sf_sessions, s);
}

bool sf_local_address(connection_t *c, sockaddr_t *sa) {
	sf_session_t *s = c->transport_data;

	if(!s) {
		return false;
	}

	socklen_t salen = sizeof(*sa);
	return getsockname(listen_socket[s->sock].udp.fd, &sa->sa, &salen) >= 0;
}

/* ---- receiving ----------------------------------------------------------- */

static void sf_deliver(sf_session_t *s, const uint8_t *payload, size_t len) {
	connection_t *c = s->c;

	/* Acknowledge first: the delivery below may terminate the connection
	   (protocol error, TERMREQ, ...) and free the session. After
	   receive_meta_bytes() returns, `s' must not be touched. */
	s->rcv_nxt += (uint32_t)len;
	s->established = true;
	sf_send_frame(s, SF_TYPE_ACK, 0, s->snd_nxt, NULL, 0);

	if(!len) {
		return;
	}

	if(!receive_meta_bytes(c, (char *)payload, (ssize_t)len)) {
		c->status.tarpit = false; /* no socket to tarpit */
		terminate_connection(c, c->edge);
	}
}

static void sf_udp_receive_generic(listen_socket_t *ls, const uint8_t *buf, size_t len, const sockaddr_t *vaddr, obfs_link_t *obfs) {
	if(len < SF_HDR_LEN) {
		return;
	}

	sockaddr_t addr = *vaddr;
	sockaddrunmap(&addr);

	uint8_t type = buf[6];
	uint8_t flags = buf[7];
	const uint8_t *cid = buf + 8;
	uint32_t seq = get32(buf + 16);
	uint32_t ack = get32(buf + 20);
	const uint8_t *payload = buf + SF_HDR_LEN;
	size_t plen = len - SF_HDR_LEN;

	if(plen > SF_MAX_PAYLOAD) {
		return;
	}

	sf_session_t *s = sf_lookup(cid);

	if(!s) {
		if(type == SF_TYPE_DATA && (flags & SF_FLAG_SYN) && seq == 0) {
			s = sf_accept(ls, cid, &addr, obfs);

			if(!s) {
				return;
			}
		} else {
			/* Unknown session: tell the sender so it fails fast instead of
			   retransmitting into the void. Rate-limited, unauthenticated
			   (an off-path attacker still needs the 64-bit cid). The reset is
			   sealed with the same obfs key when the frame arrived obfuscated. */
			static time_t last_reset;

			if(type != SF_TYPE_RESET && now.tv_sec != last_reset) {
				last_reset = now.tv_sec;
				sf_send_raw(ls - listen_socket, &addr, cid, SF_TYPE_RESET, 0, 0, 0, NULL, 0, obfs, true);
			}

			return;
		}
	} else if(sockaddrcmp(&addr, &s->peer)) {
		if(debug_level >= DEBUG_TRAFFIC) {
			char *hostname = sockaddr2hostname(&addr);
			logger(DEBUG_TRAFFIC, LOG_WARNING, "Single-flow frame for a session with %s (%s) from a different address %s; dropped", s->c->name, s->c->hostname, hostname);
			free(hostname);
		}

		return;
	}

	if(s->dead) {
		return;
	}

	connection_t *c = s->c;

	switch(type) {
	case SF_TYPE_DATA: {
		sf_process_ack(s, ack);

		int32_t diff = (int32_t)(seq - s->rcv_nxt);

		if(diff == 0) {
			sf_deliver(s, payload, plen);
		} else if(diff < 0 && (int32_t)(seq + plen - s->rcv_nxt) > 0) {
			/* Retransmission overlapping data we already have: take the tail. */
			size_t skip = (size_t)(-diff);
			sf_deliver(s, payload + skip, plen - skip);
		} else {
			/* Old duplicate, or a gap (go-back-N: not buffered). Re-ACK what
			   we have so the sender resends from there. */
			sf_send_frame(s, SF_TYPE_ACK, 0, s->snd_nxt, NULL, 0);
		}

		return;
	}

	case SF_TYPE_ACK:
		sf_process_ack(s, ack);
		return;

	case SF_TYPE_CLOSE:
		logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Single-flow session closed by %s (%s)", c->name, c->hostname);
		s->close_sent = true; /* the peer is gone; do not answer with another CLOSE */
		terminate_connection(c, c->edge);
		return;

	case SF_TYPE_RESET:
		logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Single-flow session reset by %s (%s)", c->name, c->hostname);
		s->close_sent = true;
		terminate_connection(c, c->edge);
		return;

	default:
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Unknown single-flow frame type %d from %s (%s)", type, c->name, c->hostname);
		return;
	}
}

/* Classifier path: a plain single-flow frame (SF magic on the wire). */
void sf_udp_receive(listen_socket_t *ls, const uint8_t *buf, size_t len, const sockaddr_t *vaddr) {
	sf_udp_receive_generic(ls, buf, len, vaddr, NULL);
}

/* obfs path: the frame was unsealed by the obfs carrier; `obfs' is the link it
   came in on, so a new inbound session and any reset are sealed with it too. */
void sf_udp_receive_obfs(listen_socket_t *ls, const uint8_t *buf, size_t len, const sockaddr_t *vaddr, obfs_link_t *obfs) {
	sf_udp_receive_generic(ls, buf, len, vaddr, obfs);
}

void sf_exit(void) {
	timeout_del(&sf_reaper);
	list_empty_list(&sf_sessions);
}
