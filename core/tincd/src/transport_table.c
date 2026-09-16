/*
    transport_table.c -- carrier names and the pure front classifier.

    This file has no daemon dependencies on purpose: it is linked into both
    tincd and the tinc CLI, and it is what the classifier unit test compiles
    against on its own (testing/transports/classify-test.sh).

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

#include "transport.h"

/* The single-flow magic is a reserved 6-byte "node id": the first byte has
   the QUIC fixed bit (0x40) clear so it can never be a QUIC packet, is not
   a TLS record type and is not printable ASCII. A real node id (first six
   bytes of SHA-512 of the name) equals it with probability 2^-48. */
const uint8_t sf_magic[SF_MAGIC_LEN] = { 0x9f, 0x74, 0x73, 0x66, 0x6c, 0x77 };

static const struct {
	const char *name;
	bool compiled;
} transport_table[TRANSPORT_MAX] = {
	[TRANSPORT_PLAIN] = { "plain", true },
	[TRANSPORT_SF]    = { "sf",    true },
	[TRANSPORT_OBFS]  = { "obfs",  true },
#ifdef HAVE_OPENSSL
	/* The https carrier (TLS front + decoy) is compiled whenever tinc is built
	   against OpenSSL, so it is in the default accept list and the port is
	   probe-resistant by default (PLAN decision 1). */
	[TRANSPORT_HTTPS] = { "https", true },
#else
	[TRANSPORT_HTTPS] = { "https", false },
#endif
#if defined(HAVE_QUIC) && defined(HAVE_OPENSSL)
	/* The quic carrier (ngtcp2 + GnuTLS) is compiled when meson found the
	   libraries; it serves the node certificate from tls.c (OpenSSL build). */
	[TRANSPORT_QUIC]  = { "quic",  true },
#else
	[TRANSPORT_QUIC]  = { "quic",  false },
#endif
#ifdef HAVE_TRANSPORT_TEST
	[TRANSPORT_TEST]  = { "test",  true },
#else
	[TRANSPORT_TEST]  = { "test",  false },
#endif
};

const char *transport_name(transport_id_t id) {
	if(id < 0 || id >= TRANSPORT_MAX) {
		return NULL;
	}

	return transport_table[id].name;
}

transport_id_t transport_lookup(const char *name) {
	for(int i = 0; i < TRANSPORT_MAX; i++) {
		if(!strcasecmp(name, transport_table[i].name)) {
			return (transport_id_t)i;
		}
	}

	return TRANSPORT_MAX;
}

bool transport_is_compiled(transport_id_t id) {
	return id >= 0 && id < TRANSPORT_MAX && transport_table[id].compiled;
}

uint32_t transport_compiled_mask(void) {
	uint32_t mask = 0;

	for(int i = 0; i < TRANSPORT_MAX; i++) {
		if(transport_table[i].compiled) {
			mask |= TRANSPORT_BIT(i);
		}
	}

	return mask;
}

bool transport_parse_list(const char *list, uint32_t *mask, transport_id_t *order, int *count, char *bad) {
	uint32_t m = 0;
	int n = 0;
	const char *p = list;

	if(bad) {
		*bad = 0;
	}

	while(*p) {
		while(*p == ',' || *p == ' ' || *p == '\t') {
			p++;
		}

		if(!*p) {
			break;
		}

		size_t len = strcspn(p, ", \t");
		char token[TRANSPORT_LIST_MAX];

		if(len >= sizeof(token)) {
			len = sizeof(token) - 1;
		}

		memcpy(token, p, len);
		token[len] = 0;
		p += strcspn(p, ", \t");

		transport_id_t id = transport_lookup(token);

		if(id == TRANSPORT_MAX) {
			if(bad) {
				strcpy(bad, token);
			}

			return false;
		}

		if(!(m & TRANSPORT_BIT(id))) {
			m |= TRANSPORT_BIT(id);

			if(order && n < TRANSPORT_MAX) {
				order[n] = id;
			}

			n++;
		}
	}

	if(mask) {
		*mask = m;
	}

	if(count) {
		*count = n;
	}

	return true;
}

const char *transport_mask_to_string(uint32_t mask, char *buf) {
	size_t len = 0;
	buf[0] = 0;

	for(int i = 0; i < TRANSPORT_MAX; i++) {
		if(!(mask & TRANSPORT_BIT(i))) {
			continue;
		}

		len += (size_t)snprintf(buf + len, TRANSPORT_LIST_MAX - len, "%s%s", len ? "," : "", transport_table[i].name);

		if(len >= TRANSPORT_LIST_MAX) {
			break;
		}
	}

	return buf;
}

/* ---- TCP front classifier ------------------------------------------------ */

static const char *const http_methods[] = {
	"GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
	"PRI ", /* HTTP/2 connection preface */
	NULL
};

/* Reserved for the obfs carrier's TCP preamble: first byte 0xA0..0xAF. */
#define TCP_OBFS_FIRST_MIN 0xa0
#define TCP_OBFS_FIRST_MAX 0xaf

transport_tcp_class_t transport_classify_tcp(const uint8_t *buf, size_t len) {
	if(!len) {
		return TCP_CLASS_NEED_MORE;
	}

	/* tinc ID line: "0 " followed by a name, "^cookie" (control) or "?key"
	   (invitation). Only the first two bytes matter for routing; the
	   protocol parser validates the rest. */
	if(buf[0] == '0') {
		if(len < 2) {
			return TCP_CLASS_NEED_MORE;
		}

		return buf[1] == ' ' ? TCP_CLASS_TINC : TCP_CLASS_UNKNOWN;
	}

	/* TLS record: handshake content type, legacy version 3.0..3.4. */
	if(buf[0] == 0x16) {
		if(len < 3) {
			return TCP_CLASS_NEED_MORE;
		}

		return (buf[1] == 0x03 && buf[2] <= 0x04) ? TCP_CLASS_TLS : TCP_CLASS_UNKNOWN;
	}

	if(buf[0] >= TCP_OBFS_FIRST_MIN && buf[0] <= TCP_OBFS_FIRST_MAX) {
		return TCP_CLASS_OBFS;
	}

	/* HTTP request line (or the h2c preface). */
	if(buf[0] >= 'A' && buf[0] <= 'Z') {
		bool partial = false;

		for(const char *const *m = http_methods; *m; m++) {
			size_t mlen = strlen(*m);
			size_t cmp = len < mlen ? len : mlen;

			if(memcmp(buf, *m, cmp)) {
				continue;
			}

			if(len >= mlen) {
				return TCP_CLASS_HTTP;
			}

			partial = true;
		}

		return partial ? TCP_CLASS_NEED_MORE : TCP_CLASS_UNKNOWN;
	}

	return TCP_CLASS_UNKNOWN;
}

/* ---- UDP classifier ----------------------------------------------------- */

/* Keyed lookup for QUIC 1-RTT short headers, set by transport_quic.c (or the
   classifier unit test). NULL: no short-header packet is claimed as QUIC. */
static bool (*quic_cid_matcher)(const uint8_t *dcid);

void transport_set_quic_cid_matcher(bool (*matcher)(const uint8_t *dcid)) {
	quic_cid_matcher = matcher;
}

/* Only QUIC version 1 is claimed. The carrier speaks v1 only, so v2, the
   IETF drafts, greased versions and Version Negotiation (version 0) would
   never reach a live session anyway -- and matching them widened the overlap
   with a genuine SPTPS relay datagram from 2^-34 to about 2^-17 per node
   (review R-10: 1/4 for the top two bits x ~2^17 accepted version words out
   of 2^32). With exactly one 32-bit version word the residual is 2^-34 per
   node, as documented in docs/transports.md §3. */
static bool quic_version_known(uint32_t v) {
	return v == 0x00000001;
}

transport_udp_class_t transport_classify_udp(const uint8_t *buf, size_t len, uint32_t accept_mask) {
	/* 1. single-flow frame: fixed magic in the position of the destination
	      node id, header complete. Always unambiguous. */
	if((accept_mask & TRANSPORT_BIT(TRANSPORT_SF)) && len >= SF_HDR_LEN && !memcmp(buf, sf_magic, SF_MAGIC_LEN)) {
		return UDP_CLASS_SF;
	}

	/* 2. QUIC long header: form bit + fixed bit, followed by version 1. Only
	      claimed when the quic carrier is accepted; the residual overlap with
	      an SPTPS relay datagram whose destination id starts with 0xC0..0xFF
	      and whose next four bytes are 00 00 00 01 is 2^-34 per node -- and
	      even then the carrier only consumes it if ngtcp2 accepts it as a
	      >= 1200-byte Initial, otherwise it falls through (transport.c). */
	if((accept_mask & TRANSPORT_BIT(TRANSPORT_QUIC)) && len >= 5 && (buf[0] & 0xc0) == 0xc0) {
		uint32_t v = ((uint32_t)buf[1] << 24) | ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 8) | buf[4];

		if(quic_version_known(v)) {
			return UDP_CLASS_QUIC;
		}
	}

	/* 3. QUIC 1-RTT short header: form bit clear, fixed bit set (top two bits
	      0x40), followed directly by the destination connection id. There is
	      no version word to key on, so this is a keyed lookup of the 8-byte
	      DCID against the CIDs we issued (docs/transports.md §9.6): a data
	      packet whose first byte is 0x40..0x7f and whose next 8 bytes equal a
	      live CID is 2^-64 per session, the same class of argument as the SF
	      magic. Only ever claimed when quic is accepted and a matcher is set,
	      so a build without the carrier never mis-routes a data packet. */
	if((accept_mask & TRANSPORT_BIT(TRANSPORT_QUIC)) && quic_cid_matcher &&
	                len >= 1 + TRANSPORT_QUIC_CIDLEN && (buf[0] & 0xc0) == 0x40 &&
	                quic_cid_matcher(buf + 1)) {
		return UDP_CLASS_QUIC;
	}

	/* 4. obfs: reserved. Its datagrams are keyed (they look random), so
	      they cannot be told apart by pattern; the carrier's own keyed check
	      (like try_harder() for SPTPS) claims them in transport_udp_dispatch()
	      after this returns SPTPS. */

	/* 5. everything else is the existing SPTPS / legacy data path. */
	return UDP_CLASS_SPTPS;
}
