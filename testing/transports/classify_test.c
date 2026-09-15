/*
    classify_test.c -- unit test for the transport front classifier.

    Feeds each documented byte pattern to transport_classify_tcp() and
    transport_classify_udp() and asserts it reaches the right handler class
    (docs/transports.md §3). Compiled standalone against transport_table.c by
    classify-test.sh, so it has no daemon dependencies.

    This program is free software; see the GPL v2+ (same as the rest of tinc).
*/

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "transport.h"

static int failures = 0;
static int checks = 0;

static const char *tcp_name(transport_tcp_class_t c) {
	switch(c) {
	case TCP_CLASS_NEED_MORE:
		return "NEED_MORE";

	case TCP_CLASS_UNKNOWN:
		return "UNKNOWN";

	case TCP_CLASS_TINC:
		return "TINC";

	case TCP_CLASS_TLS:
		return "TLS";

	case TCP_CLASS_HTTP:
		return "HTTP";

	case TCP_CLASS_OBFS:
		return "OBFS";

	default:
		return "?";
	}
}

static const char *udp_name(transport_udp_class_t c) {
	switch(c) {
	case UDP_CLASS_SPTPS:
		return "SPTPS";

	case UDP_CLASS_SF:
		return "SF";

	case UDP_CLASS_QUIC:
		return "QUIC";

	case UDP_CLASS_OBFS:
		return "OBFS";

	default:
		return "?";
	}
}

static void check_tcp(const char *label, const uint8_t *buf, size_t len, transport_tcp_class_t want) {
	checks++;
	transport_tcp_class_t got = transport_classify_tcp(buf, len);

	if(got != want) {
		failures++;
		printf("FAIL tcp  %-28s want %-9s got %s\n", label, tcp_name(want), tcp_name(got));
	} else {
		printf("ok   tcp  %-28s %s\n", label, tcp_name(got));
	}
}

static void check_udp(const char *label, const uint8_t *buf, size_t len, uint32_t accept, transport_udp_class_t want) {
	checks++;
	transport_udp_class_t got = transport_classify_udp(buf, len, accept);

	if(got != want) {
		failures++;
		printf("FAIL udp  %-28s want %-9s got %s\n", label, udp_name(want), udp_name(got));
	} else {
		printf("ok   udp  %-28s %s\n", label, udp_name(got));
	}
}

int main(void) {
	uint32_t all = TRANSPORT_BIT(TRANSPORT_PLAIN) | TRANSPORT_BIT(TRANSPORT_SF) |
	               TRANSPORT_BIT(TRANSPORT_QUIC) | TRANSPORT_BIT(TRANSPORT_OBFS);

	/* ---- TCP ---- */
	check_tcp("tinc ID line", (const uint8_t *)"0 nodeb 17.7", 12, TCP_CLASS_TINC);
	check_tcp("tinc control", (const uint8_t *)"0 ^cookie", 9, TCP_CLASS_TINC);
	check_tcp("tinc invitation", (const uint8_t *)"0 ?abcdef", 9, TCP_CLASS_TINC);
	check_tcp("tinc, one byte", (const uint8_t *)"0", 1, TCP_CLASS_NEED_MORE);
	check_tcp("digit but not tinc", (const uint8_t *)"0X", 2, TCP_CLASS_UNKNOWN);

	const uint8_t tls[] = {0x16, 0x03, 0x01, 0x00, 0x50};
	check_tcp("TLS 1.0 ClientHello", tls, sizeof(tls), TCP_CLASS_TLS);
	const uint8_t tls13[] = {0x16, 0x03, 0x04};
	check_tcp("TLS 1.3 record", tls13, sizeof(tls13), TCP_CLASS_TLS);
	const uint8_t tlsbad[] = {0x16, 0x02, 0x00};
	check_tcp("0x16 but SSLv2 ver", tlsbad, sizeof(tlsbad), TCP_CLASS_UNKNOWN);
	const uint8_t tls1b[] = {0x16};
	check_tcp("TLS, one byte", tls1b, sizeof(tls1b), TCP_CLASS_NEED_MORE);

	check_tcp("HTTP GET", (const uint8_t *)"GET / HTTP/1.1", 14, TCP_CLASS_HTTP);
	check_tcp("HTTP HEAD", (const uint8_t *)"HEAD / HTTP/1.0", 15, TCP_CLASS_HTTP);
	check_tcp("HTTP POST", (const uint8_t *)"POST /x", 7, TCP_CLASS_HTTP);
	check_tcp("h2c preface", (const uint8_t *)"PRI * HTTP/2.0", 14, TCP_CLASS_HTTP);
	check_tcp("HTTP partial 'GE'", (const uint8_t *)"GE", 2, TCP_CLASS_NEED_MORE);
	check_tcp("uppercase junk 'ZZ'", (const uint8_t *)"ZZ", 2, TCP_CLASS_UNKNOWN);

	const uint8_t obfs[] = {0xa3, 0x11, 0x22, 0x33};
	check_tcp("obfs preamble 0xA3", obfs, sizeof(obfs), TCP_CLASS_OBFS);

	const uint8_t rnd[] = {0xff, 0x00, 0x13, 0x37};
	check_tcp("random bytes", rnd, sizeof(rnd), TCP_CLASS_UNKNOWN);
	check_tcp("empty", rnd, 0, TCP_CLASS_NEED_MORE);

	/* ---- UDP ---- */
	uint8_t sf[SF_HDR_LEN];
	memset(sf, 0, sizeof(sf));
	memcpy(sf, sf_magic, SF_MAGIC_LEN);
	sf[6] = SF_TYPE_DATA;
	sf[7] = SF_FLAG_SYN;
	check_udp("SF frame, accepted", sf, sizeof(sf), all, UDP_CLASS_SF);
	check_udp("SF frame, not accepted", sf, sizeof(sf), TRANSPORT_MASK_PLAIN, UDP_CLASS_SPTPS);
	check_udp("SF magic, short", sf, SF_HDR_LEN - 1, all, UDP_CLASS_SPTPS);

	/* QUIC v1 long header (form|fixed = 0xC0..0xFF, version 0x00000001) */
	const uint8_t quic[] = {0xc3, 0x00, 0x00, 0x00, 0x01, 0xaa, 0xbb};
	check_udp("QUIC v1, accepted", quic, sizeof(quic), all, UDP_CLASS_QUIC);
	check_udp("QUIC v1, not accepted", quic, sizeof(quic), TRANSPORT_MASK_PLAIN, UDP_CLASS_SPTPS);
	const uint8_t quicbad[] = {0xc3, 0xde, 0xad, 0xbe, 0xef, 0x00};
	check_udp("long hdr, unknown ver", quicbad, sizeof(quicbad), all, UDP_CLASS_SPTPS);

	/* A genuine SPTPS relay datagram: dst id then src id; first byte is a
	   normal node-id byte, not the SF magic and not a QUIC long header. */
	const uint8_t sptps[] = {0x3a, 0x7c, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x11, 0x22};
	check_udp("SPTPS relay datagram", sptps, sizeof(sptps), all, UDP_CLASS_SPTPS);
	const uint8_t sptps_short[] = {0x00, 0x01, 0x02};
	check_udp("short SPTPS datagram", sptps_short, sizeof(sptps_short), all, UDP_CLASS_SPTPS);

	printf("\n%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
