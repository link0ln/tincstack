/*
    fuzz_classify.c -- libFuzzer harness for the transport front classifier
    (transport_table.c): the first bytes of unauthenticated TCP and UDP input.

    Every prefix of the input goes through transport_classify_tcp() (the
    front peeks 1..8 bytes), the whole input through transport_classify_udp()
    under every accept mask, and the input as a string through
    transport_parse_list(). Properties: no crash; a TCP verdict never flips
    back to NEED_MORE once more bytes are seen; SF is only ever claimed with
    the full magic present.

    This program is free software; see the GPL v2+ (same as the rest of tinc).
*/

#include "system.h"
#include "transport.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	transport_tcp_class_t prev = TCP_CLASS_NEED_MORE;

	for(size_t n = 0; n <= size && n <= TRANSPORT_TCP_PEEK; n++) {
		transport_tcp_class_t c = transport_classify_tcp(data, n);

		if(prev != TCP_CLASS_NEED_MORE && c != prev) {
			abort(); /* a decided verdict changed with more bytes */
		}

		prev = c;
	}

	for(uint32_t mask = 0; mask < (1u << TRANSPORT_MAX); mask++) {
		transport_udp_class_t u = transport_classify_udp(data, size, mask);

		if(u == UDP_CLASS_SF && (size < SF_HDR_LEN || memcmp(data, sf_magic, SF_MAGIC_LEN))) {
			abort();
		}

		if(u == UDP_CLASS_SF && !(mask & TRANSPORT_BIT(TRANSPORT_SF))) {
			abort();
		}

		if(u == UDP_CLASS_QUIC && !(mask & TRANSPORT_BIT(TRANSPORT_QUIC))) {
			abort();
		}
	}

	char *s = malloc(size + 1);
	memcpy(s, data, size);
	s[size] = 0;
	uint32_t m;
	transport_id_t order[TRANSPORT_MAX];
	int count;
	char bad[TRANSPORT_LIST_MAX];

	if(transport_parse_list(s, &m, order, &count, bad)) {
		char buf[TRANSPORT_LIST_MAX];
		transport_mask_to_string(m, buf);
	}

	free(s);
	return 0;
}
