#ifndef TINC_H3_H
#define TINC_H3_H

/*
    h3.h -- the HTTP/3 layer of the quic carrier: just enough of RFC 9114
            (frames, SETTINGS, unidirectional stream types) and RFC 9204
            (QPACK without a dynamic table) that the carrier is an HTTP/3
            connection on the wire and to anyone who talks to it.

    The tinc session is one HTTP/3 request: the dialler POSTs on its first
    bidirectional stream and streams its body (the authenticator, then SPTPS
    meta) in DATA frames; the listener answers 200 and streams the other
    direction the same way. A client that is not a tinc peer -- a browser, a
    prober -- gets the decoy page as an ordinary HTTP/3 response.

    Only the static QPACK table is used, and SETTINGS announce a dynamic table
    capacity of 0, so no peer may reference one. The listener decodes a
    request's pseudo-headers (h3_decode_request) to answer it as nginx would;
    nothing else is decoded.

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

#define H3_FRAME_DATA 0x00
#define H3_FRAME_HEADERS 0x01
#define H3_FRAME_SETTINGS 0x04
/* A reserved frame type (RFC 9114 §7.2.8: 0x1f * N + 0x21, N = 467), which
   HTTP/3 endpoints ignore. A listener sends it, empty, after its answer to an
   authenticated tinc dialler: "I send you datagrams you did not announce". */
#define H3_FRAME_TINC_DGRAM 0x38ae

#define H3_STREAM_CONTROL 0x00
#define H3_STREAM_QPACK_ENCODER 0x02
#define H3_STREAM_QPACK_DECODER 0x03

#define H3_NO_ERROR 0x100
#define H3_GENERAL_PROTOCOL_ERROR 0x101
#define H3_REQUEST_REJECTED 0x10b

/* Largest DATA frame header: type (1 byte) + an 8-byte varint length. */
#define H3_DATA_HDR_MAX 9

/* QUIC variable-length integer (RFC 9000 §16). Returns the bytes written
   (1, 2, 4 or 8); `out' needs room for 8. */
size_t h3_varint_put(uint8_t *out, uint64_t v);

/* Decode one varint from buf[0..len). Returns its length, 0 if more bytes are
   needed. */
size_t h3_varint_get(const uint8_t *buf, size_t len, uint64_t *v);

/* The bytes a unidirectional stream of `type' starts with: the stream type,
   and for the control stream its SETTINGS frame. Constant for the life of the
   process (ngtcp2 needs stream data to stay valid until acknowledged). */
const uint8_t *h3_uni_preamble(uint64_t type, size_t *len);

/* A DATA frame header for a payload of `len' bytes. Returns its length. */
size_t h3_data_header(uint8_t *out, uint64_t len);

/* HEADERS frame of the dialler's request: POST https://<authority><path>.
   Newly allocated; *outlen is set. */
uint8_t *h3_request(const char *authority, const char *path, size_t *outlen);

/* HEADERS frame of the listener's answer to an authenticated tinc peer:
   status 200, nothing that says what follows. */
uint8_t *h3_response_ok(size_t *outlen);

/* Turn an HTTP/1.1 response (status line, headers, blank line, body -- what
   decoy_respond_static() returns) into a HEADERS frame and one DATA frame.
   Connection-specific headers are dropped, names lowercased. Newly allocated;
   NULL if `resp' is not a response. */
uint8_t *h3_from_http1(const char *resp, size_t resplen, size_t *outlen);

/* What a web server answers a request by: its pseudo-header fields, decoded
   from a HEADERS frame's field section (RFC 9204: static table references
   and literals, Huffman-coded or not). NUL-terminated; a field that is
   missing stays empty. */
typedef struct h3_req_fields_t {
	char method[32];
	char path[8192];
	char authority[256];
} h3_req_fields_t;

/* Decode the field section `fs' (a HEADERS frame's payload). Returns false if
   it cannot be decoded: a reference to a dynamic table (we announce a
   capacity of 0, so a peer may not make one), a malformed integer, string or
   Huffman code, or a pseudo-header value longer than its buffer. */
bool h3_decode_request(const uint8_t *fs, size_t len, h3_req_fields_t *out);

/* Incremental frame parser for one stream. Frame headers may arrive split
   across packets; payloads are handed out in whatever pieces arrive. */
typedef struct h3_parser_t {
	uint8_t hdr[16];
	size_t hlen;
	uint64_t type;
	uint64_t remain;        /* payload bytes left in the current frame */
	bool in_payload;
	bool seen_headers;      /* a HEADERS frame has been parsed on this stream */
} h3_parser_t;

/* Called for every piece of a frame payload (`len' may be 0 for an empty
   frame). Return false to stop parsing. */
typedef bool (*h3_payload_cb_t)(void *data, uint64_t type, const uint8_t *payload, size_t len);

/* Feed stream bytes. Returns false on a malformed stream (a frame header
   longer than any valid one) or when `cb' returned false. */
bool h3_parse(h3_parser_t *p, const uint8_t *buf, size_t len, h3_payload_cb_t cb, void *data);

#endif /* TINC_H3_H */
