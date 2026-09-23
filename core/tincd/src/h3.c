/*
    h3.c -- HTTP/3 framing and static-table QPACK for the quic carrier
            (RFC 9114, RFC 9204). See h3.h.

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

#include "h3.h"
#include "xalloc.h"

/* QPACK static table entries this file refers to (RFC 9204 Appendix A). */
#define QPACK_AUTHORITY 0               /* :authority */
#define QPACK_PATH_ROOT 1               /* :path / */
#define QPACK_CONTENT_LENGTH 4          /* content-length 0 */
#define QPACK_METHOD_POST 20            /* :method POST */
#define QPACK_SCHEME_HTTPS 23           /* :scheme https */
#define QPACK_STATUS_200 25             /* :status 200 */
#define QPACK_STATUS_404 27             /* :status 404 */
#define QPACK_CONTENT_TYPE_OCTET 44     /* content-type application/dns-message (name only) */
#define QPACK_STATUS_400 67             /* :status 400 */
#define QPACK_USER_AGENT 95             /* user-agent */
#define QPACK_ACCEPT_ANY 29             /* accept * / * */

/* SETTINGS identifiers (RFC 9114 §7.2.4.1, RFC 9204 §5, RFC 9297 §2.1.1). */
#define H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY 0x01
#define H3_SETTINGS_MAX_FIELD_SECTION_SIZE 0x06
#define H3_SETTINGS_QPACK_BLOCKED_STREAMS 0x07
#define H3_SETTINGS_H3_DATAGRAM 0x33

size_t h3_varint_put(uint8_t *out, uint64_t v) {
	if(v < 0x40) {
		out[0] = (uint8_t)v;
		return 1;
	}

	if(v < 0x4000) {
		out[0] = (uint8_t)(0x40 | (v >> 8));
		out[1] = (uint8_t)v;
		return 2;
	}

	if(v < 0x40000000) {
		out[0] = (uint8_t)(0x80 | (v >> 24));
		out[1] = (uint8_t)(v >> 16);
		out[2] = (uint8_t)(v >> 8);
		out[3] = (uint8_t)v;
		return 4;
	}

	out[0] = (uint8_t)(0xc0 | ((v >> 56) & 0x3f));

	for(int i = 1; i < 8; i++) {
		out[i] = (uint8_t)(v >> (8 * (7 - i)));
	}

	return 8;
}

size_t h3_varint_get(const uint8_t *buf, size_t len, uint64_t *v) {
	if(!len) {
		return 0;
	}

	size_t n = (size_t)1 << (buf[0] >> 6);

	if(len < n) {
		return 0;
	}

	uint64_t r = buf[0] & 0x3f;

	for(size_t i = 1; i < n; i++) {
		r = (r << 8) | buf[i];
	}

	*v = r;
	return n;
}

/* ---- unidirectional stream preambles ---------------------------------------- */

static uint8_t control_preamble[32];
static size_t control_preamble_len;

static void build_control_preamble(void) {
	static const uint64_t settings[][2] = {
		{H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0},
		{H3_SETTINGS_QPACK_BLOCKED_STREAMS, 0},
		{H3_SETTINGS_MAX_FIELD_SECTION_SIZE, 65536},
		{H3_SETTINGS_H3_DATAGRAM, 1},
	};
	uint8_t body[24];
	size_t blen = 0;

	for(size_t i = 0; i < sizeof(settings) / sizeof(settings[0]); i++) {
		blen += h3_varint_put(body + blen, settings[i][0]);
		blen += h3_varint_put(body + blen, settings[i][1]);
	}

	size_t o = 0;
	control_preamble[o++] = H3_STREAM_CONTROL;
	control_preamble[o++] = H3_FRAME_SETTINGS;
	o += h3_varint_put(control_preamble + o, blen);
	memcpy(control_preamble + o, body, blen);
	control_preamble_len = o + blen;
}

const uint8_t *h3_uni_preamble(uint64_t type, size_t *len) {
	static const uint8_t encoder[] = {H3_STREAM_QPACK_ENCODER};
	static const uint8_t decoder[] = {H3_STREAM_QPACK_DECODER};

	switch(type) {
	case H3_STREAM_CONTROL:
		if(!control_preamble_len) {
			build_control_preamble();
		}

		*len = control_preamble_len;
		return control_preamble;

	case H3_STREAM_QPACK_ENCODER:
		*len = sizeof(encoder);
		return encoder;

	case H3_STREAM_QPACK_DECODER:
		*len = sizeof(decoder);
		return decoder;

	default:
		*len = 0;
		return NULL;
	}
}

size_t h3_data_header(uint8_t *out, uint64_t len) {
	out[0] = H3_FRAME_DATA;
	return 1 + h3_varint_put(out + 1, len);
}

/* ---- QPACK encoding ------------------------------------------------------------ */

typedef struct fbuf_t {
	uint8_t *data;
	size_t len, cap;
} fbuf_t;

static void fb_put(fbuf_t *b, const void *data, size_t len) {
	if(b->len + len > b->cap) {
		b->cap = (b->len + len) * 2 + 64;
		b->data = xrealloc(b->data, b->cap);
	}

	memcpy(b->data + b->len, data, len);
	b->len += len;
}

static void fb_byte(fbuf_t *b, uint8_t c) {
	fb_put(b, &c, 1);
}

/* QPACK/HPACK prefixed integer (RFC 7541 §5.1): `flags' occupies the bits
   above the `bits'-bit prefix of the first byte. */
static void qp_int(fbuf_t *b, uint8_t flags, int bits, uint64_t v) {
	uint64_t max = ((uint64_t)1 << bits) - 1;

	if(v < max) {
		fb_byte(b, (uint8_t)(flags | v));
		return;
	}

	fb_byte(b, (uint8_t)(flags | max));
	v -= max;

	while(v >= 0x80) {
		fb_byte(b, (uint8_t)(0x80 | (v & 0x7f)));
		v >>= 7;
	}

	fb_byte(b, (uint8_t)v);
}

/* Indexed field line, static table: 11xxxxxx. */
static void qp_indexed(fbuf_t *b, unsigned idx) {
	qp_int(b, 0xc0, 6, idx);
}

/* Literal value, no Huffman: H=0 + 7-bit length. */
static void qp_string(fbuf_t *b, uint8_t flags, int bits, const char *s, size_t len) {
	qp_int(b, flags, bits, len);
	fb_put(b, s, len);
}

/* Literal field line with a static name reference: 01N1xxxx. */
static void qp_literal_ref(fbuf_t *b, unsigned idx, const char *value, size_t vlen) {
	qp_int(b, 0x50, 4, idx);
	qp_string(b, 0x00, 7, value, vlen);
}

/* Literal field line with a literal name: 001NHxxx. */
static void qp_literal_name(fbuf_t *b, const char *name, size_t nlen, const char *value, size_t vlen) {
	qp_string(b, 0x20, 3, name, nlen);
	qp_string(b, 0x00, 7, value, vlen);
}

/* Wrap a field section (prefix + lines) into a HEADERS frame. */
static uint8_t *headers_frame(fbuf_t *fs, fbuf_t *extra, size_t *outlen) {
	fbuf_t out = {0};
	uint8_t v[8];
	fb_byte(&out, H3_FRAME_HEADERS);
	fb_put(&out, v, h3_varint_put(v, fs->len));
	fb_put(&out, fs->data, fs->len);
	free(fs->data);

	if(extra) {
		fb_put(&out, extra->data, extra->len);
		free(extra->data);
	}

	*outlen = out.len;
	return out.data;
}

static void section_prefix(fbuf_t *fs) {
	fb_byte(fs, 0x00);      /* Required Insert Count 0: static table only */
	fb_byte(fs, 0x00);      /* Delta Base 0 */
}

uint8_t *h3_request(const char *authority, const char *path, size_t *outlen) {
	static const char ua[] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
	                         "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
	static const char ctype[] = "application/octet-stream";
	fbuf_t fs = {0};

	section_prefix(&fs);
	qp_indexed(&fs, QPACK_METHOD_POST);
	qp_indexed(&fs, QPACK_SCHEME_HTTPS);
	qp_literal_ref(&fs, QPACK_AUTHORITY, authority, strlen(authority));

	if(!path || !strcmp(path, "/")) {
		qp_indexed(&fs, QPACK_PATH_ROOT);
	} else {
		qp_literal_ref(&fs, QPACK_PATH_ROOT, path, strlen(path));
	}

	qp_literal_ref(&fs, QPACK_CONTENT_TYPE_OCTET, ctype, sizeof(ctype) - 1);
	qp_indexed(&fs, QPACK_ACCEPT_ANY);
	qp_literal_ref(&fs, QPACK_USER_AGENT, ua, sizeof(ua) - 1);
	return headers_frame(&fs, NULL, outlen);
}

uint8_t *h3_response_ok(size_t *outlen) {
	static const char server[] = "nginx";
	fbuf_t fs = {0};

	section_prefix(&fs);
	qp_indexed(&fs, QPACK_STATUS_200);
	qp_literal_name(&fs, "server", 6, server, sizeof(server) - 1);
	return headers_frame(&fs, NULL, outlen);
}

static bool hop_by_hop(const char *name, size_t len) {
	static const char *const drop[] = {"connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"};

	for(size_t i = 0; i < sizeof(drop) / sizeof(drop[0]); i++) {
		if(strlen(drop[i]) == len && !strncasecmp(drop[i], name, len)) {
			return true;
		}
	}

	return false;
}

uint8_t *h3_from_http1(const char *resp, size_t resplen, size_t *outlen) {
	const char *end = resp + resplen;
	const char *eol = memchr(resp, '\n', resplen);

	if(resplen < 12 || strncmp(resp, "HTTP/1.", 7) || !eol) {
		return NULL;
	}

	int status = atoi(resp + 9);

	if(status < 100 || status > 999) {
		return NULL;
	}

	fbuf_t fs = {0};
	section_prefix(&fs);

	switch(status) {
	case 200:
		qp_indexed(&fs, QPACK_STATUS_200);
		break;

	case 404:
		qp_indexed(&fs, QPACK_STATUS_404);
		break;

	case 400:
		qp_indexed(&fs, QPACK_STATUS_400);
		break;

	default: {
		char st[4];
		snprintf(st, sizeof(st), "%d", status);
		qp_literal_ref(&fs, QPACK_STATUS_200, st, 3);
	}
	}

	const char *p = eol + 1;
	const char *body = NULL;

	while(p < end) {
		const char *le = memchr(p, '\n', (size_t)(end - p));

		if(!le) {
			break;
		}

		size_t ll = (size_t)(le - p);

		if(ll && p[ll - 1] == '\r') {
			ll--;
		}

		if(!ll) {
			body = le + 1;
			break;
		}

		const char *colon = memchr(p, ':', ll);

		if(colon && colon > p) {
			size_t nlen = (size_t)(colon - p);
			const char *v = colon + 1;

			while(v < p + ll && (*v == ' ' || *v == '\t')) {
				v++;
			}

			if(!hop_by_hop(p, nlen)) {
				char name[64];

				if(nlen < sizeof(name)) {
					for(size_t i = 0; i < nlen; i++) {
						name[i] = (char)tolower((unsigned char)p[i]);
					}

					qp_literal_name(&fs, name, nlen, v, (size_t)(p + ll - v));
				}
			}
		}

		p = le + 1;
	}

	if(!body) {
		free(fs.data);
		return NULL;
	}

	fbuf_t data = {0};
	size_t blen = (size_t)(end - body);
	uint8_t hdr[H3_DATA_HDR_MAX];

	if(blen) {
		fb_put(&data, hdr, h3_data_header(hdr, blen));
		fb_put(&data, body, blen);
	}

	return headers_frame(&fs, blen ? &data : NULL, outlen);
}

/* ---- frame parser ------------------------------------------------------------------ */

bool h3_parse(h3_parser_t *p, const uint8_t *buf, size_t len, h3_payload_cb_t cb, void *data) {
	while(len) {
		if(!p->in_payload) {
			/* Accumulate a frame header: two varints, at most 16 bytes. */
			size_t take = sizeof(p->hdr) - p->hlen;

			if(take > len) {
				take = len;
			}

			memcpy(p->hdr + p->hlen, buf, take);
			size_t have = p->hlen + take;
			uint64_t type, flen;
			size_t n1 = h3_varint_get(p->hdr, have, &type);
			size_t n2 = n1 ? h3_varint_get(p->hdr + n1, have - n1, &flen) : 0;

			if(!n1 || !n2) {
				if(have == sizeof(p->hdr)) {
					return false;
				}

				p->hlen = have;
				return true;
			}

			/* Bytes of this chunk that belonged to the header. */
			size_t used = n1 + n2 - p->hlen;
			buf += used;
			len -= used;
			p->hlen = 0;
			p->type = type;
			p->remain = flen;
			p->in_payload = true;

			if(type == H3_FRAME_HEADERS) {
				p->seen_headers = true;
			}

			if(!flen) {
				p->in_payload = false;

				if(!cb(data, type, buf, 0)) {
					return false;
				}
			}

			continue;
		}

		size_t take = p->remain < len ? (size_t)p->remain : len;

		if(!cb(data, p->type, buf, take)) {
			return false;
		}

		buf += take;
		len -= take;
		p->remain -= take;

		if(!p->remain) {
			p->in_payload = false;
		}
	}

	return true;
}
