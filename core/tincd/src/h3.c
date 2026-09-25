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
#include "h3_huffman.h"
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

static uint8_t control_preamble[2][32];
static size_t control_preamble_len[2];

static void build_control_preamble(bool server) {
	/* The dialler's; nginx's for the listener (ngx_http_v3_send_settings:
	   its QPACK table and blocked streams, nothing else). */
	static const uint64_t dialler[][2] = {
		{H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0},
		{H3_SETTINGS_QPACK_BLOCKED_STREAMS, 0},
		{H3_SETTINGS_MAX_FIELD_SECTION_SIZE, 65536},
		{H3_SETTINGS_H3_DATAGRAM, 1},
	};
	static const uint64_t listener[][2] = {
		{H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY, H3_QPACK_CAPACITY},
		{H3_SETTINGS_QPACK_BLOCKED_STREAMS, H3_QPACK_BLOCKED_STREAMS},
	};
	const uint64_t (*settings)[2] = server ? listener : dialler;
	size_t n = server ? sizeof(listener) / sizeof(listener[0]) : sizeof(dialler) / sizeof(dialler[0]);
	uint8_t body[24];
	size_t blen = 0;

	for(size_t i = 0; i < n; i++) {
		blen += h3_varint_put(body + blen, settings[i][0]);
		blen += h3_varint_put(body + blen, settings[i][1]);
	}

	uint8_t *p = control_preamble[server];
	size_t o = 0;
	p[o++] = H3_STREAM_CONTROL;
	p[o++] = H3_FRAME_SETTINGS;
	o += h3_varint_put(p + o, blen);
	memcpy(p + o, body, blen);
	control_preamble_len[server] = o + blen;
}

const uint8_t *h3_uni_preamble(uint64_t type, bool server, size_t *len) {
	static const uint8_t encoder[] = {H3_STREAM_QPACK_ENCODER};
	static const uint8_t decoder[] = {H3_STREAM_QPACK_DECODER};

	switch(type) {
	case H3_STREAM_CONTROL:
		if(!control_preamble_len[server]) {
			build_control_preamble(server);
		}

		*len = control_preamble_len[server];
		return control_preamble[server];

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

/* ---- QPACK decoding (the listener's view of a request) ------------------------- */

/* Prefixed integer (RFC 7541 5.1) with a `bits'-bit prefix at buf[*i].
   Returns false if truncated or over 2^32. */
static bool qd_int(const uint8_t *buf, size_t len, size_t *i, int bits, uint64_t *v) {
	if(*i >= len) {
		return false;
	}

	uint64_t max = ((uint64_t)1 << bits) - 1;
	*v = buf[(*i)++] & max;

	if(*v < max) {
		return true;
	}

	for(int shift = 0; shift <= 28; shift += 7) {
		if(*i >= len) {
			return false;
		}

		uint8_t b = buf[(*i)++];
		*v += (uint64_t)(b & 0x7f) << shift;

		if(!(b & 0x80)) {
			return *v <= UINT32_MAX;
		}
	}

	return false;
}

/* Canonical-code tables for decoding (the HPACK code is canonical: codes of
   one length are consecutive in symbol order). */
static uint32_t huff_first[31];
static uint16_t huff_count[31], huff_offset[31], huff_sorted[257];

static void huff_init(void) {
	static bool done;

	if(done) {
		return;
	}

	uint16_t n = 0;

	for(int l = 1; l <= 30; l++) {
		huff_offset[l] = n;
		huff_first[l] = UINT32_MAX;

		for(int sym = 0; sym < 257; sym++) {
			if(huff_len[sym] == l) {
				if(huff_first[l] == UINT32_MAX) {
					huff_first[l] = huff_code[sym];
				}

				huff_sorted[n++] = (uint16_t)sym;
				huff_count[l]++;
			}
		}
	}

	done = true;
}

/* Huffman-decode src[0..len) into out (cap bytes, NUL-terminated). */
static bool huff_decode(const uint8_t *src, size_t len, char *out, size_t cap, size_t *outlen) {
	huff_init();
	uint32_t code = 0;
	int bits = 0;
	size_t o = 0;

	for(size_t i = 0; i < len; i++) {
		for(int b = 7; b >= 0; b--) {
			code = code << 1 | ((src[i] >> b) & 1);
			bits++;

			if(huff_count[bits] && code >= huff_first[bits] && code - huff_first[bits] < huff_count[bits]) {
				uint16_t sym = huff_sorted[huff_offset[bits] + (code - huff_first[bits])];

				if(sym == 256 || o + 1 >= cap) {
					return false;   /* EOS in a string, or too long */
				}

				out[o++] = (char)sym;
				code = 0;
				bits = 0;
			} else if(bits == 30) {
				return false;
			}
		}
	}

	/* Padding: fewer than 8 bits, all ones (a prefix of EOS). */
	if(bits > 7 || code != ((uint32_t)1 << bits) - 1) {
		return false;
	}

	out[o] = 0;
	*outlen = o;
	return true;
}

/* A string literal: H flag at bit `bits' of buf[*i], then a length with a
   `bits'-bit prefix. Decoded into out (cap bytes, NUL-terminated). */
static bool qd_string(const uint8_t *buf, size_t len, size_t *i, int bits, char *out, size_t cap) {
	if(*i >= len) {
		return false;
	}

	bool huff = buf[*i] & (1 << bits);
	uint64_t slen;

	if(!qd_int(buf, len, i, bits, &slen) || slen > len - *i) {
		return false;
	}

	const uint8_t *str = buf + *i;
	*i += slen;

	if(huff) {
		size_t olen;
		return huff_decode(str, slen, out, cap, &olen);
	}

	if(slen >= cap) {
		return false;
	}

	memcpy(out, str, slen);
	out[slen] = 0;
	return true;
}

/* RFC 9204 Appendix A: the QPACK static table, generated from nginx 1.26.3's
   src/http/v3/ngx_http_v3_table.c (99 entries), values as nginx has them.
   Only the names, and the values of :method, :path and :authority, are ever
   used here. */
static const struct {
	const char *name;
	const char *value;
} qpack_static[] = {
	{":authority", ""},
	{":path", "/"},
	{"age", "0"},
	{"content-disposition", ""},
	{"content-length", "0"},
	{"cookie", ""},
	{"date", ""},
	{"etag", ""},
	{"if-modified-since", ""},
	{"if-none-match", ""},
	{"last-modified", ""},
	{"link", ""},
	{"location", ""},
	{"referer", ""},
	{"set-cookie", ""},
	{":method", "CONNECT"},
	{":method", "DELETE"},
	{":method", "GET"},
	{":method", "HEAD"},
	{":method", "OPTIONS"},
	{":method", "POST"},
	{":method", "PUT"},
	{":scheme", "http"},
	{":scheme", "https"},
	{":status", "103"},
	{":status", "200"},
	{":status", "304"},
	{":status", "404"},
	{":status", "503"},
	{"accept", "*/*"},
	{"accept", "application/dns-message"},
	{"accept-encoding", "gzip, deflate, br"},
	{"accept-ranges", "bytes"},
	{"access-control-allow-headers", "cache-control"},
	{"access-control-allow-headers", "content-type"},
	{"access-control-allow-origin", "*"},
	{"cache-control", "max-age=0"},
	{"cache-control", "max-age=2592000"},
	{"cache-control", "max-age=604800"},
	{"cache-control", "no-cache"},
	{"cache-control", "no-store"},
	{"cache-control", "public, max-age=31536000"},
	{"content-encoding", "br"},
	{"content-encoding", "gzip"},
	{"content-type", "application/dns-message"},
	{"content-type", "application/javascript"},
	{"content-type", "application/json"},
	{"content-type", "application/x-www-form-urlencoded"},
	{"content-type", "image/gif"},
	{"content-type", "image/jpeg"},
	{"content-type", "image/png"},
	{"content-type", "text/css"},
	{"content-type", "text/html;charset=utf-8"},
	{"content-type", "text/plain"},
	{"content-type", "text/plain;charset=utf-8"},
	{"range", "bytes=0-"},
	{"strict-transport-security", "max-age=31536000"},
	{"strict-transport-security", "max-age=31536000;includesubdomains"},
	{"strict-transport-security", "max-age=31536000;includesubdomains;preload"},
	{"vary", "accept-encoding"},
	{"vary", "origin"},
	{"x-content-type-options", "nosniff"},
	{"x-xss-protection", "1;mode=block"},
	{":status", "100"},
	{":status", "204"},
	{":status", "206"},
	{":status", "302"},
	{":status", "400"},
	{":status", "403"},
	{":status", "421"},
	{":status", "425"},
	{":status", "500"},
	{"accept-language", ""},
	{"access-control-allow-credentials", "FALSE"},
	{"access-control-allow-credentials", "TRUE"},
	{"access-control-allow-headers", "*"},
	{"access-control-allow-methods", "get"},
	{"access-control-allow-methods", "get, post, options"},
	{"access-control-allow-methods", "options"},
	{"access-control-expose-headers", "content-length"},
	{"access-control-request-headers", "content-type"},
	{"access-control-request-method", "get"},
	{"access-control-request-method", "post"},
	{"alt-svc", "clear"},
	{"authorization", ""},
	{"content-security-policy", "script-src 'none';object-src 'none';base-uri 'none'"},
	{"early-data", "1"},
	{"expect-ct", ""},
	{"forwarded", ""},
	{"if-range", ""},
	{"origin", ""},
	{"purpose", "prefetch"},
	{"server", ""},
	{"timing-allow-origin", "*"},
	{"upgrade-insecure-requests", "1"},
	{"user-agent", ""},
	{"x-forwarded-for", ""},
	{"x-frame-options", "deny"},
	{"x-frame-options", "sameorigin"},
};

#define QPACK_STATIC_N (sizeof(qpack_static) / sizeof(qpack_static[0]))

/* Largest name or value kept: the table's capacity is 4096. */
#define QPACK_STR_MAX 4096

typedef struct qpack_entry_t {
	char *name;
	char *value;
	size_t size;            /* name + value + 32 (RFC 9204 3.2.1) */
} qpack_entry_t;

struct h3_qpack_t {
	uint64_t max_capacity;  /* what our SETTINGS announce */
	uint64_t capacity;      /* what the encoder set */
	uint64_t size;
	uint64_t inserts;       /* entries ever inserted: the next absolute index */
	uint64_t acked;         /* the encoder knows we have this many */
	qpack_entry_t *e;       /* e[k] has absolute index inserts - n + k */
	size_t n;
	uint8_t *in;            /* encoder stream bytes not yet a whole instruction */
	size_t inlen;
};

h3_qpack_t *h3_qpack_new(uint64_t max_capacity) {
	h3_qpack_t *q = xzalloc(sizeof(*q));
	q->max_capacity = max_capacity;
	q->e = xzalloc(sizeof(*q->e) * (max_capacity / 32 + 1));
	q->in = xmalloc(2 * QPACK_STR_MAX + 64);
	return q;
}

static void qpack_drop_oldest(h3_qpack_t *q) {
	q->size -= q->e[0].size;
	free(q->e[0].name);
	free(q->e[0].value);
	memmove(q->e, q->e + 1, (q->n - 1) * sizeof(*q->e));
	q->n--;
}

void h3_qpack_free(h3_qpack_t *q) {
	if(!q) {
		return;
	}

	while(q->n) {
		qpack_drop_oldest(q);
	}

	free(q->e);
	free(q->in);
	free(q);
}

/* The entry with absolute index `abs', or NULL if it is not in the table. */
static const qpack_entry_t *qpack_get(const h3_qpack_t *q, uint64_t abs) {
	if(!q || abs >= q->inserts || abs < q->inserts - q->n) {
		return NULL;
	}

	return &q->e[abs - (q->inserts - q->n)];
}

static bool qpack_insert(h3_qpack_t *q, const char *name, const char *value) {
	size_t size = strlen(name) + strlen(value) + 32;

	if(size > q->capacity) {
		return false;
	}

	while(q->size + size > q->capacity) {
		qpack_drop_oldest(q);
	}

	q->e[q->n].name = xstrdup(name);
	q->e[q->n].value = xstrdup(value);
	q->e[q->n].size = size;
	q->n++;
	q->size += size;
	q->inserts++;
	return true;
}

/* How long the prefixed integer at buf[i] is: 0 if more bytes are needed,
   -1 if it is too large to be valid. */
static ssize_t qd_int_len(const uint8_t *buf, size_t len, size_t i, int bits, uint64_t *v) {
	size_t j = i;

	if(qd_int(buf, len, &j, bits, v)) {
		return (ssize_t)(j - i);
	}

	/* Truncated, or over 2^32: a complete integer ends with a byte whose
	   top bit is clear. */
	for(j = i + 1; j < len && j < i + 6; j++) {
		if(!(buf[j] & 0x80)) {
			return -1;
		}
	}

	return j < i + 6 ? 0 : -1;
}

/* How long the string literal at buf[i] is (0: more bytes needed, -1:
   invalid or longer than any the table can hold). */
static ssize_t qd_string_len(const uint8_t *buf, size_t len, size_t i, int bits) {
	uint64_t slen;
	ssize_t n = qd_int_len(buf, len, i, bits, &slen);

	if(n <= 0) {
		return n;
	}

	if(slen > QPACK_STR_MAX) {
		return -1;
	}

	return (size_t)n + slen <= len - i ? n + (ssize_t)slen : 0;
}

/* How long the encoder instruction at buf[0] is (0: more bytes needed,
   -1: invalid). */
static ssize_t qpack_insn_len(const uint8_t *buf, size_t len) {
	uint64_t v;
	ssize_t a, b;

	if(!len) {
		return 0;
	}

	if(buf[0] & 0x80) {                     /* Insert With Name Reference */
		a = qd_int_len(buf, len, 0, 6, &v);
		b = a > 0 ? qd_string_len(buf, len, (size_t)a, 7) : a;
		return b > 0 ? a + b : b;
	}

	if(buf[0] & 0x40) {                     /* Insert With Literal Name */
		a = qd_string_len(buf, len, 0, 5);
		b = a > 0 ? qd_string_len(buf, len, (size_t)a, 7) : a;
		return b > 0 ? a + b : b;
	}

	/* Set Dynamic Table Capacity (001), Duplicate (000) */
	return qd_int_len(buf, len, 0, 5, &v);
}

/* Carry out one whole encoder instruction. */
static bool qpack_insn(h3_qpack_t *q, const uint8_t *buf, size_t len) {
	static char name[QPACK_STR_MAX + 1], value[QPACK_STR_MAX + 1];
	size_t i = 0;
	uint64_t v;

	if(buf[0] & 0x80) {                     /* 1Txxxxxx: Insert With Name Reference */
		bool stat = buf[0] & 0x40;

		if(!qd_int(buf, len, &i, 6, &v) || !qd_string(buf, len, &i, 7, value, sizeof(value))) {
			return false;
		}

		if(stat) {
			if(v >= QPACK_STATIC_N) {
				return false;
			}

			return qpack_insert(q, qpack_static[v].name, value);
		}

		const qpack_entry_t *e = v < q->inserts ? qpack_get(q, q->inserts - 1 - v) : NULL;

		if(!e) {
			return false;
		}

		snprintf(name, sizeof(name), "%s", e->name);
		return qpack_insert(q, name, value);
	}

	if(buf[0] & 0x40) {                     /* 01Hxxxxx: Insert With Literal Name */
		return qd_string(buf, len, &i, 5, name, sizeof(name)) &&
		       qd_string(buf, len, &i, 7, value, sizeof(value)) &&
		       qpack_insert(q, name, value);
	}

	if(buf[0] & 0x20) {                     /* 001xxxxx: Set Dynamic Table Capacity */
		if(!qd_int(buf, len, &i, 5, &v) || v > q->max_capacity) {
			return false;
		}

		q->capacity = v;

		while(q->size > q->capacity) {
			qpack_drop_oldest(q);
		}

		return true;
	}

	/* 000xxxxx: Duplicate */
	if(!qd_int(buf, len, &i, 5, &v) || v >= q->inserts) {
		return false;
	}

	const qpack_entry_t *e = qpack_get(q, q->inserts - 1 - v);

	if(!e) {
		return false;
	}

	snprintf(name, sizeof(name), "%s", e->name);
	snprintf(value, sizeof(value), "%s", e->value);
	return qpack_insert(q, name, value);
}

bool h3_qpack_encoder_data(h3_qpack_t *q, const uint8_t *data, size_t len) {
	size_t cap = 2 * QPACK_STR_MAX + 64;

	while(len) {
		size_t take = cap - q->inlen < len ? cap - q->inlen : len;
		memcpy(q->in + q->inlen, data, take);
		q->inlen += take;
		data += take;
		len -= take;

		size_t off = 0;

		for(;;) {
			ssize_t n = qpack_insn_len(q->in + off, q->inlen - off);

			if(n < 0 || (n > 0 && !qpack_insn(q, q->in + off, (size_t)n))) {
				return false;
			}

			if(n == 0) {
				break;
			}

			off += (size_t)n;
		}

		memmove(q->in, q->in + off, q->inlen - off);
		q->inlen -= off;

		if(q->inlen == cap) {
			return false;   /* an instruction longer than any valid one */
		}
	}

	return true;
}

uint64_t h3_qpack_inserts(const h3_qpack_t *q) {
	return q ? q->inserts : 0;
}

size_t h3_qpack_increment(h3_qpack_t *q, uint8_t *out) {
	if(!q || q->inserts <= q->acked) {
		return 0;
	}

	uint64_t inc = q->inserts - q->acked;
	q->acked = q->inserts;
	fbuf_t fb = {out, 0, 16};
	qp_int(&fb, 0x00, 6, inc);
	return fb.len;
}

size_t h3_qpack_section_ack(h3_qpack_t *q, uint64_t ric, int64_t stream_id, uint8_t *out) {
	if(q && q->acked < ric) {
		q->acked = ric;
	}

	fbuf_t fb = {out, 0, 16};
	qp_int(&fb, 0x80, 7, (uint64_t)stream_id);
	return fb.len;
}

size_t h3_qpack_stream_cancel(int64_t stream_id, uint8_t *out) {
	fbuf_t fb = {out, 0, 16};
	qp_int(&fb, 0x40, 6, (uint64_t)stream_id);
	return fb.len;
}

/* Keep a decoded field if the decoy needs it. */
static bool qd_keep(h3_req_fields_t *out, const char *name, const char *value) {
	char *dst;
	size_t cap;

	if(!strcmp(name, ":authority")) {
		dst = out->authority;
		cap = sizeof(out->authority);
	} else if(!strcmp(name, ":path")) {
		dst = out->path;
		cap = sizeof(out->path);
	} else if(!strcmp(name, ":method")) {
		dst = out->method;
		cap = sizeof(out->method);
	} else {
		return true;
	}

	size_t n = strlen(value);

	if(n >= cap) {
		return false;
	}

	memcpy(dst, value, n + 1);
	return true;
}

/* Required Insert Count from its encoding (RFC 9204 4.5.1.1). */
static bool qd_ric(const h3_qpack_t *q, uint64_t enc, uint64_t *ric) {
	if(!enc) {
		*ric = 0;
		return true;
	}

	uint64_t max_entries = q ? q->max_capacity / 32 : 0;
	uint64_t full = 2 * max_entries;

	if(!full || enc > full) {
		return false;
	}

	uint64_t max_value = q->inserts + max_entries;
	uint64_t wrapped = max_value / full * full;
	uint64_t r = wrapped + enc - 1;

	if(r > max_value) {
		if(r <= full) {
			return false;
		}

		r -= full;
	}

	if(!r) {
		return false;
	}

	*ric = r;
	return true;
}

/* A field by static index, or by dynamic absolute index below `ric'. */
static bool qd_ref(const h3_qpack_t *q, bool stat, uint64_t abs, uint64_t ric,
                   const char **name, const char **value) {
	if(stat) {
		if(abs >= QPACK_STATIC_N) {
			return false;
		}

		*name = qpack_static[abs].name;
		*value = qpack_static[abs].value;
		return true;
	}

	const qpack_entry_t *e = abs < ric ? qpack_get(q, abs) : NULL;

	if(!e) {
		return false;
	}

	*name = e->name;
	*value = e->value;
	return true;
}

h3_decode_t h3_decode_request(const h3_qpack_t *q, const uint8_t *fs, size_t len,
                              h3_req_fields_t *out, uint64_t *ric) {
	static char name[QPACK_STR_MAX + 1], value[QPACK_STR_MAX + 1];
	size_t i = 0;
	uint64_t v, enc;

	memset(out, 0, sizeof(*out));

	if(!qd_int(fs, len, &i, 8, &enc) || !qd_ric(q, enc, ric) || i >= len) {
		return H3_DECODE_ERROR;
	}

	/* Base: Required Insert Count plus or minus Delta Base. */
	bool minus = fs[i] & 0x80;

	if(!qd_int(fs, len, &i, 7, &v) || (minus && v + 1 > *ric)) {
		return H3_DECODE_ERROR;
	}

	uint64_t base = minus ? *ric - v - 1 : *ric + v;

	if(*ric > h3_qpack_inserts(q)) {
		return H3_DECODE_BLOCKED;
	}

	while(i < len) {
		uint8_t b = fs[i];
		const char *n = NULL, *val = NULL;

		if(b & 0x80) {                          /* 1Txxxxxx: indexed */
			bool stat = b & 0x40;

			if(!qd_int(fs, len, &i, 6, &v) || (!stat && v >= base) ||
			                !qd_ref(q, stat, stat ? v : base - 1 - v, *ric, &n, &val)) {
				return H3_DECODE_ERROR;
			}
		} else if(b & 0x40) {                   /* 01NTxxxx: literal, name reference */
			bool stat = b & 0x10;

			if(!qd_int(fs, len, &i, 4, &v) || (!stat && v >= base) ||
			                !qd_ref(q, stat, stat ? v : base - 1 - v, *ric, &n, &val) ||
			                !qd_string(fs, len, &i, 7, value, sizeof(value))) {
				return H3_DECODE_ERROR;
			}

			val = value;
		} else if(b & 0x20) {                   /* 001NHxxx: literal, literal name */
			if(!qd_string(fs, len, &i, 3, name, sizeof(name)) ||
			                !qd_string(fs, len, &i, 7, value, sizeof(value))) {
				return H3_DECODE_ERROR;
			}

			n = name;
			val = value;
		} else if(b & 0x10) {                   /* 0001xxxx: indexed, post-base */
			if(!qd_int(fs, len, &i, 4, &v) || !qd_ref(q, false, base + v, *ric, &n, &val)) {
				return H3_DECODE_ERROR;
			}
		} else {                                /* 0000Nxxx: literal, post-base name */
			if(!qd_int(fs, len, &i, 3, &v) || !qd_ref(q, false, base + v, *ric, &n, &val) ||
			                !qd_string(fs, len, &i, 7, value, sizeof(value))) {
				return H3_DECODE_ERROR;
			}

			val = value;
		}

		if(!qd_keep(out, n, val)) {
			return H3_DECODE_ERROR;
		}
	}

	return H3_DECODE_OK;
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
