/*
    json.c -- a small, bounded JSON reader for the ACME and Cloudflare APIs.

    Only what those two APIs need: objects, arrays, strings, numbers, the
    three literals, and \u escapes folded to UTF-8. It is deliberately not a
    general-purpose library -- it is fed by remote servers, so it is written
    the same way yamlconf.c is: bounded depth, bounded input, no recursion the
    input can drive past JSON_MAX_DEPTH, and every allocation checked.

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

#include "json.h"
#include "xalloc.h"

#define JSON_MAX_DEPTH 32
#define JSON_MAX_MEMBERS 4096

struct json_t {
	json_type_t type;
	char *str;                 /* JSON_STRING: the decoded text */
	double num;                /* JSON_NUMBER */
	bool boolean;              /* JSON_BOOL */
	char **keys;               /* JSON_OBJECT: member names */
	json_t **items;            /* JSON_OBJECT / JSON_ARRAY: values */
	size_t count;
};

typedef struct {
	const char *p;
	const char *end;
	int depth;
	bool error;
} jparse_t;

static json_t *parse_value(jparse_t *j);

static json_t *node_new(json_type_t type) {
	json_t *v = xzalloc(sizeof(*v));
	v->type = type;
	return v;
}

void json_free(json_t *v) {
	if(!v) {
		return;
	}

	for(size_t i = 0; i < v->count; i++) {
		if(v->keys) {
			free(v->keys[i]);
		}

		json_free(v->items[i]);
	}

	free(v->keys);
	free(v->items);
	free(v->str);
	free(v);
}

static void skip_ws(jparse_t *j) {
	while(j->p < j->end && (*j->p == ' ' || *j->p == '\t' || *j->p == '\r' || *j->p == '\n')) {
		j->p++;
	}
}

static bool literal(jparse_t *j, const char *word) {
	size_t len = strlen(word);

	if((size_t)(j->end - j->p) < len || memcmp(j->p, word, len)) {
		return false;
	}

	j->p += len;
	return true;
}

/* Four hex digits at j->p as a code unit; -1 if they are not four hex
   digits. Consumes them only on success. */
static int hex4(jparse_t *j) {
	if(j->end - j->p < 4) {
		return -1;
	}

	int cp = 0;

	for(int i = 0; i < 4; i++) {
		char c = j->p[i];
		cp <<= 4;

		if(c >= '0' && c <= '9') {
			cp |= c - '0';
		} else if(c >= 'a' && c <= 'f') {
			cp |= c - 'a' + 10;
		} else if(c >= 'A' && c <= 'F') {
			cp |= c - 'A' + 10;
		} else {
			return -1;
		}
	}

	j->p += 4;
	return cp;
}

/* One \uXXXX escape as UTF-8, surrogate pairs included. Returns the number of
   bytes written (at most 4), 0 on a malformed escape. */
static size_t utf8_escape(jparse_t *j, char *out) {
	int cp = hex4(j);

	if(cp < 0) {
		return 0;
	}

	if(cp >= 0xD800 && cp <= 0xDBFF && j->end - j->p >= 6 && j->p[0] == '\\' && j->p[1] == 'u') {
		const char *save = j->p;
		j->p += 2;
		int lo = hex4(j);

		if(lo >= 0xDC00 && lo <= 0xDFFF) {
			cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
		} else {
			j->p = save;                  /* a lone high surrogate stays as-is */
		}
	}

	if(cp < 0x80) {
		out[0] = (char) cp;
		return 1;
	} else if(cp < 0x800) {
		out[0] = (char)(0xC0 | (cp >> 6));
		out[1] = (char)(0x80 | (cp & 0x3F));
		return 2;
	} else if(cp < 0x10000) {
		out[0] = (char)(0xE0 | (cp >> 12));
		out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
		out[2] = (char)(0x80 | (cp & 0x3F));
		return 3;
	} else {
		out[0] = (char)(0xF0 | (cp >> 18));
		out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
		out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
		out[3] = (char)(0x80 | (cp & 0x3F));
		return 4;
	}
}

static char *parse_string_raw(jparse_t *j) {
	if(j->p >= j->end || *j->p != '"') {
		j->error = true;
		return NULL;
	}

	j->p++;
	size_t cap = 32, len = 0;
	char *out = xmalloc(cap);

	while(j->p < j->end && *j->p != '"') {
		if(len + 8 >= cap) {
			cap *= 2;
			out = xrealloc(out, cap);
		}

		if(*j->p == '\\') {
			j->p++;

			if(j->p >= j->end) {
				break;
			}

			char c = *j->p++;

			switch(c) {
			case 'n':
				out[len++] = '\n';
				break;

			case 't':
				out[len++] = '\t';
				break;

			case 'r':
				out[len++] = '\r';
				break;

			case 'b':
				out[len++] = '\b';
				break;

			case 'f':
				out[len++] = '\f';
				break;

			case '/':
				out[len++] = '/';
				break;

			case '"':
				out[len++] = '"';
				break;

			case '\\':
				out[len++] = '\\';
				break;

			case 'u': {
				size_t n = utf8_escape(j, out + len);

				if(!n) {
					j->error = true;
					free(out);
					return NULL;
				}

				len += n;
				break;
			}

			default:
				j->error = true;
				free(out);
				return NULL;
			}
		} else {
			out[len++] = *j->p++;
		}
	}

	if(j->p >= j->end || *j->p != '"') {
		j->error = true;
		free(out);
		return NULL;
	}

	j->p++;
	out[len] = 0;
	return out;
}

static void container_add(json_t *v, char *key, json_t *item) {
	v->items = xrealloc(v->items, (v->count + 1) * sizeof(*v->items));

	if(key) {
		v->keys = xrealloc(v->keys, (v->count + 1) * sizeof(*v->keys));
		v->keys[v->count] = key;
	}

	v->items[v->count] = item;
	v->count++;
}

static json_t *parse_object(jparse_t *j) {
	json_t *v = node_new(JSON_OBJECT);
	j->p++;                                   /* '{' */
	skip_ws(j);

	if(j->p < j->end && *j->p == '}') {
		j->p++;
		return v;
	}

	for(;;) {
		skip_ws(j);
		char *key = parse_string_raw(j);

		if(!key) {
			j->error = true;
			break;
		}

		skip_ws(j);

		if(j->p >= j->end || *j->p != ':') {
			free(key);
			j->error = true;
			break;
		}

		j->p++;
		json_t *item = parse_value(j);

		if(!item) {
			free(key);
			break;
		}

		if(v->count >= JSON_MAX_MEMBERS) {
			free(key);
			json_free(item);
			j->error = true;
			break;
		}

		container_add(v, key, item);
		skip_ws(j);

		if(j->p < j->end && *j->p == ',') {
			j->p++;
			continue;
		}

		if(j->p < j->end && *j->p == '}') {
			j->p++;
			return v;
		}

		j->error = true;
		break;
	}

	json_free(v);
	return NULL;
}

static json_t *parse_array(jparse_t *j) {
	json_t *v = node_new(JSON_ARRAY);
	j->p++;                                   /* '[' */
	skip_ws(j);

	if(j->p < j->end && *j->p == ']') {
		j->p++;
		return v;
	}

	for(;;) {
		json_t *item = parse_value(j);

		if(!item) {
			break;
		}

		if(v->count >= JSON_MAX_MEMBERS) {
			json_free(item);
			j->error = true;
			break;
		}

		container_add(v, NULL, item);
		skip_ws(j);

		if(j->p < j->end && *j->p == ',') {
			j->p++;
			continue;
		}

		if(j->p < j->end && *j->p == ']') {
			j->p++;
			return v;
		}

		j->error = true;
		break;
	}

	json_free(v);
	return NULL;
}

static bool is_digit(char c) {
	return c >= '0' && c <= '9';
}

/* One or more digits at *q, not past end. False (nothing consumed) if there
   is none. */
static bool digits(const char **q, const char *end) {
	if(*q >= end || !is_digit(**q)) {
		return false;
	}

	while(*q < end && is_digit(**q)) {
		(*q)++;
	}

	return true;
}

/* A JSON number (RFC 8259 section 6), scanned against j->end before anything
   converts it. strtod() on j->p would run to the first byte that cannot be
   part of a number -- past `end' whenever the caller's buffer is not
   NUL-terminated there -- and it accepts "inf", "nan", hex and a leading '+',
   none of which is JSON. The scanned bytes are copied and converted from the
   copy. */
static json_t *parse_number(jparse_t *j) {
	const char *q = j->p;

	if(q < j->end && *q == '-') {
		q++;
	}

	if(q < j->end && *q == '0') {
		q++;
	} else if(!digits(&q, j->end)) {
		j->error = true;
		return NULL;
	}

	if(q < j->end && *q == '.') {
		q++;

		if(!digits(&q, j->end)) {
			j->error = true;
			return NULL;
		}
	}

	if(q < j->end && (*q == 'e' || *q == 'E')) {
		q++;

		if(q < j->end && (*q == '+' || *q == '-')) {
			q++;
		}

		if(!digits(&q, j->end)) {
			j->error = true;
			return NULL;
		}
	}

	/* No field of these APIs needs anywhere near this many characters; a
	   longer number is refused rather than allocated for. */
	char buf[64];
	size_t n = (size_t)(q - j->p);

	if(n >= sizeof(buf)) {
		j->error = true;
		return NULL;
	}

	memcpy(buf, j->p, n);
	buf[n] = 0;
	j->p = q;

	json_t *v = node_new(JSON_NUMBER);
	v->num = strtod(buf, NULL);
	return v;
}

static json_t *parse_value(jparse_t *j) {
	if(j->error || ++j->depth > JSON_MAX_DEPTH) {
		j->error = true;
		j->depth--;
		return NULL;
	}

	skip_ws(j);
	json_t *v = NULL;

	if(j->p >= j->end) {
		j->error = true;
	} else if(*j->p == '{') {
		v = parse_object(j);
	} else if(*j->p == '[') {
		v = parse_array(j);
	} else if(*j->p == '"') {
		char *s = parse_string_raw(j);

		if(s) {
			v = node_new(JSON_STRING);
			v->str = s;
		}
	} else if(literal(j, "true")) {
		v = node_new(JSON_BOOL);
		v->boolean = true;
	} else if(literal(j, "false")) {
		v = node_new(JSON_BOOL);
		v->boolean = false;
	} else if(literal(j, "null")) {
		v = node_new(JSON_NULL);
	} else {
		v = parse_number(j);
	}

	j->depth--;
	return j->error ? (json_free(v), NULL) : v;
}

json_t *json_parse(const char *text, size_t len) {
	if(!text) {
		return NULL;
	}

	jparse_t j = {.p = text, .end = text + len, .depth = 0, .error = false};
	json_t *v = parse_value(&j);

	if(!v) {
		return NULL;
	}

	skip_ws(&j);

	/* One value and nothing after it: `{"a":1}garbage' is not a document. */
	if(j.error || j.p != j.end) {
		json_free(v);
		return NULL;
	}

	return v;
}

const json_t *json_member(const json_t *obj, const char *key) {
	if(!obj || obj->type != JSON_OBJECT) {
		return NULL;
	}

	for(size_t i = 0; i < obj->count; i++) {
		if(!strcmp(obj->keys[i], key)) {
			return obj->items[i];
		}
	}

	return NULL;
}

const json_t *json_index(const json_t *arr, size_t i) {
	if(!arr || arr->type != JSON_ARRAY || i >= arr->count) {
		return NULL;
	}

	return arr->items[i];
}

size_t json_count(const json_t *v) {
	return v ? v->count : 0;
}

const char *json_string(const json_t *v) {
	return (v && v->type == JSON_STRING) ? v->str : NULL;
}

const char *json_member_string(const json_t *obj, const char *key) {
	return json_string(json_member(obj, key));
}

bool json_is_true(const json_t *v) {
	return v && v->type == JSON_BOOL && v->boolean;
}

double json_number(const json_t *v, double def) {
	return (v && v->type == JSON_NUMBER) ? v->num : def;
}

char *json_escape(const char *s) {
	if(!s) {
		return xstrdup("");
	}

	size_t cap = strlen(s) * 6 + 1, len = 0;
	char *out = xmalloc(cap);

	for(const unsigned char *p = (const unsigned char *) s; *p; p++) {
		switch(*p) {
		case '"':
			memcpy(out + len, "\\\"", 2);
			len += 2;
			break;

		case '\\':
			memcpy(out + len, "\\\\", 2);
			len += 2;
			break;

		case '\n':
			memcpy(out + len, "\\n", 2);
			len += 2;
			break;

		case '\r':
			memcpy(out + len, "\\r", 2);
			len += 2;
			break;

		case '\t':
			memcpy(out + len, "\\t", 2);
			len += 2;
			break;

		default:
			if(*p < 0x20) {
				len += (size_t) snprintf(out + len, cap - len, "\\u%04x", *p);
			} else {
				out[len++] = (char) * p;
			}
		}
	}

	out[len] = 0;
	return out;
}
