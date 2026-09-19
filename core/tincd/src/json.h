#ifndef TINC_JSON_H
#define TINC_JSON_H

/*
    json.h -- the bounded JSON reader used by the ACME client and the
              Cloudflare DNS provider (acme.c).

    Read-only DOM: parse a response, walk it, free it. Building a request body
    needs no DOM -- the bodies are three or four fields, so acme.c formats them
    with snprintf and escapes the values with json_escape().

    This program is free software; see the GPL v2+ (same as the rest of tinc).
*/

#include "system.h"

typedef enum {
	JSON_NULL,
	JSON_BOOL,
	JSON_NUMBER,
	JSON_STRING,
	JSON_ARRAY,
	JSON_OBJECT,
} json_type_t;

typedef struct json_t json_t;

/* Parse `len` bytes. NULL when the text is not one complete JSON value, when
   it nests deeper than 32, or when an object or array has more than 4096
   members. Caller frees with json_free(). */
json_t *json_parse(const char *text, size_t len);
void json_free(json_t *v);

json_type_t json_type(const json_t *v);

/* Object member / array element, or NULL when absent or the wrong type. The
   returned node belongs to its parent: do not free it. */
const json_t *json_member(const json_t *obj, const char *key);
const json_t *json_index(const json_t *arr, size_t i);
size_t json_count(const json_t *v);

/* Accessors that answer NULL / false / `def` rather than assert, so a
   response missing a field is a normal path, not a crash. */
const char *json_string(const json_t *v);
const char *json_member_string(const json_t *obj, const char *key);
bool json_is_true(const json_t *v);
double json_number(const json_t *v, double def);

/* `s` escaped for use between quotes in a JSON string. Caller frees. */
char *json_escape(const char *s);

#endif
