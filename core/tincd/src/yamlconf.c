/*
    yamlconf.c -- read/write tinc configuration from a single YAML file.

    A small, dependency-free parser/emitter for the canonical block-YAML that
    tincmgr (and this module) produce. Not a general YAML implementation: it
    handles block mappings, block sequences, flow sequences ([a, b]), literal
    block scalars (key: |) and plain scalars -- which is exactly our schema.
    See yamlconf.h for the schema and public API.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

#include "yamlconf.h"

/* ---- value tree ---------------------------------------------------------- */

typedef enum { Y_SCALAR, Y_SEQ, Y_MAP } ytype_t;

typedef struct yval {
	ytype_t type;
	char *scalar;                 /* Y_SCALAR (may contain '\n') */
	struct yval **items; size_t nitems;            /* Y_SEQ */
	char **keys; struct yval **vals; size_t npairs; /* Y_MAP */
} yval_t;

struct yamlconf {
	yval_t *root;
};

/* YAML mode globals (see yamlconf.h). */
char *yamlconf_path = NULL;
yamlconf_t *yamlconf_global = NULL;

static yval_t *yval_new(ytype_t t) {
	yval_t *v = calloc(1, sizeof(*v));
	v->type = t;
	return v;
}

static void yval_free(yval_t *v) {
	if(!v) return;
	free(v->scalar);
	for(size_t i = 0; i < v->nitems; i++) yval_free(v->items[i]);
	free(v->items);
	for(size_t i = 0; i < v->npairs; i++) { free(v->keys[i]); yval_free(v->vals[i]); }
	free(v->keys); free(v->vals);
	free(v);
}

static void map_put(yval_t *m, char *key, yval_t *val) {
	m->keys = realloc(m->keys, (m->npairs + 1) * sizeof(char *));
	m->vals = realloc(m->vals, (m->npairs + 1) * sizeof(yval_t *));
	m->keys[m->npairs] = key;
	m->vals[m->npairs] = val;
	m->npairs++;
}

static yval_t *map_get(const yval_t *m, const char *key) {
	if(!m || m->type != Y_MAP) return NULL;
	for(size_t i = 0; i < m->npairs; i++)
		if(!strcmp(m->keys[i], key)) return m->vals[i];
	return NULL;
}

static void seq_add(yval_t *s, yval_t *item) {
	s->items = realloc(s->items, (s->nitems + 1) * sizeof(yval_t *));
	s->items[s->nitems++] = item;
}

/* ---- line model ---------------------------------------------------------- */

typedef struct { char *raw; int indent; bool skip; } line_t;  /* skip: blank/comment */

static int leading_spaces(const char *s) {
	int n = 0;
	while(s[n] == ' ') n++;
	return n;
}

static char *trim(char *s) {
	while(*s && isspace((unsigned char) *s)) s++;
	size_t n = strlen(s);
	while(n && isspace((unsigned char) s[n - 1])) s[--n] = 0;
	return s;
}

static char *unquote(char *s) {
	size_t n = strlen(s);
	if(n >= 2 && ((s[0] == '"' && s[n - 1] == '"') || (s[0] == '\'' && s[n - 1] == '\''))) {
		s[n - 1] = 0;
		return s + 1;
	}
	return s;
}

/* ---- parser -------------------------------------------------------------- */

typedef struct { line_t *lines; size_t n; size_t i; } parser_t;

static yval_t *parse_flow_seq(const char *s) {       /* "[a, b, c]" */
	yval_t *seq = yval_new(Y_SEQ);
	const char *p = strchr(s, '[');
	if(!p) return seq;
	p++;
	char buf[1024];
	while(*p && *p != ']') {
		size_t k = 0;
		while(*p && *p != ',' && *p != ']' && k < sizeof(buf) - 1) buf[k++] = *p++;
		buf[k] = 0;
		char *t = trim(buf);
		yval_t *it = yval_new(Y_SCALAR);
		it->scalar = strdup(unquote(t));
		seq_add(seq, it);
		if(*p == ',') p++;
	}
	return seq;
}

static size_t next_sig(parser_t *p, size_t from) {   /* index of next non-skip line */
	while(from < p->n && p->lines[from].skip) from++;
	return from;
}

static yval_t *parse_block_scalar(parser_t *p, int parent_indent) {
	/* collect lines more indented than parent; dedent by the first one's indent */
	size_t j = next_sig(p, p->i);
	if(j >= p->n || p->lines[j].indent <= parent_indent) {
		yval_t *v = yval_new(Y_SCALAR); v->scalar = strdup(""); return v;
	}
	int base = p->lines[j].indent;
	char *acc = strdup("");
	size_t acclen = 0;
	bool first = true;
	while(p->i < p->n) {
		line_t *ln = &p->lines[p->i];
		bool blank = (ln->raw[0] == 0) || (leading_spaces(ln->raw) == (int) strlen(ln->raw));
		if(!blank && ln->indent <= parent_indent) break;
		const char *content = blank ? "" : (ln->indent >= base ? ln->raw + base : trim(ln->raw));
		size_t clen = strlen(content);
		acc = realloc(acc, acclen + clen + 2);
		if(!first) acc[acclen++] = '\n';
		memcpy(acc + acclen, content, clen);
		acclen += clen; acc[acclen] = 0;
		first = false;
		p->i++;
	}
	/* strip trailing newlines (chomp) */
	while(acclen && acc[acclen - 1] == '\n') acc[--acclen] = 0;
	yval_t *v = yval_new(Y_SCALAR); v->scalar = acc; return v;
}

static yval_t *parse_node(parser_t *p, int min_indent);

/* Parse a double-quoted YAML scalar (single line), processing escapes.
   PyYAML emits this form for strings whose block representation would be
   ambiguous (e.g. lines with trailing spaces), encoding newlines as \n. */
static char *parse_dq_scalar(const char *s) {
	if(*s == '"') {
		s++;
	}

	char *out = malloc(strlen(s) + 1);
	size_t k = 0;

	while(*s && *s != '"') {
		if(*s == '\\' && s[1]) {
			s++;

			switch(*s) {
			case 'n':
				out[k++] = '\n';
				break;

			case 't':
				out[k++] = '\t';
				break;

			case 'r':
				out[k++] = '\r';
				break;

			case '"':
				out[k++] = '"';
				break;

			case '\\':
				out[k++] = '\\';
				break;

			case '0':
				out[k++] = '\0';
				break;

			default:
				out[k++] = *s;
				break;
			}

			s++;
		} else {
			out[k++] = *s++;
		}
	}

	out[k] = 0;
	return out;
}

static yval_t *parse_map(parser_t *p, int indent) {
	yval_t *map = yval_new(Y_MAP);
	while(p->i < p->n) {
		size_t j = next_sig(p, p->i);
		if(j >= p->n) break;
		if(p->lines[j].indent != indent) break;          /* dedent / nested */
		p->i = j;
		char *line = p->lines[p->i].raw + indent;
		char *colon = strchr(line, ':');
		if(!colon) { p->i++; continue; }
		*colon = 0;
		char keybuf[256];
		snprintf(keybuf, sizeof(keybuf), "%s", trim(line));
		char *rest = trim(colon + 1);
		p->i++;
		yval_t *val;
		if(rest[0] == 0) {
			size_t k = next_sig(p, p->i);
			if(k < p->n && p->lines[k].indent > indent)
				val = parse_node(p, indent + 1);
			else { val = yval_new(Y_SCALAR); val->scalar = strdup(""); }
		} else if(rest[0] == '|') {
			val = parse_block_scalar(p, indent);
		} else if(rest[0] == '"') {
			val = yval_new(Y_SCALAR);
			val->scalar = parse_dq_scalar(rest);
		} else if(rest[0] == '[') {
			val = parse_flow_seq(rest);
		} else {
			val = yval_new(Y_SCALAR);
			val->scalar = strdup(unquote(rest));
		}
		map_put(map, strdup(keybuf), val);
	}
	return map;
}

static yval_t *parse_seq(parser_t *p, int indent) {
	yval_t *seq = yval_new(Y_SEQ);
	while(p->i < p->n) {
		size_t j = next_sig(p, p->i);
		if(j >= p->n) break;
		if(p->lines[j].indent != indent) break;
		char *line = p->lines[j].raw + indent;
		if(line[0] != '-') break;
		p->i = j;
		char *item = trim(line + 1);
		yval_t *val;
		if(item[0] == 0) {
			p->i++;
			val = parse_node(p, indent + 1);
		} else {
			p->i++;
			val = yval_new(Y_SCALAR);
			val->scalar = strdup(unquote(item));
		}
		seq_add(seq, val);
	}
	return seq;
}

static yval_t *parse_node(parser_t *p, int min_indent) {
	size_t j = next_sig(p, p->i);
	if(j >= p->n || p->lines[j].indent < min_indent) {
		yval_t *v = yval_new(Y_SCALAR); v->scalar = strdup(""); return v;
	}
	p->i = j;
	int indent = p->lines[j].indent;
	char *line = p->lines[j].raw + indent;
	if(line[0] == '-' && (line[1] == ' ' || line[1] == 0))
		return parse_seq(p, indent);
	return parse_map(p, indent);
}

static yval_t *parse_text(char *text) {
	/* split into lines */
	size_t cap = 64, n = 0;
	line_t *lines = malloc(cap * sizeof(line_t));
	char *s = text;
	while(*s) {
		char *eol = strchr(s, '\n');
		size_t len = eol ? (size_t)(eol - s) : strlen(s);
		char *raw = malloc(len + 1);
		memcpy(raw, s, len); raw[len] = 0;
		if(len && raw[len - 1] == '\r') raw[len - 1] = 0;
		if(n == cap) { cap *= 2; lines = realloc(lines, cap * sizeof(line_t)); }
		int ind = leading_spaces(raw);
		const char *content = raw + ind;
		lines[n].raw = raw;
		lines[n].indent = ind;
		lines[n].skip = (content[0] == 0 || content[0] == '#');
		n++;
		if(!eol) break;
		s = eol + 1;
	}
	parser_t p = { lines, n, 0 };
	yval_t *root = parse_node(&p, 0);
	for(size_t i = 0; i < n; i++) free(lines[i].raw);
	free(lines);
	return root;
}

/* ---- public: temp FILE* (portable tmpfile) ------------------------------- */

FILE *yamlconf_content_fp(const char *content) {
	FILE *f;
#ifdef _WIN32
	char dir[MAX_PATH], path[MAX_PATH];

	if(!GetTempPathA(sizeof(dir), dir) || !GetTempFileNameA(dir, "tyc", 0, path)) {
		return NULL;
	}

	f = fopen(path, "w+bTD");       /* T=temporary, D=delete-on-close (MSVCRT) */

	if(!f) {
		f = fopen(path, "w+b");
	}

#else
	f = tmpfile();
#endif

	if(f) {
		fwrite(content, 1, strlen(content), f);
		rewind(f);
	}

	return f;
}

/* ---- public: load -------------------------------------------------------- */

bool yamlconf_is_yaml_path(const char *path) {
	if(!path) return false;
	size_t n = strlen(path);
	return (n > 5 && !strcasecmp(path + n - 5, ".yaml")) ||
	       (n > 4 && !strcasecmp(path + n - 4, ".yml"));
}

static char *read_file(const char *path) {
	FILE *f = fopen(path, "rb");
	if(!f) return NULL;
	fseek(f, 0, SEEK_END);
	long sz = ftell(f);
	fseek(f, 0, SEEK_SET);
	if(sz < 0) { fclose(f); return NULL; }
	char *buf = malloc(sz + 1);
	size_t rd = fread(buf, 1, sz, f);
	buf[rd] = 0;
	fclose(f);
	return buf;
}

yamlconf_t *yamlconf_load(const char *path) {
	char *text = read_file(path);
	if(!text) return NULL;
	yamlconf_t *yc = calloc(1, sizeof(*yc));
	yc->root = parse_text(text);
	free(text);

	/* An empty / comment-only file parses to an empty scalar: treat it as an
	   empty document so the daemon can materialise defaults into it. */
	if(yc->root && yc->root->type == Y_SCALAR && yc->root->scalar[0] == 0) {
		yval_free(yc->root);
		yc->root = yval_new(Y_MAP);
	}

	if(!yc->root || yc->root->type != Y_MAP) { yamlconf_free(yc); return NULL; }
	return yc;
}

yamlconf_t *yamlconf_new(void) {
	yamlconf_t *yc = calloc(1, sizeof(*yc));
	yc->root = yval_new(Y_MAP);
	return yc;
}

void yamlconf_free(yamlconf_t *yc) {
	if(!yc) return;
	yval_free(yc->root);
	free(yc);
}

static const yval_t *net_node(const yamlconf_t *yc, const char *net) {
	return map_get(map_get(yc->root, "networks"), net);
}

/* ---- public: read accessors --------------------------------------------- */

static const char *bool_to_tinc(const char *s) {
	if(!strcasecmp(s, "true")) return "yes";
	if(!strcasecmp(s, "false")) return "no";
	return s;
}

char *yamlconf_options_text(yamlconf_t *yc, const char *net) {
	const yval_t *opts = map_get(net_node(yc, net), "options");
	if(!opts || opts->type != Y_MAP) return NULL;
	size_t cap = 1024, len = 0;
	char *out = malloc(cap);
	out[0] = 0;
	for(size_t i = 0; i < opts->npairs; i++) {
		const char *key = opts->keys[i];
		const yval_t *v = opts->vals[i];
		size_t nvals = (v->type == Y_SEQ) ? v->nitems : 1;
		for(size_t k = 0; k < nvals; k++) {
			const char *val = (v->type == Y_SEQ) ? v->items[k]->scalar
			                  : (v->type == Y_SCALAR ? bool_to_tinc(v->scalar) : "");
			if(!val) val = "";
			size_t need = strlen(key) + strlen(val) + 8;
			if(len + need > cap) { while(len + need > cap) cap *= 2; out = realloc(out, cap); }
			len += sprintf(out + len, "%s = %s\n", key, val);
		}
	}
	return out;
}

char *yamlconf_host_text(yamlconf_t *yc, const char *net, const char *name) {
	const yval_t *h = map_get(map_get(net_node(yc, net), "hosts"), name);
	if(!h || h->type != Y_SCALAR) return NULL;
	return strdup(h->scalar);
}

const char *yamlconf_key_pem(yamlconf_t *yc, const char *net, const char *which) {
	const yval_t *k = map_get(map_get(net_node(yc, net), "keys"), which);
	return (k && k->type == Y_SCALAR && k->scalar[0]) ? k->scalar : NULL;
}

const char **yamlconf_host_names(yamlconf_t *yc, const char *net) {
	const yval_t *hosts = map_get(net_node(yc, net), "hosts");
	size_t n = (hosts && hosts->type == Y_MAP) ? hosts->npairs : 0;
	const char **arr = malloc((n + 1) * sizeof(char *));
	for(size_t i = 0; i < n; i++) arr[i] = hosts->keys[i];
	arr[n] = NULL;
	return arr;
}

const char *yamlconf_first_network(yamlconf_t *yc) {
	const yval_t *nets = map_get(yc->root, "networks");
	if(!nets || nets->type != Y_MAP || !nets->npairs) return NULL;
	return nets->keys[0];
}

bool yamlconf_has_network(yamlconf_t *yc, const char *net) {
	const yval_t *n = net_node(yc, net);
	return n && n->type == Y_MAP;
}

const char *yamlconf_get_option(yamlconf_t *yc, const char *net, const char *key) {
	const yval_t *v = map_get(map_get(net_node(yc, net), "options"), key);
	return (v && v->type == Y_SCALAR) ? v->scalar : NULL;
}

/* ---- emitter (for write-back) ------------------------------------------- */

typedef struct { char *buf; size_t len, cap; } sbuf_t;

static void sb_puts(sbuf_t *b, const char *s) {
	size_t n = strlen(s);
	if(b->len + n + 1 > b->cap) { while(b->len + n + 1 > b->cap) b->cap = b->cap ? b->cap * 2 : 1024; b->buf = realloc(b->buf, b->cap); }
	memcpy(b->buf + b->len, s, n); b->len += n; b->buf[b->len] = 0;
}

static void sb_indent(sbuf_t *b, int n) { for(int i = 0; i < n; i++) sb_puts(b, " "); }

static void emit_scalar_value(sbuf_t *b, const char *s, int indent) {
	if(s[0] == 0) { sb_puts(b, " \"\"\n"); return; }
	if(strchr(s, '\n')) {                       /* literal block */
		sb_puts(b, " |\n");
		const char *p = s;
		while(*p) {
			const char *eol = strchr(p, '\n');
			size_t len = eol ? (size_t)(eol - p) : strlen(p);
			sb_indent(b, indent + 2);
			char *line = malloc(len + 2);
			memcpy(line, p, len); line[len] = '\n'; line[len + 1] = 0;
			sb_puts(b, line); free(line);
			if(!eol) { sb_puts(b, "\n"); break; }
			p = eol + 1;
		}
		return;
	}
	sb_puts(b, " "); sb_puts(b, s); sb_puts(b, "\n");
}

static void emit_node(sbuf_t *b, const yval_t *v, int indent) {
	if(v->type == Y_MAP) {
		for(size_t i = 0; i < v->npairs; i++) {
			sb_indent(b, indent);
			sb_puts(b, v->keys[i]); sb_puts(b, ":");
			const yval_t *val = v->vals[i];
			if(val->type == Y_SCALAR) {
				emit_scalar_value(b, val->scalar, indent);
			} else {
				sb_puts(b, "\n");
				emit_node(b, val, indent + 2);
			}
		}
	} else if(v->type == Y_SEQ) {
		for(size_t i = 0; i < v->nitems; i++) {
			sb_indent(b, indent);
			if(v->items[i]->type == Y_SCALAR) {
				sb_puts(b, "- "); sb_puts(b, v->items[i]->scalar); sb_puts(b, "\n");
			} else {
				sb_puts(b, "-\n");
				emit_node(b, v->items[i], indent + 2);
			}
		}
	}
}

/* ---- write-back ---------------------------------------------------------- */

static yval_t *map_get_or_create_map(yval_t *m, const char *key) {
	yval_t *v = map_get(m, key);
	if(v && v->type == Y_MAP) return v;
	if(v) {                                  /* wrong type (e.g. "hosts:" left empty) */
		for(size_t i = 0; i < m->npairs; i++) {
			if(m->vals[i] == v) {
				yval_free(v);
				m->vals[i] = yval_new(Y_MAP);
				return m->vals[i];
			}
		}
	}
	v = yval_new(Y_MAP);
	map_put(m, strdup(key), v);
	return v;
}

static void map_set_scalar(yval_t *m, const char *key, const char *value) {
	yval_t *v = map_get(m, key);
	if(v) {
		for(size_t i = 0; i < m->npairs; i++) {
			if(m->vals[i] == v) {
				yval_free(v);
				m->vals[i] = yval_new(Y_SCALAR);
				m->vals[i]->scalar = strdup(value);
				return;
			}
		}
	}
	v = yval_new(Y_SCALAR);
	v->scalar = strdup(value);
	map_put(m, strdup(key), v);
}

static yval_t *net_node_create(yamlconf_t *yc, const char *net) {
	return map_get_or_create_map(map_get_or_create_map(yc->root, "networks"), net);
}

void yamlconf_set_option(yamlconf_t *yc, const char *net, const char *key, const char *value) {
	map_set_scalar(map_get_or_create_map(net_node_create(yc, net), "options"), key, value);
}

void yamlconf_set_key_pem(yamlconf_t *yc, const char *net, const char *which, const char *pem) {
	map_set_scalar(map_get_or_create_map(net_node_create(yc, net), "keys"), which, pem);
}

bool yamlconf_has_host(yamlconf_t *yc, const char *net, const char *name) {
	const yval_t *h = map_get(map_get(net_node(yc, net), "hosts"), name);
	return h && h->type == Y_SCALAR;
}

static void host_add_line(yval_t *hosts, const char *name, const char *line) {
	yval_t *host = map_get(hosts, name);

	if(host && host->type == Y_SCALAR) {
		size_t n = strlen(host->scalar) + strlen(line) + 2;
		char *merged = malloc(n);

		if(host->scalar[0]) {
			snprintf(merged, n, "%s\n%s", host->scalar, line);
		} else {
			snprintf(merged, n, "%s", line);
		}

		free(host->scalar);
		host->scalar = merged;
	} else {
		map_set_scalar(hosts, name, line);
	}
}

void yamlconf_host_add_line(yamlconf_t *yc, const char *net, const char *name,
                            const char *key, const char *value) {
	yval_t *hosts = map_get_or_create_map(net_node_create(yc, net), "hosts");

	if(value) {
		size_t n = strlen(key) + strlen(value) + 4;
		char *line = malloc(n);
		snprintf(line, n, "%s = %s", key, value);
		host_add_line(hosts, name, line);
		free(line);
	} else {
		host_add_line(hosts, name, key);
	}
}

/* Serialise and replace `path` atomically. Private keys live in this file, so
   it is created 0600 (POSIX). */
static bool write_atomic(const char *path, const char *data, size_t len) {
	char tmp[1024];
	snprintf(tmp, sizeof(tmp), "%s.tmp", path);
#ifdef _WIN32
	FILE *f = fopen(tmp, "wb");
#else
	int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	FILE *f = fd >= 0 ? fdopen(fd, "wb") : NULL;
#endif
	if(!f) return false;
	bool ok = fwrite(data, 1, len, f) == len;
	ok = !fclose(f) && ok;
	if(!ok) { remove(tmp); return false; }
#ifdef _WIN32
	if(!MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING)) { remove(tmp); return false; }
#else
	if(rename(tmp, path)) { remove(tmp); return false; }
#endif
	return true;
}

bool yamlconf_save(yamlconf_t *yc, const char *path) {
	sbuf_t b = {0};
	emit_node(&b, yc->root, 0);
	if(!b.buf) sb_puts(&b, "");
	bool ok = write_atomic(path, b.buf, b.len);
	free(b.buf);
	return ok;
}

bool yamlconf_append_host_line(const char *path, const char *net,
                               const char *name, const char *key, const char *value) {
	/* exclusive lock so two daemons don't corrupt the shared file */
#ifdef _WIN32
	HANDLE lock = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
	                          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#else
	int lockfd = open(path, O_RDONLY);
	if(lockfd >= 0) flock(lockfd, LOCK_EX);
#endif
	bool ok = false;
	yamlconf_t *yc = yamlconf_load(path);
	if(!yc) goto out;

	yamlconf_host_add_line(yc, net, name, key, value);
	ok = yamlconf_save(yc, path);
	yamlconf_free(yc);
out:
#ifdef _WIN32
	if(lock != INVALID_HANDLE_VALUE) CloseHandle(lock);
#else
	if(lockfd >= 0) close(lockfd);
#endif
	return ok;
}
