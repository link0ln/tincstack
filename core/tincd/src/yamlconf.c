/*
    yamlconf.c -- read/write tinc configuration from a single YAML file.

    A small, dependency-free parser/emitter for the canonical block-YAML that
    tincmgr (and this module) produce. Not a general YAML implementation: it
    handles block mappings, block sequences (dashes at or below the key's
    indentation), flow sequences ([a, b]), literal
    block scalars (key: |) and plain scalars -- which is exactly our schema.
    See yamlconf.h for the schema and public API.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#include <io.h>
#include <fcntl.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

#include "yamlconf.h"
#include "ed25519/sha512.h"

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

static bool map_del(yval_t *m, const char *key) {
	if(!m || m->type != Y_MAP) return false;
	for(size_t i = 0; i < m->npairs; i++) {
		if(strcmp(m->keys[i], key)) continue;
		free(m->keys[i]);
		yval_free(m->vals[i]);
		memmove(m->keys + i, m->keys + i + 1, (m->npairs - i - 1) * sizeof(char *));
		memmove(m->vals + i, m->vals + i + 1, (m->npairs - i - 1) * sizeof(yval_t *));
		m->npairs--;
		return true;
	}
	return false;
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

/* The parser is strict about what it does not understand: a line it cannot
   place in the tree is a parse error, never silently dropped. This file is
   written back by the daemon (materialisation, learned keys, `tinc set'), so
   a parser that ignored a badly indented tail would let the next save
   discard the operator's keys and host records. A file that does not parse
   is refused and left untouched (yamlconf_load() returns NULL). */

#define YAML_MAX_DEPTH 64        /* nesting levels; the schema needs 4 */
#define YAML_MAX_KEY 255         /* longest mapping key accepted */

typedef struct {
	line_t *lines;
	size_t n;
	size_t i;
	int depth;
	bool error;
} parser_t;

static yval_t *parse_flow_seq(const char *s) {       /* "[a, b, c]" */
	yval_t *seq = yval_new(Y_SEQ);
	const char *p = strchr(s, '[');
	if(!p) return seq;
	p++;
	while(*p && *p != ']') {
		size_t len = strcspn(p, ",]");
		char *buf = malloc(len + 1);
		memcpy(buf, p, len);
		buf[len] = 0;
		p += len;
		char *t = trim(buf);
		yval_t *it = yval_new(Y_SCALAR);
		it->scalar = strdup(unquote(t));
		seq_add(seq, it);
		free(buf);
		if(*p == ',') p++;
	}
	return seq;
}

static size_t next_sig(parser_t *p, size_t from) {   /* index of next non-skip line */
	while(from < p->n && p->lines[from].skip) from++;
	return from;
}

static bool line_is_blank(const line_t *ln) {
	return ln->raw[0] == 0 || leading_spaces(ln->raw) == (int) strlen(ln->raw);
}

static yval_t *parse_block_scalar(parser_t *p, int parent_indent) {
	/* Collect every line more indented than the parent (blank lines
	   included) and dedent by the smallest indentation among them, so a
	   value whose first line is itself indented survives a round trip. The
	   header's chomping/indentation indicators (|-, |+, |2) are accepted and
	   ignored: trailing newlines are always stripped. */
	size_t j = next_sig(p, p->i);
	if(j >= p->n || p->lines[j].indent <= parent_indent) {
		yval_t *v = yval_new(Y_SCALAR); v->scalar = strdup(""); return v;
	}
	size_t end = p->i;
	int base = -1;
	while(end < p->n) {
		line_t *ln = &p->lines[end];
		if(line_is_blank(ln)) { end++; continue; }
		if(ln->indent <= parent_indent) break;
		if(base < 0 || ln->indent < base) base = ln->indent;
		end++;
	}
	char *acc = strdup("");
	size_t acclen = 0;
	bool first = true;
	for(; p->i < end; p->i++) {
		line_t *ln = &p->lines[p->i];
		const char *content = line_is_blank(ln) ? "" : ln->raw + base;
		size_t clen = strlen(content);
		acc = realloc(acc, acclen + clen + 2);
		if(!first) acc[acclen++] = '\n';
		memcpy(acc + acclen, content, clen);
		acclen += clen; acc[acclen] = 0;
		first = false;
	}
	/* strip trailing newlines (chomp) */
	while(acclen && acc[acclen - 1] == '\n') acc[--acclen] = 0;
	yval_t *v = yval_new(Y_SCALAR); v->scalar = acc; return v;
}

static yval_t *parse_node(parser_t *p, int min_indent);
static yval_t *parse_seq(parser_t *p, int indent);

static int hexval(char c) {
	if(c >= '0' && c <= '9') return c - '0';
	if(c >= 'a' && c <= 'f') return c - 'a' + 10;
	if(c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/* Parse a double-quoted YAML scalar (single line), processing escapes.
   PyYAML emits this form for strings whose block representation would be
   ambiguous (e.g. lines with trailing spaces), encoding newlines as \n; the
   emitter below does the same. Output never exceeds the input length. */
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

			case 'a':
				out[k++] = '\a';
				break;

			case 'b':
				out[k++] = '\b';
				break;

			case 'e':
				out[k++] = 0x1b;
				break;

			case 'f':
				out[k++] = '\f';
				break;

			case 'v':
				out[k++] = '\v';
				break;

			case '"':
				out[k++] = '"';
				break;

			case '/':
				out[k++] = '/';
				break;

			case '\\':
				out[k++] = '\\';
				break;

			case '0':
				out[k++] = '\0';
				break;

			case 'x':
				if(hexval(s[1]) >= 0 && hexval(s[2]) >= 0) {
					out[k++] = (char)(hexval(s[1]) * 16 + hexval(s[2]));
					s += 2;
				} else {
					out[k++] = 'x';
				}

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

/* Store key/val, replacing an existing key in place (last one wins, the
   way PyYAML builds a dict) so a GUI and the daemon agree on the value. */
static void map_put_or_replace(yval_t *m, char *key, yval_t *val) {
	for(size_t i = 0; i < m->npairs; i++) {
		if(!strcmp(m->keys[i], key)) {
			yval_free(m->vals[i]);
			m->vals[i] = val;
			free(key);
			return;
		}
	}

	map_put(m, key, val);
}

static yval_t *parse_map(parser_t *p, int indent) {
	yval_t *map = yval_new(Y_MAP);
	while(p->i < p->n && !p->error) {
		size_t j = next_sig(p, p->i);
		if(j >= p->n) break;
		if(p->lines[j].indent != indent) break;          /* dedent / nested */
		p->i = j;
		char *line = p->lines[p->i].raw + indent;
		char *key;
		char *colon;
		char *dqkey = NULL;
		if(line[0] == '"') {
			/* "quoted key": the emitter writes keys this way when they
			   contain ':' or other characters a plain key cannot hold. */
			char *end = line + 1;
			while(*end && *end != '"') end += (*end == '\\' && end[1]) ? 2 : 1;
			if(!*end) { p->error = true; break; }
			colon = end + 1 + strspn(end + 1, " \t");
			if(*colon != ':') { p->error = true; break; }
			*end = 0;
			dqkey = parse_dq_scalar(line + 1);
			key = dqkey;
		} else {
			colon = strchr(line, ':');
			if(!colon) { p->error = true; break; }          /* not "key: ..." */
			*colon = 0;
			key = trim(line);
		}
		if(!*key || strlen(key) > YAML_MAX_KEY) { free(dqkey); p->error = true; break; }
		char *rest = trim(colon + 1);
		p->i++;
		yval_t *val;
		if(rest[0] == 0) {
			size_t k = next_sig(p, p->i);
			const char *kl = k < p->n ? p->lines[k].raw + indent : NULL;
			if(k < p->n && p->lines[k].indent > indent)
				val = parse_node(p, indent + 1);
			else if(k < p->n && p->lines[k].indent == indent
			        && kl[0] == '-' && (kl[1] == ' ' || kl[1] == 0)) {
				/* A block sequence whose dashes sit at the key's own
				   indentation. Valid YAML and what PyYAML emits by
				   default, so the Windows GUI wrote configs this
				   daemon then refused to read; our own emitter
				   indents them, which is why nothing caught it. */
				p->i = k;
				val = parse_seq(p, indent);
			}
			else { val = yval_new(Y_SCALAR); val->scalar = strdup(""); }
		} else if(rest[0] == '|') {
			val = parse_block_scalar(p, indent);
		} else if(rest[0] == '"') {
			val = yval_new(Y_SCALAR);
			val->scalar = parse_dq_scalar(rest);
		} else if(rest[0] == '[') {
			val = parse_flow_seq(rest);
		} else if(!strcmp(rest, "{}")) {
			val = yval_new(Y_MAP);
		} else {
			val = yval_new(Y_SCALAR);
			val->scalar = strdup(unquote(rest));
		}
		map_put_or_replace(map, dqkey ? dqkey : strdup(key), val);
	}
	return map;
}

static yval_t *parse_seq(parser_t *p, int indent) {
	yval_t *seq = yval_new(Y_SEQ);
	while(p->i < p->n && !p->error) {
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
		} else if(item[0] == '"') {
			p->i++;
			val = yval_new(Y_SCALAR);
			val->scalar = parse_dq_scalar(item);
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
	if(++p->depth > YAML_MAX_DEPTH) {
		p->error = true;
		p->depth--;
		yval_t *v = yval_new(Y_SCALAR); v->scalar = strdup(""); return v;
	}
	p->i = j;
	int indent = p->lines[j].indent;
	char *line = p->lines[j].raw + indent;
	yval_t *v;
	if(line[0] == '-' && (line[1] == ' ' || line[1] == 0))
		v = parse_seq(p, indent);
	else
		v = parse_map(p, indent);
	p->depth--;
	return v;
}

/* Document markers and directives are ignored like comments. */
static bool line_is_marker(const char *content) {
	if(content[0] == '%') return true;
	if(!strncmp(content, "---", 3) || !strncmp(content, "...", 3))
		return content[3] == 0 || content[3] == ' ' || content[3] == '\t';
	return false;
}

/* Parse a whole document. Returns NULL on a parse error (a line that cannot
   be placed in the tree, a key that is empty or too long, nesting deeper
   than YAML_MAX_DEPTH). `text` is modified in place. */
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
		lines[n].skip = (content[0] == 0 || content[0] == '#' || (ind == 0 && line_is_marker(content)));
		n++;
		if(!eol) break;
		s = eol + 1;
	}
	parser_t p = { lines, n, 0, 0, false };
	yval_t *root = parse_node(&p, 0);
	if(!p.error && next_sig(&p, p.i) < n) {
		p.error = true;                    /* significant lines left over */
	}
	for(size_t i = 0; i < n; i++) free(lines[i].raw);
	free(lines);
	if(p.error) { yval_free(root); return NULL; }
	return root;
}

/* ---- public: temp FILE* (portable tmpfile) ------------------------------- */

#ifdef _WIN32
/* The content handed to this function is config text and private-key PEM
   (conf.c reads keys through it, zeroconf.c captures generated ones). It
   must not land in %TEMP%, a directory every process of the user -- and on
   a shared machine every user's sync/AV/backup agent -- can read (security
   review R-13). The temporary is therefore created next to the config, in
   the directory that already holds the keys, with an ACL that admits only
   the calling user and SYSTEM, opened without sharing, marked temporary and
   delete-on-close, so it has no name to reach for once the FILE* is gone.
   %TEMP% is used only when there is no config path at all (no keys then).

   private_sd() is also the descriptor the config itself is written with
   (write_atomic), so it decides who may read tls_key, acme_account and
   CloudflareToken. A protected DACL (no inherited ACEs: Program Files would
   otherwise hand Users read access) for SYSTEM and Administrators, and:
     - unelevated: the calling user too -- it is that user's own config;
     - elevated: NOT the user, and owned by Administrators. An elevated
       admin's token carries the same user SID as that user's unelevated
       processes, so an ACE for it -- or ownership by it, which implies
       WRITE_DAC -- would let any medium-integrity process of the user read
       the keys and rewrite the config the elevated daemon obeys. The
       Administrators group is deny-only in the unelevated token. */
static PSECURITY_DESCRIPTOR private_sd(void) {
	HANDLE tok;
	PSECURITY_DESCRIPTOR sd = NULL;

	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
		return NULL;
	}

	TOKEN_ELEVATION elev = {0};
	DWORD n = 0;
	bool elevated = GetTokenInformation(tok, TokenElevation, &elev, sizeof(elev), &n) && elev.TokenIsElevated;

	if(elevated) {
		ConvertStringSecurityDescriptorToSecurityDescriptorA("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",
		                SDDL_REVISION_1, &sd, NULL);
		CloseHandle(tok);
		return sd;
	}

	n = 0;
	GetTokenInformation(tok, TokenUser, NULL, 0, &n);
	TOKEN_USER *tu = n ? malloc(n) : NULL;

	if(tu && GetTokenInformation(tok, TokenUser, tu, n, &n)) {
		char *sid = NULL;

		if(ConvertSidToStringSidA(tu->User.Sid, &sid)) {
			char sddl[256];
			snprintf(sddl, sizeof(sddl), "D:P(A;;FA;;;%s)(A;;FA;;;SY)(A;;FA;;;BA)", sid);
			ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl, SDDL_REVISION_1, &sd, NULL);
			LocalFree(sid);
		}
	}

	free(tu);
	CloseHandle(tok);
	return sd;
}

static FILE *private_tmpfile(void) {
	char dir[MAX_PATH];

	if(yamlconf_path) {
		if(strlen(yamlconf_path) >= sizeof(dir)) {
			return NULL;
		}

		strcpy(dir, yamlconf_path);
		char *slash = strrchr(dir, '\\');
		char *fslash = strrchr(dir, '/');

		if(fslash > slash) {
			slash = fslash;
		}

		if(slash) {
			slash[1] = 0;
		} else {
			strcpy(dir, ".\\");
		}
	} else if(!GetTempPathA(sizeof(dir), dir)) {
		return NULL;
	}

	static unsigned counter;
	PSECURITY_DESCRIPTOR sd = private_sd();
	SECURITY_ATTRIBUTES sa = { sizeof(sa), sd, FALSE };
	FILE *f = NULL;

	for(int tries = 0; tries < 64 && !f; tries++) {
		char path[MAX_PATH];

		if(snprintf(path, sizeof(path), "%s.tyc-%lu-%lu-%u.tmp", dir,
		            (unsigned long) GetCurrentProcessId(), (unsigned long) GetTickCount(), ++counter) >= (int) sizeof(path)) {
			break;
		}

		HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, sd ? &sa : NULL, CREATE_NEW,
		                       FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);

		if(h == INVALID_HANDLE_VALUE) {
			if(GetLastError() == ERROR_FILE_EXISTS) {
				continue;
			}

			break;
		}

		int fd = _open_osfhandle((intptr_t) h, _O_RDWR | _O_BINARY);

		if(fd < 0) {
			CloseHandle(h);
			break;
		}

		f = _fdopen(fd, "w+b");

		if(!f) {
			_close(fd);
		}
	}

	if(sd) {
		LocalFree(sd);
	}

	return f;
}
#endif

#ifndef _WIN32
/* tmpfile() uses $TMPDIR or a fixed directory (/tmp; bionic: /data/local/tmp,
   which an Android app cannot write), so where there is none it fails and
   every config read that goes through here fails with it -- reported as
   "Could not open configuration file ...". The fallback is the directory
   that already holds the config and its keys: mkstemp (0600), unlinked at
   once, so it has no name either. */
static FILE *private_tmpfile(void) {
	FILE *f = tmpfile();

	if(f || !yamlconf_path) {
		return f;
	}

	const char *slash = strrchr(yamlconf_path, '/');
	size_t dirlen = slash ? (size_t)(slash - yamlconf_path + 1) : 0;
	char *path = malloc(dirlen + sizeof(".tyc-XXXXXX"));

	if(!path) {
		return NULL;
	}

	memcpy(path, yamlconf_path, dirlen);
	memcpy(path + dirlen, ".tyc-XXXXXX", sizeof(".tyc-XXXXXX"));
	int fd = mkstemp(path);

	if(fd >= 0) {
		unlink(path);
		f = fdopen(fd, "w+");

		if(!f) {
			close(fd);
		}
	}

	free(path);
	return f;
}
#endif

FILE *yamlconf_content_fp(const char *content) {
	FILE *f = private_tmpfile();

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

#define YAML_MAX_FILE (64u * 1024u * 1024u)   /* refuse anything larger */

static char *read_file(const char *path) {
	FILE *f = fopen(path, "rb");
	if(!f) return NULL;
	if(fseek(f, 0, SEEK_END)) { fclose(f); return NULL; }
	long sz = ftell(f);
	if(sz < 0 || (unsigned long) sz > YAML_MAX_FILE || fseek(f, 0, SEEK_SET)) { fclose(f); return NULL; }
	char *buf = malloc((size_t) sz + 1);
	if(!buf) { fclose(f); return NULL; }
	size_t rd = fread(buf, 1, (size_t) sz, f);
	buf[rd] = 0;
	fclose(f);
	return buf;
}

/* Parse a document held in memory (the text is modified in place). NULL on
   a parse error or when the document is not a mapping. Exposed for tests. */
yamlconf_t *yamlconf_parse(char *text) {
	yamlconf_t *yc = calloc(1, sizeof(*yc));
	yc->root = parse_text(text);

	/* An empty / comment-only file parses to an empty scalar: treat it as an
	   empty document so the daemon can materialise defaults into it. */
	if(yc->root && yc->root->type == Y_SCALAR && yc->root->scalar[0] == 0) {
		yval_free(yc->root);
		yc->root = yval_new(Y_MAP);
	}

	if(!yc->root || yc->root->type != Y_MAP) { yamlconf_free(yc); return NULL; }
	return yc;
}

yamlconf_t *yamlconf_load(const char *path) {
	char *text = read_file(path);
	if(!text) return NULL;
	yamlconf_t *yc = yamlconf_parse(text);
	free(text);
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

bool yamlconf_host_digest(yamlconf_t *yc, const char *net, const char *name, uint8_t *out) {
	const yval_t *h = map_get(map_get(net_node(yc, net), "hosts"), name);
	if(!h || h->type != Y_SCALAR) return false;

	/* SHA-512 truncated to 256 bits. The record is attacker-influenced (a
	   peer's own key and subnets are appended to it), so a non-cryptographic
	   checksum would let a peer hide a change from the reload check. */
	uint8_t full[64];
	if(sha512(h->scalar, strlen(h->scalar), full) != 0) return false;
	memcpy(out, full, YAMLCONF_DIGEST_LEN);
	return true;
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

bool yamlconf_del_network(yamlconf_t *yc, const char *net) {
	return map_del(map_get(yc->root, "networks"), net);
}

bool yamlconf_has_option(yamlconf_t *yc, const char *net, const char *key) {
	return map_get(map_get(net_node(yc, net), "options"), key) != NULL;
}

const char *yamlconf_get_option(yamlconf_t *yc, const char *net, const char *key) {
	const yval_t *v = map_get(map_get(net_node(yc, net), "options"), key);
	return (v && v->type == Y_SCALAR) ? v->scalar : NULL;
}

const char **yamlconf_option_values(yamlconf_t *yc, const char *net, const char *key) {
	const yval_t *v = map_get(map_get(net_node(yc, net), "options"), key);
	if(!v) return NULL;
	size_t n = (v->type == Y_SEQ) ? v->nitems : 1;
	const char **arr = malloc((n + 1) * sizeof(char *));
	size_t k = 0;
	if(v->type == Y_SEQ) {
		for(size_t i = 0; i < v->nitems; i++)
			if(v->items[i]->type == Y_SCALAR) arr[k++] = v->items[i]->scalar;
	} else if(v->type == Y_SCALAR) {
		arr[k++] = bool_to_tinc(v->scalar);
	}
	arr[k] = NULL;
	return arr;
}

const char **yamlconf_script_names(yamlconf_t *yc, const char *net) {
	const yval_t *scripts = map_get(net_node(yc, net), "scripts");
	size_t n = (scripts && scripts->type == Y_MAP) ? scripts->npairs : 0;
	const char **arr = malloc((n + 1) * sizeof(char *));
	size_t k = 0;
	for(size_t i = 0; i < n; i++)
		if(scripts->vals[i]->type == Y_SCALAR) arr[k++] = scripts->keys[i];
	arr[k] = NULL;
	return arr;
}

char *yamlconf_script_text(yamlconf_t *yc, const char *net, const char *name) {
	const yval_t *v = map_get(map_get(net_node(yc, net), "scripts"), name);
	if(!v || v->type != Y_SCALAR) return NULL;
	return strdup(v->scalar);
}

/* ---- emitter (for write-back) ------------------------------------------- */

typedef struct { char *buf; size_t len, cap; bool error; } sbuf_t;

static void sb_puts(sbuf_t *b, const char *s) {
	size_t n = strlen(s);
	if(b->len + n + 1 > b->cap) { while(b->len + n + 1 > b->cap) b->cap = b->cap ? b->cap * 2 : 1024; b->buf = realloc(b->buf, b->cap); }
	memcpy(b->buf + b->len, s, n); b->len += n; b->buf[b->len] = 0;
}

static void sb_indent(sbuf_t *b, int n) { for(int i = 0; i < n; i++) sb_puts(b, " "); }

static bool is_ctrl(unsigned char c) {
	return c < 0x20 || c == 0x7f;
}

/* A plain (unquoted, single-line) scalar must read back as the same string:
   no leading/trailing blanks, no indicator character in front, nothing the
   line splitter or the key/value split would misread. */
static bool plain_scalar_safe(const char *s) {
	if(s[0] == 0) return false;
	if(isspace((unsigned char) s[0]) || isspace((unsigned char) s[strlen(s) - 1])) return false;
	if(strchr("[]{}\"'|>#&*!%@`,?:-", s[0])) {
		/* "-x", "?x" and ":x" are plain in YAML, but keep it simple: quote
		   anything starting with an indicator except a lone negative
		   number, which is common in options. */
		if(!(s[0] == '-' && isdigit((unsigned char) s[1]))) return false;
	}
	for(const unsigned char *p = (const unsigned char *) s; *p; p++) {
		if(is_ctrl(*p)) return false;
	}
	if(strstr(s, ": ") || strstr(s, " #")) return false;
	return true;
}

/* Every line of a literal block must survive parse_block_scalar(): no
   control characters, no trailing blanks (the parser cannot distinguish a
   blank line from an empty one), and no leading blanks on the first line
   would be ambiguous for other YAML readers. */
static bool block_scalar_safe(const char *s) {
	if(s[0] == ' ' || s[0] == '\t') return false;
	const char *p = s;
	while(*p) {
		const char *eol = strchr(p, '\n');
		size_t len = eol ? (size_t)(eol - p) : strlen(p);
		for(size_t i = 0; i < len; i++) {
			if(is_ctrl((unsigned char) p[i])) return false;
		}
		if(len && p[len - 1] == ' ') return false;
		if(!eol) break;
		p = eol + 1;
	}
	if(strlen(s) && s[strlen(s) - 1] == '\n') return false;   /* chomping would lose it */
	return true;
}

static void emit_dq_scalar(sbuf_t *b, const char *s) {
	sb_puts(b, "\"");
	char esc[8];
	for(const unsigned char *p = (const unsigned char *) s; *p; p++) {
		switch(*p) {
		case '"': sb_puts(b, "\\\""); break;
		case '\\': sb_puts(b, "\\\\"); break;
		case '\n': sb_puts(b, "\\n"); break;
		case '\t': sb_puts(b, "\\t"); break;
		case '\r': sb_puts(b, "\\r"); break;
		default:
			if(is_ctrl(*p)) {
				snprintf(esc, sizeof(esc), "\\x%02x", *p);
				sb_puts(b, esc);
			} else {
				esc[0] = (char) *p; esc[1] = 0;
				sb_puts(b, esc);
			}
		}
	}
	sb_puts(b, "\"");
}

static void emit_scalar_value(sbuf_t *b, const char *s, int indent) {
	if(strchr(s, '\n') && block_scalar_safe(s)) {   /* literal block */
		sb_puts(b, " |\n");
		const char *p = s;
		while(*p) {
			const char *eol = strchr(p, '\n');
			size_t len = eol ? (size_t)(eol - p) : strlen(p);
			if(len) sb_indent(b, indent + 2);
			char *line = malloc(len + 2);
			memcpy(line, p, len); line[len] = '\n'; line[len + 1] = 0;
			sb_puts(b, line); free(line);
			if(!eol) break;
			p = eol + 1;
		}
		return;
	}
	sb_puts(b, " ");
	if(plain_scalar_safe(s)) sb_puts(b, s);
	else emit_dq_scalar(b, s);
	sb_puts(b, "\n");
}

/* A key is written plain only if the parser splits it back at the same
   place: no ':' (the parser takes the first one), nothing that looks like
   a quote, comment, indicator or control character, no outer blanks. */
static bool plain_key_safe(const char *k) {
	if(!plain_scalar_safe(k)) return false;
	return strchr(k, ':') == NULL;
}

static void emit_node(sbuf_t *b, const yval_t *v, int indent) {
	if(v->type == Y_MAP) {
		for(size_t i = 0; i < v->npairs; i++) {
			/* Never write what the parser would refuse: a key the setters
			   accepted but that is empty or longer than YAML_MAX_KEY (a 300
			   character node name from an invitation, say) fails the whole
			   emit/save instead of producing a file that does not load. */
			if(!*v->keys[i] || strlen(v->keys[i]) > YAML_MAX_KEY) b->error = true;
			sb_indent(b, indent);
			if(plain_key_safe(v->keys[i])) sb_puts(b, v->keys[i]);
			else emit_dq_scalar(b, v->keys[i]);
			sb_puts(b, ":");
			const yval_t *val = v->vals[i];
			if(val->type == Y_SCALAR) {
				emit_scalar_value(b, val->scalar, indent);
			} else if((val->type == Y_MAP && !val->npairs) || (val->type == Y_SEQ && !val->nitems)) {
				sb_puts(b, val->type == Y_MAP ? " {}\n" : " []\n");
			} else {
				sb_puts(b, "\n");
				emit_node(b, val, indent + 2);
			}
		}
	} else if(v->type == Y_SEQ) {
		for(size_t i = 0; i < v->nitems; i++) {
			sb_indent(b, indent);
			if(v->items[i]->type == Y_SCALAR) {
				const char *s = v->items[i]->scalar;
				sb_puts(b, "- ");
				if(!strchr(s, '\n') && plain_scalar_safe(s)) sb_puts(b, s);
				else emit_dq_scalar(b, s);
				sb_puts(b, "\n");
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

void yamlconf_add_option_value(yamlconf_t *yc, const char *net, const char *key, const char *value) {
	yval_t *opts = map_get_or_create_map(net_node_create(yc, net), "options");
	yval_t *v = map_get(opts, key);

	if(!v) {
		map_set_scalar(opts, key, value);
		return;
	}

	if(v->type == Y_SCALAR) {
		if(!strcmp(v->scalar, value)) return;
		yval_t *seq = yval_new(Y_SEQ);
		seq_add(seq, v);                      /* the old scalar becomes item 0 */
		for(size_t i = 0; i < opts->npairs; i++)
			if(opts->vals[i] == v) opts->vals[i] = seq;
		v = seq;
	} else if(v->type != Y_SEQ) {
		map_set_scalar(opts, key, value);
		return;
	}

	for(size_t i = 0; i < v->nitems; i++)
		if(v->items[i]->type == Y_SCALAR && !strcmp(v->items[i]->scalar, value)) return;

	yval_t *it = yval_new(Y_SCALAR);
	it->scalar = strdup(value);
	seq_add(v, it);
}

bool yamlconf_del_option(yamlconf_t *yc, const char *net, const char *key) {
	yval_t *opts = map_get(map_get(map_get(yc->root, "networks"), net), "options");
	return map_del(opts, key);
}

void yamlconf_set_options_text(yamlconf_t *yc, const char *net, const char *text) {
	/* Clear the map in place so `options:` keeps its position in the file. */
	yval_t *opts = map_get_or_create_map(net_node_create(yc, net), "options");

	for(size_t i = 0; i < opts->npairs; i++) {
		free(opts->keys[i]);
		yval_free(opts->vals[i]);
	}

	opts->npairs = 0;

	const char *p = text ? text : "";

	while(*p) {
		const char *eol = strchr(p, '\n');
		size_t len = eol ? (size_t)(eol - p) : strlen(p);
		char *line = malloc(len + 1);
		memcpy(line, p, len);
		line[len] = 0;
		p = eol ? eol + 1 : p + len;

		char *l = trim(line);

		if(*l && *l != '#') {
			char *val = l + strcspn(l, "\t =");
			char *key = l;

			if(*val) {
				*val++ = 0;
				val += strspn(val, "\t ");

				if(*val == '=') {
					val++;
					val += strspn(val, "\t ");
				}
			}

			if(*key) {
				yamlconf_add_option_value(yc, net, key, val);
			}
		}

		free(line);
	}
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

void yamlconf_host_set_text(yamlconf_t *yc, const char *net, const char *name, const char *text) {
	yval_t *hosts = map_get_or_create_map(net_node_create(yc, net), "hosts");
	char *copy = strdup(text ? text : "");
	size_t n = strlen(copy);

	while(n && (copy[n - 1] == '\n' || copy[n - 1] == '\r')) {
		copy[--n] = 0;
	}

	map_set_scalar(hosts, name, copy);
	free(copy);
}

bool yamlconf_host_del(yamlconf_t *yc, const char *net, const char *name) {
	yval_t *hosts = map_get(map_get(map_get(yc->root, "networks"), net), "hosts");
	return map_del(hosts, name);
}

void yamlconf_script_set_text(yamlconf_t *yc, const char *net, const char *name, const char *text) {
	yval_t *scripts = map_get_or_create_map(net_node_create(yc, net), "scripts");
	char *copy = strdup(text ? text : "");
	size_t n = strlen(copy);

	/* The emitter writes a multi-line value as a literal block and the parser
	   chomps, so a stored trailing newline would not survive the round trip
	   (block_scalar_safe() refuses it and it would become a quoted scalar).
	   Strip it here, exactly as a hand-written block in the file reads back. */
	while(n && (copy[n - 1] == '\n' || copy[n - 1] == '\r')) {
		copy[--n] = 0;
	}

	map_set_scalar(scripts, name, copy);
	free(copy);
}

bool yamlconf_script_del(yamlconf_t *yc, const char *net, const char *name) {
	yval_t *netnode = map_get(map_get(yc->root, "networks"), net);
	yval_t *scripts = map_get(netnode, "scripts");

	if(!map_del(scripts, name)) {
		return false;
	}

	/* An empty map is emitted as `scripts: {}', which the parser reads back as
	   a scalar; drop the key when its last entry goes. */
	if(!scripts->npairs) {
		map_del(netnode, "scripts");
	}

	return true;
}

/* ---- locking ------------------------------------------------------------- */

/* Writers (the daemon persisting a learned key, `tinc set', a join, the
   materialiser) serialise on `<path>.lock`, a file that is never replaced,
   so its inode -- and therefore the lock -- is stable across the atomic
   rename that every save performs. Locking the config file itself would
   only ever protect the inode the locker happened to open, which the next
   save replaces; two writers would then both hold "the" lock. The lock is
   re-entrant within one process (single-threaded daemon and CLI) so a
   caller that locks around a read-modify-write does not deadlock the save
   inside it. */
static int lock_depth;
#ifdef _WIN32
static HANDLE lock_handle = INVALID_HANDLE_VALUE;
#else
static int lock_fd = -1;
#endif

bool yamlconf_lock(const char *path) {
	if(lock_depth > 0) {
		lock_depth++;
		return true;
	}

	size_t n = strlen(path) + 6;
	char *lockpath = malloc(n);
	if(!lockpath) return false;
	snprintf(lockpath, n, "%s.lock", path);
#ifdef _WIN32
	/* Exclusive open: a second opener fails until the first closes. Spin
	   briefly instead of failing outright. */
	for(int tries = 0; tries < 200; tries++) {
		lock_handle = CreateFileA(lockpath, GENERIC_READ | GENERIC_WRITE, 0, NULL,
		                          OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if(lock_handle != INVALID_HANDLE_VALUE) break;
		Sleep(50);
	}
	free(lockpath);
	if(lock_handle == INVALID_HANDLE_VALUE) return false;
#else
	lock_fd = open(lockpath, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
	free(lockpath);
	if(lock_fd < 0) return false;
	if(flock(lock_fd, LOCK_EX)) { close(lock_fd); lock_fd = -1; return false; }
#endif
	lock_depth = 1;
	return true;
}

void yamlconf_unlock(void) {
	if(lock_depth <= 0) return;
	if(--lock_depth > 0) return;
#ifdef _WIN32
	CloseHandle(lock_handle);
	lock_handle = INVALID_HANDLE_VALUE;
#else
	close(lock_fd);          /* releases the flock */
	lock_fd = -1;
#endif
}

/* ---- save ---------------------------------------------------------------- */

/* Serialise and replace `path` atomically. Private keys live in this file, so
   it is created 0600 (POSIX) or with private_sd()'s protected DACL (Windows),
   the temporary is never a symlink target (O_NOFOLLOW) and its data is on
   disk before it replaces the config. */
static bool write_atomic(const char *path, const char *data, size_t len) {
	size_t n = strlen(path) + 5;
	char *tmp = malloc(n);
	if(!tmp) return false;
	snprintf(tmp, n, "%s.tmp", path);
	/* A leftover temporary (a crash between write and rename) is removed and
	   the new one created exclusively: opening an existing file keeps its
	   mode on POSIX, and on Windows CreateFile ignores the security
	   attributes for a file that already exists. */
#ifdef _WIN32
	FILE *f = NULL;
	DeleteFileA(tmp);
	PSECURITY_DESCRIPTOR sd = private_sd();
	if(sd) {
		/* private_sd(): protected DACL, SYSTEM + Administrators (+ the user
		   when not elevated); the rename below keeps it on the config. */
		SECURITY_ATTRIBUTES sa = { sizeof(sa), sd, FALSE };
		HANDLE h = CreateFileA(tmp, GENERIC_WRITE, 0, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
		LocalFree(sd);
		if(h != INVALID_HANDLE_VALUE) {
			int fd = _open_osfhandle((intptr_t) h, _O_WRONLY | _O_BINARY);
			if(fd < 0) CloseHandle(h);
			else if(!(f = _fdopen(fd, "wb"))) _close(fd);
		}
	} else {
		errno = EACCES;               /* never fall back to an inherited ACL */
	}
#else
	unlink(tmp);
	int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	FILE *f = fd >= 0 ? fdopen(fd, "wb") : NULL;
	if(!f && fd >= 0) close(fd);
#endif
	if(!f) { free(tmp); return false; }
	bool ok = fwrite(data, 1, len, f) == len;
	ok = !fflush(f) && ok;
#ifdef _WIN32
	ok = !_commit(_fileno(f)) && ok;
#else
	ok = !fsync(fileno(f)) && ok;
#endif
	ok = !fclose(f) && ok;
	if(!ok) { remove(tmp); free(tmp); return false; }
#ifdef _WIN32
	if(!MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) { remove(tmp); free(tmp); return false; }
#else
	if(rename(tmp, path)) { remove(tmp); free(tmp); return false; }
#endif
	free(tmp);
	return true;
}

char *yamlconf_emit(yamlconf_t *yc) {
	sbuf_t b = {0};
	emit_node(&b, yc->root, 0);
	if(!b.buf) sb_puts(&b, "");
	if(b.error) { free(b.buf); return NULL; }
	return b.buf;
}

bool yamlconf_save(yamlconf_t *yc, const char *path) {
	sbuf_t b = {0};
	emit_node(&b, yc->root, 0);
	if(!b.buf) sb_puts(&b, "");
	if(b.error) { free(b.buf); errno = EINVAL; return false; }
	bool ok = yamlconf_lock(path);
	if(ok) {
		ok = write_atomic(path, b.buf, b.len);
		yamlconf_unlock();
	}
	free(b.buf);
	return ok;
}

bool yamlconf_append_host_line(const char *path, const char *net,
                               const char *name, const char *key, const char *value) {
	/* The whole read-modify-write runs under the lock, so a concurrent
	   `tinc set' or a second daemon sharing the file cannot lose it. */
	if(!yamlconf_lock(path)) return false;
	bool ok = false;
	yamlconf_t *yc = yamlconf_load(path);
	if(!yc) goto out;

	yamlconf_host_add_line(yc, net, name, key, value);
	ok = yamlconf_save(yc, path);
	yamlconf_free(yc);
out:
	yamlconf_unlock();
	return ok;
}

bool yamlconf_reload_global(void) {
	if(!yamlconf_path) return true;
	yamlconf_t *fresh = yamlconf_load(yamlconf_path);
	if(!fresh) return false;
	yamlconf_free(yamlconf_global);
	yamlconf_global = fresh;
	return true;
}
