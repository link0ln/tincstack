/*
    conf.c -- configuration code
    Copyright (C) 1998      Robert van der Meulen
                  1998-2005 Ivo Timmermans
                  2000      Cris van Pelt
                  2010-2011 Julien Muchembled <jm@jmuchemb.eu>
                  2000-2022 Guus Sliepen <guus@tinc-vpn.org>
                  2013      Florent Clairambault <florent@clairambault.fr>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "system.h"

#include "splay_tree.h"
#include "connection.h"
#include "conf.h"
#include "list.h"
#include "logger.h"
#include "names.h"
#include "netutl.h"             /* for str2address */
#include "protocol.h"
#include "xalloc.h"
#include "yamlconf.h"

int pinginterval = 0;           /* seconds between pings */
int pingtimeout = 0;            /* seconds to wait for response */

/* global/host configuration values given at the command line */
list_t cmdline_conf = {
	.head = NULL,
	.tail = NULL,
	.count = 0,
	.delete = (list_action_t)free_config,
};

/* See conf.h: registered by the daemon, NULL in the CLI. */
void (*config_host_written_cb)(const char *name) = NULL;

static int config_compare(const config_t *a, const config_t *b) {
	int result;

	result = strcasecmp(a->variable, b->variable);

	if(result) {
		return result;
	}

	/* give priority to command line options */
	result = !b->file - !a->file;

	if(result) {
		return result;
	}

	result = a->line - b->line;

	if(result) {
		return result;
	} else {
		return a->file ? strcmp(a->file, b->file) : 0;
	}
}

splay_tree_t config_tree = {
	.compare = (splay_compare_t) config_compare,
	.delete = (splay_action_t) free_config,
};

splay_tree_t *create_configuration(void) {
	splay_tree_t *tree = splay_alloc_tree(NULL, NULL);
	init_configuration(tree);
	return tree;
}

void init_configuration(splay_tree_t *tree) {
	memset(tree, 0, sizeof(*tree));
	tree->compare = (splay_compare_t) config_compare;
	tree->delete = (splay_action_t) free_config;
}

void exit_configuration(splay_tree_t *config_tree) {
	splay_delete_tree(config_tree);
}

config_t *new_config(void) {
	return xzalloc(sizeof(config_t));
}

void free_config(config_t *cfg) {
	free(cfg->variable);
	free_string(cfg->value);
	free(cfg->file);
	free(cfg);
}

void config_add(splay_tree_t *config_tree, config_t *cfg) {
	splay_insert(config_tree, cfg);
}

config_t *lookup_config(splay_tree_t *config_tree, const char *variable) {
	const config_t cfg = {
		.variable = (char *)variable,
		.file = NULL,
		.line = 0,
	};

	config_t *found = splay_search_closest_greater(config_tree, &cfg);

	if(!found) {
		return NULL;
	}

	if(strcasecmp(found->variable, variable)) {
		return NULL;
	}

	return found;
}

config_t *lookup_config_next(splay_tree_t *config_tree, const config_t *cfg) {
	splay_node_t *node;
	config_t *found;

	node = splay_search_node(config_tree, cfg);

	if(node) {
		if(node->next) {
			found = node->next->data;

			if(!strcasecmp(found->variable, cfg->variable)) {
				return found;
			}
		}
	}

	return NULL;
}

bool get_config_bool(const config_t *cfg, bool *result) {
	if(!cfg) {
		return false;
	}

	if(!strcasecmp(cfg->value, "yes")) {
		*result = true;
		return true;
	} else if(!strcasecmp(cfg->value, "no")) {
		*result = false;
		return true;
	}

	logger(DEBUG_ALWAYS, LOG_ERR, "\"yes\" or \"no\" expected for configuration variable %s in %s line %d",
	       cfg->variable, cfg->file, cfg->line);

	return false;
}

bool get_config_int(const config_t *cfg, int *result) {
	if(!cfg) {
		return false;
	}

	if(sscanf(cfg->value, "%d", result) == 1) {
		return true;
	}

	logger(DEBUG_ALWAYS, LOG_ERR, "Integer expected for configuration variable %s in %s line %d",
	       cfg->variable, cfg->file, cfg->line);

	return false;
}

bool get_config_string(const config_t *cfg, char **result) {
	if(!cfg) {
		return false;
	}

	*result = xstrdup(cfg->value);

	return true;
}

bool get_config_address(const config_t *cfg, struct addrinfo **result) {
	struct addrinfo *ai;

	if(!cfg) {
		return false;
	}

	ai = str2addrinfo(cfg->value, NULL, 0);

	if(ai) {
		*result = ai;
		return true;
	}

	logger(DEBUG_ALWAYS, LOG_ERR, "Hostname or IP address expected for configuration variable %s in %s line %d",
	       cfg->variable, cfg->file, cfg->line);

	return false;
}

/*
  Read exactly one line and strip the trailing newline if any.
*/
static char *readline(FILE *fp, char *buf, size_t buflen) {
	char *newline = NULL;
	char *p;

	if(feof(fp)) {
		return NULL;
	}

	p = fgets(buf, (int) buflen, fp);

	if(!p) {
		return NULL;
	}

	newline = strchr(p, '\n');

	if(!newline) {
		return buf;
	}

	/* kill newline and carriage return if necessary */
	*newline = '\0';

	if(newline > p && newline[-1] == '\r') {
		newline[-1] = '\0';
	}

	return buf;
}

config_t *parse_config_line(char *line, const char *fname, int lineno) {
	config_t *cfg;
	char *variable, *value, *eol;
	variable = value = line;

	eol = line + strlen(line);

	while(strchr("\t ", *--eol)) {
		*eol = '\0';
	}

	size_t len = strcspn(value, "\t =");
	value += len;
	value += strspn(value, "\t ");

	// NOLINTNEXTLINE
	if(*value == '=') {
		value++;
		value += strspn(value, "\t ");
	}

	variable[len] = '\0';

	if(!*value) {
		const char err[] = "No value for variable";

		if(fname)
			logger(DEBUG_ALWAYS, LOG_ERR, "%s `%s' on line %d while reading config file %s",
			       err, variable, lineno, fname);
		else
			logger(DEBUG_ALWAYS, LOG_ERR, "%s `%s' in command line option %d",
			       err, variable, lineno);

		return NULL;
	}

	cfg = new_config();
	cfg->variable = xstrdup(variable);
	cfg->value = xstrdup(value);
	cfg->file = fname ? xstrdup(fname) : NULL;
	cfg->line = lineno;

	return cfg;
}

/*
  Open a config/host/key file for reading. In YAML mode (a *.yaml passed via
  -c), the classic confbase tree does not exist: serve tinc.conf, hosts/<name>
  and the private keys straight from the YAML via a temporary FILE*. Anything
  else (and all writes) falls through to a normal fopen. This single shim is
  why the rest of tinc's file-based config code works unchanged on YAML.
*/
FILE *config_fopen(const char *fname, const char *mode) {
	if(yamlconf_global && netname && mode[0] == 'r') {
		const char *base = fname;

		for(const char *p = fname; *p; p++)
			if(*p == '/' || *p == '\\') {
				base = p + 1;
			}

		char *content = NULL;
		bool owned = false;
		bool recognized = true;

		if(!strcmp(base, "tinc.conf")) {
			content = yamlconf_options_text(yamlconf_global, netname);
			owned = true;
		} else if(!strcmp(base, "ed25519_key.priv")) {
			content = (char *) yamlconf_key_pem(yamlconf_global, netname, "ed25519_priv");
		} else if(!strcmp(base, "rsa_key.priv")) {
			content = (char *) yamlconf_key_pem(yamlconf_global, netname, "rsa_priv");
		} else if(strstr(fname, "hosts")) {
			content = yamlconf_host_text(yamlconf_global, netname, base);
			owned = true;
		} else {
			recognized = false;
		}

		if(content) {
			FILE *f = yamlconf_content_fp(content);

			if(owned) {
				free(content);
			}

			return f;
		}

		if(recognized) {
			errno = ENOENT;
			return NULL;
		}
	}

	return fopen(fname, mode);
}

/*
  Parse a configuration file and put the results in the configuration tree
  starting at *base.
*/
bool read_config_file(splay_tree_t *config_tree, const char *fname, bool verbose) {
	FILE *fp;
	char buffer[MAX_STRING_SIZE];
	char *line;
	int lineno = 0;
	bool ignore = false;
	config_t *cfg;
	bool result = false;

	fp = config_fopen(fname, "r");

	if(!fp) {
		/* Only read_host_config() passes verbose = false, and it does so
		   exactly where an absent host record is a normal state: a node we
		   know from the meta graph but were never handed a record for (see
		   defect C). Logging that at LOG_ERR put a line in the operator's
		   journal at the default -d1 for every such probe -- several per dial
		   attempt, forever, while the pair stayed relayed. The verbose callers
		   (fsck, `tinc export`, the explicit key reads) are unchanged and
		   still report loudly. */
		if(verbose) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Cannot open config file %s: %s", fname, strerror(errno));
		} else {
			logger(DEBUG_PROTOCOL, LOG_DEBUG, "Cannot open config file %s: %s", fname, strerror(errno));
		}

		return false;
	}

	for(;;) {
		line = readline(fp, buffer, sizeof(buffer));

		if(!line) {
			if(feof(fp)) {
				result = true;
			}

			break;
		}

		lineno++;

		if(!*line || *line == '#') {
			continue;
		}

		if(ignore) {
			if(!strncmp(line, "-----END", 8)) {
				ignore = false;
			}

			continue;
		}

		if(!strncmp(line, "-----BEGIN", 10)) {
			ignore = true;
			continue;
		}

		cfg = parse_config_line(line, fname, lineno);

		if(!cfg) {
			break;
		}

		config_add(config_tree, cfg);
	}

	fclose(fp);

	return result;
}

void read_config_options(splay_tree_t *config_tree, const char *prefix) {
	size_t prefix_len = prefix ? strlen(prefix) : 0;

	for(const list_node_t *node = cmdline_conf.tail; node; node = node->prev) {
		const config_t *cfg = node->data;
		config_t *new;

		if(!prefix) {
			if(strchr(cfg->variable, '.')) {
				continue;
			}
		} else {
			if(strncmp(prefix, cfg->variable, prefix_len) ||
			                cfg->variable[prefix_len] != '.') {
				continue;
			}
		}

		new = new_config();

		if(prefix) {
			new->variable = xstrdup(cfg->variable + prefix_len + 1);
		} else {
			new->variable = xstrdup(cfg->variable);
		}

		new->value = xstrdup(cfg->value);
		new->file = NULL;
		new->line = cfg->line;

		config_add(config_tree, new);
	}
}

bool read_server_config(splay_tree_t *config_tree) {
	char fname[PATH_MAX];

	/* YAML mode: the file is the source of truth and may have been edited by
	   the CLI or a GUI since we last looked, so every (re)load of the server
	   config starts by re-reading it. A file that no longer parses is
	   refused here rather than half-applied. */
	if(yamlconf_path && !yamlconf_reload_global()) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not re-read YAML config `%s'", yamlconf_path);
		return false;
	}

	read_config_options(config_tree, NULL);

	snprintf(fname, sizeof(fname), "%s" SLASH "tinc.conf", confbase);

	if(!read_config_file(config_tree, fname, true)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to read `%s': %s", fname, strerror(errno));
		return false;
	}

	// We will try to read the conf files in the "conf.d" dir, if it exists
	char dname[PATH_MAX];
	snprintf(dname, sizeof(dname), "%s" SLASH "conf.d", confbase);
	DIR *dir = opendir(dname);

	if(!dir && errno == ENOENT) {
		return true;
	} else {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to read `%s': %s", dname, strerror(errno));
		return false;
	}

	// We list all the files in it
	struct dirent *ep;

	while((ep = readdir(dir))) {
		size_t l = strlen(ep->d_name);

		// And we try to read the ones that end with ".conf"
		if(l > 5 && !strcmp(".conf", & ep->d_name[ l - 5 ])) {
			if((size_t)snprintf(fname, sizeof(fname), "%s" SLASH "%s", dname, ep->d_name) >= sizeof(fname)) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Pathname too long: %s/%s", dname, ep->d_name);
				return false;
			}

			if(!read_config_file(config_tree, fname, true)) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Failed to read `%s': %s", fname, strerror(errno));
				return false;
			}
		}
	}

	return true;
}

bool read_host_config(splay_tree_t *config_tree, const char *name, bool verbose) {
	read_config_options(config_tree, name);

	char fname[PATH_MAX];
	snprintf(fname, sizeof(fname), "%s" SLASH "hosts" SLASH "%s", confbase, name);
	return read_config_file(config_tree, fname, verbose);
}

/* `text` (a host record) with every `key = ...` line replaced by one
   `key = value` line -- in place of the first, or at the end when there was
   none. Case-insensitive on the variable name, exact on its end, so
   "TlsFingerprint" does not also catch "TlsFingerprintX". Caller frees. */
char *host_text_set_var(const char *text, const char *key, const char *value) {
	size_t keylen = strlen(key);
	size_t cap = (text ? strlen(text) : 0) + keylen + strlen(value) + 8;
	char *out = xmalloc(cap);
	size_t len = 0;
	bool written = false;

	for(const char *line = text; line && *line;) {
		const char *eol = strchr(line, '\n');
		size_t linelen = eol ? (size_t)(eol - line) : strlen(line);
		const char *p = line + strspn(line, " \t");
		bool match = (size_t)(p - line) < linelen && !strncasecmp(p, key, keylen) && strchr(" \t=", p[keylen]) && p[keylen];

		if(!match) {
			memcpy(out + len, line, linelen);
			len += linelen;
			out[len++] = '\n';
		} else if(!written) {
			len += (size_t) snprintf(out + len, cap - len, "%s = %s\n", key, value);
			written = true;
		}

		line = eol ? eol + 1 : NULL;
	}

	if(!written) {
		len += (size_t) snprintf(out + len, cap - len, "%s = %s\n", key, value);
	}

	out[len] = 0;
	return out;
}

/* Like append_config_file(), but the host record ends up with exactly one
   `key` line: for values that are replaced rather than accumulated (a
   certificate pin that moved). */
bool replace_config_file(const char *name, const char *key, const char *value) {
	if(yamlconf_path && netname) {
		if(!yamlconf_lock(yamlconf_path)) {
			return false;
		}

		bool ok = false;
		yamlconf_t *yc = yamlconf_load(yamlconf_path);

		if(yc) {
			char *text = yamlconf_host_text(yc, netname, name);
			char *updated = host_text_set_var(text, key, value);
			yamlconf_host_set_text(yc, netname, name, updated);
			ok = yamlconf_save(yc, yamlconf_path);

			if(ok && yamlconf_global) {
				yamlconf_host_set_text(yamlconf_global, netname, name, updated);
			}

			free(text);
			free(updated);
			yamlconf_free(yc);
		}

		yamlconf_unlock();

		if(ok && config_host_written_cb) {
			config_host_written_cb(name);
		}

		return ok;
	}

	char fname[PATH_MAX], tmpname[PATH_MAX + 8];
	snprintf(fname, sizeof(fname), "%s" SLASH "hosts" SLASH "%s", confbase, name);
	snprintf(tmpname, sizeof(tmpname), "%s.new", fname);

	char *text = NULL;
	FILE *in = fopen(fname, "rb");

	if(in) {
		size_t cap = 4096, len = 0, n;
		text = xmalloc(cap);

		while((n = fread(text + len, 1, cap - len - 1, in)) > 0) {
			len += n;

			if(len + 1 == cap) {
				cap *= 2;
				text = xrealloc(text, cap);
			}
		}

		text[len] = 0;
		fclose(in);
	}

	char *updated = host_text_set_var(text, key, value);
	free(text);

	FILE *out = fopen(tmpname, "wb");
	bool ok = out && fputs(updated, out) >= 0;

	if(out && fclose(out)) {
		ok = false;
	}

	free(updated);

#ifdef HAVE_WINDOWS
	/* rename() does not replace an existing file there. */
	if(ok) {
		remove(fname);
	}

#endif

	if(!ok || rename(tmpname, fname)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Cannot update %s: %s", fname, strerror(errno));
		remove(tmpname);
		return false;
	}

	return true;
}

bool append_config_file(const char *name, const char *key, const char *value) {
	if(yamlconf_path && netname) {
		/* YAML mode: persist the learned line into the host's section, and
		   mirror it into the in-memory document so config_fopen() serves it
		   immediately (the daemon only re-reads the file on reload). */
		if(!yamlconf_append_host_line(yamlconf_path, netname, name, key, value)) {
			return false;
		}

		if(yamlconf_global) {
			yamlconf_host_add_line(yamlconf_global, netname, name, key, value);
		}

		if(config_host_written_cb) {
			config_host_written_cb(name);
		}

		return true;
	}

	char fname[PATH_MAX];
	snprintf(fname, sizeof(fname), "%s" SLASH "hosts" SLASH "%s", confbase, name);

	FILE *fp = fopen(fname, "a");

	if(!fp) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "Cannot open config file %s: %s", fname, strerror(errno));
		return false;
	}

	fprintf(fp, "\n# The following line was automatically added by tinc\n%s = %s\n", key, value);
	fclose(fp);
	return true;
}
