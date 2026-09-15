/*
    zeroconf.c -- materialise a working configuration into an empty YAML file.

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

#include "ecdsagen.h"
#include "fs.h"
#include "logger.h"
#include "names.h"
#include "random.h"
#include "utils.h"
#include "xalloc.h"
#include "yamlconf.h"
#include "zeroconf.h"

#ifndef DISABLE_LEGACY
#include "rsagen.h"
#endif

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif

/* ---- helpers ------------------------------------------------------------ */

/* Run a PEM writer into a temporary FILE* and return its output as a string
   with trailing newlines stripped. Caller frees. */
typedef bool (*pem_writer_t)(void *key, FILE *fp);

static char *capture_pem(pem_writer_t writer, void *key) {
	FILE *f = yamlconf_content_fp("");

	if(!f) {
		return NULL;
	}

	if(!writer(key, f)) {
		fclose(f);
		return NULL;
	}

	fflush(f);
	long sz = ftell(f);

	if(sz <= 0) {
		fclose(f);
		return NULL;
	}

	rewind(f);
	char *buf = xmalloc((size_t)sz + 1);
	size_t rd = fread(buf, 1, (size_t)sz, f);
	fclose(f);
	buf[rd] = 0;

	while(rd && (buf[rd - 1] == '\n' || buf[rd - 1] == '\r')) {
		buf[--rd] = 0;
	}

	return buf;
}

static bool write_ecdsa_priv(void *key, FILE *fp) {
	return ecdsa_write_pem_private_key(key, fp);
}

#ifndef DISABLE_LEGACY
static bool write_rsa_priv(void *key, FILE *fp) {
	return rsa_write_pem_private_key(key, fp);
}

static bool write_rsa_pub(void *key, FILE *fp) {
	return rsa_write_pem_public_key(key, fp);
}
#endif

/* True if the host-file text has a line starting with `var` (case-insensitive,
   followed by space/tab/=), or containing `needle` verbatim when var is NULL. */
static bool host_text_has(const char *text, const char *var, const char *needle) {
	if(!text) {
		return false;
	}

	if(!var) {
		return strstr(text, needle) != NULL;
	}

	size_t n = strlen(var);

	for(const char *p = text; p && *p; p = strchr(p, '\n') ? strchr(p, '\n') + 1 : NULL) {
		while(*p == ' ' || *p == '\t') {
			p++;
		}

		if(!strncasecmp(p, var, n) && (p[n] == ' ' || p[n] == '\t' || p[n] == '=')) {
			return true;
		}
	}

	return false;
}

/* ---- public helpers ------------------------------------------------------ */

bool zeroconf_pool_parse(const char *pool, uint32_t *network, int *prefix) {
	unsigned int a, b, c, d, bits;
	char tail;

	if(!pool || sscanf(pool, "%u.%u.%u.%u/%u%c", &a, &b, &c, &d, &bits, &tail) != 5) {
		return false;
	}

	if(a > 255 || b > 255 || c > 255 || d > 255 || bits < 8 || bits > 30) {
		return false;
	}

	uint32_t addr = (a << 24) | (b << 16) | (c << 8) | d;
	uint32_t mask = 0xffffffffu << (32 - bits);
	*network = addr & mask;
	*prefix = (int)bits;
	return true;
}

bool zeroconf_pool_first_host(const char *pool, char *out, size_t outlen) {
	uint32_t network;
	int prefix;

	if(!zeroconf_pool_parse(pool, &network, &prefix)) {
		return false;
	}

	uint32_t first = network + 1;

	snprintf(out, outlen, "%u.%u.%u.%u/32",
	         (first >> 24) & 255, (first >> 16) & 255, (first >> 8) & 255, first & 255);
	return true;
}

void zeroconf_default_pool(char *out, size_t outlen) {
	uint8_t r = 0;
	randomize(&r, sizeof(r));
	snprintf(out, outlen, "10.%u.0.0/24", 1 + (r % 254));
}

char *zeroconf_default_name(void) {
	char hostname[HOST_NAME_MAX + 1] = "";

	if(gethostname(hostname, sizeof(hostname))) {
		hostname[0] = 0;
	}

	hostname[HOST_NAME_MAX] = 0;

	/* Use the first label only ("laptop.lan" -> "laptop"). */
	char *dot = strchr(hostname, '.');

	if(dot) {
		*dot = 0;
	}

	bool usable = false;

	for(char *c = hostname; *c; c++) {
		if(isalnum((uint8_t) *c)) {
			usable = true;
		} else {
			*c = '_';
		}
	}

	if(usable && check_id(hostname)) {
		return xstrdup(hostname);
	}

	uint32_t r = 0;
	randomize(&r, sizeof(r));
	char *name = NULL;
	xasprintf(&name, "node_%08x", r);
	return name;
}

/* ---- scripts ------------------------------------------------------------- */

int zeroconf_materialise_scripts(void) {
	if(!yamlconf_path || !yamlconf_global || !netname || !confbase) {
		return 0;
	}

	const char **names = yamlconf_script_names(yamlconf_global, netname);

	if(!names) {
		return 0;
	}

	int written = 0;

	for(size_t i = 0; names[i]; i++) {
		const char *name = names[i];

		/* A script name is a plain file name inside the runtime dir. */
		if(!*name || strpbrk(name, "/\\") || name[0] == '.') {
			logger(DEBUG_ALWAYS, LOG_ERR, "Ignoring script with unsafe name `%s' in `%s'", name, yamlconf_path);
			continue;
		}

		char *text = yamlconf_script_text(yamlconf_global, netname, name);

		if(!text) {
			continue;
		}

		char path[PATH_MAX];
		snprintf(path, sizeof(path), "%s" SLASH "%s", confbase, name);

		FILE *f = fopenmask(path, "w", 0700);

		if(!f) {
			free(text);
			free(names);
			return -1;
		}

		fputs(text, f);

		if(text[0] && text[strlen(text) - 1] != '\n') {
			fputc('\n', f);
		}

		fclose(f);
		chmod(path, 0700);
		free(text);
		written++;
	}

	free(names);
	return written;
}

/* ---- materialisation ----------------------------------------------------- */

bool zeroconf_materialise(void) {
	if(!yamlconf_path) {
		return true;  /* classic confbase mode: nothing to do here */
	}

	if(!netname) {
		logger(DEBUG_ALWAYS, LOG_ERR, "YAML mode needs a network name (-n) to materialise defaults into `%s'", yamlconf_path);
		return false;
	}

	yamlconf_t *yc = yamlconf_global;
	bool fresh = false;

	if(!yc) {
		if(!access(yamlconf_path, F_OK)) {
			/* Exists but did not parse: never overwrite someone's config. */
			logger(DEBUG_ALWAYS, LOG_ERR, "Refusing to overwrite unparsable YAML config `%s'", yamlconf_path);
			return false;
		}

		yc = yamlconf_new();
		fresh = true;
	}

	bool changed = false;
	char msg[512] = "";
	size_t mlen = 0;
#define NOTE(...) do { if(mlen < sizeof(msg)) mlen += snprintf(msg + mlen, sizeof(msg) - mlen, __VA_ARGS__); } while(0)

	/* --- Name --- */
	const char *cfgname = yamlconf_get_option(yc, netname, "Name");
	char *name;

	if(!cfgname || !*cfgname) {
		name = zeroconf_default_name();
		yamlconf_set_option(yc, netname, "Name", name);
		changed = true;
		NOTE("Name=%s ", name);
	} else {
		name = replace_name(cfgname);

		if(!name) {
			yamlconf_free(fresh ? yc : NULL);
			return false;
		}
	}

	/* --- scalar defaults --- */
	/* Port: a founding node (nothing to ConnectTo) is the rendezvous for its
	   invitees, so it keeps tinc's standard port; a node that dials out gets
	   an ephemeral port (fresh NAT mapping per start). */
	const char *port_default = yamlconf_has_option(yc, netname, "ConnectTo") ? "0" : "655";
	const struct {
		const char *key, *value;
	} defaults[] = {
		{"Mode", "router"},
		{"Port", port_default},
	};

	for(size_t i = 0; i < sizeof(defaults) / sizeof(*defaults); i++) {
		if(!yamlconf_get_option(yc, netname, defaults[i].key)) {
			yamlconf_set_option(yc, netname, defaults[i].key, defaults[i].value);
			changed = true;
			NOTE("%s=%s ", defaults[i].key, defaults[i].value);
		}
	}

	/* --- AddressPool --- */
	const char *pool = yamlconf_get_option(yc, netname, "AddressPool");
	char poolbuf[64];
	char first[64];

	if(!pool || !*pool) {
		zeroconf_default_pool(poolbuf, sizeof(poolbuf));
		yamlconf_set_option(yc, netname, "AddressPool", poolbuf);
		pool = poolbuf;
		changed = true;
		NOTE("AddressPool=%s ", pool);
	}

	if(!zeroconf_pool_first_host(pool, first, sizeof(first))) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Invalid AddressPool `%s' in `%s' (expected IPv4 a.b.c.d/8..30)", pool, yamlconf_path);
		free(name);
		yamlconf_free(fresh ? yc : NULL);
		return false;
	}

	/* --- own host record: Subnet --- */
	char *host = yamlconf_host_text(yc, netname, name);

	if(!host_text_has(host, "Subnet", NULL)) {
		yamlconf_host_add_line(yc, netname, name, "Subnet", first);
		changed = true;
		NOTE("Subnet=%s ", first);
	}

	/* Advertise our transport accept list in our own host record, so it
	   propagates through the mesh and through invitations exactly like
	   Subnet/Ed25519PublicKey. This is the compiled-in default (the carriers
	   this build understands); an operator who narrows `Transports` in
	   options: overrides it at runtime. Kept in sync with
	   transport_compiled_mask() in transport_table.c. */
	if(!host_text_has(host, "Transports", NULL)) {
		yamlconf_host_add_line(yc, netname, name, "Transports", "plain, sf");
		changed = true;
		NOTE("Transports=plain,sf ");
	}

	free(host);

	/* --- Ed25519 key pair --- */
	const char *ed_pem = yamlconf_key_pem(yc, netname, "ed25519_priv");
	ecdsa_t *ed = NULL;

	if(!ed_pem) {
		ed = ecdsa_generate();

		if(!ed) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Ed25519 key generation failed");
			free(name);
			yamlconf_free(fresh ? yc : NULL);
			return false;
		}

		char *pem = capture_pem(write_ecdsa_priv, ed);

		if(!pem) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not serialise Ed25519 private key");
			ecdsa_free(ed);
			free(name);
			yamlconf_free(fresh ? yc : NULL);
			return false;
		}

		yamlconf_set_key_pem(yc, netname, "ed25519_priv", pem);
		free(pem);
		changed = true;
		NOTE("ed25519_priv ");
	}

	host = yamlconf_host_text(yc, netname, name);

	if(!host_text_has(host, "Ed25519PublicKey", NULL)) {
		if(!ed) {
			FILE *f = yamlconf_content_fp(ed_pem);

			if(f) {
				ed = ecdsa_read_pem_private_key(f);
				fclose(f);
			}
		}

		if(!ed) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not read Ed25519 private key from `%s'", yamlconf_path);
			free(host);
			free(name);
			yamlconf_free(fresh ? yc : NULL);
			return false;
		}

		char *pub = ecdsa_get_base64_public_key(ed);
		yamlconf_host_add_line(yc, netname, name, "Ed25519PublicKey", pub);
		free(pub);
		changed = true;
		NOTE("Ed25519PublicKey ");
	}

	free(host);

	if(ed) {
		ecdsa_free(ed);
	}

#ifndef DISABLE_LEGACY
	/* --- legacy RSA key pair --- */
	const char *rsa_pem = yamlconf_key_pem(yc, netname, "rsa_priv");
	host = yamlconf_host_text(yc, netname, name);
	bool have_rsa_pub = host_text_has(host, NULL, "BEGIN RSA PUBLIC KEY") ||
	                    host_text_has(host, "PublicKey", NULL) ||
	                    host_text_has(host, "PublicKeyFile", NULL);
	free(host);

	if(!rsa_pem || !have_rsa_pub) {
		rsa_t *rsa = NULL;

		if(rsa_pem) {
			FILE *f = yamlconf_content_fp(rsa_pem);

			if(f) {
				rsa = rsa_read_pem_private_key(f);
				fclose(f);
			}
		} else {
			rsa = rsa_generate(2048, 0x10001);
		}

		if(!rsa) {
			logger(DEBUG_ALWAYS, LOG_ERR, "RSA key %s failed", rsa_pem ? "read" : "generation");
			free(name);
			yamlconf_free(fresh ? yc : NULL);
			return false;
		}

		if(!rsa_pem) {
			char *pem = capture_pem(write_rsa_priv, rsa);

			if(pem) {
				yamlconf_set_key_pem(yc, netname, "rsa_priv", pem);
				free(pem);
				changed = true;
				NOTE("rsa_priv ");
			}
		}

		if(!have_rsa_pub) {
			char *pub = capture_pem(write_rsa_pub, rsa);

			if(pub) {
				yamlconf_host_add_line(yc, netname, name, pub, NULL);
				free(pub);
				changed = true;
				NOTE("RSA-public ");
			}
		}

		rsa_free(rsa);
	}

#endif

	free(name);

	if(changed) {
		if(!yamlconf_save(yc, yamlconf_path)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not write `%s': %s", yamlconf_path, strerror(errno));
			yamlconf_free(fresh ? yc : NULL);
			return false;
		}

		logger(DEBUG_ALWAYS, LOG_NOTICE, "Materialised defaults into `%s' [%s]: %s", yamlconf_path, netname, msg);
	}

	if(fresh) {
		yamlconf_global = yc;
	}

	int scripts = zeroconf_materialise_scripts();

	if(scripts < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not write scripts from `%s' into `%s': %s", yamlconf_path, confbase, strerror(errno));
		return false;
	} else if(scripts > 0) {
		logger(DEBUG_ALWAYS, LOG_INFO, "Wrote %d script(s) from `%s' into `%s'", scripts, yamlconf_path, confbase);
	}

#undef NOTE
	return true;
}
