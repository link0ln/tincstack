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
#include "tls.h"
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

/* Every script name execute_script() (script.c) can ask for from the runtime
   dir. Used only to tell the operator, once, about a side file that is on
   disk but not in the YAML; such a file is never touched. */
static const char *const known_scripts[] = {
	"tinc-up", "tinc-down", "host-up", "host-down", "subnet-up", "subnet-down",
	"invitation-created", "invitation-accepted", NULL
};

/* Names this process has written into the runtime dir (kept across reloads
   so a key deleted from the YAML has its file removed, and only that one). */
static char **managed_scripts;
static size_t managed_count;

/* Side files already reported (see known_scripts). */
static char **noted_scripts;
static size_t noted_count;

static bool in_list(char **list, size_t n, const char *name) {
	for(size_t i = 0; i < n; i++) {
		if(!strcmp(list[i], name)) {
			return true;
		}
	}

	return false;
}

static void list_add(char ***list, size_t *n, const char *name) {
	if(in_list(*list, *n, name)) {
		return;
	}

	*list = xrealloc(*list, (*n + 1) * sizeof(**list));
	(*list)[(*n)++] = xstrdup(name);
}

static void list_del(char **list, size_t *n, const char *name) {
	for(size_t i = 0; i < *n; i++) {
		if(!strcmp(list[i], name)) {
			free(list[i]);
			memmove(list + i, list + i + 1, (*n - i - 1) * sizeof(*list));
			(*n)--;
			return;
		}
	}
}

static bool in_yaml(const char **names, const char *name) {
	for(size_t i = 0; names[i]; i++) {
		if(!strcmp(names[i], name)) {
			return true;
		}
	}

	return false;
}

/* A script name is a plain file name inside the runtime dir: no path
   separators, not hidden, not a temp name of ours. */
static bool script_name_ok(const char *name) {
	return *name && !strpbrk(name, "/\\") && name[0] != '.' && strlen(name) < 200;
}

/* Current content of <confbase>/<name>, or NULL. Caller frees. */
static char *script_read(const char *path) {
	FILE *f = fopen(path, "rb");

	if(!f) {
		return NULL;
	}

	size_t cap = 4096, len = 0;
	char *buf = xmalloc(cap);

	for(;;) {
		if(len + 1 >= cap) {
			cap *= 2;
			buf = xrealloc(buf, cap);
		}

		size_t rd = fread(buf + len, 1, cap - len - 1, f);
		len += rd;

		if(rd == 0) {
			break;
		}
	}

	fclose(f);
	buf[len] = 0;
	return buf;
}

/* Write `text` to <confbase>/<name> atomically: a temp file in the same
   directory, created executable-by-owner only (0700, fchmod after open so
   the umask cannot widen or narrow it), fsynced, then renamed over the
   target. A script that tincd is about to run is therefore never observed
   half-written, and a failed write leaves the previous file in place. */
static bool script_write(const char *path, const char *text) {
	char tmp[PATH_MAX];

	if((size_t)snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= sizeof(tmp)) {
		errno = ENAMETOOLONG;
		return false;
	}

#ifdef HAVE_WINDOWS
	FILE *f = fopen(tmp, "wb");
#else
	int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0700);
	FILE *f = fd >= 0 ? fdopen(fd, "wb") : NULL;

	if(!f && fd >= 0) {
		close(fd);
	}

	if(f) {
		fchmod(fd, 0700);
	}

#endif

	if(!f) {
		return false;
	}

	size_t len = strlen(text);
	bool ok = fwrite(text, 1, len, f) == len;

	if(ok && len && text[len - 1] != '\n') {
		ok = fputc('\n', f) != EOF;
	}

	ok = !fflush(f) && ok;
#ifndef HAVE_WINDOWS
	ok = !fsync(fileno(f)) && ok;
#endif
	ok = !fclose(f) && ok;

	if(!ok) {
		int saved = errno;
		unlink(tmp);
		errno = saved;
		return false;
	}

#ifdef HAVE_WINDOWS

	if(!MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
		unlink(tmp);
		return false;
	}

#else

	if(rename(tmp, path)) {
		int saved = errno;
		unlink(tmp);
		errno = saved;
		return false;
	}

#endif
	return true;
}

int zeroconf_sync_scripts(void) {
	if(!yamlconf_path || !yamlconf_global || !netname || !confbase) {
		return 0;
	}

	const char **names = yamlconf_script_names(yamlconf_global, netname);

	if(!names) {
		return 0;
	}

	int changed = 0;

	/* 1. Every scripts.<name> in the YAML is on disk with that content. */
	for(size_t i = 0; names[i]; i++) {
		const char *name = names[i];

		if(!script_name_ok(name)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Ignoring script with unsafe name `%s' in `%s'", name, yamlconf_path);
			continue;
		}

		char *text = yamlconf_script_text(yamlconf_global, netname, name);

		if(!text) {
			continue;
		}

		char path[PATH_MAX];

		if((size_t)snprintf(path, sizeof(path), "%s" SLASH "%s", confbase, name) >= sizeof(path)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Script name `%s' too long for `%s'", name, confbase);
			free(text);
			continue;
		}

		/* Same content already there (and ours or a side file with the same
		   text): only make sure the mode is right, do not churn the file. */
		char *have = script_read(path);
		size_t tlen = strlen(text);
		bool same = have && !strncmp(have, text, tlen) && (have[tlen] == 0 || (have[tlen] == '\n' && have[tlen + 1] == 0));
		free(have);

		if(same) {
#ifndef HAVE_WINDOWS
			chmod(path, 0700);
#endif
			list_add(&managed_scripts, &managed_count, name);
			free(text);
			continue;
		}

		if(!script_write(path, text)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not write script `%s' from `%s' into `%s': %s", name, yamlconf_path, confbase, strerror(errno));
			free(text);
			free(names);
			return -1;
		}

		logger(DEBUG_ALWAYS, LOG_INFO, "Wrote script `%s' from `%s' into `%s'", name, yamlconf_path, confbase);
		list_add(&managed_scripts, &managed_count, name);
		free(text);
		changed++;
	}

	/* 2. A script this process wrote earlier whose key is gone from the YAML
	   is removed: the YAML is the source of truth for what it put there. */
	for(size_t i = 0; i < managed_count;) {
		const char *name = managed_scripts[i];

		if(in_yaml(names, name)) {
			i++;
			continue;
		}

		char path[PATH_MAX];
		snprintf(path, sizeof(path), "%s" SLASH "%s", confbase, name);

		if(unlink(path) && errno != ENOENT) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not remove script `%s' (no longer in `%s'): %s", path, yamlconf_path, strerror(errno));
			i++;
			continue;
		}

		logger(DEBUG_ALWAYS, LOG_INFO, "Removed script `%s': no longer in `%s'", path, yamlconf_path);
		list_del(managed_scripts, &managed_count, name);
		changed++;
	}

	/* 3. A side file dropped in by hand (not from the YAML, not ours) is left
	   alone -- it still runs -- and mentioned once so nobody wonders why the
	   YAML does not describe what the node executes. */
	for(size_t i = 0; known_scripts[i]; i++) {
		const char *name = known_scripts[i];

		if(in_yaml(names, name) || in_list(managed_scripts, managed_count, name) || in_list(noted_scripts, noted_count, name)) {
			continue;
		}

		char path[PATH_MAX];
		snprintf(path, sizeof(path), "%s" SLASH "%s", confbase, name);

		if(!access(path, F_OK)) {
			logger(DEBUG_ALWAYS, LOG_NOTICE, "Script `%s' is a side file not described by `%s' (scripts.%s); it runs as is and is left alone", path, yamlconf_path, name);
			list_add(&noted_scripts, &noted_count, name);
		}
	}

	free(names);
	return changed;
}

/* ---- materialisation ----------------------------------------------------- */

static bool zeroconf_materialise_locked(bool reread);

bool zeroconf_materialise(bool reread) {
	if(!yamlconf_path) {
		return true;  /* classic confbase mode: nothing to do here */
	}

	if(!netname) {
		logger(DEBUG_ALWAYS, LOG_ERR, "YAML mode needs a network name (-n) to materialise defaults into `%s'", yamlconf_path);
		return false;
	}

	/* Read-modify-write of a file other writers (a CLI, a GUI, a second
	   daemon sharing it) may touch: hold the writers' lock from the
	   re-read to the save. */
	if(!yamlconf_lock(yamlconf_path)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not lock `%s': %s", yamlconf_path, strerror(errno));
		return false;
	}

	bool result = zeroconf_materialise_locked(reread);
	yamlconf_unlock();
	return result;
}

static bool zeroconf_materialise_locked(bool reread) {
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
	} else if(reread && !access(yamlconf_path, F_OK)) {
		/* Re-read under the lock so we start from what is on disk now
		   (the daemon's start path; a joiner has unsaved changes in memory
		   and re-reads before it applies them instead). */
		if(!yamlconf_reload_global()) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not re-read YAML config `%s'", yamlconf_path);
			return false;
		}

		yc = yamlconf_global;
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
	/* The compiled-in default accept list. Kept in sync with
	   transport_compiled_mask() in transport_table.c; hardcoded here because
	   zeroconf.c is in the common library, below the daemon transport code. */
#if defined(HAVE_OPENSSL) && defined(HAVE_QUIC)
	static const char *const default_transports = "plain, sf, obfs, https, quic";
#elif defined(HAVE_OPENSSL)
	static const char *const default_transports = "plain, sf, obfs, https";
#else
	static const char *const default_transports = "plain, sf, obfs";
#endif

	if(!host_text_has(host, "Transports", NULL)) {
		yamlconf_host_add_line(yc, netname, name, "Transports", default_transports);
		changed = true;
		NOTE("Transports=%s ", default_transports);
	}

	free(host);

#ifdef HAVE_OPENSSL

	/* --- TLS certificate (shared by the HTTPS front and QUIC; decision 1) ---
	   If neither TlsCert/TlsKey nor keys.tls_cert/tls_key is present, generate
	   a self-signed P-256 certificate and persist it, then advertise its
	   SHA-256 fingerprint in our own host record so it propagates through the
	   mesh and through invitations (M2), letting an invitee pin the inviter's
	   cert. The certificate uses a generic `localhost' subject on purpose (see
	   tls.c): a scanner must not be able to tie the port to this node. */
	const char *tls_cert_pem = yamlconf_key_pem(yc, netname, "tls_cert");
	const char *tls_key_pem = yamlconf_key_pem(yc, netname, "tls_key");
	char tls_fp_hex[TLS_FP_HEX_LEN] = "";

	if(!tls_cert_pem || !tls_key_pem) {
		char *cert = NULL, *key = NULL;

		if(!tls_generate_pem(TLS_DEFAULT_CN, &cert, &key)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "TLS certificate generation failed");
			free(name);
			yamlconf_free(fresh ? yc : NULL);
			return false;
		}

		yamlconf_set_key_pem(yc, netname, "tls_cert", cert);
		yamlconf_set_key_pem(yc, netname, "tls_key", key);
		tls_cert_pem_fingerprint(cert, tls_fp_hex);
		memzero(key, strlen(key));
		free(cert);
		free(key);
		changed = true;
		NOTE("tls_cert/tls_key ");
	} else {
		tls_cert_pem_fingerprint(tls_cert_pem, tls_fp_hex);
	}

	host = yamlconf_host_text(yc, netname, name);

	if(tls_fp_hex[0] && !host_text_has(host, "TlsFingerprint", NULL)) {
		yamlconf_host_add_line(yc, netname, name, "TlsFingerprint", tls_fp_hex);
		changed = true;
		NOTE("TlsFingerprint ");
	}

	free(host);

#endif

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

#undef NOTE
	return true;
}
