/*
    fuzz_yamlconf.c -- libFuzzer harness for yamlconf.c (security review R).

    Input = an arbitrary document. Properties checked, beyond "no crash":
      - whatever the parser accepts, the emitter writes back in a form the
        parser accepts again (our own output must load: the daemon overwrites
        the config with it);
      - emit(parse(emit(parse(x)))) == emit(parse(x)): one normalisation, then
        stable, so a save never drifts;
      - the mutation API and save/load on a real file do not crash and the
        saved file loads.
    Built by Makefile against src/yamlconf.c alone.

    This program is free software; see the GPL v2+ (same as the rest of tinc).
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include "yamlconf.h"

static char tmpdir[] = "/tmp/fuzz_yamlconf.XXXXXX";
static char path[256];

int LLVMFuzzerInitialize(int *argc, char ***argv) {
	(void)argc;
	(void)argv;

	if(!mkdtemp(tmpdir)) {
		abort();
	}

	snprintf(path, sizeof(path), "%s/tinc.yaml", tmpdir);
	return 0;
}

static void check(bool cond, const char *what) {
	if(!cond) {
		fprintf(stderr, "PROPERTY VIOLATED: %s\n", what);
		abort();
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	char *text = malloc(size + 1);
	memcpy(text, data, size);
	text[size] = 0;

	yamlconf_t *yc = yamlconf_parse(text);
	free(text);

	if(!yc) {
		return 0;
	}

	/* Round trip. */
	char *e1 = yamlconf_emit(yc);
	check(e1 != NULL, "parsed document does not emit");
	char *copy = strdup(e1);
	yamlconf_t *yc2 = yamlconf_parse(copy);
	free(copy);
	check(yc2 != NULL, "emitted document does not parse");
	char *e2 = yamlconf_emit(yc2);
	if(strcmp(e1, e2)) {
		fprintf(stderr, "--- first ---\n%s\n--- second ---\n%s\n", e1, e2);
	}

	check(!strcmp(e1, e2), "emit is not idempotent");
	free(e2);
	yamlconf_free(yc2);

	/* Read accessors on the first network. */
	const char *net = yamlconf_first_network(yc);

	if(net) {
		char *netcopy = strdup(net);
		char *opts = yamlconf_options_text(yc, netcopy);
		const char **hosts = yamlconf_host_names(yc, netcopy);

		for(size_t i = 0; hosts[i]; i++) {
			char *h = yamlconf_host_text(yc, netcopy, hosts[i]);
			free(h);
		}

		free(hosts);
		(void)yamlconf_key_pem(yc, netcopy, "ed25519_priv");
		(void)yamlconf_key_pem(yc, netcopy, "rsa_priv");
		(void)yamlconf_get_option(yc, netcopy, "Name");
		free(yamlconf_option_values(yc, netcopy, "ConnectTo"));
		const char **scripts = yamlconf_script_names(yc, netcopy);

		for(size_t i = 0; scripts[i]; i++) {
			free(yamlconf_script_text(yc, netcopy, scripts[i]));
		}

		free(scripts);

		/* Mutations: the options text must survive its own inverse. */
		if(opts) {
			yamlconf_set_options_text(yc, netcopy, opts);
			char *again = yamlconf_options_text(yc, netcopy);
			check(again != NULL, "options vanished after set_options_text");
			free(again);
		}

		free(opts);
		yamlconf_set_option(yc, netcopy, "Port", "0");
		yamlconf_add_option_value(yc, netcopy, "ConnectTo", "peer");
		yamlconf_add_option_value(yc, netcopy, "ConnectTo", "other");
		yamlconf_del_option(yc, netcopy, "Mode");
		yamlconf_host_add_line(yc, netcopy, "peer", "Ed25519PublicKey", "AAAA");
		yamlconf_host_add_line(yc, netcopy, "peer", "-----BEGIN RSA PUBLIC KEY-----\nQUJD\n-----END RSA PUBLIC KEY-----", NULL);
		yamlconf_host_set_text(yc, netcopy, "other", "Address = 1.2.3.4\n\n");
		yamlconf_host_del(yc, netcopy, "peer");
		yamlconf_set_key_pem(yc, netcopy, "ed25519_priv", "-----BEGIN X-----\nQUJD\n-----END X-----");
		free(netcopy);
	}

	/* Save to a real file, reload, and compare. */
	check(yamlconf_save(yc, path), "save failed");
	yamlconf_t *yc3 = yamlconf_load(path);
	check(yc3 != NULL, "saved file does not load");
	char *e3 = yamlconf_emit(yc3);
	char *e4 = yamlconf_emit(yc);
	check(e3 && e4, "document does not emit after mutation");
	if(strcmp(e3, e4)) {
		fprintf(stderr, "--- memory ---\n%s\n--- file ---\n%s\n", e4, e3);
	}

	check(!strcmp(e3, e4), "saved file differs from memory");
	free(e3);
	free(e4);
	yamlconf_free(yc3);

	if(net) {
		check(yamlconf_append_host_line(path, "n", "h", "Subnet", "10.0.0.1/32"), "append_host_line failed");
	}

	free(e1);
	yamlconf_free(yc);
	return 0;
}
