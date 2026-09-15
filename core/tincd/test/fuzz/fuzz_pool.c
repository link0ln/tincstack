/*
    fuzz_pool.c -- libFuzzer harness for the address-pool code:
    zeroconf_pool_parse() / zeroconf_pool_first_host() (zeroconf.c) and
    pool_allocate() (pool.c), which parses pending-invitation files and host
    records ("Subnet = ..." lines) from disk.

    Input layout: line 1 = the AddressPool string; the rest is written both as
    a pending invitation file (<runtime>/invitations/<24 chars>) and as the
    text of a host record in the in-memory YAML, then pool_allocate() runs
    against them. No daemon is running, so the live-subnet dump is skipped.

    This program is free software; see the GPL v2+ (same as the rest of tinc).
*/

#include "system.h"
#include "names.h"
#include "pool.h"
#include "yamlconf.h"
#include "zeroconf.h"

static char tmpdir[] = "/tmp/fuzz_pool.XXXXXX";
static char invdir[512];
static char invfile[512];

int LLVMFuzzerInitialize(int *argc, char ***argv) {
	(void)argc;
	(void)argv;

	if(!mkdtemp(tmpdir)) {
		abort();
	}

	snprintf(invdir, sizeof(invdir), "%s/invitations", tmpdir);
	mkdir(invdir, 0700);
	snprintf(invfile, sizeof(invfile), "%s/AAAAAAAAAAAAAAAAAAAAAAAA", invdir);
	confbase = strdup(tmpdir);
	netname = strdup("net");
	char pid[600];
	snprintf(pid, sizeof(pid), "%s/pid", tmpdir);
	pidfilename = strdup(pid);
	/* The code under test reports on stderr for every odd line; send that
	   to /dev/null while the sanitizer keeps writing to the real fd 2. */
	stderr = fopen("/dev/null", "w");
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	char *text = malloc(size + 1);
	memcpy(text, data, size);
	text[size] = 0;

	char *nl = strchr(text, '\n');
	const char *rest = "";

	if(nl) {
		*nl = 0;
		rest = nl + 1;
	}

	uint32_t network;
	int prefix;
	char first[64];

	if(zeroconf_pool_parse(text, &network, &prefix)) {
		if(prefix < 8 || prefix > 30) {
			abort();
		}

		if(!zeroconf_pool_first_host(text, first, sizeof(first))) {
			abort();
		}
	}

	FILE *f = fopen(invfile, "w");

	if(f) {
		fputs(rest, f);
		fclose(f);
	}

	yamlconf_free(yamlconf_global);
	yamlconf_global = yamlconf_new();
	yamlconf_host_set_text(yamlconf_global, netname, "me", rest);
	yamlconf_host_add_line(yamlconf_global, netname, "peer", "Subnet", "10.1.0.2/32");

	char *addr = pool_allocate(*text ? text : "10.1.0.0/24");
	free(addr);
	free(text);
	return 0;
}
