/* throwaway unit test for yamlconf.c — compile with: gcc -Isrc -o yctest yamlconf_test.c src/yamlconf.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "yamlconf.h"

static void firstline(const char *s, char *out, size_t n) {
	size_t i = 0;
	while(s[i] && s[i] != '\n' && i < n - 1) { out[i] = s[i]; i++; }
	out[i] = 0;
}

static void dump(yamlconf_t *yc, const char *net) {
	printf("===== %s =====\n", net);
	char *opt = yamlconf_options_text(yc, net);
	printf("--- options ---\n%s", opt ? opt : "(none)\n");
	free(opt);
	const char **hn = yamlconf_host_names(yc, net);
	printf("--- hosts (%d) ---\n", (int)({ int c = 0; while(hn[c]) c++; c; }));
	for(int j = 0; hn[j]; j++) printf("  %s\n", hn[j]);
	if(hn[0]) {
		char *ht = yamlconf_host_text(yc, net, hn[0]);
		printf("--- host[%s] ---\n%s\n", hn[0], ht ? ht : "(null)");
		free(ht);
	}
	free(hn);
	const char *which[] = { "ed25519_priv", "rsa_priv" };
	for(int k = 0; k < 2; k++) {
		const char *pem = yamlconf_key_pem(yc, net, which[k]);
		if(pem) {
			char fl[80]; firstline(pem, fl, sizeof(fl));
			printf("  key %-13s len=%zu  firstline=%s\n", which[k], strlen(pem), fl);
		} else printf("  key %-13s ABSENT\n", which[k]);
	}
}

int main(int argc, char **argv) {
	const char *path = argc > 1 ? argv[1] : "tinc.yaml";
	yamlconf_t *yc = yamlconf_load(path);
	if(!yc) { printf("LOAD FAILED: %s\n", path); return 1; }
	dump(yc, "gnet");
	dump(yc, "gnet2");

	/* regression: double-quoted host scalar (trailing-space lines) must unescape */
	char *vr = yamlconf_host_text(yc, "gnet", "vpnmaster_ru");
	printf("\n##### gnet/vpnmaster_ru host_text #####\n%s\n", vr ? vr : "(null)");
	printf("=> contains 'Address = 141.105.68.202': %s\n",
	       (vr && strstr(vr, "Address = 141.105.68.202")) ? "YES" : "NO");
	free(vr);

	yamlconf_free(yc);

	if(argc > 2 && !strcmp(argv[2], "append")) {
		printf("\n##### append-host round-trip on %s #####\n", path);
		bool ok = yamlconf_append_host_line(path, "gnet2", "newpeer",
		                                    "Ed25519PublicKey", "TESTKEY123abc");
		printf("append_host_line: %s\n", ok ? "OK" : "FAIL");
		yamlconf_t *yc2 = yamlconf_load(path);
		if(!yc2) { printf("RELOAD FAILED\n"); return 1; }
		const char **hn = yamlconf_host_names(yc2, "gnet2");
		int found = 0;
		for(int j = 0; hn[j]; j++) if(!strcmp(hn[j], "newpeer")) found = 1;
		printf("newpeer present after reload: %s\n", found ? "YES" : "NO");
		char *ht = yamlconf_host_text(yc2, "gnet2", "newpeer");
		printf("newpeer text: [%s]\n", ht ? ht : "(null)");
		/* ensure existing host + options survived the rewrite */
		char *opt = yamlconf_options_text(yc2, "gnet2");
		printf("gnet2 still has Name? %s\n", (opt && strstr(opt, "Name = gnet2book")) ? "YES" : "NO");
		char *gw = yamlconf_host_text(yc2, "gnet2", "gnet2gway");
		printf("gnet2gway host survived? %s\n", gw ? "YES" : "NO");
		free(ht); free(opt); free(gw); free(hn);
		yamlconf_free(yc2);
	}
	return 0;
}
