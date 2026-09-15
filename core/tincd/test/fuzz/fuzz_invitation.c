/*
    fuzz_invitation.c -- libFuzzer harness for the two invitation parsers in
    invitation.c that sit on a trust boundary:

      first byte 0x00: invitation_url_parse() on the rest (what a user pastes);
      otherwise:       invitation_yaml_apply() on the rest, the payload the
                       INVITER sends to the invitee (bit0 of the first byte =
                       --force). The document it produces must then load
                       again (emit -> parse), because the join writes it to
                       the invitee's tinc.yaml and the daemon reads it back.

    Links the real libtinc.a / libcommon.a (invitation.c, yamlconf.c, utils.c)
    plus tincctl.c with its main() renamed (variables[] lives there).

    This program is free software; see the GPL v2+ (same as the rest of tinc).
*/

#include "system.h"
#include "invitation.h"
#include "yamlconf.h"

static FILE *report;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
	(void)argc;
	(void)argv;
	/* invitation_yaml_apply() reports every ignored line on stderr; send
	   that to /dev/null while the sanitizer keeps writing to the real fd 2. */
	report = fdopen(dup(2), "w");
	setvbuf(report, NULL, _IONBF, 0);   /* abort() must not lose the message */
	stderr = fopen("/dev/null", "w");
	return 0;
}

static void check(bool cond, const char *what) {
	if(!cond) {
		fprintf(report, "PROPERTY VIOLATED: %s\n", what);
		abort();
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if(!size) {
		return 0;
	}

	char *text = malloc(size);
	memcpy(text, data + 1, size - 1);
	text[size - 1] = 0;

	if(data[0] == 0) {
		char *address, *port;
		uint8_t hash[18], cookie[18];

		if(invitation_url_parse(text, &address, &port, hash, cookie)) {
			check(*address != 0, "empty address accepted");
			check(*port != 0, "empty port accepted");
		}

		free(text);
		return 0;
	}

	yamlconf_t *yc = yamlconf_new();
	bool ok = invitation_yaml_apply(yc, "net", "me", text, data[0] & 1);
	free(text);

	if(ok) {
		char *e1 = yamlconf_emit(yc);
		check(e1 != NULL, "document produced by join does not emit");
		yamlconf_t *yc2 = yamlconf_parse(e1);
		check(yc2 != NULL, "document written by join does not load");
		char *opts = yamlconf_options_text(yc2, "net");
		check(opts != NULL, "options lost");
		free(opts);
		yamlconf_free(yc2);
		free(e1);
	}

	yamlconf_free(yc);
	return 0;
}
