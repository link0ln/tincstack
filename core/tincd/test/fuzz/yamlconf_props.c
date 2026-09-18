/*
    yamlconf_props.c -- regression tests for the yamlconf.c parser/emitter
    properties established by security review R (2026-09-16). Each case is a
    behaviour the daemon relies on when it writes the config back:

      1. a document with an unplaceable line is refused, not truncated
         (before: the tail after a misindented line was silently dropped and
         the next save deleted it -- host records and keys included);
      2. duplicate keys: the last one wins, as in PyYAML (the Windows GUI),
         so both readers see the same value;
      3. nesting is bounded (no unbounded recursion on a hostile file);
      4. scalars that look like YAML syntax ('[a', '|', '"x', '#c', ' pad ')
         round-trip through emit/parse unchanged;
      5. a block scalar whose first line is indented round-trips unchanged;
      6. empty maps/sequences round-trip as maps/sequences;
      7. the options-text inverse (tinc set path) round-trips;
      8. "---" / "%YAML" markers are accepted, a bare scalar document is not;
      9. a key the parser would refuse (a 300-byte node name) makes emit()
         return NULL and save() fail instead of writing an unloadable file
         (found by fuzz_invitation: the inviter chooses the invitee's Name);
     10. the scripts: block (stream S, 2026-09-16): a literal-block script
         with a shebang, `#` comment lines, blank lines, indented bodies and
         a trailing-space line is listed by yamlconf_script_names(), read
         back byte-for-byte by yamlconf_script_text(), survives
         emit -> parse unchanged, and a `scripts:` map with a non-scalar
         entry lists only the scalar ones;
     11. a block sequence whose dashes sit at the key's own indentation
         (valid YAML, PyYAML's default output, so what the Windows GUI
         wrote) parses and means the same as the indented form, while a
         dash after a key that already has a scalar value stays refused.

    Built and run by `make props` / run.sh check (plain C, ASan+UBSan).

    This program is free software; see the GPL v2+ (same as the rest of tinc).
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "yamlconf.h"

static int failures;

#define CHECK(cond) do { if(!(cond)) { failures++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while(0)

static yamlconf_t *parse(const char *text) {
	char *copy = strdup(text);
	yamlconf_t *yc = yamlconf_parse(copy);
	free(copy);
	return yc;
}

/* Does x parse? (frees the document) */
static bool parses(const char *text) {
	yamlconf_t *yc = parse(text);
	yamlconf_free(yc);
	return yc != NULL;
}

/* emit(parse(x)) as a string, or NULL if x does not parse. */
static char *normalise(const char *text) {
	yamlconf_t *yc = parse(text);

	if(!yc) {
		return NULL;
	}

	char *e = yamlconf_emit(yc);
	yamlconf_free(yc);
	return e;
}

static bool roundtrip_option(const char *value) {
	yamlconf_t *yc = yamlconf_new();
	yamlconf_set_option(yc, "n", "K", value);
	char *e = yamlconf_emit(yc);
	yamlconf_free(yc);
	yamlconf_t *yc2 = parse(e);
	free(e);

	if(!yc2) {
		return false;
	}

	const char *back = yamlconf_get_option(yc2, "n", "K");
	bool same = back && !strcmp(back, value);
	yamlconf_free(yc2);
	return same;
}

int main(void) {
	/* 1. strict: unplaceable tail refused */
	CHECK(!parses("networks:\n  net:\n    options:\n      Name: a\n   weird: 1\n    hosts:\n      a: |\n        Subnet = 1.2.3.4/32\n"));
	CHECK(!parses("networks:\n  net:\n    options:\n      Name: a\n      garbage line without colon\n"));
	CHECK(parses("networks:\n  net:\n    options:\n      Name: a\n"));

	/* 2. duplicate keys: last wins */
	{
		yamlconf_t *yc = parse("networks:\n  net:\n    options:\n      Name: first\n      Name: second\n");
		CHECK(yc && !strcmp(yamlconf_get_option(yc, "net", "Name"), "second"));
		char *e = yamlconf_emit(yc);
		CHECK(strstr(e, "first") == NULL);
		free(e);
		yamlconf_free(yc);
	}

	/* 3. bounded nesting */
	{
		char deep[100 * 110];
		size_t len = 0;

		for(int i = 0; i < 100; i++) {
			for(int j = 0; j < i; j++) {
				deep[len++] = ' ';
			}

			len += (size_t)sprintf(deep + len, "k%d:\n", i);
		}

		deep[len] = 0;
		CHECK(!parses(deep));
	}

	/* 4. syntax-looking scalars round-trip */
	CHECK(roundtrip_option("[a, b]"));
	CHECK(roundtrip_option("|"));
	CHECK(roundtrip_option("\"quoted\""));
	CHECK(roundtrip_option("'single'"));
	CHECK(roundtrip_option("#comment"));
	CHECK(roundtrip_option(" padded "));
	CHECK(roundtrip_option("a: b"));
	CHECK(roundtrip_option("tab\there"));
	CHECK(roundtrip_option("-1"));
	CHECK(roundtrip_option("- item"));
	CHECK(roundtrip_option("line1\nline2 \n"));
	CHECK(roundtrip_option("\x01\x7f"));

	/* 5. block scalar with an indented first line */
	{
		yamlconf_t *yc = yamlconf_new();
		yamlconf_host_set_text(yc, "n", "h", "  indented first\nplain second");
		char *e = yamlconf_emit(yc);
		yamlconf_free(yc);
		yamlconf_t *yc2 = parse(e);
		free(e);
		char *t = yc2 ? yamlconf_host_text(yc2, "n", "h") : NULL;
		CHECK(t && !strcmp(t, "  indented first\nplain second"));
		free(t);
		yamlconf_free(yc2);
	}

	/* 6. empty containers keep their type */
	{
		char *e = normalise("networks:\n  net:\n    hosts: {}\n    options:\n      ConnectTo: []\n");
		CHECK(e && strstr(e, "hosts: {}") && strstr(e, "ConnectTo: []"));
		free(e);
	}

	/* 7. options text inverse */
	{
		yamlconf_t *yc = parse("networks:\n  net:\n    options:\n      Name: a\n      ConnectTo: [b, c]\n      Port: 0\n");
		char *opts = yamlconf_options_text(yc, "net");
		CHECK(opts && !strcmp(opts, "Name = a\nConnectTo = b\nConnectTo = c\nPort = 0\n"));
		yamlconf_set_options_text(yc, "net", opts);
		char *again = yamlconf_options_text(yc, "net");
		CHECK(again && !strcmp(again, opts));
		free(opts);
		free(again);
		yamlconf_free(yc);
	}

	/* 8. markers ok, bare scalar document refused, emit is idempotent */
	CHECK(parses("%YAML 1.1\n---\nnetworks:\n  net:\n    options:\n      Name: a\n...\n"));
	CHECK(!parses("just a scalar\n"));
	{
		char *e1 = normalise("networks:\n  net:\n    options:\n      Name: a\n      X: \"a\\nb\"\n    hosts:\n      h: |\n        A = 1\n\n        B = 2\n");
		char *e2 = e1 ? normalise(e1) : NULL;
		CHECK(e1 && e2 && !strcmp(e1, e2));
		free(e1);
		free(e2);
	}

	/* 9. never write what the parser would refuse */
	{
		char longname[301];
		memset(longname, 'a', 300);
		longname[300] = 0;
		yamlconf_t *yc = yamlconf_new();
		yamlconf_set_option(yc, "n", "Name", "me");
		yamlconf_host_set_text(yc, "n", longname, "Address = 1.2.3.4");
		CHECK(yamlconf_emit(yc) == NULL);
		CHECK(!yamlconf_save(yc, "/dev/null"));
		yamlconf_host_del(yc, "n", longname);
		char *e = yamlconf_emit(yc);
		CHECK(e != NULL);
		free(e);
		yamlconf_free(yc);
	}

	/* 10. scripts block round-trip */
	{
		const char *doc =
		    "networks:\n"
		    "  net:\n"
		    "    options:\n"
		    "      Name: a\n"
		    "    scripts:\n"
		    "      host-up: |\n"
		    "        #!/bin/sh\n"
		    "        # comment: with a colon\n"
		    "\n"
		    "        if [ -n \"$NODE\" ]; then\n"
		    "            touch \"/run/marker-$NODE\"   # trailing comment\n"
		    "        fi\n"
		    "      tinc-up: |\n"
		    "        ip link set \"$INTERFACE\" up\n"
		    "      odd:\n"
		    "        nested: map\n";
		const char *host_up =
		    "#!/bin/sh\n"
		    "# comment: with a colon\n"
		    "\n"
		    "if [ -n \"$NODE\" ]; then\n"
		    "    touch \"/run/marker-$NODE\"   # trailing comment\n"
		    "fi";
		yamlconf_t *yc = parse(doc);
		CHECK(yc != NULL);

		if(yc) {
			const char **names = yamlconf_script_names(yc, "net");
			CHECK(names && names[0] && names[1] && !names[2]);   /* odd: (a map) is not a script */
			CHECK(names && names[0] && !strcmp(names[0], "host-up"));
			CHECK(names && names[1] && !strcmp(names[1], "tinc-up"));
			free(names);
			char *t = yamlconf_script_text(yc, "net", "host-up");
			CHECK(t && !strcmp(t, host_up));
			free(t);
			CHECK(yamlconf_script_text(yc, "net", "odd") == NULL);
			CHECK(yamlconf_script_text(yc, "net", "missing") == NULL);

			/* emit -> parse keeps the script byte for byte; emit is stable */
			char *e1 = yamlconf_emit(yc);
			yamlconf_t *yc2 = e1 ? parse(e1) : NULL;
			CHECK(yc2 != NULL);
			char *t2 = yc2 ? yamlconf_script_text(yc2, "net", "host-up") : NULL;
			CHECK(t2 && !strcmp(t2, host_up));
			char *e2 = yc2 ? yamlconf_emit(yc2) : NULL;
			CHECK(e1 && e2 && !strcmp(e1, e2));
			free(t2);
			free(e2);
			free(e1);
			yamlconf_free(yc2);
			yamlconf_free(yc);
		}

		/* A script line with trailing blanks or a tab cannot be a literal
		   block (the parser would trim it); it must still read back exactly
		   (the emitter falls back to a double-quoted scalar). */
		{
			char *e = normalise("networks:\n  net:\n    scripts:\n      tinc-up: \"a \\n\\tb\\n\"\n");
			yamlconf_t *yc3 = e ? parse(e) : NULL;
			char *t3 = yc3 ? yamlconf_script_text(yc3, "net", "tinc-up") : NULL;
			CHECK(t3 && !strcmp(t3, "a \n\tb\n"));
			free(t3);
			free(e);
			yamlconf_free(yc3);
		}
	}

	/* 11. A block sequence written with its dashes at the key's own
	      indentation -- valid YAML, and what PyYAML (the Windows GUI)
	      emits by default -- parses, and means exactly what the indented
	      form means. Before this, every config the GUI saved with a list
	      in it was refused by the daemon at the next start. A dash that
	      follows a key which already has a scalar value is still an
	      unplaceable line and must stay refused. */
	{
		const char *flat =
		        "networks:\n  net:\n    options:\n      PreferredTransports:\n"
		        "      - quic\n      - https\n      Mode: router\n";
		const char *nested =
		        "networks:\n  net:\n    options:\n      PreferredTransports:\n"
		        "        - quic\n        - https\n      Mode: router\n";
		char *ef = normalise(flat);
		char *en = normalise(nested);
		CHECK(ef && en && !strcmp(ef, en));
		free(ef);
		free(en);

		CHECK(!parses("networks:\n  net:\n    options:\n      Mode: router\n      - quic\n"));
	}

	if(failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}

	printf("yamlconf_props: all checks passed\n");
	return 0;
}
