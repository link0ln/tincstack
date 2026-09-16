/*
    yamlconf.h -- read/write tinc configuration from a single YAML file.

    In YAML mode the daemon and CLI do not use the classic confbase tree
    (tinc.conf + hosts/<name> + *_key.priv). Instead one YAML file holds every
    network; tinc reads the section for the current netname and writes learned
    state (e.g. a peer's Ed25519 public key) straight back into it.

    Schema (canonical, as emitted here and by tincmgr):

        networks:
          <netname>:
            options:            # -> tinc.conf lines (scalar=one line, list=many)
              Name: ...
              ConnectTo: [a, b]
            keys:
              ed25519_priv: |   # PEM
              rsa_priv: |
            hosts:
              <node>: |         # host-file text
*/

#ifndef TINC_YAMLCONF_H
#define TINC_YAMLCONF_H

#include <stdbool.h>
#include <stdio.h>

typedef struct yamlconf yamlconf_t;

/* YAML mode state, set by make_names() when -c points at a *.yaml file.
   yamlconf_path is the file (NULL = classic confbase mode); yamlconf_global is
   the parsed config. The current network is the global `netname` (names.h). */
extern char *yamlconf_path;
extern yamlconf_t *yamlconf_global;

/* True if `path` looks like a YAML config file (ends in .yaml/.yml). */
bool yamlconf_is_yaml_path(const char *path);

/* Return a readable, rewound FILE* holding `content` (config text or a
   private-key PEM). Portable replacement for tmpfile(), which on Windows
   creates files in C:\, unwritable for non-admins: POSIX uses tmpfile()
   (0600, unlinked at once); Windows creates a delete-on-close temporary
   next to the config file (the directory that already holds the keys) with
   an ACL for the calling user and SYSTEM only -- never in %TEMP% (security
   review R-13). Caller fclose()s it. */
FILE *yamlconf_content_fp(const char *content);

/* Parse a YAML config file. Returns NULL on error (unreadable, larger than
   64 MiB, a parse error, or not a mapping). An empty or comment-only file
   parses to an empty document. The parser is strict: a line it cannot place
   in the tree, an empty or over-long (>255) key, or nesting deeper than 64
   levels is an error, never silently dropped -- the file is written back by
   the daemon, so dropped lines would be lost on the next save. Duplicate
   keys in one mapping: the last one wins (as in PyYAML). */
yamlconf_t *yamlconf_load(const char *path);
void yamlconf_free(yamlconf_t *yc);

/* Same parser on an in-memory document (modified in place); NULL on error. */
yamlconf_t *yamlconf_parse(char *text);

/* Serialise the document exactly as yamlconf_save() would write it. Caller
   frees. Scalars that would not read back verbatim are double-quoted.
   Returns NULL (and yamlconf_save() fails with EINVAL) if the document holds
   a mapping key the parser would refuse -- empty or longer than 255 bytes --
   so that a document which would not load is never written. */
char *yamlconf_emit(yamlconf_t *yc);

/* Serialise writers on `<path>.lock` (stable inode; the config file itself
   is replaced by every save). Re-entrant within a process. yamlconf_save()
   and yamlconf_append_host_line() lock on their own; a caller doing a
   read-modify-write of its own should hold the lock across the whole
   sequence. */
bool yamlconf_lock(const char *path);
void yamlconf_unlock(void);

/* An empty document (no networks). */
yamlconf_t *yamlconf_new(void);

/* Name of the first network in the document, or NULL if there is none.
   Owned by yc. */
const char *yamlconf_first_network(yamlconf_t *yc);
bool yamlconf_has_network(yamlconf_t *yc, const char *net);

/* Remove networks.<net> entirely. Returns true if it existed. */
bool yamlconf_del_network(yamlconf_t *yc, const char *net);

/* ---- in-memory mutation (call yamlconf_save() to persist) ---------------- */

/* Scalar option networks.<net>.options.<key>, or NULL if absent / not a
   scalar. Owned by yc. */
const char *yamlconf_get_option(yamlconf_t *yc, const char *net, const char *key);

/* True if networks.<net>.options.<key> is present (scalar or list). */
bool yamlconf_has_option(yamlconf_t *yc, const char *net, const char *key);

/* Set networks.<net>.options.<key> to a scalar, creating the path as needed
   and replacing any existing value (scalar or list). */
void yamlconf_set_option(yamlconf_t *yc, const char *net, const char *key, const char *value);

/* Set networks.<net>.keys.<which> ("ed25519_priv" | "rsa_priv") to a PEM. */
void yamlconf_set_key_pem(yamlconf_t *yc, const char *net, const char *which, const char *pem);

/* Every value of networks.<net>.options.<key> as a NULL-terminated array (a
   scalar yields one entry, a list its items, in order). NULL if the option is
   absent. Caller frees the array only; the strings are owned by yc. */
const char **yamlconf_option_values(yamlconf_t *yc, const char *net, const char *key);

/* Add one more value to networks.<net>.options.<key>: an absent option becomes
   a scalar, a scalar becomes a two-item list, a list grows by one. A value
   already present is not duplicated. */
void yamlconf_add_option_value(yamlconf_t *yc, const char *net, const char *key, const char *value);

/* Remove networks.<net>.options.<key> entirely. Returns true if it existed. */
bool yamlconf_del_option(yamlconf_t *yc, const char *net, const char *key);

/* Replace networks.<net>.options wholesale from tinc.conf-style text
   ("Key = value" lines; a key that repeats becomes a list, in file order).
   Blank and '#' lines are dropped. This is the inverse of
   yamlconf_options_text() and what the CLI's set/add/del use. */
void yamlconf_set_options_text(yamlconf_t *yc, const char *net, const char *text);

/* True if networks.<net>.hosts.<name> exists. */
bool yamlconf_has_host(yamlconf_t *yc, const char *net, const char *name);

/* Replace the whole host-file text of networks.<net>.hosts.<name>, creating
   the entry if needed. Trailing newlines are stripped. */
void yamlconf_host_set_text(yamlconf_t *yc, const char *net, const char *name, const char *text);

/* Remove networks.<net>.hosts.<name>. Returns true if it existed. */
bool yamlconf_host_del(yamlconf_t *yc, const char *net, const char *name);

/* NULL-terminated array of script names under networks.<net>.scripts (caller
   frees the array only), and a script's text (caller frees) or NULL. */
const char **yamlconf_script_names(yamlconf_t *yc, const char *net);
char *yamlconf_script_text(yamlconf_t *yc, const char *net, const char *name);

/* Re-read yamlconf_path from disk into yamlconf_global. On a parse error the
   previous document is kept and false is returned. No-op (true) outside YAML
   mode. The daemon calls this on every (re)load of its configuration. */
bool yamlconf_reload_global(void);

/* Append one host-file line ("key = value", or raw text if value is NULL)
   to networks.<net>.hosts.<name>, creating the host entry if needed. */
void yamlconf_host_add_line(yamlconf_t *yc, const char *net, const char *name,
                            const char *key, const char *value);

/* Write the document to `path` atomically (temp file + rename) under the
   writers' lock. The file is created mode 0600 since it holds private keys.
   Returns true on success; false (errno EINVAL) if the document cannot be
   emitted, see yamlconf_emit(). */
bool yamlconf_save(yamlconf_t *yc, const char *path);

/* Newly-allocated tinc.conf-equivalent text for `net` (caller frees), or NULL.
   Bools become yes/no; list options expand to one line each. */
char *yamlconf_options_text(yamlconf_t *yc, const char *net);

/* Newly-allocated host-file text for net/name (caller frees), or NULL. */
char *yamlconf_host_text(yamlconf_t *yc, const char *net, const char *name);

/* Private-key PEM for net ("ed25519_priv" | "rsa_priv"), or NULL (owned by yc). */
const char *yamlconf_key_pem(yamlconf_t *yc, const char *net, const char *which);

/* NULL-terminated array of host names for net (caller frees the array only). */
const char **yamlconf_host_names(yamlconf_t *yc, const char *net);

/* Read-modify-write the file (under an exclusive lock): append "key = value"
   to networks.<net>.hosts.<name>, creating the host entry if needed. This is
   what the daemon uses to persist a learned peer key. Returns true on success. */
bool yamlconf_append_host_line(const char *path, const char *net,
                               const char *name, const char *key, const char *value);

#endif
