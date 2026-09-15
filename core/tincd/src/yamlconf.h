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

/* Return a readable, rewound FILE* holding `content`. Portable replacement for
   tmpfile() (which on Windows creates files in C:\, unwritable for non-admins):
   uses %TEMP% on Windows, tmpfile() on POSIX. Caller fclose()s it. */
FILE *yamlconf_content_fp(const char *content);

/* Parse a YAML config file. Returns NULL on error. */
yamlconf_t *yamlconf_load(const char *path);
void yamlconf_free(yamlconf_t *yc);

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
