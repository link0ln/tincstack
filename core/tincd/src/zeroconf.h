/*
    zeroconf.h -- materialise a working configuration into an empty YAML file.

    In YAML mode the daemon must start against an empty or absent config and
    become invite-ready with no manual editing (ARCHITECTURE.md principle 2).
    zeroconf_materialise() fills in whatever is missing for the current
    network: Name, Mode, Port (655 for a founding node, 0 for one that dials
    out via ConnectTo), AddressPool, the node's own Subnet, and the
    Ed25519 (and legacy RSA) key pairs, then writes the file back.
*/

#ifndef TINC_ZEROCONF_H
#define TINC_ZEROCONF_H

#include "system.h"

/* No-op in classic confbase mode. In YAML mode: ensure networks.<netname>
   holds everything the daemon needs, generating keys and defaults for any
   missing field, and persist the result. Requires random_init() and
   crypto_init() to have run. Returns false if the config cannot be made
   usable (unparsable existing file, unwritable path, key generation failure). */
bool zeroconf_materialise(void);

/* Parse an IPv4 pool "a.b.c.d/n" (n in 8..30) into its host-order network
   address and prefix length. Returns false if the string is not such a pool. */
bool zeroconf_pool_parse(const char *pool, uint32_t *network, int *prefix);

/* Compute the first host address of an IPv4 pool ("a.b.c.d/n") as "x.y.z.w/32".
   Returns false if the pool is not a valid IPv4 prefix of 8..30 bits. */
bool zeroconf_pool_first_host(const char *pool, char *out, size_t outlen);

/* Write every networks.<netname>.scripts.<name> to <confbase>/<name>
   (mode 0700), so the daemon runs the scripts embedded in the YAML. Scripts
   are rewritten on every start: the YAML is the source of truth. Returns
   the number of scripts written, -1 on error. No-op outside YAML mode. */
int zeroconf_materialise_scripts(void);

/* Pick a default pool for a brand-new network: 10.<random 1..254>.0.0/24. */
void zeroconf_default_pool(char *out, size_t outlen);

/* Hostname-derived node name sanitised to tinc's [A-Za-z0-9_] alphabet;
   falls back to "node_<random>" if the hostname is unusable. Caller frees. */
char *zeroconf_default_name(void);

#endif
