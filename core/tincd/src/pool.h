/*
    pool.h -- assign invitee addresses from AddressPool.

    The inviter hands every invitee the lowest free IPv4 address of its
    AddressPool. "Free" means: not the pool's network or broadcast address,
    not covered by any Subnet in the host database (own record included),
    not promised by a pending invitation in <confbase>/invitations, and not
    announced by a live node (asked from the running daemon over the control
    socket). ARCHITECTURE.md section 7.
*/

#ifndef TINC_POOL_H
#define TINC_POOL_H

#include "system.h"

/* Parse "a.b.c.d/n" (n in 8..30) into a host-order network address and its
   prefix length. Returns false if the string is not such a pool. */
bool pool_parse(const char *pool, uint32_t *network, int *prefix);

/* Lowest free host address in `pool` as a newly-allocated "a.b.c.d" string
   (no prefix), or NULL with a message on stderr when the pool is exhausted.
   Consults the host database, pending invitations and, if a daemon is
   running, its live subnet table; an address held by a live node is never
   handed out even when it is absent from the host database. */
char *pool_allocate(const char *pool);

#endif
