#ifndef TINC_DNSREFRESH_H
#define TINC_DNSREFRESH_H

/*
    dnsrefresh.h -- Watch Address = <hostname> entries and follow DNS changes

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "netutl.h"                    /* sockaddr_t */

/* Poll interval for DNS names in Address statements, in seconds. 0 disables
   the watcher. Re-read on reload. */
extern int dnsrefresh_interval;

/* Start the resolver thread and the standing timer. Safe to call when
   already started or disabled (no-op). Call after load_all_nodes(). */
extern void dnsrefresh_init(void);

/* Stop the worker and free the watch list. */
extern void dnsrefresh_exit(void);

/* Re-read interval / rebuild the watch list after a config reload. */
extern void dnsrefresh_reload(void);

/* The last address a watched name resolved to, or NULL. The dial walk may
   offer it as a candidate (below the live address cache, above re-reading
   the Address statement). */
extern const sockaddr_t *dnsrefresh_last_good(const char *node_name, const char *hostname);

#endif
