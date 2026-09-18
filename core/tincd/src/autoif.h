/*
    autoif.h -- built-in interface addressing for YAML-mode nodes.

    In YAML mode a node knows its own address (its /32 Subnet, or an explicit
    InterfaceAddress) and the network prefix (AddressPool), so on platforms
    where the daemon cannot set the address itself (Linux tun) it can run the
    two commands a hand-written tinc-up would, when no tinc-up script exists.
    Windows creates and addresses the Wintun adapter itself, from
    WintunAddress or, failing that, from the same Subnet + AddressPool pair
    this file uses; Android hands in a pre-configured fd.
*/

#ifndef TINC_AUTOIF_H
#define TINC_AUTOIF_H

#include "system.h"

/* Bring `iface` up with the node's address and routes. Returns true if the
   platform has a built-in and it succeeded (or nothing had to be done). */
bool autoif_up(void);

/* The node's own address as "A.B.C.D/prefix": InterfaceAddress if set, else
   the first IPv4 /32 Subnet carried at the AddressPool's prefix length.
   Caller frees; NULL when neither is known. */
char *autoif_own_address(void);

#endif
