/*
    autoif.h -- built-in interface addressing for YAML-mode nodes.

    In YAML mode a node knows its own address (its /32 Subnet, or an explicit
    InterfaceAddress) and the network prefix (AddressPool), so on platforms
    where the daemon cannot set the address itself (Linux tun) it can run the
    two commands a hand-written tinc-up would, when no tinc-up script exists.
    Windows sets the address through WintunAddress; Android hands in a
    pre-configured fd; both are untouched by this.
*/

#ifndef TINC_AUTOIF_H
#define TINC_AUTOIF_H

#include "system.h"

/* Bring `iface` up with the node's address and routes. Returns true if the
   platform has a built-in and it succeeded (or nothing had to be done). */
bool autoif_up(void);

#endif
