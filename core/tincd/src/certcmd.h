#ifndef TINC_CERTCMD_H
#define TINC_CERTCMD_H

/*
    certcmd.h -- `tinc cert': show, check and obtain the node's TLS certificate.

    This program is free software; see the GPL v2+ (same as the rest of tinc).
*/

/* Entry point for the `cert' command in tincctl.c's table. Returns an exit
   status: 0 when the requested action succeeded. */
int cert_command(int argc, char *argv[]);

#endif
