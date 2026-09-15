#ifndef TINC_DECOY_H
#define TINC_DECOY_H

/*
    decoy.h -- the HTTPS/HTTP decoy served to anything that reaches the listen
               port without authenticating as a tinc peer.

    This is the active-probing resistance (REALITY-analogue, PLAN M5, decision
    1): a prober -- over plain HTTP, or inside a completed TLS handshake with
    the node's certificate but without a valid tinc authenticator -- is served
    a plausible web page, or is transparently proxied to a real upstream site.
    It never reveals that a VPN is here; no response path contains a tinc
    string. It needs no configuration to work (a default page ships).

    Config (docs/config-schema.md):
      HttpsDecoyRoot      static files served to probers (a default page if unset)
      HttpsDecoyUpstream  host:port -- transparently proxy probers here instead

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
*/

#include "system.h"

/* Read HttpsDecoyRoot / HttpsDecoyUpstream from the config. Safe to call on
   every (re)load. */
void decoy_read_config(void);
void decoy_exit(void);

/* Build the decoy response for a client whose full request head (up to and
   including the blank line) is `request` (`reqlen` bytes). Returns a
   newly-allocated response (headers + body), its length in *resplen, or NULL
   on allocation failure. When HttpsDecoyUpstream is set, the request is
   proxied there (Host rewritten) and the upstream's response is returned;
   otherwise a static page (from HttpsDecoyRoot, or the built-in default) is
   returned. */
char *decoy_respond(const char *request, size_t reqlen, size_t *resplen);

/* Plain-HTTP path: read the request from a bare TCP socket, answer with the
   decoy, and close. Used by the front dispatcher for a cleartext prober. The
   already-peeked bytes are still in the socket. */
struct connection_t;
void decoy_serve_plain(struct connection_t *c);

#endif /* TINC_DECOY_H */
