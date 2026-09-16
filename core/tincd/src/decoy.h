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

/* Build the *static* decoy response for a client whose request head (up to
   and including the blank line) is `request` (`reqlen` bytes): a file under
   HttpsDecoyRoot, or the built-in page. Returns a newly-allocated response
   (headers + body) and its length in *resplen. Never touches the network. */
char *decoy_respond_static(const char *request, size_t reqlen, size_t *resplen);

/* Upstream proxy (HttpsDecoyUpstream), event-driven (review M5-1): the fetch
   runs on the daemon's event loop with a non-blocking connect, a total
   deadline and a size cap, so a slow, black-holed or malicious upstream never
   stalls the loop. The upstream address is resolved once, in
   decoy_read_config(). Headers that carry the tinc authenticator (Cookie,
   Upgrade, Sec-WebSocket-*) are stripped before forwarding (review M5-10).

   decoy_fetch_start() returns NULL when no upstream is configured or usable:
   the caller then serves decoy_respond_static() itself. Otherwise `cb` is
   called exactly once, later (never from inside decoy_fetch_start), with a
   newly-allocated response the caller owns -- the upstream's, or the static
   page if the upstream failed -- after which the handle is gone. A caller
   that goes away first must decoy_fetch_cancel() its handle. */
typedef struct decoy_fetch_t decoy_fetch_t;
typedef void (*decoy_cb_t)(void *data, char *resp, size_t resplen);
decoy_fetch_t *decoy_fetch_start(const char *request, size_t reqlen, decoy_cb_t cb, void *data);
void decoy_fetch_cancel(decoy_fetch_t *f);

/* Plain-HTTP path: take over a bare TCP connection the front classified as
   HTTP, read the request head, answer with the decoy and close -- all driven
   by the event loop (review M5-8: never a busy-wait on a client that does not
   read). The already-peeked bytes are still in the socket. The connection is
   reaped by the authentication timeout (pingtimeout) if the exchange does not
   finish, like any other unauthenticated connection. */
struct connection_t;
void decoy_serve_plain(struct connection_t *c);

#endif /* TINC_DECOY_H */
