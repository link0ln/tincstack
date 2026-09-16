#ifndef TINC_AUTHN_H
#define TINC_AUTHN_H

/*
    authn.h -- the in-session peer authenticator shared by the `https' and
               `quic' carriers (docs/transports.md §8.3).

    A dialling peer proves it is a tinc node -- before a single tinc request
    is parsed -- with one Ed25519 signature bound to the server's certificate
    and to the TLS session it is sent inside:

        payload = ver(1) || namelen(1) || node-name || nonce(16) || ts_be(8) || sig(64)
        sig     = Ed25519_sign(node key,
                    server-cert-fp(32) || TLS-exporter(32) || nonce(16) || ts_be(8))

    The https carrier carries the payload base64url-encoded in a WebSocket
    upgrade Cookie; the quic carrier sends the raw payload as the first bytes
    of its stream 0. One implementation, one replay cache, one verification
    for both. SPTPS is untouched: this only decides whether the carrier lets
    the tinc protocol start at all (principle 1, ARCHITECTURE §5).

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

/* Version 2 (review M5-11): the signed message starts with a fixed
   domain-separation label. Both ends must run this build; a v1 authenticator
   is refused like any other malformed one. */
#define AUTHN_VERSION 2
#define AUTHN_LABEL "tincstack-authn-v2"
#define AUTHN_LABEL_LEN (sizeof(AUTHN_LABEL))   /* including the NUL */
#define AUTHN_FP_LEN 32                 /* SHA-256 of the server certificate (== TLS_FP_LEN) */
#define AUTHN_EXPORTER_LEN 32           /* RFC 5705 / TLS 1.3 exporter output */
#define AUTHN_EXPORTER_LABEL "EXPORTER-tincstack-https-v1"
#define AUTHN_NONCE_LEN 16
#define AUTHN_TS_LEN 8
#define AUTHN_SIG_LEN 64                /* Ed25519 */
#define AUTHN_TS_SKEW 90                /* seconds of clock skew tolerated */
#define AUTHN_HDR_LEN 2                 /* ver + namelen */
#define AUTHN_MAX_NAME 255
#define AUTHN_MAX_LEN (AUTHN_HDR_LEN + AUTHN_MAX_NAME + AUTHN_NONCE_LEN + AUTHN_TS_LEN + AUTHN_SIG_LEN)

/* Build this node's authenticator bound to `server_fp' (the certificate the
   peer presented) and `exporter' (this TLS session). Returns the payload
   length, or 0 on failure. `out' must hold AUTHN_MAX_LEN bytes. */
size_t authn_build(const uint8_t *server_fp, const uint8_t *exporter, uint8_t *out, size_t outcap);

/* Length of the complete authenticator whose first `len' bytes are in `buf':
   0 = need more bytes to tell; (size_t)-1 = malformed (bad version or empty
   name), never a valid authenticator. Lets a stream carrier delimit the
   payload before it has the signer's key. */
size_t authn_expected_len(const uint8_t *buf, size_t len);

/* Verify a received authenticator against our own certificate fingerprint and
   this session's exporter. On success `*name' is the signer's node name
   (caller frees). `carrier' and `hostname' are for the log only. Any failure
   -- unknown node, bad signature, stale timestamp, replayed nonce -- returns
   false and the carrier treats the peer as a prober. */
bool authn_verify(const uint8_t *payload, size_t plen, const uint8_t *server_fp, const uint8_t *exporter,
                  const char *carrier, const char *hostname, char **name);

#endif /* TINC_AUTHN_H */
