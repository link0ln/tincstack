# testing/quic-spike — stream Q: QUIC carrier primitives on ngtcp2

Standalone proof (no tincd code involved) that the library chosen for the M5
QUIC carrier does everything the carrier contract needs, driven the way tincd
will drive it: one unconnected UDP socket, one single-threaded `poll()` loop,
the library never touching the socket. Everything runs in Docker; nothing is
installed on the host.

    testing/quic-spike/run.sh          # OUT=/tmp/wsq-spike by default

`run.sh` builds `tincstack/core:ws-q-build` from `core/Dockerfile.build-quic`
(target `build`: ngtcp2 1.25.0 + its GnuTLS backend under /usr/local) if it is
missing, builds the spike image on top (tcpdump, openssl, the two binaries),
and runs `test.sh` in one container over loopback. Exit code 0 only when every
line below is `PASS`.

## What test.sh proves

A self-signed EC P-256 certificate is generated at run time (the format G1
stores in `keys.tls_cert` / `keys.tls_key`); nothing is committed.

| line | primitive | how it is checked |
|---|---|---|
| `handshake` | QUIC v1 + TLS 1.3, server cert/key from PEM, client verifies by **SHA-256 fingerprint pin** (no CA, no name check) | client `RESULT PASS handshake`, `PIN ok sha256=…`, server `HANDSHAKE ok` |
| `pin-mismatch-rejected` | a wrong pin must abort the handshake | second session with an all-zero pin: client exits non-zero with TLS alert 42 (bad_certificate), server never reaches `HANDSHAKE ok` |
| `datagram` | unreliable DATAGRAM frames both ways (the SPTPS data path) | 5 datagrams client→server, each echoed server→client |
| `stream` | bytes both ways on one bidirectional stream (the SPTPS meta path) | `meta:…` line answered with `server-ack:…` on stream 0 |
| `rebind` | **NAT rebind**: the client's UDP source port changes, the client only tells ngtcp2 its new local address, the server sees a new source port under the same connection id and validates the path | server `PATH_VALIDATION success remote=127.0.0.1:<new port>`; stream + datagrams still flow |
| `migrate` | **explicit migration** to a third port with a fresh connection id (`ngtcp2_conn_initiate_immediate_migration`) | client-side and server-side path validation succeed; stream + datagrams still flow |
| `alpn-sni` | what the handshake shows on the wire for later DPI shaping | server reports `alpn=h3 sni=cdn.example.net`, cipher and group |
| `close` | orderly CONNECTION_CLOSE, both processes exit 0 | |
| `classifier` | the **first packet on the wire** (from the tcpdump capture, not from the client's buffer) is a long header, fixed bit set, type Initial, version `0x00000001` | `pcap_first.py` decodes the capture |

Observed (three consecutive runs, all `ALL PASS`):

    pkt 1  len=1200  bytes[0..7]=c3 00 00 00 01 08 …  form=long fixed=1 type=Initial version=0x00000001 dcidlen=8
    server HANDSHAKE ok alpn=h3 sni=cdn.example.net tls=TLS1.3 cipher=AES-128-GCM group=X25519
    server PATH_VALIDATION success remote=127.0.0.1:<port after rebind>
    server PATH_VALIDATION success remote=127.0.0.1:<port after migrate>
    packets=71 long_header=3 short_header=68

## Files

- `common.[ch]` — the glue a carrier needs around ngtcp2: TLS session with
  pinning, callback table, write loop (datagrams first, then the stream), read
  loop passing every datagram's real source address to the library, timers.
- `server.c` — accepts one connection from its first Initial packet
  (`ngtcp2_pkt_decode_version_cid` + `ngtcp2_accept`, the same decision the
  M4 UDP classifier makes), echoes, logs path validations.
- `client.c` — runs the phases above and prints `RESULT PASS|FAIL <name>`.
- `test.sh` — in-container driver; `pcap_first.py` — stdlib pcap decoder.
- `Dockerfile` — spike image on top of the ws-q build stage.

## Two things the spike found that G3 must carry over

1. `active_connection_id_limit` must be raised from the default 2 (set to 8
   here). With 2, the second migration in one session killed the server with
   `ERR_CONNECTION_ID_LIMIT`. A laptop that sleeps and wakes repeatedly needs
   several migrations per session.
2. tcpdump on loopback needs `--immediate-mode` for sub-second sessions,
   otherwise the capture is still in the kernel ring when tcpdump is stopped.
   Not a carrier issue, but it will bite the G3 proof script too.
