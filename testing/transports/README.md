# testing/transports — M4 transport layer proofs

Three self-contained checks. All tooling runs in throwaway Docker containers;
nothing is installed on the host. They need the core image built first:

    docker build -f core/Dockerfile.build -t tincstack/core:ws-b core/

## classify-test.sh — front classifier unit test

Compiles `classify_test.c` against the real `transport_table.c` (the classifier
and carrier table, which have no daemon dependencies) in a Debian container and
feeds every documented byte pattern (docs/transports.md §3) to
`transport_classify_tcp()` / `transport_classify_udp()`, asserting each reaches
the right handler class.

    sh testing/transports/classify-test.sh

Expect: `26 checks, 0 failures`.

## matrix-test.sh — outbound selection & fallback

Two nodes. The dialling node prefers the `test` stub carrier (whose dial always
fails) ahead of `plain`, so the selector must fall back to `plain` and the
tunnel must still come up. Proves the (preference × accept) walk and the
handshake-failure fallback with a deterministic failure.

Needs an image built with the stub carrier:

    sed 's/-Dbuildtype=release/-Dbuildtype=release -Dtransport_test=true/' \
        core/Dockerfile.build > /tmp/Dockerfile.test
    docker build -f /tmp/Dockerfile.test -t tincstack/core:ws-b-test core/
    sh testing/transports/matrix-test.sh

Expect: `PASS: test carrier tried, fell back to plain, tunnel came up`.

The `test` carrier is compiled only under `-Dtransport_test=true`; a normal
build does not contain it and never accepts or dials it.

## singleflow-test.sh — meta-over-UDP single flow

Part 1: two `SingleFlow=yes` nodes. The tunnel comes up from cold, ping works,
and `tcpdump` on the tinc port (run in a container sharing the node's netns)
shows only UDP and zero TCP — there is no tinc-shaped TCP connection.

Part 2: three nodes A–R–B with A↔B direct reachability severed by an `iptables`
DROP in A and B. Traffic still flows A↔B, relayed through R over the unchanged
SPTPS relay path, proving single-flow does not corrupt relayed records. (The
relayed SPTPS key exchange can take ~20 s to establish; the script retries.)

    sh testing/transports/singleflow-test.sh

Expect: `PASS: single-flow tunnel is UDP-only, cold-start works, relay path intact`.
