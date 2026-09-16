# testing/transports — M4/M5 transport layer proofs

Self-contained checks. All tooling runs in throwaway Docker containers;
nothing is installed on the host. They need the core image built first:

    docker build -f core/Dockerfile.build -t tincstack/core:ws-b core/

## Running two proofs at once (`LAB=`, `SUBNET=`)

Every docker-based proof here (`singleflow`, `tls-front`, `https-carrier`,
`quic-carrier`, `matrix`) sources `lab-env.sh` and takes `LAB=<prefix>`
like `platforms/linux/docker/two-nodes.sh`: the prefix goes into every
container and network name and the `/tmp/<LAB>*` data directory, and a
non-default `LAB` also moves the lab `/24` to a `LAB`-derived third octet
(`SUBNET=10.31.42` overrides it). The defaults are the historical names
(`wsbsf-*`, `wsl-*`, `wslh-*`, `wsg3q-*`, `wsbmtx-*`), so the commands below
still work unchanged, and the scripts still remove *their own* leftovers on
start — only those. Two concurrent runs:

    LAB=wst1 sh testing/transports/singleflow-test.sh tincstack/core:dev &
    LAB=wst2 sh testing/transports/singleflow-test.sh tincstack/core:dev

`obfs-test.sh` still hard-codes `wsg2o-*` / `wsg2obfs` / `10.37.9.0/24`
(it is being edited by stream O; give it the same `lab-env.sh` treatment when
that lands). `classify-test.sh` creates no named container.

## classify-test.sh — front classifier unit test

Compiles `classify_test.c` against the real `transport_table.c` (the classifier
and carrier table, which have no daemon dependencies) in a Debian container and
feeds every documented byte pattern (docs/transports.md §3) to
`transport_classify_tcp()` / `transport_classify_udp()`, asserting each reaches
the right handler class.

    sh testing/transports/classify-test.sh

Expect: `37 checks, 0 failures` (M5 G3 added the QUIC v1-only long-header
rows and the keyed short-header rows, docs/transports.md §9.5).

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

## quic-carrier-test.sh — the `quic` carrier (M5, G3)

Needs the QUIC-enabled image (the default `core/Dockerfile.build` since G3) and,
for the "built without QUIC" fallback case, the same Dockerfile with
`--build-arg QUIC=disabled`:

    docker build -f core/Dockerfile.build -t tincstack/core:ws-g3 core/
    docker build -f core/Dockerfile.build --build-arg QUIC=disabled -t tincstack/core:ws-g3-noquic core/
    sh testing/transports/quic-carrier-test.sh [image] [image-without-quic]

Sections (`ONLY="a b"` runs a subset, `KEEP=1` leaves the containers up):
(a) A `PreferredTransports: [quic, plain]`, B default -> ping both ways,
`dump connections` shows `quic` on both, tcpdump on the port shows QUIC only
(three long headers then short headers, no datagram without the QUIC fixed
bit, no TCP connection established); (b) NAT rebind: an SNAT rule in A's netns
maps its source port, is flipped 40000 -> 40001 mid-session and conntrack is
flushed -> B logs `quic: path validated ... port 40001`, no re-handshake, ping
continues; (c) fallback with B `Transports: [plain]`, B built without QUIC, and
UDP to B DROP'd (handshake timeout -> `Carrier quic failed ... falling back to
plain`); (d) a dialler with the wrong Ed25519 key: `quic: authenticator ...
rejected` on B, dialler falls back; (f) relay A-R-B with A-R on quic and R-B on
plain, A<->B severed.

Expect: `PASS: quic carrier negotiates, survives NAT rebind, falls back, rejects bad auth, relays`.
