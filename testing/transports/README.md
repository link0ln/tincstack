# testing/transports — M4/M5 transport layer proofs

Self-contained checks. All tooling runs in throwaway Docker containers;
nothing is installed on the host. They need the core image built first:

    docker build -f core/Dockerfile.build -t tincstack/core:dev core/

Every proof takes the image as its first argument and otherwise builds the name
from `TINCSTACK_TAG` (default `dev`), the same selector `testing/smoke/run.sh`
and the `platforms/linux/docker/` labs take. Passing neither used to select the
stream image each test was written against, which silently reported a
months-old core's behaviour as today's.

## Running two proofs at once (`LAB=`, `SUBNET=`)

Every docker-based proof here (`singleflow`, `tls-front`, `https-carrier`,
`quic-carrier`, `obfs`, `matrix`, `plain-refuse`) sources `lab-env.sh` and takes `LAB=<prefix>`
like `platforms/linux/docker/two-nodes.sh`: the prefix goes into every
container and network name and the `/tmp/<LAB>*` data directory, and a
non-default `LAB` also moves the lab `/24` to a `LAB`-derived third octet
(`SUBNET=10.31.42` overrides it). Only 200 octets exist, so two prefixes can
derive the same one; when a docker network that is not this lab's own already
holds it, `lab-env.sh` takes the lowest free octet instead and prints which.
That check reads the network list rather than taking a lock, so two labs
started in the same second can still collide -- stagger them or pass `SUBNET=`. The defaults are the historical names
(`wsbsf-*`, `wsl-*`, `wslh-*`, `wsg3q-*`, `wso-*`, `wsbmtx-*`, `wspr-*`), so the commands
below still work unchanged, and the scripts still remove *their own* leftovers
on start — only those. Two concurrent runs:

    LAB=wst1 sh testing/transports/singleflow-test.sh tincstack/core:dev &
    LAB=wst2 sh testing/transports/singleflow-test.sh tincstack/core:dev

`obfs-test.sh` keeps its historical names too (`wso-*` containers, the
`<LAB>obfs` network, `10.37.90.0/24`, `/tmp/wso-obfs*`), and a non-default
`LAB` moves all five — including the two off-path attacker addresses of the
replay/reflection checks. `classify-test.sh` creates no named container.

`make lint` shellchecks every script here at shellcheck's default (full)
severity; keep them clean rather than lowering the bar.

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
    docker build -f /tmp/Dockerfile.test -t tincstack/core:dev-test core/
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

    docker build -f core/Dockerfile.build -t tincstack/core:dev core/
    docker build -f core/Dockerfile.build --build-arg QUIC=disabled -t tincstack/core:dev-noquic core/
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

## plain-refuse-test.sh — `AllowPlainMeta` (refusing cleartext meta)

The proof for PLAN.md's Known Issue "a node cannot refuse cleartext tinc on its
listening port" and its fix, the `AllowPlainMeta` option
(`docs/transports.md` §2.1). Two nodes plus a raw TCP prober on a third
address, which opens an unwrapped tinc meta connection and sends the ID line
`0 nodea 17.7`.

    sh testing/transports/plain-refuse-test.sh [image]

(a) default, no `AllowPlainMeta` line: the plain link comes up, the accept list
contains `plain`, and the prober gets `0 nodeb 17.7` back — the fingerprint the
Known Issue described. (b) `AllowPlainMeta: no` on nodeb: the accept list loses
`plain`, the prober gets **nothing** (the socket is tarpitted, as for an
unrecognised preamble), nodeb logs *Front: refusing cleartext tinc meta
connection from … `plain' is not in this node's Transports accept list*, an
obfs link to the same node still passes traffic 0 %-loss, nodea's view of
nodeb's accept list (from the ACK) has no `plain`, and `tinc dump nodes` on the
refusing node still works, and **`tinc join` against it fails** — the
documented cost, asserted so it cannot change silently. (c) `tinc set
AllowPlainMeta yes` + `tinc reload`: the prober is answered again and the same
`tinc join` succeeds, with no restart.

Expect: `PASS: AllowPlainMeta refuses inbound cleartext tinc, keeps obfs, the CLI and reload`.

## carrier-switch-test.sh — changing the carrier of a *running* node

The proof for PLAN.md's Known Issue "`tinc disconnect` killed the re-dial it
had just started": `tinc set PreferredTransports <c>` + `tinc reload` +
`tinc disconnect <peer>` always ended on `transport plain`, while the same
configuration read at startup came up on `<c>`.

    sh testing/transports/carrier-switch-test.sh [image]

Two nodes (`<LAB>-a` founding, `<LAB>-b` invited). For each carrier the build
accepts (`obfs`, `sf`, `https`, `quic` — the daemon's own "Transports accept="
line decides, so a `-noquic` core skips `quic` instead of failing) the invitee
is restarted on `plain` first, and the case waits for `udp_confirmed` in
`tinc info` before switching. That wait is not decoration: `terminate_connection()`
only re-dials inside the `disconnect` when the address cache can hand it an
address, which is what a confirmed UDP path restores — without it the re-dial
is deferred 5 s to `retry_outgoing()`, the defect cannot bite, and the test
would pass on a broken build. Each case then asserts the link is ACTIVATED on
the new carrier, the tunnel pings 0 %-loss, and no "Carrier `<c>` failed" was
logged; switching back to `plain` is asserted too, and so is `disconnect`
saying why it closed a link.

Expect: `PASS: the carrier of a running node can be changed with set + reload + disconnect`.
## invitee-mesh-test.sh — defects C and D (two invitees of the same node)

The proof for PLAN.md's Known Issues "Defect C — two invitees of the same node
never peer directly" and "Defect D — `Transports` is not propagated past one
hop". Three containers: a public founder that issues both invitations, and two
leaves that join with `tinc join` and are never given a host record for each
other (the script asserts that before it measures anything).

    sh testing/transports/invitee-mesh-test.sh [image] [--expect-defect]

Default mode asserts the fix: both leaves see the other at `distance 1` with
the other leaf as its own `nexthop`, each knows the other's real carrier accept
mask (defect D — it now travels on ANS_PUBKEY, not only on a direct ACK), and
the tunnel carries traffic both ways **with the founder container stopped**,
which is what rules out a relay. Neither leaf may log `unknown identity`,
`Could not set up a meta connection to <peer>` or `Timeout from <peer> …
during authentication`.

`--expect-defect` asserts the opposite and is how the defect was reproduced
against a pre-fix image: the two field error lines must appear and both leaves
must end at `nexthop founder … distance 2`. Run it against
`tincstack/core:<pre-fix tag>` to see the original behaviour; against a fixed
build it fails, which is the point.

Expect: `PASS: two invitees of the same node peer directly, with the founder stopped`
(or `PASS(repro): both leaves are permanently relayed through their inviter`).

## obfs-confirmed-peer-test.sh — turning a *running* network covert

The proof for PLAN.md's Known Issue "an already-running network cannot be
switched to obfs". On the stand, two nodes with a confirmed UDP data path
could never bring up an obfs link: the dial timed out in authentication and
fell back to plain, while the acceptor logged, at the same seconds,
`Received UDP packet from <peer> … with unknown source and/or destination ID`.
The sealed frames arrived and the acceptor refused to look at them, because
`obfs_udp_try()` skipped its keyed check for any source address bound to a
node with `udp_confirmed` — which is the normal state of every working pair.

    sh testing/transports/obfs-confirmed-peer-test.sh [image] [--expect-defect]
    CARRIER=sf   sh testing/transports/obfs-confirmed-peer-test.sh [image]
    CARRIER=quic sh testing/transports/obfs-confirmed-peer-test.sh [image]

Three containers: `nodea` (founder, the acceptor, at `-d5` so the drop is
visible), `nodeb` (the dialler) and `nodec`. The third node is the whole
difference from `carrier-switch-test.sh`: with only two nodes, `tinc disconnect`
makes the dialler **unreachable** on the acceptor, `graph.c` clears
`udp_confirmed`, the guard does not fire and the two-node test passes on a
broken daemon. `nodec` keeps the dialler reachable through the mesh, so the
acceptor's `udp_confirmed` survives the disconnect — the script asserts that
in six consecutive samples taken from the instant of the disconnect, and
retries the whole switch (up to three times) if the mesh reconverges in a way
that loses it, because a run that loses it proves nothing either way.

PART 4 is the control: remove `nodec`, restart the dialler with the same
configuration, and the carrier comes up **even on a pre-fix image** — which is
what isolates the failure to the acceptor's stale `udp_confirmed`.

`CARRIER=sf` and `CARRIER=quic` run the identical scenario over the other two
UDP carriers in `transport_udp_dispatch()`; both pass on a pre-fix image, so
neither is shadowed by a confirmed plain peer (`transport_classify_udp()`
claims them on a magic prefix, a version word or a live connection id and
never looks the source address up).

`KEEP=1` leaves `/tmp/<LAB>-{a,b,c}/tincd.log` behind for a post-mortem.

Expect: `PASS: a running network with a confirmed UDP path can be switched to obfs`
(or `PASS(repro): a peer whose UDP path the acceptor has confirmed cannot be
dialled over obfs`).

## same-nat-meta-test.sh — defect E (two nodes behind one NAT)

The proof for PLAN.md's Known Issue "two nodes behind the same NAT never form a
meta connection, and retry forever". On the field stand, `router` and `laptop`
sit behind one home NAT, both know each other, both dial, and both fail for
ever — while their **data** path is direct and healthy, because that NAT
hairpins UDP and not TCP. The pair ends up half-connected: packets take the
short path, the meta connection is relayed through a VPS abroad, and each node
logs an ERROR every backoff round.

    sh testing/transports/same-nat-meta-test.sh [image] [--expect-defect]
    SET_OPTS='UdpMetaFallback no' \
        sh testing/transports/same-nat-meta-test.sh [image] --expect-relayed

Four containers on three docker networks: `relay` (the public founder),
`natgw` (the NAT, routing between all three), and `nodea`/`nodeb`, each in its
**own** inside segment. Separate segments are the point: the gateway does not
route between them, so — exactly as in the field — the only address either node
has for the other is the shared public one, and "advertise your LAN address"
cannot help. The gateway is a port-preserving cone NAT for UDP *including
hairpin*, and a black hole (DROP, not REJECT) for TCP to the public address in
either direction.

Five preconditions are asserted before the script believes anything, none of
them through tinc: TCP `nodea → relay` connects, TCP `nodea → public:6552`
times out, UDP `nodea → public:7552` reaches a listener in nodeb's namespace,
neither protocol reaches nodeb's private address, and both nodes already hold
the other's Ed25519 key. The last one is what makes this defect E and not
defect C: the accept mask rides on ANS_PUBKEY, which only a key-less node ever
asks for, so the pair is left believing each other plain-only. The relay stays
up for the whole run — a two-node lab does not reproduce mesh-dependent
behaviour (see `obfs-confirmed-peer-test.sh`).

Docker 28+ installs a `! -i br-X -o br-X -j DROP` rule per bridge, which
black-holes exactly the traffic this lab is made of, so the three networks are
created with `gateway_mode_ipv4=nat-unprotected`; the relaxation lives and dies
with them. On an older daemon the option does not exist and is not needed.

Expect: `PASS: two nodes behind one NAT peer directly over a UDP carrier, with
no ERROR loop` (or `PASS(repro): the pair's data path is direct, its meta path
is relayed for ever, and both log ERRORs`, or `PASS(control): with the UDP meta
fallback off the pair stays in the half-state`).
