# testing/nat-sim — NAT-type lab for the tincstack core

Verifies the NAT-traversal layer (ARCHITECTURE.md §2: `UDPDiscoveryBurst`,
`UDPRebindOnWake`, SPTPS stale-seqno tolerance — `core/tincd/PATCHES.md`)
against emulated NAT types, and compares the core with **unpatched upstream
tinc 1.1pre18** built from the release tarball (`testing/baseline/`).

Everything runs inside **one privileged Docker container**
(`tincstack/natlab:<tag>`, built from `testing/image/Dockerfile`): the
topology is made of Linux network namespaces and veth pairs, NAT gateways are
namespaces with their own iptables/conntrack, and tincd (core or baseline
binary) runs in the node namespaces. Nothing is installed on the host and
nothing touches the host's network stack. `--privileged` is required for
netns/iptables/conntrack sysctls/netem/tun inside the container.

Why not Docker networks + gateway containers (the netmaker lab's shape)? On
Docker 28+/Cilium hosts the daemon installs nft rules that drop bridged packets
destined to another network's addresses, so a dual-homed gateway container
never sees forwarded traffic. The netns design is host-independent and CI-safe.

## Quick use

```
testing/nat-sim/lab.sh validate-nat        # prove the NAT emulation (udpprobe)
testing/nat-sim/lab.sh scenario masq restricted --image core
testing/nat-sim/lab.sh matrix --quick --image core     # what `make check` runs
testing/nat-sim/lab.sh matrix                          # 5x5 + udpblock, core AND baseline
testing/nat-sim/lab.sh laptop                          # the named regression, core vs baseline
testing/nat-sim/lab.sh glare                           # simultaneous REQ_KEY
```

Results go to `results/run/<run-id>/` (logs, `dump nodes/edges`, `info`,
gateway rule/conntrack dumps, `summary.md`); the run id is `$WSF_RUN` or
`<date>-<HHMMSS>-<pid>`, and `make check` exports one `WSF_RUN` for all its
lab steps. `results/run/` is git-ignored: a run never touches the committed
evidence. Keys are generated inside the container and are never written
there. Exit code: 0 = every scenario PASS.

The committed tree `results/<date>/` is a *curated* subset, produced by
`lab.sh promote results/run/<run-id> [results/<date>]` (or `make promote
RUN=<run-id>`): every `summary.md` / `result.json`, the validate-nat JSON
lines, the laptop regression's `nodel.log` + port/conntrack notes, every
glare-fix log, the dpi-proof report/fingerprint/pcap. Per-pair node logs,
dumps and gateway dumps are not promoted and `.gitignore` refuses them under
`results/` (the two gateway dumps cited below are un-ignored by path). Until
2026-09-16 (stream T) the full 2026-09-16 run was committed: 767 files /
17.7 MiB; the curated tree is 112 files / 0.83 MiB.

Options: `--image core|baseline|both`, `--rtt MS` (netem on every gateway's
external interface), `--wait S` (direct-UDP budget, default 90),
`--recover S` (laptop stages, default 60), `--pause S` (simulated sleep,
default 70 > 2 × `UDPDiscoveryTimeout`), `--cgnat-udp-timeout S` /
`--cgnat-udp-stream-timeout S` (carrier-tier conntrack windows, default 10/30).

## Topology

```
                         br0  "internet" 100.64.0.0/24
   relay 100.64.0.10 ──────┼────── 100.64.0.2 gwa ── 192.168.110.0/24 ── nodea .5
   (public, Port 655)      ├────── 100.64.0.3 gwb ── 192.168.120.0/24 ── nodeb .5
                           └────── 100.64.0.4 gwl2 (carrier) ── 10.200.0.0/24 ──
                                    gwl1 (home) ── 192.168.130.0/24 ── nodel .5
```

Every node has a full host DB (all host records, explicit `Subnet`), the relay
is the only node with an `Address`, NATed nodes `ConnectTo = relay`,
`Port = 655`, `UDPDiscoveryBurst = 5` (ignored by the baseline daemon, which
simply keeps its single probe per round), `PingInterval = 10`. `nodel`
additionally has `UDPRebindOnWake = yes`. Both daemons run the identical classic
config tree (`tinc.conf` + `hosts/`); the YAML mode is exercised by
`testing/smoke/` instead, so the NAT comparison is not confounded by config
parsing.

## How each NAT type is emulated (`natprofile.sh`) and how it was validated

RFC 4787 vocabulary: mapping = EIM (endpoint-independent) or APDM
(address-and-port-dependent); filtering = EIF / ADF / APDF.

| profile | netfilter recipe | measured by udpprobe (kernel 6.8) |
|---|---|---|
| `fullcone` | static pair: `PREROUTING DNAT ext:P → inside:655`, `POSTROUTING SNAT inside:655 → ext:P` (P ≠ 655, i.e. non-port-preserving), plus `FORWARD` ACCEPT for any inbound to `inside:655` | EIM + EIF |
| `restricted` | same static pair; inbound to `inside:655` accepted only if the inside host has sent UDP to that *source IP* before — `xt_recent` list keyed on destination address (`--rdest --set` on every outbound datagram, `--rsource --rcheck --seconds 300` inbound) | EIM + ADF |
| `portrestricted` | same static pair; inbound only for conntrack `ESTABLISHED` tuples (exact ip:port) | EIM + APDF |
| `masq` | stock `MASQUERADE` (what a Linux router / Linux CGN does), dynamic: works for any inside port | **EIM-after-first** + APDF in the probe (the first destination keeps the source port; the next three shared one other port), but tinc runs also showed three distinct ports — treat it as APDM-ish. Kernels ≥ 6.7 no longer give endpoint-independent mapping with plain MASQUERADE |
| `symmetric` | `MASQUERADE --random-fully` + inbound only `ESTABLISHED` | APDM + APDF |
| `udpblock` | all UDP dropped both ways; TCP MASQUERADEd | no UDP at all (TCP meta path only) |

Limits, stated plainly:

- The three cone profiles are **static per port**: the gateway must know the
  inside host's UDP port (655). That is faithful for a node with a fixed
  port, and it is exactly the "external port ≠ listen port" case the relay's
  observed address must fix. A node that *rebinds* its port (`UDPRebindOnWake`)
  cannot sit behind a static cone profile, so the laptop scenario uses the
  dynamic `masq` profile on both CGNAT tiers.
- A dynamic EIM NAT cannot be built from stock netfilter on this kernel
  (`MASQUERADE` is EIM-after-first, `--random*` is APDM, a port range excluding
  the source port is random). So there is no "dynamic full-cone/restricted"
  tier; RFC 6888 CGNs (EIM) are approximated by `masq`, which is EIM for every
  destination after the first. Since the first flow of a NATed node is always
  to the relay, all *peers* see one stable port — the practical effect for
  tinc is EIM.
- "Restricted" is address-restricted (ADF) per RFC 4787; the netmaker lab's
  "restricted" was in fact port-restricted (conntrack-state filter).

`lab.sh validate-nat` runs the classifier (`udpprobe.py`, stdlib only) from a
LAN namespace behind each profile against a two-address server on the public
side: PROBE → observed mapping; XPORT (same IP, other port) and XHOST (other IP)
test the filter before the client has ever sent to those endpoints; three more
PROBEs to other endpoints test the mapping. The measured classification must
equal the declared one, otherwise the lab refuses to call itself faithful
(`make check` runs it first). The JSON lines are copied into the results.

## Pair scenarios and verdicts

`scenario A B`: nodea behind profile A, nodeb behind profile B, relay public.
Traffic is driven from nodea (`ping` to nodeb's tunnel address) — one-sided on
purpose, see the glare note. The lab polls `tinc info <peer>` on both sides for
`Reachability: directly with UDP` (which in tinc 1.1 also requires PMTU
discovery to have completed) and records the seconds it took, then pings both
ways.

Expected outcome table (RFC 5128 logic; tinc does no port prediction):

| A \ B | fullcone | restricted | portrestricted | masq | symmetric |
|---|---|---|---|---|---|
| fullcone | direct | direct | direct | direct | direct |
| restricted | direct | direct | direct | direct | direct |
| portrestricted | direct | direct | direct | relay | relay |
| masq | direct | direct | relay | relay | relay |
| symmetric | direct | direct | relay | relay | relay |

Why `symmetric x fullcone` and `symmetric x restricted` come up direct (and
this is not a mislabelled cone): in `results/2026-09-16/pair-restricted-symmetric/core/gw-gwb.txt`
the symmetric gateway's conntrack maps `nodeb:655` to external port 760 towards
the relay and 841 towards nodea (per-destination ports = APDM; udpprobe saw four
different ports for four destinations). nodea first learns the relay-facing
port via `UDP_INFO` ("UDP address of nodeb set to … port 760"), then nodeb's
own probe arrives from the real port 841 — the address-dependent filter admits
it because nodea had already sent to that IP — and tinc updates the peer
address from the authenticated datagram ("… set to … port 841"). That is RFC
5128 §3.3: symmetric ↔ full-cone/address-restricted is traversable; symmetric ↔
port-restricted/symmetric is not, and the matrix shows exactly those as relay.

`masq` is not deterministic beyond "the first destination keeps the source
port": in the 2026-09-16 run the baseline's `masq x portrestricted` came up
direct because gwa happened to give the relay flow and the peer flow the same
external port (997, `pair-masq-portrestricted/baseline/gw-gwa.txt`), while the
core's run of the same pair got three different ports (655/782/694) and stayed
on the relay. `expected=no` pairs therefore only require the relay path to
carry traffic; a direct cell there is luck, not a verdict.

Verdict: `expected=yes` → PASS iff direct UDP on both sides within `--wait`
and ping OK; `expected=no` → PASS iff ping OK (traffic must flow via the
relay = TCP-meta / SPTPS-over-relay path, whatever UDP does);
`udpblock` pairs → PASS iff ping OK and the peer is *not* reported as direct
UDP (the meta connection carried the traffic).

## The laptop regression (`lab.sh laptop`)

Node L behind two NAT tiers (home router `masq` → carrier `masq` with UDP
conntrack windows 10 s unreplied / 30 s stream), peer P behind `restricted`,
relay R public. L drives traffic. Stages, each with a 60 s recovery budget and
the requirement *direct UDP reported **and** a tunnel ping answered*:

- `setup` — direct L↔P must come up through both tiers.
- `peer-restart` — P's tincd is stopped and started (same config). L must
  re-key and re-establish direct UDP without restarting.
- `sleep-resume` — L's tincd is frozen with `SIGSTOP` for 70 s and resumed
  (`docker pause` would freeze the whole lab container; SIGSTOP on the one
  process is the same thing for tincd's 1-second timer: it logs
  `Awaking from dead after N seconds of sleep` because N > 2 × `UDPDiscoveryTimeout`,
  tears down its connections, and — with `UDPRebindOnWake = yes` — rebinds its
  UDP socket to a fresh port).
- `mapping-dropped` — L is frozen again; while it sleeps the carrier tier's
  conntrack is flushed **and** the home tier black-holes every inbound datagram
  to L's old socket (`-d L --dport <oldport> DROP` after de-NAT). This is the
  field symptom of a mapping the carrier keeps filtering after resume: the old
  socket never receives again, only a fresh socket (fresh mapping) gets
  through. Stock netfilter cannot keep a *mapping* filtered while re-creating
  it on demand, hence the black-hole by inside socket; the effect on tincd is
  identical. L's UDP port before/after is recorded (`nodel-udp-port.txt`).

Pass = all stages recovered within 60 s, the same tincd process alive
throughout, fewer than 20 `Invalid packet seqno` and fewer than 20
`Got REQ_KEY … while we already started a SPTPS session` lines across all logs
(the livelock signatures PATCHES.md §1 removes). Run for `core` and `baseline`;
the delta is the proof. L's log (`nodel.log`), `nodel-udp-port.txt`, the
carrier conntrack snapshot and the summaries of both runs are committed under
`results/<date>/laptop/`; the full run stays in `results/run/`.

## REQ_KEY glare (`lab.sh glare`) — found during M9

If both nodes start sending to each other in the same instant, both send
`REQ_KEY` (SPTPS initiator) at once. tinc 1.1 — upstream **and** the core — has
no tie-break in the `REQ_KEY` handler: each side stops its own session and
becomes a responder, so each side's `ANS_KEY` arrives at a fresh responder that
expects seqno 1 and logs `Invalid packet seqno: 0 != 1`. Recovery relies on the
"No key from X after N seconds, restarting SPTPS" timer, and because both timers
were started together the retry collides again; the session eventually
succeeds by jitter. The core's 30 s cooldown (PATCHES.md §1, 10 s upstream)
makes every round three times longer. The `glare` scenario measures the time
to the first successful key exchange for both binaries.

**Fixed in the core on 2026-09-16 (PATCHES.md §5):** the lexicographically
smaller `Name` keeps its pending initiator session and ignores the peer's
`REQ_KEY`, the other side yields as responder, and the restart cooldown is
jittered ±20 %. The "glare lines" column counts both the stock "already
started" message and the core's "glare tie-break" message, so a 1 s key with
glare lines > 0 means the glare happened *and* was resolved; 0 glare lines
means the two pings did not actually collide in that run (it is a race —
`--rtt 50` makes the collision near-certain). `--image-b core|baseline` runs
nodeb on the other binary for the mixed pairs (`--image core --image-b
baseline` = patched initiator against a stock responder). Evidence:
`results/2026-09-16/glare-fix/`.

## Files

- `lab.sh` — host wrapper (build the lab image, run one command in it).
- `natlab.sh` — the lab itself (runs inside the container).
- `natprofile.sh` — NAT profiles (runs inside a gateway namespace).
- `udpprobe.py` — NAT classifier used by `validate-nat`.
- `results/run/<run-id>/` — full output of every run (git-ignored).
- `results/<date>/` — committed, curated evidence (`lab.sh promote`; no keys —
  promote greps for key material and fails if it finds any).
