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
testing/nat-sim/lab.sh matrix --image core --pairs "masqfw/masqfw cgnat/cgnat" --transport quic
testing/nat-sim/lab.sh mesh --image both               # 5 NATed nodes + relay: % direct, relay load
testing/nat-sim/lab.sh mesh --image core --relay-down 20
testing/nat-sim/lab.sh rekey restricted symmetric --keyexpire 20
testing/nat-sim/lab.sh portmap                         # what each NAT does to source ports (no tincd)
testing/nat-sim/lab.sh punch masq/masq --sync --rtt 40 # hole-punch techniques (no tincd)
```

Stream N (2026-09-26) added the arms below the matrix; `docs/nat.md` is the
analysis they feed (trace of the traversal code, per-NAT behaviour, ranked
fixes). Evidence: `results/2026-09-26/`.

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
| `masq` | stock `MASQUERADE`, gateway INPUT chain open (a Linux box doing NAT with no firewall; the lab's CGN tier), dynamic: works for any inside port | **EIM-after-first** + APDF in the probe (the first destination keeps the source port; the next three shared one other port). 2026-09-26: EIM and port-preserving until an unsolicited inbound datagram leaves a local conntrack entry; after that new flows move to another port (see "masq vs masqfw") |
| `symmetric` | `MASQUERADE --random-fully` + inbound only `ESTABLISHED` | APDM + APDF |
| `masqfw` | `masq` plus the router's own firewall: `INPUT -i ext` drops everything but `ESTABLISHED,RELATED` | EIM + APDF, port-preserving (2026-09-26, `expect masqfw`) |
| `cgnat` | two `masq` tiers (home router, then a carrier tier with short UDP timeouts); pair scenarios only | as `masq`, twice |
| `udpblock` | all UDP dropped both ways; TCP MASQUERADEd | no UDP at all (TCP meta path only) |

### `masq` vs `masqfw` — what "Linux MASQUERADE is not EIM" really was

Until 2026-09-26 this README said MASQUERADE on kernels >= 6.7 is
"EIM-after-first" and the matrix treated `masq` like a symmetric NAT. Stream N
measured where the second port comes from (`lab.sh portmap`,
`results/2026-09-26/portmap/`, kernel 6.8, two trials each):

- **Nothing unsolicited → EIM and port-preserving.** Five destinations from
  one socket: all five see source port 655, on `masq`, `masqfw` and `cgnat`.
- **An unsolicited datagram to the mapping** (a reflector socket the client
  never sent to, i.e. exactly what a peer's early hole-punch probe is) reaches
  the gateway's own INPUT chain in `masq` and leaves a *local* conntrack entry
  `peer:port -> gw:sport`. Every later outbound flow whose reply tuple clashes
  with it is moved to another port (656 -> 935 / 647, 4004 -> 60376 / 44401),
  and so is every later new flow after that, clash or not. Flows opened before
  the poke keep the source port. The new port stays in the source port's class
  (512-1023 -> 600-1023, >= 1024 -> 1024-65535).
- **`masqfw` drops the unsolicited datagram before conntrack confirms it**, so
  it leaves nothing behind: every destination, poked or not, keeps the source
  port. That is how a Linux home router with its firewall on (OpenWrt, every
  CPE) behaves.
- A throwaway first datagram that is never answered (`burn`) changes nothing.

udpprobe's own XPORT/XHOST filter tests are such unsolicited datagrams, which
is why it saw "the first destination keeps the port, the rest share another".
Conntrack shows the same mechanism deadlocking tinc in `pair-masq-masq/core`
(ww-n base run, `gw-gwa.txt` / `gw-gwb.txt`): nodeb's probe to `gwa:655`
arrives first and pushes all of nodea's later flows to 684; nodea's probes
from 684 do the same to nodeb (818); each side keeps probing the other's
previous port every 2 s, which refreshes the entries — a permanent deadlock.

So `masq` is still a valid profile — it is a Linux NAT that accepts WAN input
(the lab's CGN tier, a bare Linux box doing NAT with no firewall) — but it is
not the typical home router; `masqfw` is. The matrix table below keeps `masq`
as measured and judges `masqfw` as a port-restricted cone (`nat_class`).

Limits, stated plainly:

- The three cone profiles are **static per port**: the gateway must know the
  inside host's UDP port (655). That is faithful for a node with a fixed
  port, and it is exactly the "external port ≠ listen port" case the relay's
  observed address must fix. A node that *rebinds* its port (`UDPRebindOnWake`)
  cannot sit behind a static cone profile, so the laptop scenario uses the
  dynamic `masq` profile on both CGNAT tiers.
- Dynamic EIM exists after all: `masqfw` (MASQUERADE behind a closed INPUT
  chain) is EIM + APDF and port-preserving. What was read as "MASQUERADE is
  EIM-after-first" is the open INPUT chain of `masq` (next section). There is
  still no dynamic full-cone/address-restricted tier (EIF/ADF filtering needs
  the static profiles).
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

`masqfw` rows (judged as `portrestricted`) and `cgnat` (judged as `masq`)
come from `nat_class()`; `--pairs "A/B ..."` runs any subset, and a direct
cell where the table says relay is reported, not failed.

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

### Grading: each image is judged against what it should do

Until 2026-09-18 both images were graded by one rule — "a key within `--wait`
(90 s)" — so the arm exited non-zero whenever the **unpatched control behaved
exactly as the defect predicts**. That happened in the regression of that day:
core 1 s / 0 restarts (PASS), baseline 90 s / 14 restarts (FAIL), arm red, no
regression anywhere. Three more baseline runs at the same RTT took 46 / 12 / 35 s,
so the previous green arm had been luck rather than a different outcome.

Each image now carries an expectation, printed in the summary table:

| expectation | who gets it by default | PASS means |
|---|---|---|
| `clean` | `core` | key within `--clean-max` (default 10 s), **0** SPTPS restarts, **0** `Invalid packet seqno` |
| `defect` | `baseline` | the collision happened (glare lines > 0) **and** cost something: ≥ 1 SPTPS restart, ≥ 1 seqno error, or no key within `--wait` |
| `any` | mixed pairs (`--image-b`) | a key was established within `--wait` |

So a control that quietly recovers now **fails** — it is no longer the control
the patch is compared against — and a patched binary that needs a restart fails
too. Mixed pairs are not graded by default because which side keeps its session
depends on the node names (the tie-break is lexicographic): `core x baseline` is
clean, `baseline x core` pays the stock 10 s timer. Assert one deliberately with
`--expect clean|defect|any`.

A `defect` run in which the two sides never collided is **INCONCLUSIVE**, not a
failure of the binary: it is retried once, and if it still does not collide the
arm exits 2 and says so, because a run that never provoked the race proves
nothing about it.

## Stream N arms (2026-09-26)

- `matrix`/`scenario` options: `--transport T` (NATed nodes get
  `PreferredTransports = T,plain`; the summary shows the meta carrier each
  side actually used, as listed by `dump connections` — a dial still pending
  or refused is listed too), `--pairs`, `--node-conf "Key=Value ..."`,
  `--ipv6 both|a` (a routed 2001:db8::/32 behind stateful ip6tables
  firewalls, `AddressFamily = any`, the relay's IPv6 address first),
  `--capture` (tcpdump of gwa's WAN side towards gwb, classified by
  `dpi-fingerprint`: what the direct peer-to-peer path looks like on the wire).
- `mesh [--nodes "T1 T2 ..."]`: every node behind its own NAT, one public
  relay, every ordered pair pings at 1 pps. Per pair: seconds to direct in
  each direction; overall % direct and the relay's steady-state packet/byte
  rate over 20 s. `--relay-down S` then stops the relay's tincd for S seconds
  while one direct and one relayed pair ping at 5 pps (replies while down,
  longest gap, first reply after restart).
- `rekey A B --keyexpire S --duration S`: a direct pair under SPTPS rekeys;
  counts peer-address resets and data packets sent via the relay instead of
  direct after the pair went direct.
- `portmap`: see "masq vs masqfw" above.
- `punch [A/B ...]`: `nattrav punch` on both sides through the real gateway
  profiles, no tincd: `--strategies "first second burn burn-keep"`,
  `--spray N` (also send to N ports around the advertised one), `--sync` (a
  rendezvous GO to both sides at once), `--rtt MS`, `--trials N`. Results
  accumulate in `punch/punch.jsonl`; the first trial's gateway conntrack is
  kept as `punch/<pair>/<strategy>-gw-gw?.txt`.

## Files

- `lab.sh` — host wrapper (build the lab image, run one command in it).
- `natlab.sh` — the lab itself (runs inside the container).
- `natprofile.sh` — NAT profiles (runs inside a gateway namespace).
- `udpprobe.py` — NAT classifier used by `validate-nat`.
- `nattrav.py` — reflector/rendezvous, port-allocation map and hole-punch
  client used by `portmap` and `punch` (stdlib only).
- `results/run/<run-id>/` — full output of every run (git-ignored).
- `results/<date>/` — committed, curated evidence (`lab.sh promote`; no keys —
  promote greps for key material and fails if it finds any).
