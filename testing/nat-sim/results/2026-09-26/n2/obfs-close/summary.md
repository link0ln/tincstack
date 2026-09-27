# obfs black hole after a stalled dial's close (N2, found in the final regression)

Symptom: `lab.sh matrix --image core --transport obfs` -- a pair reports
"directly with UDP" on both ends and pings 0 %. One end logs "Received UDP
packet from <peer> ... with unknown source and/or destination ID" for every
datagram the peer sends.

Cause (`obfs.c obfs_close()`): both ends AutoConnect to each other over obfs
at the same second and both dials stall (neither address accepts a dial). The
end whose dial times out first falls back to a dial over the confirmed UDP
data path (`UdpMetaFallback`), which activates and keys the link
(`OBFS_KEY`); or the pair has just keyed its sealed direct path
(`DSEAL_KEX`). Then the other end's own stalled dial times out, and its close
reset the shared per-node obfs link -- keys included -- because the survivor
scan looked for `c->node`, which is NULL before `ack_h()`. That end then opens
nothing its peer seals, and with the link marked inactive it never re-keys
until the meta connection dies (~15 s, one observation: `ww-n2-final-cap`).

Fix: b1c71d7 (survivor scan by the link's node; a connection that never
authenticated never drops the link's keys). Deterministic proof: `fuzz_obfs`
self-test `selftest_unauth_close_keeps_session` (aborts on the old code and on
the survivor-scan half alone).

Lab, six expected-direct pairs per run (fullcone/fullcone,
restricted/restricted, portrestricted/portrestricted, masq/restricted,
masqfw/masqfw, symmetric/restricted), `runs/*/summary.md`:

| image | runs | pair-runs FAIL (ping 0) | runs with a FAIL |
|---|---|---|---|
| before: `ww-n2` = bc86d234ee94 (`ww-n2-final-mat-obfs`, `ww-n2-fg-ww-n2-obfs-{1,2}`, `ww-n2-oc-ww-n2-pre-g-{1..5}`) | 8 | 5 of 48 (masq x restricted 3, symmetric x restricted 1, portrestricted x portrestricted 1) | 5 of 8 |
| before + a discarded fallback tie-break (`ww-n2-f`, same `obfs_close`) | 2 | 1 of 12 (masq x restricted) | 1 of 2 |
| after: `ww-n2-g` (b1c71d7 code; `ww-n2-oc-ww-n2-g-{1..5}`) | 5 | **0 of 30** | **0 of 5** |

Runs failing, before (both images) vs after: 6/10 vs 0/5, Fisher exact
one-sided p = 0.04. Small n; the mechanism is proven by the self-test and by
the log trace below, not by this count alone.

Log trace (`race.py`, node logs in `results/run/`): "race fired" = a node's
own dial to the peer's port 655 timed out in authentication after a
connection with that peer on another port had been activated or a DSEAL_KEX
session with it established; then the count of "unknown source and/or
destination ID" lines from that peer on that node.

- before: every FAIL above has the race followed by 11-37 such lines; one
  more (`pre-g-3`, masq x restricted, 10 lines) came after the lab's ping
  check and counted as PASS. Races followed by 0-4 lines are the benign cases
  (the wiped side's self-heal won, or nothing was sealed under the session).
- after: the race fired in 7 pair-runs; each was followed by 0-1 such lines
  (one datagram across the key switch) and every pair pinged.

`repro-runs.txt`: the first reproduction, when a double UDP-fallback dial
(glare) was the suspect. quic rows PASS throughout -- quic has no per-node
link keys to wipe. The tie-break experiment (`ww-n2-f`) failed 1 of 2 and
was discarded; it is not in the branch.
