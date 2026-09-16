# testing/dpi-proof — wire-image fingerprints of a tinc session

Skeleton for M5: captures what a tinc session looks like on the wire and
reports the byte patterns a DPI box can key on. Each obfuscation tier is later
fed in as a *profile*, and `compare.py` decides whether the tier actually
removed the plain-tinc fingerprints.

Runs in the privileged lab image (`tincstack/natlab:<tag>`, see
`testing/nat-sim/README.md`): two nodes in two network namespaces over one
veth pair, `tcpdump -w` on the peer's end of the veth. Nothing on the host.

```
testing/dpi-proof/run.sh baseline                 # capture plain tinc, assert fingerprints PRESENT
testing/dpi-proof/run.sh capture obfs             # profiles/obfs.conf appended to both tinc.conf (M5)
testing/dpi-proof/run.sh compare results/run/<id>/plain.fingerprint.json results/run/<id>/obfs.fingerprint.json
```

Every run writes into `results/run/<run-id>/` (git-ignored; `<run-id>` =
`$WSF_RUN` or `<date>-<HHMMSS>-<pid>`, shared with the NAT lab under
`make check`). The committed `results/<date>/` tree holds only the curated
`*.report.txt`, `*.fingerprint.json` and `*.pcap`, copied by
`testing/nat-sim/lab.sh promote results/run/<run-id> results/<date>`.

`compare` exits 1 while any fingerprint that was PRESENT in the plain capture
is still PRESENT in the tier's capture, 2 if the tier's capture carried no tinc
traffic at all (tunnel never came up — not a valid comparison), 0 otherwise.

## Fingerprints reported by `fingerprint.py` (stdlib pcap parser)

| id | what | why it identifies tinc |
|---|---|---|
| `tcp_id_line` | first TCP payload bytes match `0 <name> 17.x\n` | tinc's cleartext ID request, both directions, carries the node *name* and protocol version |
| `tcp_sptps_handshake` | right after the banner: `[len:2][0x80]` + KEX body (65/64 bytes observed) | SPTPS handshake record type 128 in the clear on the meta connection |
| `udp_null_dstid` | datagram starts with 6 zero bytes | tinc ≥ 17.4 "direct path" null destination node id in front of every SPTPS datagram |
| `udp_constant_srcid` | bytes 6–11 identical for every datagram from one sender | the sender's node id in the clear |
| `udp_seqno_counter` | bytes 12–15 = big-endian counter, +1 per datagram, starting near 0 | SPTPS datagram sequence number in the clear |
| `udp_probe_size` | ≥ 3 datagrams of exactly 51 bytes | tinc's minimum UDP probe: 18 B + 21 B SPTPS + 12 B ids |
| `udp_size_histogram` | informative | e.g. plain: 51 (probes), 81 (small ping), 261 (200-byte ping), 1472 (PMTU probe) |

Layout of a plain tinc 1.1 UDP datagram as captured:
`[dst node id 6 = 000000000000][src node id 6][seqno 4 BE][ChaCha20-Poly1305(type ‖ payload)][tag 16]`.

Only the payload after the 16-byte header is encrypted; everything a tier must
hide is in those first 16 bytes plus the sizes/timing, and the TCP banner.

## Baseline (proof for the M9 box)

`results/2026-09-16/plain.report.txt` — all six fingerprints PRESENT on the
core's plain wire image (`plain.fingerprint.json` + `plain.pcap` next to it;
the tincd logs of that capture were not kept). `run.sh compare plain plain`
exits 1 (self-test of the harness: an unchanged wire image must fail).

## Adding a tier (M5)

1. `profiles/<tier>.conf` — the tinc.conf lines that enable the tier on both nodes.
2. `run.sh capture <tier>` → `results/run/<id>/<tier>.fingerprint.json`.
3. `run.sh compare results/run/<id>/plain.fingerprint.json results/run/<id>/<tier>.fingerprint.json`.
4. Extend `fingerprint.py` when a tier introduces a *new* pattern worth
   guarding (e.g. a fixed TLS SNI, a constant QUIC connection-id length).
