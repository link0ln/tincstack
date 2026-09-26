# quic: stream bytes handed to ngtcp2 must not move until acknowledged

`testing/transports/quic-loss-test.sh`, 2026-09-26. Fix: commit 175bd51
(`quic_txq.c`: a chunk list whose chunks never move; the meta stream, the
unidirectional streams and the decoder stream all send from one).

| run | image | result | log |
| --- | --- | --- | --- |
| meta, quic, TCPOnly, 10 % loss + 10 ms both ways, 2000 x 1200 B pings | `ww-q-base` (master 5076472) | **FAIL**, exit 1: 2/2000 answered, link dead afterwards, the leaf dialled twice | `loss-meta-base.txt` |
| same | `ww-q0` (175bd51) | PASS, exit 0: 2000/2000, still on quic, dialled once | `loss-meta-fix.txt` |
| same over `https` (reference) | `ww-q-base` | PASS, exit 0: 2000/2000 | `loss-meta-https.txt` |
| qpack: aioquic, 20 connections x 40 GETs with repeating fields (the listener's decoder stream grows), 10 % loss, ASan tincd | `ww-q-asan-base` (master, `-Db_sanitize=address`) | **FAIL**, exit 1: `heap-use-after-free` read in `ngtcp2_pkt_encode_stream_frame` <- `quic_flush`, freed by `xrealloc` in `decoder_append` | `loss-qpack-asan-base.txt` |
| same | `ww-q0-asan` (175bd51, ASan) | PASS, exit 0: every connection answered, tincd runs, no ASan report | `loss-qpack-asan-fix.txt` |

The final tree (ed58a14, ASan) passes both sections too (exit 0).
