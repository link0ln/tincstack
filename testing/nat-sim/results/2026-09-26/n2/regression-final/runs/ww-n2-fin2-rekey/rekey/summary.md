### SPTPS rekey on a direct pair (KeyExpire on every node; counted over a window after the pair went direct)

| A x B | image (extra config) | KeyExpire | window | rekeys (A) | A: peer UDP address reset | B: peer UDP address reset | A->B packets via relay / direct | relayed share | ping replies / sent | longest ping gap |
|---|---|---|---|---|---|---|---|---|---|---|
| restricted x symmetric | baseline (UdpMetaFallback=no) | 20 s | 120 s | 6 | 38 | 33 | 143 / 515 | 0.217 | 578 / 600 | 0.42 s |
| restricted x symmetric | core (UdpMetaFallback=no) | 20 s | 120 s | 6 | 0 | 0 | 0 / 632 | 0.0 | 577 / 600 | 0.42 s |
