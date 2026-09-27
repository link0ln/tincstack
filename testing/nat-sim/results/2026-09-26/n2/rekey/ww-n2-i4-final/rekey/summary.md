### SPTPS rekey on a direct pair (KeyExpire on every node; counted over a window after the pair went direct)

| A x B | image (extra config) | KeyExpire | window | rekeys (A) | A: peer UDP address reset | B: peer UDP address reset | A->B packets via relay / direct | relayed share | ping replies / sent | longest ping gap |
|---|---|---|---|---|---|---|---|---|---|---|
| restricted x symmetric | core (UdpMetaFallback=no) | 20 s | 120 s | 6 | 0 | 0 | 0 / 634 | 0.0 | 580 / 600 | 0.23 s |
