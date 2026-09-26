### SPTPS rekey on a direct pair (KeyExpire on every node; counted over a window after the pair went direct)

| A x B | image (extra config) | KeyExpire | window | rekeys (A) | A: peer UDP address reset | B: peer UDP address reset | A->B packets via relay / direct | relayed share | ping replies / sent | longest ping gap |
|---|---|---|---|---|---|---|---|---|---|---|
| restricted x symmetric | baseline | 20 s | 120 s | 6 | 46 | 36 | 206 / 464 | 0.307 | 578 / 600 | 0.22 s |
| restricted x symmetric | core (UdpMetaFallback=no) | 20 s | 120 s | 6 | 48 | 36 | 61 / 649 | 0.086 | 578 / 600 | 0.25 s |
| restricted x symmetric | core | 20 s | 120 s | 6 | 0 | 0 | 0 / 641 | 0.0 | 578 / 600 | 0.21 s |
| restricted x symmetric | core | 3600 s | 120 s | 0 | 0 | 0 | 0 / 631 | 0.0 | 577 / 600 | 0.21 s |
