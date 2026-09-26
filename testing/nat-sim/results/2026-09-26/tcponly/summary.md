# NAT lab summary — 2026-09-26T02:08Z

Cell = seconds until `tinc info <peer>` reported *directly with UDP* on that side; `-` = never within the wait. `expected` = yes (direct UDP must come up), no (pair cannot hole-punch: traffic must still flow via the relay), tcp (UDP blocked: meta/TCP path must carry traffic).

| A x B | image | carrier | expected | direct a->b | direct b->a | ping | verdict |
|---|---|---|---|---|---|---|---|
| fullcone x fullcone | baseline | plain | tcp | - | - | FAIL | FAIL |
| fullcone x fullcone | core | plain | tcp | - | - | FAIL | FAIL |
| restricted x restricted | baseline | plain | tcp | - | - | FAIL | FAIL |
| restricted x restricted | core | plain | tcp | - | - | FAIL | FAIL |
