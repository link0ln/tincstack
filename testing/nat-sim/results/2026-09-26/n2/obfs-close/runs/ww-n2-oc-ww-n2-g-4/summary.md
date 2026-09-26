# NAT lab summary — 2026-09-26T23:34Z

Cell = seconds until `tinc info <peer>` reported *directly with UDP* on that side; `-` = never within the wait. `expected` = yes (direct UDP must come up), no (pair cannot hole-punch: traffic must still flow via the relay), tcp (UDP blocked: meta/TCP path must carry traffic).

| A x B | image | carrier | expected | direct a->b | direct b->a | ping | verdict |
|---|---|---|---|---|---|---|---|
| fullcone x fullcone | core | obfs | yes | 4s | 0s | ok | PASS |
| masq x restricted | core | obfs | yes | 8s | 0s | ok | PASS |
| masqfw x masqfw | core | obfs | yes | 4s | 0s | ok | PASS |
| portrestricted x portrestricted | core | obfs | yes | 4s | 0s | ok | PASS |
| restricted x restricted | core | obfs | yes | 6s | 0s | ok | PASS |
| symmetric x restricted | core | obfs | yes | 4s | 3s | ok | PASS |
