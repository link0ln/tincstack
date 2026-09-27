# NAT lab summary — 2026-09-27T00:31Z

Cell = seconds until `tinc info <peer>` reported *directly with UDP* on that side; `-` = never within the wait. `expected` = yes (direct UDP must come up), no (pair cannot hole-punch: traffic must still flow via the relay), tcp (UDP blocked: meta/TCP path must carry traffic).

| A x B | image | carrier | expected | direct a->b | direct b->a | ping | verdict |
|---|---|---|---|---|---|---|---|
| fullcone x fullcone | core | plain | yes | 4s | 0s | ok | PASS |
| masq x restricted | core | plain | yes | 4s | 0s | ok | PASS |
| masqfw x masqfw | core | plain | yes | 4s | 0s | ok | PASS |
| portrestricted x portrestricted | core | plain | yes | 6s | 0s | ok | PASS |
| symmetric x symmetric | core | plain | no | - | - | ok | PASS |
| udpblock x portrestricted | core | plain | tcp | - | - | ok | PASS |
