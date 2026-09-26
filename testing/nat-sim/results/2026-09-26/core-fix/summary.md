# NAT lab summary — 2026-09-26T01:30Z

Cell = seconds until `tinc info <peer>` reported *directly with UDP* on that side; `-` = never within the wait. `expected` = yes (direct UDP must come up), no (pair cannot hole-punch: traffic must still flow via the relay), tcp (UDP blocked: meta/TCP path must carry traffic).

| A x B | image | carrier | expected | direct a->b | direct b->a | ping | verdict |
|---|---|---|---|---|---|---|---|
| fullcone x fullcone | core | plain | yes | 6s | 0s | ok | PASS |
| masq x masq | core | https | tcp | - | - | ok | PASS |
| masq x restricted | core | plain | yes | 10s | 0s | ok | PASS |
| portrestricted x portrestricted | core | https | tcp | - | - | ok | PASS |
| portrestricted x portrestricted | core | plain | yes | 10s | 0s | ok | PASS |
| restricted x restricted | core | https | tcp | - | - | ok | PASS |
| restricted x restricted | core | plain | yes | - | - | ok | FAIL |
| symmetric x restricted | core | https | tcp | - | - | ok | PASS |
| symmetric x symmetric | core | plain | no | - | - | ok | PASS |
| udpblock x portrestricted | core | plain | tcp | - | - | ok | PASS |
