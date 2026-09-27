# NAT lab summary — 2026-09-27T00:54Z

Cell = seconds until `tinc info <peer>` reported *directly with UDP* on that side; `-` = never within the wait. `expected` = yes (direct UDP must come up), no (pair cannot hole-punch: traffic must still flow via the relay), tcp (UDP blocked: meta/TCP path must carry traffic).

| A x B | image | carrier | expected | direct a->b | direct b->a | ping | verdict |
|---|---|---|---|---|---|---|---|
| fullcone x fullcone | core | plain | yes | 4s | 0s | ok | PASS |
| fullcone x masq | core | plain | yes | 6s | 0s | ok | PASS |
| fullcone x portrestricted | core | plain | yes | 4s | 0s | ok | PASS |
| fullcone x restricted | core | plain | yes | 4s | 0s | ok | PASS |
| fullcone x symmetric | core | plain | yes | 6s | 0s | ok | PASS |
| masq x fullcone | core | plain | yes | 4s | 0s | ok | PASS |
| masq x masq | core | plain | no | - | - | ok | PASS |
| masq x portrestricted | core | plain | no | 6s | 0s | ok | PASS |
| masq x restricted | core | plain | yes | 4s | 0s | ok | PASS |
| masq x symmetric | core | plain | no | - | - | ok | PASS |
| portrestricted x fullcone | core | plain | yes | 6s | 0s | ok | PASS |
| portrestricted x masq | core | plain | no | 4s | 0s | ok | PASS |
| portrestricted x portrestricted | core | plain | yes | 4s | 0s | ok | PASS |
| portrestricted x restricted | core | plain | yes | 6s | 0s | ok | PASS |
| portrestricted x symmetric | core | plain | no | - | - | ok | PASS |
| restricted x fullcone | core | plain | yes | 6s | 0s | ok | PASS |
| restricted x masq | core | plain | yes | 6s | 0s | ok | PASS |
| restricted x portrestricted | core | plain | yes | 6s | 0s | ok | PASS |
| restricted x restricted | core | plain | yes | 4s | 0s | ok | PASS |
| restricted x symmetric | core | plain | yes | 6s | 0s | ok | PASS |
| symmetric x fullcone | core | plain | yes | 6s | 0s | ok | PASS |
| symmetric x masq | core | plain | no | - | - | ok | PASS |
| symmetric x portrestricted | core | plain | no | - | - | ok | PASS |
| symmetric x restricted | core | plain | yes | 8s | 0s | ok | PASS |
| symmetric x symmetric | core | plain | no | - | - | ok | PASS |
| udpblock x fullcone | core | plain | tcp | - | - | ok | PASS |
| udpblock x portrestricted | core | plain | tcp | - | - | ok | PASS |
| udpblock x udpblock | core | plain | tcp | - | - | ok | PASS |
