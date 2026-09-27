# NAT lab summary — 2026-09-27T01:08Z

Cell = seconds until `tinc info <peer>` reported *directly with UDP* on that side; `-` = never within the wait. `expected` = yes (direct UDP must come up), no (pair cannot hole-punch: traffic must still flow via the relay), tcp (UDP blocked: meta/TCP path must carry traffic).

| A x B | image | carrier | expected | direct a->b | direct b->a | ping | verdict |
|---|---|---|---|---|---|---|---|
| fullcone x fullcone | core | https | tcp | - | - | ok | PASS |
| masq x restricted | core | https | tcp | - | - | ok | PASS |
| masqfw x masqfw | core | https | tcp | - | - | ok | PASS |
| portrestricted x portrestricted | core | https | tcp | - | - | ok | PASS |
| restricted x restricted | core | https | tcp | - | - | ok | PASS |
| symmetric x restricted | core | https | tcp | - | - | ok | PASS |
