# NAT lab summary — 2026-09-26T20:39Z

Cell = seconds until `tinc info <peer>` reported *directly with UDP* on that side; `-` = never within the wait. `expected` = yes (direct UDP must come up), no (pair cannot hole-punch: traffic must still flow via the relay), tcp (UDP blocked: meta/TCP path must carry traffic).

| A x B | image | carrier | expected | direct a->b | direct b->a | ping | verdict |
|---|---|---|---|---|---|---|---|
| cgnat x cgnat | core | plain | no | 4s | 0s | ok | PASS |
| cgnat x masq | core | plain | no | 4s | 0s | ok | PASS |
| masq x masq | core | plain | no | 6s | 0s | ok | PASS |
| masq x portrestricted | core | plain | no | 4s | 0s | ok | PASS |
