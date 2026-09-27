# NAT lab summary — 2026-09-26T19:03Z

Cell = seconds until `tinc info <peer>` reported *directly with UDP* on that side; `-` = never within the wait. `expected` = yes (direct UDP must come up), no (pair cannot hole-punch: traffic must still flow via the relay), tcp (UDP blocked: meta/TCP path must carry traffic).

| A x B | image | carrier | expected | direct a->b | direct b->a | ping | verdict |
|---|---|---|---|---|---|---|---|
| fullcone x fullcone | core | quic | yes | 6s | 0s | ok | PASS |
| masqfw x masqfw | core | quic | yes | 4s | 0s | ok | PASS |
| restricted x restricted | core | quic | yes | 6s | 0s | ok | PASS |
