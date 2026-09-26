# NAT lab summary — 2026-09-26T18:44Z

Cell = seconds until `tinc info <peer>` reported *directly with UDP* on that side; `-` = never within the wait. `expected` = yes (direct UDP must come up), no (pair cannot hole-punch: traffic must still flow via the relay), tcp (UDP blocked: meta/TCP path must carry traffic).

| A x B | image | carrier | expected | direct a->b | direct b->a | ping | verdict |
|---|---|---|---|---|---|---|---|
| masq x restricted | core | quic | yes | - | - | FAIL | FAIL |
| portrestricted x portrestricted | core | quic | yes | - | - | FAIL | FAIL |
| symmetric x restricted | core | quic | yes | - | - | FAIL | FAIL |
