### mesh — image baseline, carrier plain, 10 pairs, wait 90s

| A x B | expected | direct a->b | direct b->a | direct both | state at end (a / b) |
|---|---|---|---|---|---|
| fullcone x restricted | yes | 15s | 15s | yes | directly with UDP / directly with UDP |
| fullcone x portrestricted | yes | 13s | 13s | yes | directly with UDP / directly with UDP |
| fullcone x masq | yes | 13s | 15s | yes | directly with UDP / directly with UDP |
| fullcone x symmetric | yes | 34s | 34s | yes | directly with UDP / directly with UDP |
| restricted x portrestricted | yes | 15s | 13s | yes | directly with UDP / directly with UDP |
| restricted x masq | yes | 31s | 29s | yes | directly with UDP / directly with UDP |
| restricted x symmetric | yes | 13s | 13s | yes | directly with UDP / directly with UDP |
| portrestricted x masq | no | - | - | no | none, forwarded via relay / none, forwarded via relay |
| portrestricted x symmetric | no | - | - | no | none, forwarded via relay / none, forwarded via relay |
| masq x symmetric | no | - | - | no | none, forwarded via relay / none, forwarded via relay |

- direct: **7/10** pairs (7/7 of the pairs the table calls traversable, 0 beyond it); all traversable pairs direct after 34 s
- relay load, steady state (every ordered pair pings at 1 pps): rx 18.1 pkt/s 2652 B/s, tx 17.9 pkt/s 2630 B/s
- meta connections at the end of the wait (node(type): peer:carrier ...): m1(fullcone): relay:? <control>:?; m2(restricted): relay:? <control>:?; m3(portrestricted): relay:? <control>:?; m4(masq): relay:? <control>:?; m5(symmetric): relay:? <control>:?
