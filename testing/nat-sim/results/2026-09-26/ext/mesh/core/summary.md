### mesh — image core, carrier plain, 10 pairs, wait 90s

| A x B | expected | direct a->b | direct b->a | direct both | state at end (a / b) |
|---|---|---|---|---|---|
| fullcone x restricted | yes | 8s | 8s | yes | directly with UDP / directly with UDP |
| fullcone x portrestricted | yes | 8s | 8s | yes | directly with UDP / directly with UDP |
| fullcone x masq | yes | 8s | 8s | yes | directly with UDP / directly with UDP |
| fullcone x symmetric | yes | 8s | 8s | yes | directly with UDP / directly with UDP |
| restricted x portrestricted | yes | 8s | 8s | yes | directly with UDP / directly with UDP |
| restricted x masq | yes | 8s | 8s | yes | directly with UDP / directly with UDP |
| restricted x symmetric | yes | 8s | 8s | yes | directly with UDP / directly with UDP |
| portrestricted x masq | no | - | - | no | none, forwarded via relay / none, forwarded via relay |
| portrestricted x symmetric | no | - | - | no | none, forwarded via m2 / none, forwarded via m2 |
| masq x symmetric | no | - | - | no | none, forwarded via m1 / none, forwarded via m1 |

- direct: **7/10** pairs (7/7 of the pairs the table calls traversable, 0 beyond it); all traversable pairs direct after 8 s
- relay load, steady state (every ordered pair pings at 1 pps): rx 7.0 pkt/s 1040 B/s, tx 7.0 pkt/s 1036 B/s
- meta connections at the end of the wait (node(type): peer:carrier ...): m1(fullcone): m4:sf m3:sf m5:sf <control>:plain; m2(restricted): m5:sf m4:sf m3:sf <control>:plain; m3(portrestricted): relay:plain m1:sf m2:sf <control>:plain; m4(masq): relay:plain m1:sf m2:sf <control>:plain; m5(symmetric): relay:plain m2:sf m1:sf <control>:plain
