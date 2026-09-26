### mesh — image baseline, carrier plain, 10 pairs, wait 90s

| A x B | expected | direct a->b | direct b->a | direct both | state at end (a / b) |
|---|---|---|---|---|---|
| fullcone x restricted | yes | 61s | 61s | yes | directly with UDP / directly with UDP |
| fullcone x portrestricted | yes | 9s | 9s | yes | directly with UDP / directly with UDP |
| fullcone x masq | yes | 18s | 18s | yes | directly with UDP / directly with UDP |
| fullcone x symmetric | yes | 13s | 13s | yes | directly with UDP / directly with UDP |
| restricted x portrestricted | yes | 16s | 16s | yes | directly with UDP / directly with UDP |
| restricted x masq | yes | 20s | 20s | yes | directly with UDP / directly with UDP |
| restricted x symmetric | yes | 32s | 32s | yes | directly with UDP / directly with UDP |
| portrestricted x masq | no | 18s | 18s | yes | directly with UDP / directly with UDP |
| portrestricted x symmetric | no | - | - | no | none, forwarded via relay / none, forwarded via relay |
| masq x symmetric | no | - | - | no | none, forwarded via relay / none, forwarded via relay |

- direct: **8/10** pairs (7/7 of the pairs the table calls traversable, 1 beyond it); all traversable pairs direct after 61 s
- relay load, steady state (every ordered pair pings at 1 pps): rx 13.3 pkt/s 1932 B/s, tx 13.1 pkt/s 1918 B/s
- meta connections at the end of the wait (node(type): peer:carrier ...): m1(fullcone): relay:? <control>:?; m2(restricted): relay:? <control>:?; m3(portrestricted): relay:? <control>:?; m4(masq): relay:? <control>:?; m5(symmetric): relay:? <control>:?
- relay tincd down 20 s, direct pair (5 pps): replies while down 0, longest gap 30.8 s, first reply 10.7 s after the relay restarted
- relay tincd down 20 s, relayed pair (5 pps): replies while down 0, longest gap 30.8 s, first reply 10.6 s after the relay restarted
