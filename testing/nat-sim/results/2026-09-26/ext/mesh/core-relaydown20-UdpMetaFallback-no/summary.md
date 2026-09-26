### mesh — image core, carrier plain, 10 pairs, wait 90s

| A x B | expected | direct a->b | direct b->a | direct both | state at end (a / b) |
|---|---|---|---|---|---|
| fullcone x restricted | yes | 6s | 6s | yes | directly with UDP / directly with UDP |
| fullcone x portrestricted | yes | 8s | 8s | yes | directly with UDP / directly with UDP |
| fullcone x masq | yes | 8s | 6s | yes | directly with UDP / directly with UDP |
| fullcone x symmetric | yes | 6s | 8s | yes | directly with UDP / directly with UDP |
| restricted x portrestricted | yes | 6s | 6s | yes | directly with UDP / directly with UDP |
| restricted x masq | yes | 8s | 8s | yes | directly with UDP / directly with UDP |
| restricted x symmetric | yes | 8s | 8s | yes | directly with UDP / directly with UDP |
| portrestricted x masq | no | 6s | 6s | yes | directly with UDP / directly with UDP |
| portrestricted x symmetric | no | - | - | no | none, forwarded via relay / none, forwarded via relay |
| masq x symmetric | no | - | - | no | none, forwarded via relay / none, forwarded via relay |

- direct: **8/10** pairs (7/7 of the pairs the table calls traversable, 1 beyond it); all traversable pairs direct after 8 s
- relay load, steady state (every ordered pair pings at 1 pps): rx 12.6 pkt/s 1855 B/s, tx 12.7 pkt/s 1858 B/s
- meta connections at the end of the wait (node(type): peer:carrier ...): m1(fullcone): relay:plain <control>:plain; m2(restricted): relay:plain <control>:plain; m3(portrestricted): relay:plain <control>:plain; m4(masq): relay:plain <control>:plain; m5(symmetric): relay:plain <control>:plain
- relay tincd down 20 s, direct pair (5 pps): replies while down 0, longest gap 30.5 s, first reply 10.5 s after the relay restarted
- relay tincd down 20 s, relayed pair (5 pps): replies while down 0, longest gap 30.7 s, first reply 10.7 s after the relay restarted
