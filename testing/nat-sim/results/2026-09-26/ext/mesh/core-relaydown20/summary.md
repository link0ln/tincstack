### mesh — image core, carrier plain, 10 pairs, wait 90s

| A x B | expected | direct a->b | direct b->a | direct both | state at end (a / b) |
|---|---|---|---|---|---|
| fullcone x restricted | yes | 6s | 6s | yes | directly with UDP / directly with UDP |
| fullcone x portrestricted | yes | 8s | 8s | yes | directly with UDP / directly with UDP |
| fullcone x masq | yes | 10s | 10s | yes | directly with UDP / directly with UDP |
| fullcone x symmetric | yes | 8s | 8s | yes | directly with UDP / directly with UDP |
| restricted x portrestricted | yes | 8s | 6s | yes | directly with UDP / directly with UDP |
| restricted x masq | yes | 8s | 8s | yes | directly with UDP / directly with UDP |
| restricted x symmetric | yes | 8s | 8s | yes | directly with UDP / directly with UDP |
| portrestricted x masq | no | 6s | 6s | yes | directly with UDP / directly with UDP |
| portrestricted x symmetric | no | - | - | no | none, forwarded via m1 / none, forwarded via m1 |
| masq x symmetric | no | - | - | no | none, forwarded via m2 / none, forwarded via m2 |

- direct: **8/10** pairs (7/7 of the pairs the table calls traversable, 1 beyond it); all traversable pairs direct after 10 s
- relay load, steady state (every ordered pair pings at 1 pps): rx 2.0 pkt/s 171 B/s, tx 2.0 pkt/s 171 B/s
- meta connections at the end of the wait (node(type): peer:carrier ...): m1(fullcone): relay:plain m5:sf m3:sf <control>:plain; m2(restricted): m5:sf m3:sf m4:sf <control>:plain; m3(portrestricted): m4:sf m2:sf m1:sf <control>:plain; m4(masq): m3:sf relay:plain m2:sf <control>:plain; m5(symmetric): relay:plain m2:sf m1:sf <control>:plain
- relay tincd down 20 s, direct pair (5 pps): replies while down 96, longest gap 0.2 s, first reply 0.1 s after the relay restarted
- relay tincd down 20 s, relayed pair (5 pps): replies while down 96, longest gap 0.2 s, first reply 0.0 s after the relay restarted
