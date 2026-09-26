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

