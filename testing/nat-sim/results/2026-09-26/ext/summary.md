# NAT lab summary — 2026-09-26T01:48Z

Cell = seconds until `tinc info <peer>` reported *directly with UDP* on that side; `-` = never within the wait. `expected` = yes (direct UDP must come up), no (pair cannot hole-punch: traffic must still flow via the relay), tcp (UDP blocked: meta/TCP path must carry traffic).

| A x B | image | carrier | expected | direct a->b | direct b->a | ping | verdict |
|---|---|---|---|---|---|---|---|
| cgnat x cgnat | baseline | plain | no | - | - | ok | PASS |
| cgnat x cgnat | core | plain | no | - | - | ok | PASS |
| cgnat x fullcone | core | plain | yes | 6s | 2s | ok | PASS |
| cgnat x masq | core | plain | no | - | - | ok | PASS |
| cgnat x masqfw | core | plain | no | 4s | 0s | ok | PASS |
| cgnat x restricted | core | plain | yes | 6s | 0s | ok | PASS |
| fullcone x fullcone | core | quic | yes | - | - | ok | FAIL |
| masq x masq | core | https | no | - | - | FAIL | FAIL |
| masq x masq | core | quic | no | - | - | ok | PASS |
| masq x masq | core | plain +v6both | no | 4s | 0s | ok | PASS |
| masq x masqfw | core | plain | no | 10s | 0s | ok | PASS |
| masq x portrestricted | core | quic | no | - | - | ok | PASS |
| masq x restricted | core | obfs | yes | - | - | FAIL | FAIL |
| masq x restricted | core | plain +v6a | yes | - | - | ok | FAIL |
| masq x symmetric | core | quic | no | - | - | ok | PASS |
| masqfw x masqfw | baseline | plain | yes | 4s | 0s | ok | PASS |
| masqfw x masqfw | core | quic | yes | 4s | 0s | ok | PASS |
| masqfw x masqfw | core | plain | yes | 4s | 0s | ok | PASS |
| masqfw x portrestricted | core | plain | yes | 6s | 2s | ok | PASS |
| masqfw x restricted | core | plain | yes | 6s | 0s | ok | PASS |
| masqfw x symmetric | core | plain | no | - | - | ok | PASS |
| portrestricted x portrestricted | core | https | yes | - | - | FAIL | FAIL |
| portrestricted x symmetric | core | quic | no | - | - | ok | PASS |
| restricted x restricted | core | https | yes | - | - | FAIL | FAIL |
| restricted x restricted | core | obfs | yes | 6s | 0s | ok | PASS |
| restricted x restricted | core | quic | yes | - | - | ok | FAIL |
| restricted x restricted | core | plain | yes | 6s | 0s | ok | PASS |
| symmetric x restricted | core | https | yes | - | - | FAIL | FAIL |
| symmetric x symmetric | core | quic | no | - | - | ok | PASS |
| symmetric x symmetric | core | plain +v6both | no | 4s | 0s | ok | PASS |

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


### SPTPS rekey on a direct pair (KeyExpire on every node; counted over a window after the pair went direct)

| A x B | image (extra config) | KeyExpire | window | rekeys (A) | A: peer UDP address reset | B: peer UDP address reset | A->B packets via relay / direct | relayed share | ping replies / sent | longest ping gap |
|---|---|---|---|---|---|---|---|---|---|---|
| restricted x symmetric | baseline | 20 s | 120 s | 6 | 46 | 36 | 206 / 464 | 0.307 | 578 / 600 | 0.22 s |
| restricted x symmetric | core (UdpMetaFallback=no) | 20 s | 120 s | 6 | 48 | 36 | 61 / 649 | 0.086 | 578 / 600 | 0.25 s |
| restricted x symmetric | core | 20 s | 120 s | 6 | 0 | 0 | 0 / 641 | 0.0 | 578 / 600 | 0.21 s |
| restricted x symmetric | core | 3600 s | 120 s | 0 | 0 | 0 | 0 / 631 | 0.0 | 577 / 600 | 0.21 s |

### NAT port allocation (nattrav portmap; one inside socket, destinations in order)

A: ip1:3478, ip1:3479, ip2:3478, ip2:3479, ip3:3478 -- nothing unsolicited. P: ip1:3478, then ip2:3478 and ip1:3479 each send one unsolicited datagram to the mapping (`poke`), then ip3:3478, ip2:3478 (poked), ip1:3479 (poked), ip3:3479. C (masq/masqfw, unreplied UDP timeout 5 s): a burn datagram nobody answers, ip1:3478, ip2:3478, 10 s with the answered flows kept alive, ip3:3479, ip2:3479.

| NAT | trial | sequence | external port per destination (poke: arrived?) | first keeps source port | later destinations share one port |
|---|---|---|---|---|---|
| masq | 1 | A-nopoke-sport655 | 20:3478->655, 20:3479->655, 21:3478->655, 21:3479->655, 22:3478->655 | True | True |
| masq | 1 | P-poked-sport656 | 20:3478->656, poke:dropped, poke:dropped, 22:3478->656, 21:3478->935, 20:3479->935, 22:3479->935 | True | False |
| masq | 1 | P-poked-sport4004 | 20:3478->4004, poke:dropped, poke:dropped, 22:3478->4004, 21:3478->60376, 20:3479->60376, 22:3479->60376 | True | False |
| masq | 1 | C-burn-then-expire | burn, 20:3478->657, 21:3478->657, 22:3479->657, 21:3479->657 | True | True |
| masq | 2 | A-nopoke-sport655 | 20:3478->655, 20:3479->655, 21:3478->655, 21:3479->655, 22:3478->655 | True | True |
| masq | 2 | P-poked-sport656 | 20:3478->656, poke:dropped, poke:dropped, 22:3478->656, 21:3478->647, 20:3479->647, 22:3479->647 | True | False |
| masq | 2 | P-poked-sport4004 | 20:3478->4004, poke:dropped, poke:dropped, 22:3478->4004, 21:3478->44401, 20:3479->44401, 22:3479->44401 | True | False |
| masq | 2 | C-burn-then-expire | burn, 20:3478->657, 21:3478->657, 22:3479->657, 21:3479->657 | True | True |
| masqfw | 1 | A-nopoke-sport655 | 20:3478->655, 20:3479->655, 21:3478->655, 21:3479->655, 22:3478->655 | True | True |
| masqfw | 1 | P-poked-sport656 | 20:3478->656, poke:dropped, poke:dropped, 22:3478->656, 21:3478->656, 20:3479->656, 22:3479->656 | True | True |
| masqfw | 1 | P-poked-sport4004 | 20:3478->4004, poke:dropped, poke:dropped, 22:3478->4004, 21:3478->4004, 20:3479->4004, 22:3479->4004 | True | True |
| masqfw | 1 | C-burn-then-expire | burn, 20:3478->657, 21:3478->657, 22:3479->657, 21:3479->657 | True | True |
| masqfw | 2 | A-nopoke-sport655 | 20:3478->655, 20:3479->655, 21:3478->655, 21:3479->655, 22:3478->655 | True | True |
| masqfw | 2 | P-poked-sport656 | 20:3478->656, poke:dropped, poke:dropped, 22:3478->656, 21:3478->656, 20:3479->656, 22:3479->656 | True | True |
| masqfw | 2 | P-poked-sport4004 | 20:3478->4004, poke:dropped, poke:dropped, 22:3478->4004, 21:3478->4004, 20:3479->4004, 22:3479->4004 | True | True |
| masqfw | 2 | C-burn-then-expire | burn, 20:3478->657, 21:3478->657, 22:3479->657, 21:3479->657 | True | True |
| cgnat | 1 | A-nopoke-sport655 | 20:3478->655, 20:3479->655, 21:3478->655, 21:3479->655, 22:3478->655 | True | True |
| cgnat | 1 | P-poked-sport656 | 20:3478->656, poke:dropped, poke:dropped, 22:3478->656, 21:3478->766, 20:3479->766, 22:3479->766 | True | False |
| cgnat | 1 | P-poked-sport4004 | 20:3478->4004, poke:dropped, poke:dropped, 22:3478->4004, 21:3478->57361, 20:3479->57361, 22:3479->57361 | True | False |
| cgnat | 2 | A-nopoke-sport655 | 20:3478->655, 20:3479->655, 21:3478->655, 21:3479->655, 22:3478->655 | True | True |
| cgnat | 2 | P-poked-sport656 | 20:3478->656, poke:dropped, poke:dropped, 22:3478->656, 21:3478->1010, 20:3479->1010, 22:3479->1010 | True | False |
| cgnat | 2 | P-poked-sport4004 | 20:3478->4004, poke:dropped, poke:dropped, 22:3478->4004, 21:3478->38517, 20:3479->38517, 22:3479->38517 | True | False |
| symmetric | 1 | A-nopoke-sport655 | 20:3478->932, 20:3479->787, 21:3478->882, 21:3479->755, 22:3478->929 | False | False |
| symmetric | 1 | P-poked-sport656 | 20:3478->876, poke:dropped, poke:dropped, 22:3478->879, 21:3478->740, 20:3479->807, 22:3479->605 | False | False |
| symmetric | 1 | P-poked-sport4004 | 20:3478->52737, poke:dropped, poke:dropped, 22:3478->30974, 21:3478->28307, 20:3479->48336, 22:3479->37241 | False | False |
| symmetric | 2 | A-nopoke-sport655 | 20:3478->617, 20:3479->752, 21:3478->731, 21:3479->639, 22:3478->649 | False | False |
| symmetric | 2 | P-poked-sport656 | 20:3478->986, poke:dropped, poke:dropped, 22:3478->913, 21:3478->636, 20:3479->912, 22:3479->607 | False | False |
| symmetric | 2 | P-poked-sport4004 | 20:3478->3067, poke:dropped, poke:dropped, 22:3478->36446, 21:3478->1909, 20:3479->3644, 22:3479->17496 | False | False |

### Hole punch without tinc (nattrav punch; both sides send every 100 ms for 8 s to the address the other advertised)

strategy: `first` = advertise what the rendezvous (first destination) saw -- what tinc's UDP_INFO/ANS_KEY carry today; `second` = advertise what a second reflector port on the same host saw; `burn` = one throwaway datagram before the rendezvous, advertise the rendezvous' view; `+sprayN` = also send to N ports around the advertised one; `+sync` = neither side sends to the other before the rendezvous says GO to both at once; `+rttN` = netem on every gateway's external interface.

| A x B | strategy | bidirectional contact | median time to contact | advertised ports (a/b, per trial) |
|---|---|---|---|---|
| masq x masq | first | 0/3 | - | 655/655 |
| masq x masq | second | 0/3 | - | 655/655 |
| masqfw x masqfw | first | 3/3 | 0.50 s | 655/655 |
| masqfw x masqfw | second | 3/3 | 0.50 s | 655/655 |
| masq x portrestricted | first | 2/3 | 0.00 s | 655/41655 |
| masq x portrestricted | second | 1/3 | 0.50 s | 655/41655 |
| masqfw x portrestricted | first | 3/3 | 0.50 s | 655/41655 |
| masqfw x portrestricted | second | 3/3 | 0.00 s | 655/41655 |
| masq x symmetric | first | 0/3 | - | 655/1003 655/744 655/766 |
| masq x symmetric | second | 0/3 | - | 655/817 655/920 655/972 |
| cgnat x cgnat | first | 0/3 | - | 655/655 |
| cgnat x cgnat | second | 0/3 | - | 655/655 |
| symmetric x symmetric | first | 0/3 | - | 1002/609 673/702 888/983 |
| symmetric x symmetric | second | 0/3 | - | 608/929 843/835 886/939 |
| restricted x masq | first | 3/3 | 0.49 s | 40655/655 |
| restricted x masq | second | 3/3 | 0.00 s | 40655/655 |
| masqfw x symmetric | first+spray848 | 2/3 | 0.50 s | 655/699 655/811 655/861 |
| portrestricted x symmetric | first+spray848 | 3/3 | 0.01 s | 40655/829 40655/931 40655/976 |
| masq x symmetric | first+spray848 | 0/3 | - | 655/692 655/702 655/719 |
| symmetric x symmetric | first+spray848 | 0/3 | - | 653/983 665/896 896/1005 |
| masq x masq | first+rtt40 | 3/3 | 0.04 s | 655/655 |
| masq x symmetric | first+spray848+sync+rtt40 | 3/3 | 0.12 s | 655/676 655/767 655/975 |
| masqfw x symmetric | first+spray848+sync+rtt40 | 3/3 | 0.13 s | 655/654 655/757 655/795 |
| cgnat x symmetric | first+spray848+sync+rtt40 | 3/3 | 0.07 s | 655/1012 655/777 655/846 |
| masq x masq | first+sync | 3/3 | 0.00 s | 655/655 |
| masq x portrestricted | first+sync | 3/3 | 0.00 s | 655/41655 |
| cgnat x cgnat | first+sync | 2/3 | 0.00 s | 655/655 |
| masq x masqfw | first+sync | 2/3 | 0.00 s | 655/655 |
| masq x masq | first+sync+rtt40 | 3/3 | 0.04 s | 655/655 |
| masq x portrestricted | first+sync+rtt40 | 3/3 | 0.04 s | 655/41655 |
| cgnat x cgnat | first+sync+rtt40 | 3/3 | 0.06 s | 655/655 |
| masq x symmetric | first+spray848+rtt40 | 3/3 | 0.14 s | 655/1012 655/812 655/886 |
| masqfw x symmetric | first+spray848+rtt40 | 3/3 | 0.14 s | 655/604 655/768 655/897 |
| symmetric x symmetric | first+spray848+rtt40 | 3/3 | 0.14 s | 670/912 729/869 957/989 |
| symmetric x symmetric | first+spray848+sync+rtt40 | 1/3 | 0.06 s | 660/810 767/722 892/999 |

## NAT emulation self-check (udpprobe)

```
fullcone: {"sport": 4001, "obs": {"s1": ["100.64.0.2", 40655], "s1b": ["100.64.0.2", 40655], "s2": ["100.64.0.2", 40655], "s2b": ["100.64.0.2", 40655]}, "xport": true, "xhost": true, "mapping": "EIM", "filtering": "EIF", "type": "fullcone", "port_preserving": false, "expect": "fullcone", "ok": true}
restricted: {"sport": 4002, "obs": {"s1": ["100.64.0.2", 40655], "s1b": ["100.64.0.2", 40655], "s2": ["100.64.0.2", 40655], "s2b": ["100.64.0.2", 40655]}, "xport": true, "xhost": false, "mapping": "EIM", "filtering": "ADF", "type": "restricted", "port_preserving": false, "expect": "restricted", "ok": true}
portrestricted: {"sport": 4003, "obs": {"s1": ["100.64.0.2", 40655], "s1b": ["100.64.0.2", 40655], "s2": ["100.64.0.2", 40655], "s2b": ["100.64.0.2", 40655]}, "xport": false, "xhost": false, "mapping": "EIM", "filtering": "APDF", "type": "portrestricted", "port_preserving": false, "expect": "portrestricted", "ok": true}
masq: {"sport": 4004, "obs": {"s1": ["100.64.0.2", 4004], "s1b": ["100.64.0.2", 51727], "s2": ["100.64.0.2", 51727], "s2b": ["100.64.0.2", 51727]}, "xport": false, "xhost": false, "mapping": "EIM-after-first", "filtering": "APDF", "type": "masq", "port_preserving": true, "expect": "masq", "ok": true}
masqfw: {"sport": 4005, "obs": {"s1": ["100.64.0.2", 4005], "s1b": ["100.64.0.2", 4005], "s2": ["100.64.0.2", 4005], "s2b": ["100.64.0.2", 4005]}, "xport": false, "xhost": false, "mapping": "EIM", "filtering": "APDF", "type": "portrestricted", "port_preserving": true, "expect": "masqfw", "ok": true}
symmetric: {"sport": 4006, "obs": {"s1": ["100.64.0.2", 11456], "s1b": ["100.64.0.2", 25620], "s2": ["100.64.0.2", 25242], "s2b": ["100.64.0.2", 11056]}, "xport": false, "xhost": false, "mapping": "APDM", "filtering": "APDF", "type": "symmetric", "port_preserving": false, "expect": "symmetric", "ok": true}
udpblock: {"sport": 4007, "obs": {}, "xport": false, "xhost": false, "type": "udpblock", "mapping": null, "filtering": null, "expect": "udpblock", "ok": true}
```
