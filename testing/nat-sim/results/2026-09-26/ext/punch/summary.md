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
| masq x portrestricted | first+rtt40 | 3/3 | 0.04 s | 655/41655 |
| cgnat x cgnat | first+rtt40 | 3/3 | 0.06 s | 655/655 |
