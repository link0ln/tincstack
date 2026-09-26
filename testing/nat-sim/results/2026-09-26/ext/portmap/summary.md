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
