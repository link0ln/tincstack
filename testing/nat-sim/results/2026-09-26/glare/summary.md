## REQ_KEY glare (both sides initiate at once; full-cone x full-cone)

Each image is graded against what it is SUPPOSED to do: `clean` = the
tie-break holds (key within 10s, no SPTPS restart, no seqno error),
`defect` = the unpatched control still demonstrates the glare it is there
to demonstrate. A control that recovers cleanly fails this table, and so
does a patched binary that does not.

| image | expected | key established after | `Invalid packet seqno` | glare lines | SPTPS restarts | verdict |
|---|---|---|---|---|---|---|
| core | clean | 1s | 0 | 2 | 0 | PASS |
| baseline | defect | 12s | 2 | 3 | 1 | PASS |

- core: PASS -- key in 1s (limit 10s), no SPTPS restart, no seqno error
- baseline: PASS -- the defect reproduced: 1 SPTPS restart(s), 2 seqno error(s), key after 12s
