## REQ_KEY glare — before/after the tie-break (patch 5), full-cone x full-cone, both sides ping at once

Before = core built from fef10b9 (no tie-break); after = core with patch 5. Baseline = upstream 1.1pre18 (unchanged).
`glare lines` counts the stock "already started" message and the core's "glare tie-break" message; 0 = the two pings did not collide in that run (it is a race; `--rtt 50` makes the collision near-certain). The after-rtt* core x core rows were recounted from their logs (see `note` in the result files).

| run | pair (nodea x nodeb) | key after | `Invalid packet seqno` | glare lines | SPTPS restarts | verdict |
|---|---|---|---|---|---|---|
| after-baseline-x-core-run1 | baseline x core | 13s | 2 | 3 | 1 | PASS |
| after-baseline-x-core-run2 | baseline x core | 12s | 2 | 3 | 1 | PASS |
| after-baseline-x-core-run3 | baseline x core | 13s | 2 | 3 | 1 | PASS |
| after-core-x-baseline-run1 | core x baseline | 1s | 0 | 2 | 0 | PASS |
| after-core-x-baseline-run2 | core x baseline | 1s | 0 | 2 | 0 | PASS |
| after-core-x-baseline-run3 | core x baseline | 1s | 0 | 2 | 0 | PASS |
| after-rtt1-run1 | core | 1s | 0 | 2 | 0 | PASS |
| after-rtt1-run2 | core | 1s | 0 | 2 | 0 | PASS |
| after-rtt1-run3 | core | 1s | 0 | 0 | 0 | PASS |
| after-rtt50-run1 | core | 1s | 0 | 2 | 0 | PASS |
| after-rtt50-run2 | core | 1s | 0 | 2 | 0 | PASS |
| after-rtt50-run3 | core | 1s | 0 | 2 | 0 | PASS |
| before-rtt1-run1 | core | 32s | 2 | 3 | 1 | PASS |
| before-rtt1-run2 | core | 1s | 0 | 0 | 0 | PASS |
| before-rtt1-run3 | core | 1s | 0 | 0 | 0 | PASS |
| before-rtt50-run1 | baseline | 23s | 4 | 5 | 3 | PASS |
| before-rtt50-run1 | core | 90s | 6 | 6 | 4 | FAIL |
| before-rtt50-run2 | baseline | 46s | 8 | 9 | 7 | PASS |
| before-rtt50-run2 | core | 32s | 2 | 3 | 1 | PASS |
| before-rtt50-run3 | baseline | 35s | 6 | 7 | 5 | PASS |
| before-rtt50-run3 | core | 31s | 2 | 3 | 1 | PASS |
