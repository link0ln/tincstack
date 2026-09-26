#!/usr/bin/env python3
# Usage: python3 race.py <run dir>... (the full node logs are in results/run/, not promoted)
"""obfs_close race, per obfs pair run: did it fire (a node's own dial to the
peer's port 655 timed out in authentication AFTER a connection with the same
peer on another port had been activated, or a DSEAL_KEX session with it had been established), and how many 'unknown source and/or
destination ID' lines from that peer followed on that node."""
import glob, json, os, re, sys

print("| run | pair | verdict | race fired on | unknown-ID lines after it |")
print("|---|---|---|---|---|")
for run in sys.argv[1:]:
    for d in sorted(glob.glob(run + "/pair-*/core-obfs")):
        res = json.load(open(d + "/result.json"))
        fired, after = [], []
        for me, peer in (("nodea", "nodeb"), ("nodeb", "nodea")):
            if not os.path.exists(f"{d}/{me}.log"):
                sys.exit(f"{d}/{me}.log: no node log (promoted runs keep none; use results/run/<run>)")
            lines = open(f"{d}/{me}.log", errors="replace").read().splitlines()
            act = None
            for i, l in enumerate(lines):
                if re.search(rf"Connection with {peer} \(\S+ port \d+\) activated", l) and "port 655)" not in l:
                    act = i
                if f"Direct-seal session key established with {peer}" in l:
                    act = i
                if act is not None and re.search(rf"Timeout from {peer} \(\S+ port 655\) during authentication", l):
                    fired.append(me)
                    after.append(str(sum(1 for x in lines[i:] if f"from {peer}" in x and "unknown source and/or destination ID" in x)))
                    break
        pair = os.path.basename(os.path.dirname(d))[5:].replace("-", " x ")
        print(f"| {os.path.basename(run.rstrip('/'))} | {pair} | {res['verdict']} | {', '.join(fired) or '-'} | {', '.join(after) or '-'} |")
