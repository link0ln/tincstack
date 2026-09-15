#!/usr/bin/env python3
"""Compare two dpi-fingerprint JSON reports: the plain baseline ("before") and an
obfuscation tier ("after").

    dpi-compare before.fingerprint.json after.fingerprint.json

Exit 0  every fingerprint that was PRESENT in `before` is absent in `after`
Exit 1  at least one of them is still present (the tier did not change the
        wire image away from the tinc/SPTPS fingerprint)
Exit 2  `after` carried no traffic at all (tunnel never came up: not a valid
        comparison) or the files cannot be read
"""
import json
import sys


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    try:
        before = json.load(open(sys.argv[1]))
        after = json.load(open(sys.argv[2]))
    except (OSError, ValueError) as e:
        print(f"dpi-compare: {e}")
        return 2
    sa, sb = after["summary"], before["summary"]
    if sa["udp_datagrams"] + sa["tcp_payload_segments"] == 0:
        print("dpi-compare: 'after' capture has no tinc traffic; nothing to compare")
        return 2
    still = []
    print(f"{'fingerprint':26s} {'before':8s} {'after':8s}")
    for k, vb in before["fingerprints"].items():
        va = after["fingerprints"].get(k, {"present": None})
        fmt = {True: "PRESENT", False: "absent", None: "info"}
        print(f"{k:26s} {fmt[vb['present']]:8s} {fmt[va['present']]:8s}")
        if vb["present"] and va["present"]:
            still.append(k)
    print(f"traffic: before udp={sb['udp_datagrams']} tcp={sb['tcp_payload_segments']}; "
          f"after udp={sa['udp_datagrams']} tcp={sa['tcp_payload_segments']}")
    if still:
        print(f"FAIL: still fingerprintable by: {', '.join(still)}")
        return 1
    print("OK: no baseline fingerprint survives in the 'after' capture")
    return 0


if __name__ == "__main__":
    sys.exit(main())
