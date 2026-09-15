#!/usr/bin/env bash
# Host-side wrapper for the dpi-proof harness (runs in the privileged lab image).
#
#   run.sh capture <profile> [--image core|baseline] [--seconds N] [--out DIR]
#   run.sh compare <before.fingerprint.json> <after.fingerprint.json>
#   run.sh baseline                 = capture plain (+ assert fingerprints present)
#
# Profiles are testing/dpi-proof/profiles/<name>.conf (extra tinc.conf lines for
# both nodes). Results: testing/dpi-proof/results/<date>/ (pcap, fingerprint
# JSON, text report, tincd logs; no keys).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAG="${WSF_TAG:-ws-f}"
LAB_IMAGE="tincstack/natlab:$TAG"

ensure_image() { docker image inspect "$LAB_IMAGE" >/dev/null 2>&1 || "$HERE/../nat-sim/lab.sh" build; }

capture() {
    local prof="$1"; shift
    local out="" args=()
    while [ $# -gt 0 ]; do
        case "$1" in --out) out="$2"; shift 2 ;; *) args+=("$1"); shift ;; esac
    done
    out="${out:-$HERE/results/$(date +%Y-%m-%d)}"
    mkdir -p "$out"; out="$(cd "$out" && pwd)"
    ensure_image
    docker run --rm --privileged --name "wsf-dpi-$$" \
        -v "$out:/out" -v "$HERE/profiles:/opt/dpi-profiles:ro" "$LAB_IMAGE" \
        dpi-capture "$prof" --out /out "${args[@]}"
}

compare() {
    local b a
    b="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
    a="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
    ensure_image
    docker run --rm --name "wsf-dpi-$$" -v "$b:/before.json:ro" -v "$a:/after.json:ro" "$LAB_IMAGE" \
        dpi-compare /before.json /after.json
}

baseline() {
    local out="${1:-$HERE/results/$(date +%Y-%m-%d)}"
    capture plain --out "$out"
    # The plain capture must be fingerprintable, otherwise the detectors are
    # broken and any later "absent" verdict would be meaningless.
    python3 - "$out/plain.fingerprint.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
need={"tcp_id_line","udp_null_dstid","udp_seqno_counter"}
have=set(r["summary"]["fingerprints_present"])
missing=need-have
print("baseline fingerprints present:", ", ".join(sorted(have)))
if missing:
    print("ERROR: expected plain-tinc fingerprints not detected:", ", ".join(sorted(missing))); sys.exit(1)
PY
}

cmd="${1:-}"; shift || true
case "$cmd" in
    capture) capture "$@" ;;
    compare) compare "$@" ;;
    baseline) baseline "$@" ;;
    *) sed -n '2,12p' "$0"; exit 2 ;;
esac
