#!/usr/bin/env bash
# Host-side wrapper for the tincstack NAT lab. Builds the lab image and runs
# natlab (testing/nat-sim/natlab.sh) inside ONE privileged container; results
# land under testing/nat-sim/results/run/<run-id>/ (git-ignored: full logs,
# dumps, summaries, no keys). The committed evidence tree results/<date>/ is
# curated by `lab.sh promote` and is never written by a lab run.
#
#   lab.sh build                       build tincstack/natlab:<tag> (needs
#                                      tincstack/core:<tag> and tincstack/baseline:<tag>)
#   lab.sh validate-nat                prove the NAT emulation with udpprobe
#   lab.sh scenario A_TYPE B_TYPE      one pair, exit 0 = PASS
#   lab.sh matrix [--quick]            all pairs (core and baseline)
#   lab.sh laptop                      the CGNAT / sleep-resume regression
#   lab.sh glare [--image-b IMG]       simultaneous REQ_KEY (both sides start; --image-b: mixed pair).
#                                      core is graded `clean', the baseline control
#                                      `defect' (--expect / --clean-max override)
#   lab.sh shell                       interactive shell in the lab container
#   lab.sh clean                       remove leftover wsf-* containers
#   lab.sh promote SRC [DEST]          copy the curated evidence subset of a run
#                                      directory into the committed tree
#                                      (default DEST results/<YYYY-MM-DD>)
#
# Options are passed through to natlab (--image, --rtt, --wait, --recover,
# --pause, --expect, --clean-max, --cgnat-udp-timeout,
# --cgnat-udp-stream-timeout). --out DIR sets the
# host results directory (default results/run/$WSF_RUN, WSF_RUN defaulting to
# <YYYY-MM-DD>-<HHMMSS>-<pid>; `make check` exports one WSF_RUN for all its
# lab steps so they share a directory).
# Env: WSF_TAG (default ws-f), WSF_RUN, CORE_IMAGE, BASELINE_IMAGE.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAG="${WSF_TAG:-ws-f}"
LAB_IMAGE="tincstack/natlab:$TAG"
CORE_IMAGE="${CORE_IMAGE:-tincstack/core:$TAG}"
BASELINE_IMAGE="${BASELINE_IMAGE:-tincstack/baseline:$TAG}"
NAME="wsf-natlab-$$"
RUN_ID="${WSF_RUN:-$(date +%Y-%m-%d)-$(date +%H%M%S)-$$}"

build() {
    local blog
    blog="$(mktemp /tmp/wsf-natlab-build.XXXXXX)"
    if ! docker build -t "$LAB_IMAGE" --build-arg "CORE_IMAGE=$CORE_IMAGE" \
            --build-arg "BASELINE_IMAGE=$BASELINE_IMAGE" -f "$HERE/../image/Dockerfile" "$HERE/.." > "$blog" 2>&1; then
        cat "$blog"; rm -f "$blog"; echo "lab image build failed" >&2; exit 2
    fi
    rm -f "$blog"
    echo "built $LAB_IMAGE" >&2
}

clean() {
    local ids
    ids="$(docker ps -aq --filter "name=wsf-natlab" || true)"
    # shellcheck disable=SC2086
    [ -z "$ids" ] || docker rm -f $ids >/dev/null 2>&1 || true
}

run_lab() { # cmd args...  (extracts --out for the host bind mount)
    local out="" args=() a
    while [ $# -gt 0 ]; do
        case "$1" in
            --out) out="$2"; shift 2 ;;
            *) args+=("$1"); shift ;;
        esac
    done
    out="${out:-$HERE/results/run/$RUN_ID}"
    mkdir -p "$out"
    out="$(cd "$out" && pwd)"
    echo "results: $out" >&2
    a=()
    [ -t 0 ] && a=(-it)
    # --privileged: network namespaces, iptables/conntrack sysctls, netem,
    # /dev/net/tun inside the container. Nothing touches the host's network.
    docker run --rm "${a[@]}" --privileged --name "$NAME" \
        -v "$out:/lab/results" "$LAB_IMAGE" natlab "${args[@]}" --out /lab/results
}

# The committed evidence is a curated subset (what PLAN.md / the READMEs cite):
# every summary.md and result.json, the validate-nat JSON lines, the laptop
# regression's nodel.log + port/conntrack notes, every glare-fix log, and the
# dpi-proof report/fingerprint/pcap. Per-pair node logs, dumps, info and
# gateway dumps stay in results/run/ (git-ignored). .gitignore enforces the
# same list, so a stray `git add` cannot bring the full logs back.
promote() { # SRC [DEST]
    local src="$1" dest="${2:-$HERE/results/$(date +%Y-%m-%d)}" n=0 f rel
    [ -d "$src" ] || { echo "promote: no such run directory: $src" >&2; return 2; }
    while IFS= read -r -d '' f; do
        rel="${f#"$src"/}"
        mkdir -p "$dest/$(dirname "$rel")"
        cp -p "$f" "$dest/$rel"
        n=$((n + 1))
    done < <(find "$src" -type f \( \
        -name summary.md -o -name result.json -o -name '*.result.json' -o -name '*.jsonl' \
        -o -path '*/laptop/*/nodel.log' -o -path '*/laptop/*/nodel-udp-port.txt' \
        -o -path '*/laptop/*/gwl2-conntrack-before-stage-c.txt' \
        -o -path '*/glare-fix/*.log' \
        -o -name '*.report.txt' -o -name '*.fingerprint.json' -o -name '*.pcap' \) -print0)
    echo "promoted $n file(s) from $src to $dest" >&2
    grep -rlE 'PRIVATE KEY|^Ed25519PrivateKey' "$dest" 2>/dev/null && { echo "promote: key material found in $dest" >&2; return 3; }
    return 0
}

cmd="${1:-}"; shift || true
case "$cmd" in
    build) build ;;
    validate-nat|scenario|matrix|laptop|glare|summarize) build; run_lab "$cmd" "$@" ;;
    shell) build; docker run --rm -it --privileged --name "$NAME" "$LAB_IMAGE" bash ;;
    clean) clean ;;
    promote) promote "$@" ;;
    *) sed -n '2,26p' "$0"; exit 2 ;;
esac
