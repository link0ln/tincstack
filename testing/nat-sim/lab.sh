#!/usr/bin/env bash
# Host-side wrapper for the tincstack NAT lab. Builds the lab image and runs
# natlab (testing/nat-sim/natlab.sh) inside ONE privileged container; results
# land under testing/nat-sim/results/<date>/ (logs and summaries only, no keys).
#
#   lab.sh build                       build tincstack/natlab:<tag> (needs
#                                      tincstack/core:<tag> and tincstack/baseline:<tag>)
#   lab.sh validate-nat                prove the NAT emulation with udpprobe
#   lab.sh scenario A_TYPE B_TYPE      one pair, exit 0 = PASS
#   lab.sh matrix [--quick]            all pairs (core and baseline)
#   lab.sh laptop                      the CGNAT / sleep-resume regression
#   lab.sh glare [--image-b IMG]       simultaneous REQ_KEY (both sides start; --image-b: mixed pair)
#   lab.sh shell                       interactive shell in the lab container
#   lab.sh clean                       remove leftover wsf-* containers
#
# Options are passed through to natlab (--image, --rtt, --wait, --recover,
# --pause, --cgnat-udp-timeout, --cgnat-udp-stream-timeout). --out DIR sets the
# host results directory (default results/<YYYY-MM-DD>).
# Env: WSF_TAG (default ws-f), CORE_IMAGE, BASELINE_IMAGE.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAG="${WSF_TAG:-ws-f}"
LAB_IMAGE="tincstack/natlab:$TAG"
CORE_IMAGE="${CORE_IMAGE:-tincstack/core:$TAG}"
BASELINE_IMAGE="${BASELINE_IMAGE:-tincstack/baseline:$TAG}"
NAME="wsf-natlab-$$"

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
    out="${out:-$HERE/results/$(date +%Y-%m-%d)}"
    mkdir -p "$out"
    out="$(cd "$out" && pwd)"
    a=()
    [ -t 0 ] && a=(-it)
    # --privileged: network namespaces, iptables/conntrack sysctls, netem,
    # /dev/net/tun inside the container. Nothing touches the host's network.
    docker run --rm "${a[@]}" --privileged --name "$NAME" \
        -v "$out:/lab/results" "$LAB_IMAGE" natlab "${args[@]}" --out /lab/results
}

cmd="${1:-}"; shift || true
case "$cmd" in
    build) build ;;
    validate-nat|scenario|matrix|laptop|glare|summarize) build; run_lab "$cmd" "$@" ;;
    shell) build; docker run --rm -it --privileged --name "$NAME" "$LAB_IMAGE" bash ;;
    clean) clean ;;
    *) sed -n '2,20p' "$0"; exit 2 ;;
esac
