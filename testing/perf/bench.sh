#!/bin/sh
# throughput / CPU / memory benchmark: hardened tincstack tincd against upstream
# tinc 1.1pre18, at a fixed offered rate.
#
#     sh testing/perf/bench.sh [core-image] [baseline-image]
#
# Env: RATE (default 100M), SECONDS_RUN (30), REPEATS (3), CPUSET (0-3),
#      ARMS ("baseline plain sf obfs"), MODE (udp|tcp, default udp),
#      DGRAM (UDP payload, default 1300).
#
# Both daemons run in ONE privileged container from ONE image, in two network
# namespaces joined by a veth pair -- no NAT, no shaping, no docker bridge. The
# arms therefore differ in the tincd binary and the transport lines and in
# nothing else. The container is pinned to a fixed cpuset so that other load on
# the host moves all arms together instead of one of them.
set -eu

CORE_IMAGE=${1:-tincstack/core:sf5}
BASELINE_IMAGE=${2:-tincstack/baseline:ws-f}
BASELINE_O3_IMAGE=${BASELINE_O3_IMAGE:-tincstack/baseline:o3}
RATE=${RATE:-100M}
SECONDS_RUN=${SECONDS_RUN:-30}
REPEATS=${REPEATS:-3}
CPUSET=${CPUSET:-0-3}
ARMS=${ARMS:-"baseline plain sf obfs quic https"}
MODE=${MODE:-udp}
DGRAM=${DGRAM:-1300}
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
LAB_IMAGE=${LAB_IMAGE:-tincstack/perf-lab:bench}
BENCH_IMAGE=tincstack/perf-bench:bench

for img in "$CORE_IMAGE" "$BASELINE_IMAGE" "$BASELINE_O3_IMAGE"; do
	docker image inspect "$img" >/dev/null 2>&1 || { echo "bench.sh: no image $img" >&2; exit 2; }
done

echo "building the lab image (core + baseline in one image)..." >&2
docker build -q -t "$LAB_IMAGE" \
	--build-arg "CORE_IMAGE=$CORE_IMAGE" --build-arg "BASELINE_IMAGE=$BASELINE_IMAGE" \
	-f "$HERE/../image/Dockerfile" "$HERE/.." >/dev/null
echo "building the bench image (+ iperf3)..." >&2
docker build -q -t "$BENCH_IMAGE" --build-arg "LAB_IMAGE=$LAB_IMAGE" \
	--build-arg "BASELINE_O3_IMAGE=$BASELINE_O3_IMAGE" \
	-f "$HERE/Dockerfile" "$HERE" >/dev/null

echo "arm,carrier,path,mode,mbits,gb,mpkts,cpu_s_a,cpu_s_b,cpu_pct_a,cpu_pct_b,cpu_s_per_mpkt_a,cpu_s_per_mpkt_b,hwm_kb_a,hwm_kb_b,pmtu,wall_s,calib_s,norm_a,norm_b"
i=0
while [ "$i" -lt "$REPEATS" ]; do
	i=$((i + 1))
	for arm in $ARMS; do
		# One arm that fails to bring its tunnel up must not throw away the
		# repeats already collected: record it on stderr and carry on.
		docker run --rm --privileged --cpuset-cpus="$CPUSET" \
			-e "RATE=$RATE" -e "SECONDS_RUN=$SECONDS_RUN" \
			-e "MODE=$MODE" -e "DGRAM=$DGRAM" \
			-v "$HERE/bench-inner.sh:/bench-inner.sh:ro" \
			"$BENCH_IMAGE" sh /bench-inner.sh "$arm" \
			|| echo "bench: arm $arm failed in repeat $i, skipping it" >&2
	done
done
