#!/bin/sh
# Saturation ladder: run bench.sh at rising offered rates and let each arm fall
# over. Answers "how much can one tincd carry", which the fixed-rate bench
# cannot -- at 100 Mbit every arm keeps up, so the only difference visible there
# is CPU per packet, and the ceiling has to be extrapolated. Extrapolation is not
# a measurement.
#
#     sh testing/perf/ladder.sh [core-image] [baseline-image] > ladder.csv
#
# Env: RATES (the ladder), ARMS, REPEATS (2), SECONDS_RUN (20), CPUSET (0-7).
#
# CPUSET is wider than the fixed-rate bench's on purpose: near the ceiling
# iperf3 itself needs a core at each end, and a harness starving the daemon it
# is measuring would report the harness's limit as the daemon's.
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
RATES=${RATES:-"200M 400M 600M 800M 1000M 1200M"}
first=1
for rate in $RATES; do
	if [ "$first" = 1 ]; then
		RATE="$rate" REPEATS="${REPEATS:-2}" SECONDS_RUN="${SECONDS_RUN:-20}" \
			CPUSET="${CPUSET:-0-7}" sh "$HERE/bench.sh" "$@"
		first=0
	else
		# One header only: the rows concatenate into a single table.
		RATE="$rate" REPEATS="${REPEATS:-2}" SECONDS_RUN="${SECONDS_RUN:-20}" \
			CPUSET="${CPUSET:-0-7}" sh "$HERE/bench.sh" "$@" | tail -n +2
	fi
done
