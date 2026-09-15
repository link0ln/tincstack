#!/bin/sh
# run.sh -- build and run the libFuzzer harnesses in a throwaway container.
#
# Nothing is installed on the host: the toolbox image (Dockerfile here) holds
# clang + libFuzzer + meson; the core is built with ASan+UBSan and coverage
# instrumentation into $OUT/build, the harnesses into $OUT/bin, corpora grow
# in $OUT/corpus/<harness>, crashes land in $OUT/artifacts/<harness>/.
#
#   test/fuzz/run.sh build             build image + core + harnesses
#   test/fuzz/run.sh fuzz [secs] [h..] run every (or the named) harness for
#                                      `secs' seconds (default 600) in parallel
#   test/fuzz/run.sh check             run each harness once over its committed
#                                      corpus (regression inputs included);
#                                      exit 1 on any crash -- the CI-style gate
#
# Environment: OUT (default /tmp/wsr-fuzz), IMAGE (default tincstack/fuzz:ws-r).
# The binaries run under `setarch -R` (ASLR off for that process): ASan on a
# kernel with vm.mmap_rnd_bits=32 otherwise segfaults at random on startup.
# setarch needs personality(ADDR_NO_RANDOMIZE), which Docker's default seccomp
# profile blocks, hence seccomp=unconfined for these throwaway containers.
set -e

here=$(cd "$(dirname "$0")" && pwd)
src=$(cd "$here/../.." && pwd)            # core/tincd
OUT=${OUT:-/tmp/wsr-fuzz}
IMAGE=${IMAGE:-tincstack/fuzz:ws-r}
HARNESSES="fuzz_yamlconf fuzz_classify fuzz_invitation fuzz_pool fuzz_sf"

# Per-harness libFuzzer options (max input size; the sf harness is stateful
# and wants longer inputs so several frames fit).
opts() {
    case $1 in
        fuzz_yamlconf)   echo "-max_len=8192" ;;
        fuzz_classify)   echo "-max_len=1500" ;;
        fuzz_invitation) echo "-max_len=8192" ;;
        fuzz_pool)       echo "-max_len=4096" ;;
        fuzz_sf)         echo "-max_len=16384" ;;
    esac
}

run_in_box() {
    # $1 = extra docker args, rest = command
    extra=$1; shift
    # shellcheck disable=SC2086
    docker run --rm --security-opt seccomp=unconfined $extra -v "$src":/src:ro -v "$OUT":/out -v "$here":/fuzz:ro "$IMAGE" sh -c "$*"
}

cmd_build() {
    mkdir -p "$OUT"
    docker image inspect "$IMAGE" >/dev/null 2>&1 || docker build -t "$IMAGE" "$here"
    run_in_box "" '
        set -e
        if [ ! -f /out/build/build.ninja ]; then
            meson setup /out/build /src --buildtype=debugoptimized \
                -Db_sanitize=address,undefined -Db_lundef=false -Dhardening=false \
                -Dtests=disabled -Ddocs=disabled -Dminiupnpc=disabled \
                -Dc_args="-fsanitize=fuzzer-no-link -fno-omit-frame-pointer" \
                -Dc_link_args="-fsanitize=fuzzer-no-link" >/out/meson-setup.log
        fi
        ninja -C /out/build >/out/ninja.log
        make -s -C /fuzz SRC=/src BUILD=/out/build OUT=/out/bin
    '
    echo "built: $(ls "$OUT/bin" | tr "\n" " ")"
}

cmd_fuzz() {
    secs=${1:-600}; shift || true
    list=${*:-$HARNESSES}
    mkdir -p "$OUT/logs"
    for h in $list; do
        mkdir -p "$OUT/corpus/$h" "$OUT/artifacts/$h"
        cp -n "$here/corpus/$h/"* "$OUT/corpus/$h/" 2>/dev/null || true
        # shellcheck disable=SC2046
        run_in_box "-d --name wsr-$h" "cd /out && setarch $(uname -m) -R ./bin/$h $(opts "$h") \
            -max_total_time=$secs -rss_limit_mb=2048 -timeout=20 \
            -artifact_prefix=/out/artifacts/$h/ -print_final_stats=1 \
            /out/corpus/$h > /out/logs/$h.log 2>&1" >/dev/null
        echo "started $h for ${secs}s (log: $OUT/logs/$h.log)"
    done
}

cmd_check() {
    rc=0
    printf '%-16s ' "yamlconf_props"
    if run_in_box "" "make -s -C /fuzz SRC=/src BUILD=/out/build OUT=/out/bin props >/out/check-props.log 2>&1"; then
        echo "ok"
    else
        echo "FAIL -- see $OUT/check-props.log"; rc=1
    fi
    for h in $HARNESSES; do
        printf '%-16s ' "$h"
        if run_in_box "" "cd /out && setarch $(uname -m) -R ./bin/$h -runs=0 /fuzz/corpus/$h >/out/check-$h.log 2>&1"; then
            echo "ok ($(ls "$here/corpus/$h" | wc -l) inputs)"
        else
            echo "CRASH -- see $OUT/check-$h.log"; rc=1
        fi
    done
    exit $rc
}

case ${1:-} in
    build) cmd_build ;;
    fuzz)  shift; cmd_fuzz "$@" ;;
    check) cmd_check ;;
    *) echo "usage: $0 build | fuzz [secs] [harness..] | check" >&2; exit 2 ;;
esac
