#!/bin/sh
# classify-test.sh -- build and run the transport front classifier unit test.
#
# Compiles classify_test.c against the real transport_table.c (the classifier
# and the carrier table) inside a throwaway Debian container, so nothing is
# installed on the host. A small shim system.h supplies the standard headers
# that transport_table.c would otherwise get from tinc's system.h; the file
# under test has no other daemon dependency.
#
# Usage: testing/transports/classify-test.sh
# Exit code 0 = all patterns classified correctly.
set -e

here=$(cd "$(dirname "$0")" && pwd)
src="$here/../../core/tincd/src"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cp "$src/transport.h" "$src/transport_table.c" "$here/classify_test.c" "$work/"

# Minimal stand-in for tinc's system.h (only what transport_table.c uses).
cat > "$work/system.h" <<'EOF'
#ifndef TINC_SYSTEM_H
#define TINC_SYSTEM_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#endif
EOF

docker run --rm -v "$work":/w -w /w debian:12-slim sh -c '
    set -e
    apt-get update >/dev/null 2>&1
    apt-get install -y --no-install-recommends gcc libc6-dev >/dev/null 2>&1
    gcc -Wall -Wextra -std=c11 -I/w transport_table.c classify_test.c -o classify_test
    ./classify_test
'
