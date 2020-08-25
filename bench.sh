#!/bin/sh

# Build and run the on-host benchmark program.
# (See also: on-target-benchmark directory.)

set -eu

# Anything capable of running gcc has CT 64-bit mul in practice
gcc --std=c99 -Werror -Wall -Wextra -pedantic \
    -march=native -DMUL64_IS_CONSTANT_TIME \
    -Os p256-m.c benchmark.c -o benchmark

./benchmark

rm benchmark
