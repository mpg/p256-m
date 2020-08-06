#!/bin/sh

set -eu

# This is meant to be used on A-class cores, which all have CT 64-bit mul.
gcc --std=c99 -Werror -Wall -Wextra -pedantic \
    -DMUL64_IS_CONSTANT_TIME \
    -Os p256-m.c benchmark.c -o benchmark

./benchmark

rm benchmark
