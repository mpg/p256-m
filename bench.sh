#!/bin/sh

set -eu

gcc --std=c99 -Werror -Wall -Wextra -pedantic \
    -Os p256-m.c benchmark.c -o benchmark

./benchmark

rm benchmark
