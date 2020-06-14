#!/bin/sh

set -eu

make clean
make CC=gcc CFLAGS='-Werror -Wall -Wextra -O1 -g3 --coverage' test-blackbox test-whitebox

LCOV_FLAGS="--directory . --rc lcov_branch_coverage=1 --no-external"

./test-blackbox
lcov $LCOV_FLAGS --exclude $PWD/'test-*.c' --capture --output-file black.info
./test-whitebox
lcov $LCOV_FLAGS --exclude $PWD/'test-*.c' --capture --output-file white.info

genhtml --branch-coverage black.info -o cov-black
genhtml --branch-coverage white.info -o cov-white

