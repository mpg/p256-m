#!/bin/sh

set -eu

make clean

make CFLAGS_SAN='-DCT_MEMSAN -fsanitize=memory -g3'
make clean

# valgrind is slow, save some time by using the CPU's mul64
# this also ensure the trivial definition of u32_mul64 is tested as well
make CFLAGS_SAN='-D CT_VALGRIND -g3 -D MUL64_IS_CONSTANT_TIME' test-blackbox test-whitebox
valgrind --track-origins=yes ./test-blackbox
valgrind --track-origins=yes ./test-whitebox
make clean
