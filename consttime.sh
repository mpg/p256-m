#!/bin/sh

set -eu

make clean

make CFLAGS_SAN='-DCT_MEMSAN -fsanitize=memory -g3'
make clean

make CFLAGS_SAN='-D CT_VALGRIND -g3' test-blackbox test-whitebox
valgrind --track-origins=yes ./test-blackbox
valgrind --track-origins=yes ./test-whitebox
make clean
