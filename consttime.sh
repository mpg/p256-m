#!/bin/sh

set -eu

make clean

make CFLAGS_SAN='-DCT_MEMSAN -fsanitize=memory -g3'
make clean

# valgrind seems to have ordering issues, where a call to poison at some line
# in a function seems to make earlier uses in the same function undefined:
#
# ==29297== Conditional jump or move depends on uninitialised value(s)
# ==29297==    at 0x40296A: m256_from_bytes (p256-m.c:491)
# ==29297==    by 0x40257B: p256_ecdsa_sign (p256-m.c:1072)
# ==29297==    by 0x401BBF: assert_ecdsa_sign_one (test-blackbox.c:116)
# ==29297==    by 0x401581: assert_ecdsa_sign (test-blackbox.c:124)
# ==29297==    by 0x4011AA: main (test-blackbox.c:219)
# ==29297==  Uninitialised value was created by a client request
# ==29297==    at 0x40263C: p256_ecdsa_sign (p256-m.c:1079)
# ==29297==    by 0x401BBF: assert_ecdsa_sign_one (test-blackbox.c:116)
# ==29297==    by 0x401572: assert_ecdsa_sign (test-blackbox.c:123)
# ==29297==    by 0x4011AA: main (test-blackbox.c:219)
#
# Perhaps there are details for valgrind user requests that I'm not fully
# grasping yet, but for now only test with memsan (which is so much faster
# anyway).
exit

make CFLAGS_SAN='-D CT_VALGRIND -g3' test-blackbox test-whitebox
valgrind --track-origins=yes ./test-blackbox
valgrind --track-origins=yes ./test-whitebox
make clean
