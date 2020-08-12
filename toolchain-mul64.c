/*
 * This file is used by toolchain-mul64.sh to be able to examine the
 * implementation of long multiplication used by the toolchain.
 */
#include <stdint.h>

uint64_t mul64(uint32_t x, uint32_t y, uint32_t z, uint32_t t) {
    return (uint64_t) x * y + z + t;
}
