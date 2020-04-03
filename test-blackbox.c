/*
 * Black-box testing of curve P-256 (ECDH and ECDSA)
 *
 * - validate determinstic public functions against standard test vectors
 * - validate non-deterministic public functions against other functions
 * - exercise error cases that can be reached in a deterministic way
 */

#include "p256-m.h"
#define TEST_WHITE
#include "test-data.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

/* test version based on stdlib - never do this in production! */
int p256_generate_random(uint8_t *output, unsigned output_size)
{
    for (unsigned i = 0; i < output_size; i++) {
        output[i] = (uint8_t) rand();
    }

    return 0;
}

int main(void)
{
    assert(1);
}
