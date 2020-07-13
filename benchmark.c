#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <inttypes.h>

#include "p256-m.h"

/* test version based on stdlib - never do this in production! */
int p256_generate_random(uint8_t *output, unsigned output_size)
{
    for (unsigned i = 0; i < output_size; i++) {
        output[i] = (uint8_t) rand();
    }

    return 0;
}

static uint64_t usec(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t) tv.tv_sec * 1000000 + (uint64_t) tv.tv_usec;
}

#define TIMES   100

#define TIMEIT(NAME, CODE)                                          \
do {                                                                \
    const uint64_t start = usec();                                  \
    for (unsigned i = 0; i < TIMES; i++) {                          \
        CODE;                                                       \
    }                                                               \
    const uint64_t ellapsed = usec() - start;                       \
    printf("%s: %4"PRIu64" us\n", NAME, ellapsed / TIMES);          \
    if( ret != 0)                                                   \
        printf("FAILED\n");                                         \
} while (0)

int main(void)
{
    int ret;
    uint8_t priv[32], pub[64], secret[32], sig[64], hash[32];

    TIMEIT("Keygen", ret = p256_gen_keypair(priv, pub));
    TIMEIT("ECDH", ret = p256_ecdh_shared_secret(secret, priv, pub));
    TIMEIT("Sign", ret = p256_ecdsa_sign(sig, priv, hash, sizeof hash));
    TIMEIT("Verify", ret = p256_ecdsa_verify(sig, pub, hash, sizeof hash));

    return 0;
}
