/*
 * Black-box testing of curve P-256 (ECDH and ECDSA)
 *
 * - validate determinstic public functions against standard test vectors
 * - validate non-deterministic public functions against other functions
 * - exercise error cases that can be reached in a deterministic way
 */

#include "p256-m.h"
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

/* validate ecdsa_verify against one set of test vectors */
static void assert_ecdsa_verify_one(const uint8_t sig[64],
                                    const uint8_t *hash, size_t hlen)
{
    int ret;

    /* valid */
    ret = p256_ecdsa_verify(sig, ecdsa_pub, hash, hlen);
    assert(ret == 0);

    /* corrupt the first or last bit of r or s */
    uint8_t bad_sig[64];

    memcpy(bad_sig, sig, sizeof bad_sig);
    bad_sig[0] ^= 0x80;
    ret = p256_ecdsa_verify(bad_sig, ecdsa_pub, hash, hlen);
    assert(ret != 0);

    memcpy(bad_sig, sig, sizeof bad_sig);
    bad_sig[31] ^= 0x01;
    ret = p256_ecdsa_verify(bad_sig, ecdsa_pub, hash, hlen);
    assert(ret != 0);

    memcpy(bad_sig, sig, sizeof bad_sig);
    bad_sig[32] ^= 0x80;
    ret = p256_ecdsa_verify(bad_sig, ecdsa_pub, hash, hlen);
    assert(ret != 0);

    memcpy(bad_sig, sig, sizeof bad_sig);
    bad_sig[63] ^= 0x01;
    ret = p256_ecdsa_verify(bad_sig, ecdsa_pub, hash, hlen);
    assert(ret != 0);

    /* corrupt the first bit of hash (the last one may be truncated away) */
    uint8_t bad_hash[64];

    memcpy(bad_hash, hash, hlen);
    bad_hash[0] ^= 0x80;
    ret = p256_ecdsa_verify(sig, ecdsa_pub, bad_hash, hlen);
    assert(ret != 0);
}

static void assert_ecdsa_verify(void)
{
    /* known-good values */
    assert_ecdsa_verify_one(sig160a, h160a, sizeof h160a);
    assert_ecdsa_verify_one(sig224a, h224a, sizeof h224a);
    assert_ecdsa_verify_one(sig256a, h256a, sizeof h256a);
    assert_ecdsa_verify_one(sig384a, h384a, sizeof h384a);
    assert_ecdsa_verify_one(sig512a, h512a, sizeof h512a);
    assert_ecdsa_verify_one(sig160b, h160b, sizeof h160b);
    assert_ecdsa_verify_one(sig224b, h224b, sizeof h224b);
    assert_ecdsa_verify_one(sig256b, h256b, sizeof h256b);
    assert_ecdsa_verify_one(sig384b, h384b, sizeof h384b);
    assert_ecdsa_verify_one(sig512b, h512b, sizeof h512b);

    /* TODO: invalid input
     * r, s out of range
     * pub invalid
     */
}

/* validate sign against verify */
static void assert_ecdsa_sign_one(const uint8_t *hash, size_t hlen)
{
    int ret;
    uint8_t sig[64];

    ret = p256_ecdsa_sign(sig, ecdsa_priv, hash, hlen);
    assert(ret == 0);
    assert(p256_ecdsa_verify(sig, ecdsa_pub, hash, hlen) == 0);
}

static void assert_ecdsa_sign(void)
{
    assert_ecdsa_sign_one(h160a, sizeof h160a);
    assert_ecdsa_sign_one(h224a, sizeof h224a);
    assert_ecdsa_sign_one(h256a, sizeof h256a);
    assert_ecdsa_sign_one(h384a, sizeof h384a);
    assert_ecdsa_sign_one(h512a, sizeof h512a);
    assert_ecdsa_sign_one(h160b, sizeof h160b);
    assert_ecdsa_sign_one(h224b, sizeof h224b);
    assert_ecdsa_sign_one(h256b, sizeof h256b);
    assert_ecdsa_sign_one(h384b, sizeof h384b);
    assert_ecdsa_sign_one(h512b, sizeof h512b);

    /* TODO: bad priv */
}

int main(void)
{
    assert_ecdsa_verify();
    assert_ecdsa_sign();
}
