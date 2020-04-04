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

/* validate ecdh_shared_secret() against one test vector */
static void assert_ecdh_shared_one(const uint8_t refsec[32],
                                   const uint8_t priv[32],
                                   const uint8_t pub[64])
{
    uint8_t sec[32];
    int ret = p256_ecdh_shared_secret(sec, priv, pub);
    assert(ret == 0);
    assert(memcmp(sec, refsec, sizeof sec) == 0);
}

static void assert_ecdh_shared(void)
{
    assert_ecdh_shared_one(ecdh0_z, ecdh0_d, ecdh0_o);
    assert_ecdh_shared_one(ecdh1_z, ecdh1_d, ecdh1_o);
    assert_ecdh_shared_one(ecdh2_z, ecdh2_d, ecdh2_o);
    assert_ecdh_shared_one(ecdh3_z, ecdh3_d, ecdh3_o);
    assert_ecdh_shared_one(ecdh4_z, ecdh4_d, ecdh4_o);
    assert_ecdh_shared_one(ecdh5_z, ecdh5_d, ecdh5_o);
    assert_ecdh_shared_one(ecdh6_z, ecdh6_d, ecdh6_o);
    assert_ecdh_shared_one(ecdh7_z, ecdh7_d, ecdh7_o);
    assert_ecdh_shared_one(ecdh8_z, ecdh8_d, ecdh8_o);
    assert_ecdh_shared_one(ecdh9_z, ecdh9_d, ecdh9_o);

    /* TODO: bad priv, bad pub */
}

/* validate ecdh_gen_pair() against ecdh_shared_secret() */
static void assert_ecdh_gen_pair_one(void)
{
    int ret;
    uint8_t a_priv[32], a_pub[64], a_sec[32];
    uint8_t b_priv[32], b_pub[64], b_sec[32];

    ret = p256_ecdh_gen_pair(a_priv, a_pub);
    assert(ret == 0);

    ret = p256_ecdh_gen_pair(b_priv, b_pub);
    assert(ret == 0);

    ret = p256_ecdh_shared_secret(a_sec, a_priv, b_pub);
    assert(ret == 0);

    ret = p256_ecdh_shared_secret(b_sec, b_priv, a_pub);
    assert(ret == 0);

    assert(memcmp(a_sec, b_sec, 32) == 0);
}

static void assert_ecdh_gen_pair(void)
{
    for (unsigned i = 0; i < 5; i++)
        assert_ecdh_gen_pair_one();

    /* TODO: failing RNG */
}

int main(void)
{
    assert_ecdsa_verify();
    assert_ecdsa_sign();

    assert_ecdh_shared();
    assert_ecdh_gen_pair();
}
