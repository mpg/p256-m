/*
 * White-box testing of curve P-256 (ECDH and ECDSA)
 *
 * - unit-tests for static function (by including the C file)
 * - tests using a fixed RNG (and knowledge of how it's used)
 */

#include "p256-m.c"
#include "test-data.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

static void assert_add(const uint32_t x[8], const uint32_t y[8],
                       const uint32_t z[8], uint32_t c)
{
    uint32_t myz[8];
    uint32_t myc = u256_add(myz, x, y);
    assert(memcmp(myz, z, sizeof myz) == 0);
    assert(myc == c);
}

static void assert_sub(const uint32_t x[8], const uint32_t y[8],
                       const uint32_t z[8], uint32_t c)
{
    uint32_t myz[8];
    uint32_t myc = u256_sub(myz, x, y);
    assert(memcmp(myz, z, sizeof myz) == 0);
    assert(myc == c);
}

static void assert_cmov()
{
    uint32_t z[8];
    memcpy(z, r, sizeof z);
    u256_cmov(z, s, 0u);
    assert(memcmp(z, r, sizeof z) == 0);
    u256_cmov(z, s, 1u);
    assert(memcmp(z, s, sizeof z) == 0);
}

static void assert_ubytes(void)
{
    uint32_t z[8];
    u256_from_bytes(z, rbytes);
    assert(memcmp(z, r, sizeof z) == 0);

    uint8_t p[32];
    u256_to_bytes(p, r);
    assert(memcmp(p, rbytes, sizeof p) == 0);
}

static void assert_madd()
{
    uint32_t z[8];

    /* x + y < p */
    m256_add(z, p256_n, word, p256_p);
    assert(memcmp(z, npwmp, sizeof z) == 0);

    /* p <= x + y < 2^256 */
    m256_add(z, p256_n, b128, p256_p);
    assert(memcmp(z, npbmp, sizeof z) == 0);

    /* x + y >= 2^256 */
    m256_add(z, p256_n, p256_n, p256_p);
    assert(memcmp(z, npnmp, sizeof z) == 0);
}

static void assert_msub()
{
    uint32_t z[8];

    /* x > y */
    m256_sub(z, one, zero, p256_p);
    assert(memcmp(z, one, sizeof z) == 0);

    /* x == y */
    m256_sub(z, one, one, p256_p);
    assert(memcmp(z, zero, sizeof z) == 0);

    /* x < y by few */
    m256_sub(z, zero, one, p256_p);
    assert(memcmp(z, pm1, sizeof z) == 0);

    /* x < y by far */
    m256_sub(z, zero, pm1, p256_p);
    assert(memcmp(z, one, sizeof z) == 0);
}

static void assert_mmul(void)
{
    uint32_t z[8];

    m256_mul(z, r, s, p256_p);
    assert(memcmp(z, rsRip, sizeof z) == 0);

    m256_mul(z, r, s, p256_n);
    assert(memcmp(z, rsRin, sizeof z) == 0);
}

static void assert_prep_mul_done(void)
{
    uint32_t rm[8], sm[8], z[8];

    /* mod p */
    memcpy(rm, r, sizeof rm);
    memcpy(sm, s, sizeof rm);

    m256_prep(rm, p256_p);
    m256_prep(sm, p256_p);

    m256_mul(z, rm, sm, p256_p);

    m256_done(z, p256_p);

    assert(memcmp(z, rtsmp, sizeof z) == 0);

    /* mod n */
    memcpy(rm, r, sizeof rm);
    memcpy(sm, s, sizeof rm);

    m256_prep(rm, p256_n);
    m256_prep(sm, p256_n);

    m256_mul(z, rm, sm, p256_n);

    m256_done(z, p256_n);

    assert(memcmp(z, rtsmn, sizeof z) == 0);
}

static void assert_inv(void)
{
    uint32_t rm[8], z[8];

    memcpy(rm, r, sizeof rm);
    m256_prep(rm, p256_p);
    m256_inv(z, rm, p256_p);
    m256_done(z, p256_p);
    assert(memcmp(z, rip, sizeof z) == 0);

    memcpy(rm, r, sizeof rm);
    m256_prep(rm, p256_n);
    m256_inv(z, rm, p256_n);
    m256_done(z, p256_n);
    assert(memcmp(z, rin, sizeof z) == 0);
}

static void assert_mbytes()
{
    int ret;
    uint32_t z[8];
    uint8_t p[32];

    /* mod p */
    ret = m256_from_bytes(z, rbytes, p256_p);
    assert(ret == 0);
    assert(memcmp(z, rmontp, sizeof z) == 0);

    m256_to_bytes(p, z, p256_p);
    assert(memcmp(p, rbytes, sizeof p) == 0);

    /* mod n */
    ret = m256_from_bytes(z, rbytes, p256_n);
    assert(ret == 0);
    assert(memcmp(z, rmontn, sizeof z) == 0);

    m256_to_bytes(p, z, p256_n);
    assert(memcmp(p, rbytes, sizeof p) == 0);

    /* too large by one, mod p and n */
    u256_to_bytes(p, p256_p);
    ret = m256_from_bytes(z, p, p256_p);
    assert(ret == -1);

    u256_to_bytes(p, p256_n);
    ret = m256_from_bytes(z, p, p256_n);
    assert(ret == -1);
}

static void assert_pt_params(void)
{
    uint32_t z[8];

    u256_cmov(z, p256_b, 1);
    m256_done(z, p256_p);
    assert(memcmp(z, b_raw, sizeof z) == 0);

    u256_cmov(z, p256_gx, 1);
    m256_done(z, p256_p);
    assert(memcmp(z, gx_raw, sizeof z) == 0);

    u256_cmov(z, p256_gy, 1);
    m256_done(z, p256_p);
    assert(memcmp(z, gy_raw, sizeof z) == 0);
}

static void assert_pt_check(void)
{
    assert(point_check(p256_gx, p256_gy) == 0);

    assert(point_check(p256_gx, p256_gx) != 0);
    assert(point_check(p256_gy, p256_gx) != 0);
    assert(point_check(p256_gy, p256_gy) != 0);
}

static void assert_pt_affine(void)
{
    uint32_t x[8], y[8], z[8];

    u256_cmov(x, jac_gx, 1);
    u256_cmov(y, jac_gy, 1);
    u256_cmov(z, jac_gz, 1);

    point_to_affine(x, y, z);

    assert(memcmp(x, p256_gx, sizeof x) == 0);
    assert(memcmp(y, p256_gy, sizeof y) == 0);
}

static void assert_pt_double(void)
{
    uint32_t dx[8], dy[8], dz[8];

    u256_cmov(dx, jac_gx, 1);
    u256_cmov(dy, jac_gy, 1);
    u256_cmov(dz, jac_gz, 1);

    point_double(dx, dy, dz);

    point_to_affine(dx, dy, dz);
    m256_done(dx, p256_p);
    m256_done(dy, p256_p);

    assert(memcmp(dx, g2x, sizeof dx) == 0);
    assert(memcmp(dy, g2y, sizeof dy) == 0);
}

static void assert_pt_add(void)
{
    uint32_t tx[8], ty[8], tz[8], mg2x[8], mg2y[8];

    u256_cmov(mg2x, g2x, 1);
    u256_cmov(mg2y, g2y, 1);
    m256_prep(mg2x, p256_p);
    m256_prep(mg2y, p256_p);

    u256_cmov(tx, jac_gx, 1);
    u256_cmov(ty, jac_gy, 1);
    u256_cmov(tz, jac_gz, 1);

    point_add(tx, ty, tz, mg2x, mg2y);

    point_to_affine(tx, ty, tz);
    m256_done(tx, p256_p);
    m256_done(ty, p256_p);

    assert(memcmp(tx, g3x, sizeof tx) == 0);
    assert(memcmp(ty, g3y, sizeof ty) == 0);
}

static void assert_pt_add_or_double(void)
{
    uint32_t rx[8], ry[8], rz[8], mx[8], my[8];

    /* r = 2G + G (generic addition) */
    u256_cmov(mx, g2x, 1);
    u256_cmov(my, g2y, 1);
    m256_prep(mx, p256_p);
    m256_prep(my, p256_p);

    point_add_or_double_leaky(rx, ry, rz, mx, my, p256_gx, p256_gy);

    point_to_affine(rx, ry, rz);
    m256_done(rx, p256_p);
    m256_done(ry, p256_p);

    assert(memcmp(rx, g3x, sizeof rx) == 0);
    assert(memcmp(ry, g3y, sizeof ry) == 0);

    /* r = G + G (double) */
    point_add_or_double_leaky(rx, ry, rz, p256_gx, p256_gy, p256_gx, p256_gy);

    point_to_affine(rx, ry, rz);
    m256_done(rx, p256_p);
    m256_done(ry, p256_p);

    assert(memcmp(rx, g2x, sizeof rx) == 0);
    assert(memcmp(ry, g2y, sizeof ry) == 0);

    /* r = (-G) + G (zero) */
    u256_cmov(my, g1yn, 1);
    m256_prep(my, p256_p);

    point_add_or_double_leaky(rx, ry, rz, p256_gx, my, p256_gx, p256_gy);

    m256_done(rx, p256_p);
    m256_done(ry, p256_p);

    u256_set32(mx, 0);
    assert(memcmp(rz, mx, sizeof rz) == 0);
    u256_set32(mx, 1);
    assert(memcmp(rx, mx, sizeof rx) == 0);
    assert(memcmp(ry, mx, sizeof rx) == 0);
}

static void assert_pt_bytes(void)
{
    uint8_t p[64];
    uint32_t x[8], y[8];
    int ret;

    /* valid */
    ret = point_from_bytes(x, y, gbytes);
    assert(ret == 0);
    assert(memcmp(x, p256_gx, sizeof x) == 0);
    assert(memcmp(y, p256_gy, sizeof y) == 0);

    point_to_bytes(p, x, y);
    assert(memcmp(p, gbytes, sizeof p) == 0);

    /* invalid: x or y too big, (x, y) not on curve */
    u256_to_bytes(p, p256_p);
    ret = point_from_bytes(x, y, p);
    assert(ret != 0);

    u256_to_bytes(p, one);
    u256_to_bytes(p + 32, p256_p);
    ret = point_from_bytes(x, y, p);
    assert(ret != 0);

    u256_to_bytes(p, one);
    u256_to_bytes(p + 32, one);
    ret = point_from_bytes(x, y, p);
    assert(ret != 0);
}

static void assert_scalar_mult(void)
{
    uint32_t x[8], y[8], z[8], k[8], xx[8], yy[8];

    /* 1 * g */
    u256_set32(k, 1);
    scalar_mult(x, y, z, p256_gx, p256_gy, k);
    point_to_affine(x, y, z);
    assert(memcmp(x, p256_gx, sizeof x) == 0);
    assert(memcmp(y, p256_gy, sizeof y) == 0);

    /* 2 * g */
    u256_set32(k, 2);
    scalar_mult(x, y, z, p256_gx, p256_gy, k);
    point_to_affine(x, y, z);
    m256_done(x, p256_p);
    m256_done(y, p256_p);
    assert(memcmp(x, g2x, sizeof x) == 0);
    assert(memcmp(y, g2y, sizeof y) == 0);

    /* 3 * g */
    u256_set32(k, 3);
    scalar_mult(x, y, z, p256_gx, p256_gy, k);
    point_to_affine(x, y, z);
    m256_done(x, p256_p);
    m256_done(y, p256_p);
    assert(memcmp(x, g3x, sizeof x) == 0);
    assert(memcmp(y, g3y, sizeof y) == 0);

    /* (n-1) * g */
    u256_sub(k, p256_n, one);
    scalar_mult(x, y, z, p256_gx, p256_gy, k);
    point_to_affine(x, y, z);
    m256_done(x, p256_p);
    m256_done(y, p256_p);
    assert(memcmp(x, gx_raw, sizeof x) == 0);
    assert(memcmp(y, g1yn, sizeof y) == 0);

    /* (n-2) * g */
    u256_sub(k, k, one);
    scalar_mult(x, y, z, p256_gx, p256_gy, k);
    point_to_affine(x, y, z);
    m256_done(x, p256_p);
    m256_done(y, p256_p);
    assert(memcmp(x, g2x, sizeof x) == 0);
    assert(memcmp(y, g2yn, sizeof y) == 0);

    /* (n-3) * g */
    u256_sub(k, k, one);
    scalar_mult(x, y, z, p256_gx, p256_gy, k);
    point_to_affine(x, y, z);
    m256_done(x, p256_p);
    m256_done(y, p256_p);
    assert(memcmp(x, g3x, sizeof x) == 0);
    assert(memcmp(y, g3yn, sizeof y) == 0);

    /* rG then s(rG) */
    scalar_mult(x, y, z, p256_gx, p256_gy, r);
    point_to_affine(x, y, z);
    u256_cmov(xx, x, 1);
    u256_cmov(yy, y, 1);
    m256_done(x, p256_p);
    m256_done(y, p256_p);
    assert(memcmp(x, rgx, sizeof x) == 0);
    assert(memcmp(y, rgy, sizeof y) == 0);

    scalar_mult(x, y, z, xx, yy, s);
    point_to_affine(x, y, z);
    m256_done(x, p256_p);
    m256_done(y, p256_p);
    assert(memcmp(x, rsgx, sizeof x) == 0);
    assert(memcmp(y, rsgy, sizeof y) == 0);

    /* sG then r(sG) */
    scalar_mult(x, y, z, p256_gx, p256_gy, s);
    point_to_affine(x, y, z);
    u256_cmov(xx, x, 1);
    u256_cmov(yy, y, 1);
    m256_done(x, p256_p);
    m256_done(y, p256_p);
    assert(memcmp(x, sgx, sizeof x) == 0);
    assert(memcmp(y, sgy, sizeof y) == 0);

    scalar_mult(x, y, z, xx, yy, r);
    point_to_affine(x, y, z);
    m256_done(x, p256_p);
    m256_done(y, p256_p);
    assert(memcmp(x, rsgx, sizeof x) == 0);
    assert(memcmp(y, rsgy, sizeof y) == 0);
}

static void assert_sbytes(void)
{
    uint32_t z[8];

    uint8_t p[32] = { 0 };
    assert(scalar_from_bytes(z, p) == -1);

    p[31] = 1;
    assert(scalar_from_bytes(z, p) == 0);
    assert(memcmp(z, one, sizeof z) == 0);

    u256_cmov(z, p256_n, 1);
    u256_to_bytes(p, z);
    assert(scalar_from_bytes(z, p) == -1);

    u256_sub(z, p256_n, one);
    u256_to_bytes(p, z);
    assert(scalar_from_bytes(z, p) == 0);

    assert(scalar_from_bytes(z, rbytes) == 0);
    assert(memcmp(z, r, sizeof z) == 0);
}

/*
 * RNG for testing - may optionally return fixed bytes at the beginning
 */
static uint8_t fixed[128];
static unsigned nb_fixed, nb_drawn;
static int fixed_ret;

static void fix_rng(const uint8_t *bytes, unsigned nb_bytes, int retval)
{
    assert(nb_bytes <= sizeof fixed);
    if (bytes != NULL) {
        memcpy(fixed, bytes, nb_bytes);
    } else {
        memset(fixed, 0, nb_bytes);
    }
    nb_fixed = nb_bytes;
    nb_drawn = 0;
    fixed_ret = retval;
}

static void unfix_rng(void)
{
    nb_fixed = 0;
    nb_drawn = 0;
    fixed_ret = 0;
}

int p256_generate_random(uint8_t *output, unsigned output_size)
{
    unsigned output_offset = 0;

    while (output_offset < output_size && nb_drawn < nb_fixed) {
        output[output_offset++] = fixed[nb_drawn++];
    }

    while (output_offset < output_size) {
        output[output_offset++] = (uint8_t) rand();
        nb_drawn++;
    }

    return fixed_ret;
}

static void printout(char *name, uint8_t *p, unsigned len,
                     unsigned drawn, int ret)
{
    printf("%s: ", name);
    for (unsigned i = 0; i < len; i++)
        printf("%02x", p[i]);
    printf(" (%d, %d)\n", drawn, ret);
}

static void assert_rng_for_tests(void)
{
    uint8_t out[80], fix[64];
    int ret;

    for (uint8_t i = 0; i < 64; i++)
        fix[i] = i;

    ret = p256_generate_random(out, 80);
    printout("rnd", out, 32, nb_drawn, ret);
    assert(ret == 0);

    fix_rng(fix, 32, -1);
    ret = p256_generate_random(out, 80);
    //printout("f32", out, 80, nb_drawn, ret);
    assert(memcmp(fix, out, 32) == 0);
    assert(ret == -1);

    unfix_rng();
    ret = p256_generate_random(out, 80);
    //printout("rnd", out, 80, nb_drawn, ret);
    assert(ret == 0);

    fix_rng(fix, 64, 0);
    ret = p256_generate_random(out, 32);
    ret = p256_generate_random(out + 32, 32);
    ret = p256_generate_random(out + 64, 16);
    //printout("f64", out, 80, nb_drawn, ret);
    assert(memcmp(fix, out, 32) == 0);

    unfix_rng();
    ret = p256_generate_random(out, 80);
    //printout("rnd", out, 80, nb_drawn, ret);
    assert(ret == 0);
}

/*
 * ECDH functions
 */
static void assert_ecdh(void)
{
    int ret;
    uint8_t priv[32], pub[64];

    /* gen_pair - known values */
    fix_rng(rbytes, 32, 0);
    ret = p256_ecdh_gen_pair(priv, pub);
    assert(ret == 0);
    assert(memcmp(priv, rbytes, sizeof priv) == 0);
    assert(memcmp(pub, rgb, sizeof pub) == 0);

    fix_rng(sbytes, 32, 0);
    ret = p256_ecdh_gen_pair(priv, pub);
    assert(ret == 0);
    assert(memcmp(priv, sbytes, sizeof priv) == 0);
    assert(memcmp(pub, sgb, sizeof pub) == 0);

    /* gen_pair - error conditions */
    fix_rng(rbytes, 32, 42);
    ret = p256_ecdh_gen_pair(priv, pub);
    assert(ret == 42);

    fix_rng(NULL, 128, 0);
    ret = p256_ecdh_gen_pair(priv, pub);
    assert(ret == -1);

    memset(pub, 0, 32);
    u256_to_bytes(pub + 32, p256_n);
    fix_rng(pub, 64, 0);
    ret = p256_ecdh_gen_pair(priv, pub);
    assert(ret == 0);
    assert(nb_drawn == 96);

    /* shared secret - known values */
    uint8_t secret[32];
    ret = p256_ecdh_shared_secret(secret, rbytes, sgb);
    assert(ret == 0);
    assert(memcmp(secret, rsgxb, sizeof secret) == 0);

    ret = p256_ecdh_shared_secret(secret, sbytes, rgb);
    assert(ret == 0);
    assert(memcmp(secret, rsgxb, sizeof secret) == 0);

    /* shared secret - error conditions */
    u256_to_bytes(priv, p256_n);
    ret = p256_ecdh_shared_secret(secret, priv, sgb);
    assert(ret != 0);

    u256_to_bytes(pub, p256_p);
    ret = p256_ecdh_shared_secret(secret, rbytes, pub);
    assert(ret != 0);
}

/*
 * ECDSA
 */

static void assert_ecdsa_from_hash(void)
{
    uint32_t z[8];

    ecdsa_m256_from_hash(z, h160a, sizeof h160a);
    assert(memcmp(z, h160a_e, sizeof z) == 0);

    ecdsa_m256_from_hash(z, h224a, sizeof h224a);
    assert(memcmp(z, h224a_e, sizeof z) == 0);

    ecdsa_m256_from_hash(z, h256a, sizeof h256a);
    assert(memcmp(z, h256a_e, sizeof z) == 0);

    ecdsa_m256_from_hash(z, h384a, sizeof h384a);
    assert(memcmp(z, h384a_e, sizeof z) == 0);

    ecdsa_m256_from_hash(z, h512a, sizeof h512a);
    assert(memcmp(z, h512a_e, sizeof z) == 0);

    ecdsa_m256_from_hash(z, h160b, sizeof h160b);
    assert(memcmp(z, h160b_e, sizeof z) == 0);

    ecdsa_m256_from_hash(z, h224b, sizeof h224b);
    assert(memcmp(z, h224b_e, sizeof z) == 0);

    ecdsa_m256_from_hash(z, h256b, sizeof h256b);
    assert(memcmp(z, h256b_e, sizeof z) == 0);

    ecdsa_m256_from_hash(z, h384b, sizeof h384b);
    assert(memcmp(z, h384b_e, sizeof z) == 0);

    ecdsa_m256_from_hash(z, h512b, sizeof h512b);
    assert(memcmp(z, h512b_e, sizeof z) == 0);
}

static void assert_ecdsa_sign_one(const uint8_t k[32], const uint8_t sigref[64],
                                  const uint8_t *hash, size_t hlen)
{
    int ret;
    uint8_t sig[64];

    fix_rng(k, 32, 0);
    ret = p256_ecdsa_sign(sig, ecdsa_priv, hash, hlen);
    assert(ret == 0);
    assert(memcmp(sig, sigref, sizeof sig) == 0);
}

static void assert_ecdsa_sign(void)
{
    /* known values */
    assert_ecdsa_sign_one(k160a, sig160a, h160a, sizeof h160a);
    assert_ecdsa_sign_one(k224a, sig224a, h224a, sizeof h224a);
    assert_ecdsa_sign_one(k256a, sig256a, h256a, sizeof h256a);
    assert_ecdsa_sign_one(k384a, sig384a, h384a, sizeof h384a);
    assert_ecdsa_sign_one(k512a, sig512a, h512a, sizeof h512a);
    assert_ecdsa_sign_one(k160b, sig160b, h160b, sizeof h160b);
    assert_ecdsa_sign_one(k224b, sig224b, h224b, sizeof h224b);
    assert_ecdsa_sign_one(k256b, sig256b, h256b, sizeof h256b);
    assert_ecdsa_sign_one(k384b, sig384b, h384b, sizeof h384b);
    assert_ecdsa_sign_one(k512b, sig512b, h512b, sizeof h512b);

    /* TODO: failing RNG, bad priv) */
}

/* TODO: ecdsa verify internal edge case for add_or_double? */

int main(void)
{
    /* testing the test RNG */
    assert_rng_for_tests();

    /* u256 */
    assert_add(r, s, rps, 0u);
    assert_sub(r, s, rms, 0u);
    assert_sub(s, r, smr, 1u);
    assert_cmov();
    assert_ubytes();

    /* m256 */
    assert_madd();
    assert_msub();
    assert_mmul();
    assert_prep_mul_done();
    assert_inv();
    assert_mbytes();

    /* point */
    assert_pt_params();
    assert_pt_check();
    assert_pt_affine();
    assert_pt_double();
    assert_pt_add();
    assert_pt_add_or_double();
    assert_pt_bytes();

    /* scalar */
    assert_scalar_mult();
    assert_sbytes();

    /* ecdh */
    assert_ecdh();

    /* ecdsa */
    assert_ecdsa_from_hash();
    assert_ecdsa_sign();
}
