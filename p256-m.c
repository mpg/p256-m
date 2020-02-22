#include "p256-m.h"

#if !defined(NO_MAIN)
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#endif

#if defined(NO_MAIN)
#define STATIC
#else
#define STATIC static
#endif

/**********************************************************************
 *
 * Operations on fixed-width unsigned integers
 *
 * Represented using 32-bit limbs, least significant limb first.
 * That is: x = x[0] + 2^32 x[1] + ... + 2^224 x[7] for 256-bit.
 *
 **********************************************************************/

/*
 * 256-bit set to 32-bit value
 *
 * in: x in [0, 2^32)
 * out: z = x
 */
static void u256_set32(uint32_t z[8], uint32_t x)
{
    z[0] = x;
    for (unsigned i = 1; i < 8; i++) {
        z[i] = 0;
    }
}

/*
 * 256-bit addition
 *
 * in: x, y in [0, 2^256)
 * out: z = (x + y) mod 2^256
 *      c = (x + y) div 2^256
 * That is, z + c * 2^256 = x + y
 *
 * Note: as a memory area, z must be either equal to x or y, or not overlap.
 */
static uint32_t u256_add(uint32_t z[8],
                         const uint32_t x[8], const uint32_t y[8])
{
    uint32_t carry = 0;

    for (unsigned i = 0; i < 8; i++) {
        uint64_t sum = (uint64_t) carry + x[i] + y[i];
        z[i] = (uint32_t) sum;
        carry = (uint32_t) (sum >> 32);
    }

    return carry;
}

/*
 * 256-bit subtraction
 *
 * in: x, y in [0, 2^256)
 * out: z = (x - y) mod 2^256
 *      c = 0 if x >=y, 1 otherwise
 * That is, z = c * 2^256 + x - y
 *
 * Note: as a memory area, z must be either equal to x or y, or not overlap.
 */
static uint32_t u256_sub(uint32_t z[8],
                         const uint32_t x[8], const uint32_t y[8])
{
    uint32_t carry = 0;

    for (unsigned i = 0; i < 8; i++) {
        uint64_t diff = (uint64_t) x[i] - y[i] - carry;
        z[i] = (uint32_t) diff;
        carry = -(uint32_t) (diff >> 32);
    }

    return carry;
}

/*
 * 256-bit conditional assignment
 *
 * in: x in [0, 2^256)
 *     c in [0, 1]
 * out: z = x if c == 1, z unchanged otherwise
 *
 * Note: as a memory area, z must be either equal to x, or not overlap.
 */
static void u256_cmov(uint32_t z[8], const uint32_t x[8], uint32_t c)
{
    const uint32_t x_mask = -c;
    for (unsigned i = 0; i < 8; i++) {
        z[i] = (z[i] & ~x_mask) | (x[i] & x_mask);
    }
}

/*
 * 256-bit compare for equality
 *
 * in: x in [0, 2^256)
 *     y in [0, 2^256)
 * out: 0 if x == y, unspecified non-zero otherwise
 */
static uint32_t u256_diff(const uint32_t x[8], const uint32_t y[8])
{
    uint32_t diff = 0;
    for (unsigned i = 0; i < 8; i++) {
        diff |= x[i] ^ y[i];
    }
    return diff;
}

/*
 * 288 + 32 x 256 -> 288-bit multiply and add
 *
 * in: x in [0, 2^32)
 *     y in [0, 2^256)
 *     z in [0, 2^288)
 * out: z_out = z_in + x * y mod 2^288
 *      c     = z_in + x * y div 2^288
 * That is, z_out + c * 2^288 = z_in + x * y
 *
 * Note: as a memory area, z must be either equal to y, or not overlap.
 *
 * This is a helper for Montgomery multiplication.
 */
static uint32_t u288_muladd(uint32_t z[9], uint32_t x, const uint32_t y[8])
{
    uint32_t carry = 0;

    for (unsigned i = 0; i < 8; i++) {
        uint64_t prod = (uint64_t) x * y[i] + z[i] + carry;
        z[i] = (uint32_t) prod;
        carry = (uint32_t) (prod >> 32);
    }

    uint64_t sum = (uint64_t) z[8] + carry;
    z[8] = (uint32_t) sum;
    carry = (uint32_t) (sum >> 32);

    return carry;
}

/*
 * 288-bit in-place right shift by 32 bits
 *
 * in: z in [0, 2^288)
 *     c in [0, 2^32)
 * out: z_out = z_in div 2^32 + c * 2^256
 *            = (z_in + c * 2^288) div 2^32
 *
 * This is a helper for Montgomery multiplication.
 */
static void u288_rshift32(uint32_t z[9], uint32_t c)
{
    for (unsigned i = 0; i < 8; i++) {
        z[i] = z[i + 1];
    }
    z[8] = c;
}

/*
 * 256-bit import from big-endian bytes
 *
 * in: p = p0, ..., p31
 * out: z = p0 * 2^248 + p1 * 2^240 + ... + p30 * 2^8 + p31
 */
STATIC void u256_from_bytes(uint32_t z[8], const uint8_t p[32])
{
    for (unsigned i = 0; i < 8; i++) {
        unsigned j = 4 * (7 - i);
        z[i] = ((uint32_t) p[j + 0] << 24) |
               ((uint32_t) p[j + 1] << 16) |
               ((uint32_t) p[j + 2] <<  8) |
               ((uint32_t) p[j + 3] <<  0);
    }
}

/*
 * 256-bit export to big-endian bytes
 *
 * in: z in [0, 2^256)
 * out: p = p0, ..., p31 such that
 *      z = p0 * 2^248 + p1 * 2^240 + ... + p30 * 2^8 + p31
 */
STATIC void u256_to_bytes(uint8_t p[32], const uint32_t z[8])
{
    for (unsigned i = 0; i < 8; i++) {
        unsigned j = 4 * (7 - i);
        p[j + 0] = (uint8_t) (z[i] >> 24);
        p[j + 1] = (uint8_t) (z[i] >> 16);
        p[j + 2] = (uint8_t) (z[i] >>  8);
        p[j + 3] = (uint8_t) (z[i] >>  0);
    }
}

/**********************************************************************
 *
 * Operations modulo a 256-bit prime m
 *
 * These are done in the Montgomery domain, that is x is represented by
 *  x * 2^256 mod m
 * Numbers need to be converted to that domain before computations,
 * and back from it afterwards.
 *
 * Inversion is computed using Fermat's little theorem.
 *
 * Montgomery operations require that m is odd,
 * and Fermat's little theorem require it to be a prime.
 * In practice operations are done modulo the curve's p and n,
 * both of which are large primes.
 *
 **********************************************************************/

/*
 * Primes associated to the curve, modulo which we'll compute
 */
static const uint32_t p256_p[8] = {     /* the curve's p */
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
    0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF,
};

STATIC const uint32_t p256_n[8] = {     /* the curve's n */
    0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD,
    0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF,
};

/*
 * Montgomery constants associated to the above primes
 *
 * Order them in a tables with:
 *  the value associated to p in position 1,
 *  the value associated to n in position 0.
 *
 * This is a trick to allow selecting the proper value given m = p or n
 * by using m[6] as the index in this table (see values or p and n above).
 */
static inline uint32_t m256_mont_idx(const uint32_t m[8])
{
    return m[6];        /* conveniently happens to be 0 for n, 1 for p */
}

static const uint32_t m256_mont_ni[2] = {       /* negative inverses or n and p */
    0xee00bc4f, /* -n^-1 mod 32 */
    0x00000001, /* -p^-1 mod 32 */
};

static const uint32_t m256_mont_R2[2][8] = {    /* R^2 mod n and p, with R = 2^256 */
    {   /* 2^512 mod n */
     0xbe79eea2, 0x83244c95, 0x49bd6fa6, 0x4699799c,
     0x2b6bec59, 0x2845b239, 0xf3d95620, 0x66e12d94,
      },
    {   /* 2^512 mod p */
     0x00000003, 0x00000000, 0xffffffff, 0xfffffffb,
     0xfffffffe, 0xffffffff, 0xfffffffd, 0x00000004,
      },
};

/*
 * Modular addition
 *
 * in: x, y in [0, m)
 *     m in [0, 2^256)
 * out: z = (x + y) mod m, in [0, m)
 *
 * Note: as a memory area, z must be either equal to x or y, or not overlap.
 */
static void m256_add(uint32_t z[8],
                     const uint32_t x[8], const uint32_t y[8],
                     const uint32_t m[8])
{
    uint32_t r[8];
    uint32_t carry_add = u256_add(z, x, y);
    uint32_t carry_sub = u256_sub(r, z, m);
    /* Need to subract m if:
     *      x+y >= 2^256 > m (that is, carry_add == 1)
     *   OR z >= m (that is, carry_sub == 0) */
    uint32_t use_sub = carry_add | (1 - carry_sub);
    u256_cmov(z, r, use_sub);
}

/*
 * Modular subtraction
 *
 * in: x, y in [0, m)
 *     m in [0, 2^256)
 * out: z = (x - y) mod m, in [0, m)
 *
 * Note: as a memory area, z must be either equal to x or y, or not overlap.
 */
static void m256_sub(uint32_t z[8],
                     const uint32_t x[8], const uint32_t y[8],
                     const uint32_t m[8])
{
    uint32_t r[8];
    uint32_t carry = u256_sub(z, x, y);
    (void) u256_add(r, z, m);
    /* Need to add m if and only if x < y, that is carry == 1.
     * In that case z is in [2^256 - m + 1, 2^256 - 1], so the
     * addition will have a carry as well, which cancels out. */
    u256_cmov(z, r, carry);
}

/*
 * Montgomery modular multiplication
 *
 * in: x, y in [0, m)
 *     m must be either p256_p or p256_n
 * out: z = (x * y) / 2^256 mod m, in [0, m)
 *
 * Note: as a memory area, z may overlap with x or y.
 */
static void m256_mul(uint32_t z[8],
                     const uint32_t x[8], const uint32_t y[8],
                     const uint32_t m[8])
{
    /*
     * Algorithm 14.36 in Handbook of Applied Cryptography with:
     * b = 2^32, n = 8, R = 2^256
     */
    uint32_t m_prime = m256_mont_ni[m256_mont_idx(m)];
    uint32_t a[9] = { 0 };

    for (unsigned i = 0; i < 8; i++) {
        /* the "mod 2^32" is implicit from the type */
        uint32_t u = (a[0] + x[i] * y[0]) * m_prime;

        /* a = (a + x[i] * y + u * m) div b */
        uint32_t c = u288_muladd(a, x[i], y);
        c += u288_muladd(a, u, m);
        u288_rshift32(a, c);
    }

    /* a = a > m ? a - m : a */
    uint32_t carry_add = a[8];  // 0 or 1 since a < 2m, see HAC Note 14.37
    uint32_t carry_sub = u256_sub(z, a, m);
    uint32_t use_sub = carry_add | (1 - carry_sub);     // see m256_add()
    u256_cmov(z, a, 1 - use_sub);
}

/*
 * In-place conversion to Montgomery form
 *
 * in: z in [0, m)
 *     m must be either p256_p or p256_n
 * out: z_out = z_in * 2^256 mod m, in [0, m)
 */
static void m256_prep(uint32_t z[8], const uint32_t m[8])
{
    const uint32_t *R2m = m256_mont_R2[m256_mont_idx(m)];

    m256_mul(z, z, R2m, m);
}

/*
 * In-place conversion from Montgomery form
 *
 * in: z in [0, m)
 *     m must be either p256_p or p256_n
 * out: z_out = z_in / 2^256 mod m, in [0, m)
 * That is, z_in was z_actual * 2^256 mod m, and z_out is z_actual
 */
STATIC void m256_done(uint32_t z[8], const uint32_t m[8])
{
    uint32_t one[8];
    u256_set32(one, 1);
    m256_mul(z, z, one, m);
}

/*
 * Set to 32-bit value
 *
 * in: x in [0, 2^32)
 *     m must be either p256_p or p256_n
 * out: z = x * 2^256 mod m, in [0, m)
 * That is, z is set to the image of x in the Montgomery domain.
 */
static void m256_set32(uint32_t z[8], uint32_t x, const uint32_t m[8])
{
    u256_set32(z, x);
    m256_prep(z, m);
}

/*
 * Modular inversion in Montgomery form
 *
 * in: x in [0, m)
 *     m must be either p256_p or p256_n
 * out: z = = x^-1 * 2^512 mod m
 * That is, if x = x_actual    * 2^256 mod m, then
 *             z = x_actual^-1 * 2^256 mod m
 *
 * Note: as a memory area, z may overlap with x or y.
 */
static void m256_inv(uint32_t z[8], const uint32_t x[8],
                     const uint32_t m[8])
{
    /*
     * Use Fermat's little theorem to compute x^-1 as x^(m-2).
     *
     * Take advantage of the fact that both p's and n's least significant limb
     * is greater that 2 to perform the subtraction on the flight (no carry).
     *
     * Use plain right-to-left binary exponentiation;
     * branches are OK as the exponent is not a secret.
     */
    uint32_t bitval[8];
    u256_cmov(bitval, x, 1);    /* copy x before writing to z */

    m256_set32(z, 1, m);

    unsigned i = 0;
    uint32_t limb = m[i] - 2;
    while (1) {
        for (unsigned j = 0; j < 32; j++) {
            if ((limb & 1) != 0) {
                m256_mul(z, z, bitval, m);
            }
            m256_mul(bitval, bitval, bitval, m);
            limb >>= 1;
        }

        if (i == 7)
            break;

        i++;
        limb = m[i];
    }
}

/*
 * Import modular integer from bytes to Montgomery domain
 *
 * in: p = p0, ..., p32
 *     m must be either p256_p or p256_n
 * out: z = (p0 * 2^248 + ... + p31) * 2^256 mod m, in [0, m)
 *      return 0 if the number was already in [0, m), or -1.
 *      z may be incorrect and must be discared when -1 is returned.
 */
STATIC int m256_from_bytes(uint32_t z[8],
                           const uint8_t p[32], const uint32_t m[8])
{
    u256_from_bytes(z, p);

    uint32_t t[8];
    uint32_t lt_m = u256_sub(t, z, m);
    if (lt_m != 1)
        return -1;

    m256_prep(z, m);
    return 0;
}

/*
 * Export modular integer from Montgomery domain to bytes
 *
 * in: z in [0, 2^256)
 * out: p = p0, ..., p31 such that
 *      z = (p0 * 2^248 + ... + p31) * 2^256 mod m
 */
STATIC void m256_to_bytes(uint8_t p[32],
                          const uint32_t z[8], const uint32_t m[8])
{
    uint32_t zi[8];
    u256_cmov(zi, z, 1);
    m256_done(zi, m);

    u256_to_bytes(p, zi);
}

/**********************************************************************
 *
 * Operations on curve points
 *
 * Points are represented in two coordinates system:
 *  - affine (x, y)
 *  - jacobian (x:y:z)
 * In either case, coordinates are integers modulo p256_p and
 * are always represented in the Montgomery domain.
 *
 * For background on jacobian coordinates, see for example [GECC] 3.2.2:
 * - conversions go (x, y) -> (x:y:1) and (x:y:z) -> (x/z^2, y/z^3)
 * - the curve equation becomes y^2 = x^3 - 3 x z^4 + b z^6
 * - the origin (aka 0 aka point at infinity) is (x:y:0) with y^2 = x^3.
 * - point negation goes -(x:y:z) = (x:-y:z)
 *
 * References:
 * - [GECC]: Guide to Elliptic Curve Cryptography; Hankerson, Menezes,
 *   Vanstone; Springer, 2004.
 * - [CMO98]: Efficient Elliptic Curve Exponentiation Using Mixed Coordinates;
 *   Cohen, Miyaji, Ono; Springer, ASIACRYPT 1998.
 *   https://link.springer.com/content/pdf/10.1007/3-540-49649-1_6.pdf
 * - [RCB15]: Complete addition formulas for prime order elliptic curves;
 *   Renes, Costello, Batina; IACR e-print 2015-1060.
 *   https://eprint.iacr.org/2015/1060.pdf
 *
 **********************************************************************/

/*
 * The curve's b parameter in the Short Weierstrass equation
 *  y^2 = x^3 - 3*x + b
 * Compared to the standard, this is converted to the Montgomery domain.
 */
static const uint32_t p256_b[8] = { /* b * 2^256 mod p */
    0x29c4bddf, 0xd89cdf62, 0x78843090, 0xacf005cd,
    0xf7212ed6, 0xe5a220ab, 0x04874834, 0xdc30061d,
};

/*
 * The curve's conventional base point G.
 * Compared to the standard, coordinates converted to the Montgomery domain.
 */
STATIC const uint32_t p256_gx[8] = { /* G_x * 2^256 mod p */
    0x18a9143c, 0x79e730d4, 0x5fedb601, 0x75ba95fc,
    0x77622510, 0x79fb732b, 0xa53755c6, 0x18905f76,
};
STATIC const uint32_t p256_gy[8] = { /* G_y * 2^256 mod p */
    0xce95560a, 0xddf25357, 0xba19e45c, 0x8b4ab8e4,
    0xdd21f325, 0xd2e88688, 0x25885d85, 0x8571ff18,
};

/*
 * Point-on-curve check - do the coordinates satisfy the curve's equation?
 *
 * in: x, y in [0, p)   (Montgomery domain)
 * out: 0 if the point lies on the curve, unspecified non-zero otherwise
 */
STATIC uint32_t point_check(const uint32_t x[8], const uint32_t y[8])
{
    uint32_t lhs[8], rhs[8];

    /* lhs = y^2 */
    m256_mul(lhs, y, y, p256_p);

    /* rhs = x^3 - 3x + b */
    m256_mul(rhs, x,   x, p256_p);      /* x^2 */
    m256_mul(rhs, rhs, x, p256_p);      /* x^3 */
    for (unsigned i = 0; i < 3; i++)
        m256_sub(rhs, rhs, x, p256_p);  /* x^3 - 3x */
    m256_add(rhs, rhs, p256_b, p256_p); /* x^3 - 3x + b */

    return u256_diff(lhs, rhs);
}

/*
 * In-place jacobian to affine coordinate conversion
 *
 * in: x, y, z in [0, p)        (Montgomery domain)
 * out: x_out = x_in / z_in^2   (Montgomery domain)
 *      y_out = y_in / z_in^3   (Montgomery domain)
 *      z_out unspecified, must be disregarded
 */
STATIC void point_to_affine(uint32_t x[8], uint32_t y[8], uint32_t z[8])
{
    uint32_t t[8];

    m256_inv(z, z, p256_p);     /* z = z^-1 */

    m256_mul(t, z, z, p256_p);  /* t = z^-2 */
    m256_mul(x, x, t, p256_p);  /* x = x * z^-2 */

    m256_mul(t, t, z, p256_p);  /* t = z^-3 */
    m256_mul(y, y, t, p256_p);  /* y = y * z^-3 */
}

/*
 * In-place point doubling in jacobian coordinates (Montgomery domain)
 *
 * in: P_in = (x:y:z), must be on the curve
 * out: (x:y:z) = P_out = 2 * P_in
 */
static void point_double(uint32_t x[8], uint32_t y[8], uint32_t z[8])
{
    /*
     * This is formula 6 from [CMO98], cited as complete in [RCB15] (table 1).
     * Notations as in the paper, except u added and t ommited (it's x3).
     */
    uint32_t m[8], s[8], u[8];

    /* m = 3 * x^2 + a * z^4 = 3 * (x + z^2) * (x - z^2) */
    m256_mul(s, z, z, p256_p);
    m256_add(m, x, s, p256_p);
    m256_sub(u, x, s, p256_p);
    m256_mul(s, m, u, p256_p);
    m256_add(m, s, s, p256_p);
    m256_add(m, m, s, p256_p);

    /* s = 4 * x * y^2 */
    m256_mul(u, y, y, p256_p);
    m256_add(u, u, u, p256_p); /* u = 2 * y^2 (used below) */
    m256_mul(s, x, u, p256_p);
    m256_add(s, s, s, p256_p);

    /* u = 8 * y^4 (not named in the paper, first term of y3) */
    m256_mul(u, u, u, p256_p);
    m256_add(u, u, u, p256_p);

    /* x3 = t = m^2 - 2 * s */
    m256_mul(x, m, m, p256_p);
    m256_sub(x, x, s, p256_p);
    m256_sub(x, x, s, p256_p);

    /* z3 = 2 * y * z */
    m256_mul(z, y, z, p256_p);
    m256_add(z, z, z, p256_p);

    /* y3 = -u + m * (s - t) */
    m256_sub(y, s, x, p256_p);
    m256_mul(y, y, m, p256_p);
    m256_sub(y, y, u, p256_p);
}

/*
 * In-place point addition in jacobian-affine coordinates (Montgomery domain)
 *
 * in: P_in = (x1:y1:z1), must be on the curve and not the origin
 *     Q = (x2, y2), must be on the curve and not P_in or -P_in
 * out: P_out = (x1:y1:z1) = P_in + Q
 */
STATIC void point_add(uint32_t x1[8], uint32_t y1[8], uint32_t z1[8],
                      const uint32_t x2[8], const uint32_t y2[8])
{
    /*
     * This is formula 5 from [CMO98], with z2 == 1 substituted. We use
     * intermediates with neutral names, and names from the paper in comments.
     */
    uint32_t t1[8], t2[8], t3[8];

    /* u1 = x1 and s1 = y1 (no computations) */

    /* t1 = u2 = x2 z1^2 */
    m256_mul(t1, z1, z1, p256_p);
    m256_mul(t2, t1, z1, p256_p);
    m256_mul(t1, t1, x2, p256_p);

    /* t2 = s2 = y2 z1^3 */
    m256_mul(t2, t2, y2, p256_p);

    /* t1 = h = u2 - u1 */
    m256_sub(t1, t1, x1, p256_p); /* t1 = x2 * z1^2 - x1 */

    /* t2 = r = s2 - s1 */
    m256_sub(t2, t2, y1, p256_p);

    /* z3 = z1 * h */
    m256_mul(z1, z1, t1, p256_p);

    /* t1 = h^3 */
    m256_mul(t3, t1, t1, p256_p);
    m256_mul(t1, t3, t1, p256_p);

    /* t3 = x1 * h^2 */
    m256_mul(t3, t3, x1, p256_p);

    /* x3 = r^2 - 2 * x1 * h^2 - h^3 */
    m256_mul(x1, t2, t2, p256_p);
    m256_sub(x1, x1, t3, p256_p);
    m256_sub(x1, x1, t3, p256_p);
    m256_sub(x1, x1, t1, p256_p);

    /* y3 = r * (x1 * h^2 - x3) - y1 h^3 */
    m256_sub(t3, t3, x1, p256_p);
    m256_mul(t3, t3, t2, p256_p);
    m256_mul(t1, t1, y1, p256_p);
    m256_sub(y1, t3, t1, p256_p);
}

/*
 * Point addition or doubling (affine to jacobian, Montgomery domain)
 *
 * in: P = (x1, y1) - must be on the curve and not the origin
 *     Q = (x2, y2) - must be on the curve and not the origin
 * out: (x3:y3:z3) = R = P + Q
 *
 * Note: unlike point_add(), this function works if P = +- Q;
 * however it leaks information on its input through timing,
 * branches taken and memory access patterns (if observable).
 */
STATIC void point_add_or_double_leaky(
                        uint32_t x3[8], uint32_t y3[8], uint32_t z3[8],
                        const uint32_t x1[8], const uint32_t y1[8],
                        const uint32_t x2[8], const uint32_t y2[8])
{
    if (u256_diff(x1, x2) != 0) {
        // P != +- Q -> generic addition
        u256_cmov(x3, x1, 1);
        u256_cmov(y3, y1, 1);
        m256_set32(z3, 1, p256_p);
        point_add(x3, y3, z3, x2, y2);
    }
    else if (u256_diff(y1, y2) == 0) {
        // P == Q -> double
        u256_cmov(x3, x1, 1);
        u256_cmov(y3, y1, 1);
        m256_set32(z3, 1, p256_p);
        point_double(x3, y3, z3);
    } else {
        // P == -Q -> zero
        m256_set32(x3, 1, p256_p);
        m256_set32(y3, 1, p256_p);
        m256_set32(z3, 0, p256_p);
    }
}

/*
 * Import curve point from bytes
 *
 * in: p = (x, y) concatenated, fixed-width 256-bit big-endian integers
 * out: x, y in Mongomery domain
 *      return 0 if x and y are both in [0, p) and (x, y) is on the curve,
 *             unspecified non-zero otherwise.
 *      x and y are unspecified and must be discarded if returning non-zero.
 */
STATIC int point_from_bytes(uint32_t x[8], uint32_t y[8], const uint8_t p[64])
{
    int ret;

    ret = m256_from_bytes(x, p, p256_p);
    if (ret != 0)
        return ret;

    ret = m256_from_bytes(y, p + 32, p256_p);
    if (ret != 0)
        return ret;

    return (int) point_check(x, y);
}

/*
 * Export curve point to bytes
 *
 * in: x, y affine coordinates of a point (Montgomery domain)
 * out: p = (x, y) concatenated, fixed-width 256-bit big-endian integers
 */
STATIC void point_to_bytes(uint8_t p[64],
                           const uint32_t x[8], const uint32_t y[8])
{
    m256_to_bytes(p,        x, p256_p);
    m256_to_bytes(p + 32,   y, p256_p);
}

/**********************************************************************
 *
 * Scalar multiplication and other scalar-related operations
 *
 **********************************************************************/

/*
 * Scalar multiplication
 *
 * in: P = (px, py), affine (Montgomery), must be on the curve
 *     s in [1, n-1]
 * out: R = s * P = (rx:ry:rz), jacobian coordinates (Montgomery).
 */
STATIC void scalar_mult(uint32_t rx[8], uint32_t ry[8], uint32_t rz[8],
                        const uint32_t px[8], const uint32_t py[8],
                        const uint32_t s[8])
{
    /*
     * We use a signed binary ladder, see for example slides 10-14 of
     * http://ecc2015.math.u-bordeaux1.fr/documents/hamburg.pdf but with
     * implicit recoding, and a different loop initialisation to avoid feeding
     * 0 to our addition formulas, as they don't support it.
     */
    uint32_t s_odd[8], py_neg[8], py_use[8];

    /*
     * Make s odd by replacing it with n - s if necessary.
     *
     * If s was odd, we'll have s_odd = s, and define P' = P.
     * Otherwise, we'll have s_odd = n - s and define P' = -P.
     *
     * Either way, we can compute s * P as s_odd * P'.
     */
    u256_sub(s_odd, p256_n, s); /* no carry, result still in [1, n-1] */
    uint32_t negate = ~s[0] & 1;
    u256_cmov(s_odd, s, 1 - negate);

    /* Compute py_neg = - py mod p (that's the y coordinate of -P) */
    u256_set32(py_use, 0);
    m256_sub(py_neg, py_use, py, p256_p);

    /* Initialize R = P' = (x:(-1)^negate * y:1) */
    u256_cmov(rx, px, 1);
    u256_cmov(ry, py, 1);
    m256_set32(rz, 1, p256_p);
    u256_cmov(ry, py_neg, negate);

    /*
     * For any odd number s_odd = b255 ... b1 1, we have
     *      s_odd = 2^255 + 2^254 sbit(b255) + ... + 2 sbit(b2) + sbit(b1)
     * writing
     *      sbit(b) = 2 * b - 1 = b ? 1 : 1
     *
     * Use that to compute s_odd * P' by repeating R = 2 * R +- P':
     *      s_odd * P' = 2 * ( ... (2 * P' + sbit(b255) P') ... ) + sbit(b1) P'
     *
     * The loop invariant is that when beginning an iteration we have
     *      R = s_i P'
     * with
     *      s_i = 2^(255-i) + 2^(254-i) sbit(b_255) + ...
     * where the sum has 256 - i terms.
     *
     * When updating R we need to make sure the input to point_add() is
     * neither 0 not +-P'. Since that input is 2 s_i P', it is sufficient to
     * see that 1 < 2 s_i < n-1. The lower bound is obvious since s_i is a
     * positive integer, and for the upper bound we distinguish three cases.
     *
     * If i > 1, then s_i < 2^254, so 2 s_i < 2^255 < n-1.
     * Otherwise, i == 1 and we have 2 s_i = s_odd - * sbit(b1).
     *      If s_odd <= n-4, then 2 s_1 <= n-3.
     *      Otherwise, s_odd = n-2, and for this curve's value of n,
     *      we have b1 == 1, so sbit(b1) = 1 and 2 s_1 <= n-3.
     */
    for (unsigned i = 255; i > 0; i--) {
        uint32_t bit = (s_odd[i / 32] >> i % 32) & 1;

        /* set (px, py_use) = sbit(bit) P' = sbit(bit) * (-1)^negate P' */
        u256_cmov(py_use, py, bit ^ negate);
        u256_cmov(py_use, py_neg, (1 - bit) ^ negate);

        /* Update R = 2 * R +- P' */
        point_double(rx, ry, rz);
        point_add(rx, ry, rz, px, py_use);
    }
}

/*
 * Scalar import from big-endian bytes
 *
 * in: p = p0, ..., p31
 * out: s = p0 * 2^248 + p1 * 2^240 + ... + p30 * 2^8 + p31
 *      return 0 if s in [1, n-1],
 *            -1 otherwise.
 */
STATIC int scalar_from_bytes(uint32_t s[8], const uint8_t p[32])
{
    u256_from_bytes(s, p);

    uint32_t r[8];
    uint32_t lt_n = u256_sub(r, s, p256_n);

    u256_set32(r, 1);
    uint32_t lt_1 = u256_sub(r, s, r);

    if (lt_n && !lt_1)
        return 0;

    return -1;
}

/*
 * Scalar generation, with public key
 *
 * out: sbytes the big-endian bytes representation of the scalar
 *      s its u256 representation
 *      x, y the affine coordinates of s * G (Montgomery domain)
 *      return 0 if OK, non-zero on failure
 *      sbytes, s, x, y must be discarded when returning non-zero.
 */
static int scalar_gen_with_pub(uint8_t sbytes[32], uint32_t s[8],
                               uint32_t x[8], uint32_t y[8])
{
    /* generate a random valid scalar */
    int ret;
    unsigned nb_tried = 0;
    do {
        if (nb_tried++ >= 4)
            return -1;

        ret = p256_generate_random(sbytes, 32);
        if (ret != 0)
            return ret;

        ret = scalar_from_bytes(s, sbytes);
    }
    while (ret != 0);

    /* compute and ouput the associated public key */
    uint32_t z[8];
    scalar_mult(x, y, z, p256_gx, p256_gy, s);
    point_to_affine(x, y, z);

    return 0;
}

/**********************************************************************
 *
 * ECDH
 *
 **********************************************************************/

/*
 * ECDH generate pair
 */
int p256_ecdh_gen_pair(uint8_t priv[32], uint8_t pub[64])
{
    uint32_t s[8], x[8], y[8];
    int ret = scalar_gen_with_pub(priv, s, x, y);

    point_to_bytes(pub, x, y);
    return ret;
}

/*
 * ECDH compute shared secret
 */
int p256_ecdh_shared_secret(uint8_t secret[32],
                            const uint8_t priv[32], const uint8_t peer[64])
{
    uint32_t s[8], px[8], py[8], x[8], y[8], z[8];
    int ret;

    ret = scalar_from_bytes(s, priv);
    if (ret != 0)
        return ret;

    ret = point_from_bytes(px, py, peer);
    if (ret != 0)
        return ret;

    scalar_mult(x, y, z, px, py, s);
    point_to_affine(x, y, z);

    m256_to_bytes(secret, x, p256_p);
    return 0;
}

/**********************************************************************
 *
 * ECDSA
 *
 * Reference:
 * [SEC1] SEC 1: Elliptic Curve Cryptography, Certicom research, 2009.
 *        http://www.secg.org/sec1-v2.pdf
 **********************************************************************/

/*
 * Import integer mod n (Montgomery domain) from hash
 *
 * in: h = h0, ..., h_hlen
 *     hlen the length of h in bytes
 * out: z = (h0 * 2^l-8 + ... + h_l) * 2^256 mod n
 *      with l = min(32, hlen)
 *
 * Note: in [SEC1] this is step 5 of 4.1.3 (sign) or step 3 or 4.1.4 (verify),
 * with obvious simplications since n's bit-length is a multiple of 8.
 */
STATIC void ecdsa_m256_from_hash(uint32_t z[8],
                                 const uint8_t *h, size_t hlen)
{
    /* convert from h (big-endian) */
    if (hlen < 32) {
        uint8_t p[32] = { 0 };
        for (unsigned i = 0; i < hlen; i++)
            p[32 - hlen + i] = h[i];
        u256_from_bytes(z, p);
    } else {
        u256_from_bytes(z, h);
    }

    /* ensure the result is in [0, n) */
    uint32_t t[8];
    uint32_t c = u256_sub(t, z, p256_n);
    u256_cmov(z, t, 1 - c);

    /* map to Montgomery domain */
    m256_prep(z, p256_n);
}

/*
 * ECDSA sign
 */
int p256_ecdsa_sign(uint8_t sig[64], const uint8_t priv[32],
                    const uint8_t *hash, size_t hlen)
{
    /*
     * Steps and notations from [SEC1] 4.1.3
     *
     * Instead of retrying on r == 0 or s == 0, just abort,
     * as those events have negligible probability.
     */
    int ret;

    /* 1. Set ephemeral keypair */
    uint8_t kb[32];
    uint32_t k[8], xr[8], yr[8];
    ret = scalar_gen_with_pub(kb, k, xr, yr);
    if (ret != 0)
        return ret;
    m256_prep(k, p256_n);

    /* 2. Convert xr to an integer */
    m256_done(xr, p256_p);

    /* 3. Reduce xr mod n (extra: output it while at it) */
    uint32_t c = u256_sub(yr, xr, p256_n);
    u256_cmov(xr, yr, 1 - c);

    u256_to_bytes(sig, xr);
    // TODO: if xr == 0 return -1

    m256_prep(xr, p256_n);

    /* 4. Skipped - we take the hash as an input, not the message */

    /* 5. Derive an integer from the hash */
    uint32_t e[8];
    ecdsa_m256_from_hash(e, hash, hlen);

    /* 6. Compute s = k^-1 * (e + r * dU) */
    uint32_t du[8];
    ret = m256_from_bytes(du, priv, p256_n);
    if (ret != 0)
        return ret;

    uint32_t s[8];
    m256_inv(s, k, p256_n);         /* s = k^-1 */
    m256_mul(yr, xr, du, p256_n);   /* yr = r * dU */
    m256_add(yr, e, yr, p256_n);    /* yr = e + r * dU */
    m256_mul(s, s, yr, p256_n);     /* s = k^-1 * (e + r * dU) */

    /* 7. Output s (r already outputed at step 3) */
    m256_to_bytes(sig + 32, s, p256_n);
    // TODO: if s == 0 return -1

    return 0;
}

/**********************************************************************
 *
 * Functions and data for testing and debugging
 *
 **********************************************************************/

#if !defined(NO_MAIN)
static void print_u256(const char *name, const uint32_t x[8], uint32_t c)
{
    printf("%s: ", name);
    for (int i = 7; i >= 0; i--)
        printf("%08x", x[i]);
    printf(" (%08x)\n", c);
}

static void print_m256(const char *name, const uint32_t x[8], const uint32_t m[8])
{
    uint32_t z[8];
    u256_cmov(z, x, 1);
    m256_done(z, m);
    print_u256(name, z, 0);
}

static const uint32_t r[8] = {
    0xdcd1d063, 0x7d3d0eb8, 0x9c4ecc3c, 0xd937cbcb,
    0x0a14613e, 0xf76db5ed, 0xec0db49c, 0x760cd745,
};

static const uint32_t s[8] = {
    0x514595c2, 0xc5e403b2, 0x5444fc98, 0xb3b1c6ed,
    0xaccbcfff, 0xdde65249, 0x120eb6d7, 0x17380bcf,
};

static const uint32_t rps[8] = {
    0x2e176625, 0x4321126b, 0xf093c8d5, 0x8ce992b8,
    0xb6e0313e, 0xd5540836, 0xfe1c6b74, 0x8d44e314,
};

static const uint32_t rms[8] = {
    0x8b8c3aa1, 0xb7590b06, 0x4809cfa3, 0x258604de,
    0x5d48913f, 0x198763a3, 0xd9fefdc5, 0x5ed4cb76,
};

static const uint32_t smr[8] = {
    0x7473c55f, 0x48a6f4f9, 0xb7f6305c, 0xda79fb21,
    0xa2b76ec0, 0xe6789c5c, 0x2601023a, 0xa12b3489,
};

static const uint32_t zero[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
static const uint32_t one[8] = { 1, 0, 0, 0, 0, 0, 0, 0 };
static const uint32_t word[8] = { -1u, 0, 0, 0, 0, 0, 0, 0 };
static const uint32_t b128[8] = { 0, 0, 0, 0, 1, 0, 0, 0 };

/* n + 2**32 - 1 mod p */
static const uint32_t npwmp[8] = {
    0xfc632550, 0xf3b9cac3, 0xa7179e84, 0xbce6faad,
    0xffffffff, 0xffffffff, 0x00000000, 0xffffffff,
};

/* n + 2**128 mod p */
static const uint32_t npbmp[8] = {
    0xfc632552, 0xf3b9cac2, 0xa7179e84, 0xbce6faac,
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/* n + n mod p */
static const uint32_t npnmp[8] = {
    0xf8c64aa3, 0xe7739585, 0x4e2f3d09, 0x79cdf55a,
    0xffffffff, 0xffffffff, 0x00000000, 0xffffffff,
};

/* p - 1 */
static const uint32_t pm1[8] = {
    0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
    0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF,
};

/* r * 2^256 mod p and mod n */
static const uint32_t rmontp[8] = {
    0x93474788, 0xb5ef37e6, 0x1bfe5637, 0xedea599f,
    0xd58607fe, 0xc77d1451, 0x4da1a333, 0xc7efa702,
};
static const uint32_t rmontn[8] = {
    0x4f81c97b, 0xb371a1c3, 0x45711856, 0x5e77eeb5,
    0x5b9517c0, 0x2fbb3648, 0xda55d090, 0xafbeb442,
};

/* r * s / 2^256 mod p */
static const uint32_t rsRip[8] = {
    0x82f52d8b, 0xa771a352, 0x262dcb9c, 0x523cbab8,
    0x1d8cbcee, 0x0f1808ad, 0x693cd97e, 0x899b52d1,
};

/* r * s / 2^256 mod n */
static const uint32_t rsRin[8] = {
    0x37ac4273, 0xb2c0f863, 0xc22f08f1, 0x00db3b58,
    0x2c404b3a, 0x572adc0c, 0x8c4d944d, 0x831900ac,
};

/* r * s mod p */
static const uint32_t rtsmp[8] = {
    0x4248770d, 0xae227d04, 0x767a5157, 0x3aa8d449,
    0xf4e6f5c5, 0x01da90d2, 0x339e69ec, 0x7ab7da11,
};

/* r * s mod n */
static const uint32_t rtsmn[8] = {
    0x423cddd0, 0xd6b649b6, 0x6513a38b, 0xb0a1c71b,
    0xe5437d3f, 0xecc8e34d, 0x80d2de2e, 0x31c7183c,
};

/* r^-1 mod p */
static const uint32_t rip[8] = {
    0x514828bf, 0xb98d5fdc, 0x705423b5, 0x547ecba2,
    0xc433b9d7, 0x5c353713, 0x95d128fe, 0xf0f207dc,
};

/* r^-1 mod n */
static const uint32_t rin[8] = {
    0x9b056a09, 0x1c0e8002, 0x4ce07edc, 0xe0a2e9d2,
    0x549e5b84, 0x9dd2b102, 0x6749fe75, 0x5decae3f,
};

/* actual curve parameters (not in Montgomery domain) */
static const uint32_t b_raw[8] = {
    0x27d2604b, 0x3bce3c3e, 0xcc53b0f6, 0x651d06b0,
    0x769886bc, 0xb3ebbd55, 0xaa3a93e7, 0x5ac635d8,
};
static const uint32_t gx_raw[8] = {
    0xd898c296, 0xf4a13945, 0x2deb33a0, 0x77037d81,
    0x63a440f2, 0xf8bce6e5, 0xe12c4247, 0x6b17d1f2,
};
static const uint32_t gy_raw[8] = {
    0x37bf51f5, 0xcbb64068, 0x6b315ece, 0x2bce3357,
    0x7c0f9e16, 0x8ee7eb4a, 0xfe1a7f9b, 0x4fe342e2,
};

/* some jacobian coordinates for the base point, in Montgomery domain */
static const uint32_t jac_gx[8] = {
    0xc7998061, 0x75d76ddd, 0x62454d48, 0x2d434483,
    0xd24a0728, 0x03f8d955, 0x1fae694f, 0x5f4b18c2,
};
static const uint32_t jac_gy[8] = {
    0x2666a327, 0xe5e92860, 0x2c65268b, 0xf8cd5cfe,
    0x0a10503e, 0xd7491c98, 0xb2ceff1a, 0xb72a1c2e,
};
static const uint32_t jac_gz[8] = {
    0x8b622f45, 0x7f8503c6, 0x00f250d0, 0xf5d756cc,
    0xfc84a8bf, 0x3486a9ed, 0xa1ba8ea7, 0x0a8b5909,
};

/* affine coordinates (not Montgomery) for 2 * G */
static const uint32_t g2x[8] = {
    0x47669978, 0xa60b48fc, 0x77f21b35, 0xc08969e2,
    0x04b51ac3, 0x8a523803, 0x8d034f7e, 0x7cf27b18,
};
static const uint32_t g2y[8] = {
    0x227873d1, 0x9e04b79d, 0x3ce98229, 0xba7dade6,
    0x9f7430db, 0x293d9ac6, 0xdb8ed040, 0x07775510,
};

/* affine coordinates (not Montgomery) for 3 * G */
static const uint32_t g3x[8] = {
    0xc6e7fd6c, 0xfb41661b, 0xefada985, 0xe6c6b721,
    0x1d4bf165, 0xc8f7ef95, 0xa6330a44, 0x5ecbe4d1,
};
static const uint32_t g3y[8] = {
    0xa27d5032, 0x9a79b127, 0x384fb83d, 0xd82ab036,
    0x1a64a2ec, 0x374b06ce, 0x4998ff7e, 0x8734640c,
};

/* affine (non-Montgomery) y coordinates for -G, -2G, -3G */
static const uint32_t g1yn[8] = {
    0xc840ae0a, 0x3449bf97, 0x94cea131, 0xd431cca9,
    0x83f061e9, 0x711814b5, 0x01e58065, 0xb01cbd1c,
};
static const uint32_t g2yn[8] = {
    0xdd878c2e, 0x61fb4862, 0xc3167dd6, 0x4582521a,
    0x608bcf24, 0xd6c26539, 0x24712fc0, 0xf888aaee,
};
static const uint32_t g3yn[8] = {
    0x5d82afcd, 0x65864ed8, 0xc7b047c2, 0x27d54fca,
    0xe59b5d13, 0xc8b4f931, 0xb6670082, 0x78cb9bf2,
};

/* affine (non-Montgomery) coordinates for rG, sG, and rsG */
static const uint32_t rgx[8] = {
    0x2d7d8169, 0xa5fcd718, 0x9419df62, 0x206c7b0d,
    0xa45f816d, 0x3513df65, 0x4527d237, 0x2494c867,
};
static const uint32_t rgy[8] = {
    0x9a8acdf6, 0x431c11fb, 0x816684fa, 0x89511fbe,
    0x6d78ef6a, 0x39feebbc, 0xb317baac, 0xe3537a5f,
};
static const uint32_t sgx[8] = {
    0x3d7aefb9, 0xed941943, 0xc8fd42b5, 0x7fb27d58,
    0xc385563d, 0xae5fd1e5, 0xd8b665c7, 0x91dd2c43,
};
static const uint32_t sgy[8] = {
    0xed32ff2d, 0x2d348936, 0x1fae3cce, 0xb71bae36,
    0xf7e483eb, 0x3fad9e82, 0xcf1094d0, 0x34e0eede,
};
static const uint32_t rsgx[8] = {
    0x581428d1, 0xc785bafd, 0x98dfb0b4, 0x232c0874,
    0xfad7f44b, 0x7de31996, 0x527f0fc5, 0x698fd765,
};
static const uint32_t rsgy[8] = {
    0x638717a6, 0x22ca2482, 0x8b1e0f69, 0xab90be4b,
    0x1aed141e, 0x562a441d, 0x61bcda5c, 0xb44b3f84,
};

/* r and s as bytes, big-endian */
static const uint8_t rbytes[32] = {
    0x76, 0x0c, 0xd7, 0x45, 0xec, 0x0d, 0xb4, 0x9c,
    0xf7, 0x6d, 0xb5, 0xed, 0x0a, 0x14, 0x61, 0x3e,
    0xd9, 0x37, 0xcb, 0xcb, 0x9c, 0x4e, 0xcc, 0x3c,
    0x7d, 0x3d, 0x0e, 0xb8, 0xdc, 0xd1, 0xd0, 0x63,
};
static const uint8_t sbytes[32] = {
    0x17, 0x38, 0x0b, 0xcf, 0x12, 0x0e, 0xb6, 0xd7,
    0xdd, 0xe6, 0x52, 0x49, 0xac, 0xcb, 0xcf, 0xff,
    0xb3, 0xb1, 0xc6, 0xed, 0x54, 0x44, 0xfc, 0x98,
    0xc5, 0xe4, 0x03, 0xb2, 0x51, 0x45, 0x95, 0xc2,
};

/* the curve's base point as bytes */
static const uint8_t gbytes[64] = {
    /* x */
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
    0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
    0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
    /* y */
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
    0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
    0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
};

/* rG, sG and rsG as bytes */
static const uint8_t rgb[64] = {
    0x24, 0x94, 0xc8, 0x67, 0x45, 0x27, 0xd2, 0x37,
    0x35, 0x13, 0xdf, 0x65, 0xa4, 0x5f, 0x81, 0x6d,
    0x20, 0x6c, 0x7b, 0x0d, 0x94, 0x19, 0xdf, 0x62,
    0xa5, 0xfc, 0xd7, 0x18, 0x2d, 0x7d, 0x81, 0x69,
    0xe3, 0x53, 0x7a, 0x5f, 0xb3, 0x17, 0xba, 0xac,
    0x39, 0xfe, 0xeb, 0xbc, 0x6d, 0x78, 0xef, 0x6a,
    0x89, 0x51, 0x1f, 0xbe, 0x81, 0x66, 0x84, 0xfa,
    0x43, 0x1c, 0x11, 0xfb, 0x9a, 0x8a, 0xcd, 0xf6,
};
static const uint8_t sgb[64] = {
    0x91, 0xdd, 0x2c, 0x43, 0xd8, 0xb6, 0x65, 0xc7,
    0xae, 0x5f, 0xd1, 0xe5, 0xc3, 0x85, 0x56, 0x3d,
    0x7f, 0xb2, 0x7d, 0x58, 0xc8, 0xfd, 0x42, 0xb5,
    0xed, 0x94, 0x19, 0x43, 0x3d, 0x7a, 0xef, 0xb9,
    0x34, 0xe0, 0xee, 0xde, 0xcf, 0x10, 0x94, 0xd0,
    0x3f, 0xad, 0x9e, 0x82, 0xf7, 0xe4, 0x83, 0xeb,
    0xb7, 0x1b, 0xae, 0x36, 0x1f, 0xae, 0x3c, 0xce,
    0x2d, 0x34, 0x89, 0x36, 0xed, 0x32, 0xff, 0x2d,
};
static const uint8_t rsgxb[32] = {
    0x69, 0x8f, 0xd7, 0x65, 0x52, 0x7f, 0x0f, 0xc5,
    0x7d, 0xe3, 0x19, 0x96, 0xfa, 0xd7, 0xf4, 0x4b,
    0x23, 0x2c, 0x08, 0x74, 0x98, 0xdf, 0xb0, 0xb4,
    0xc7, 0x85, 0xba, 0xfd, 0x58, 0x14, 0x28, 0xd1,
};

/* hashes from RFC 6979 A.2.5 and their derived integer */
static const uint8_t h1[20] = {
    0x81, 0x51, 0x32, 0x5d, 0xcd, 0xba, 0xe9, 0xe0,
    0xff, 0x95, 0xf9, 0xf9, 0x65, 0x84, 0x32, 0xdb,
    0xed, 0xfd, 0xb2, 0x09,
};
static const uint8_t h256[32] = {
    0xaf, 0x2b, 0xdb, 0xe1, 0xaa, 0x9b, 0x6e, 0xc1,
    0xe2, 0xad, 0xe1, 0xd6, 0x94, 0xf4, 0x1f, 0xc7,
    0x1a, 0x83, 0x1d, 0x02, 0x68, 0xe9, 0x89, 0x15,
    0x62, 0x11, 0x3d, 0x8a, 0x62, 0xad, 0xd1, 0xbf,
};
static const uint8_t h512[64] = {
    0x39, 0xa5, 0xe0, 0x4a, 0xaf, 0xf7, 0x45, 0x5d,
    0x98, 0x50, 0xc6, 0x05, 0x36, 0x4f, 0x51, 0x4c,
    0x11, 0x32, 0x4c, 0xe6, 0x40, 0x16, 0x96, 0x0d,
    0x23, 0xd5, 0xdc, 0x57, 0xd3, 0xff, 0xd8, 0xf4,
    0x9a, 0x73, 0x94, 0x68, 0xab, 0x80, 0x49, 0xbf,
    0x18, 0xee, 0xf8, 0x20, 0xcd, 0xb1, 0xad, 0x6c,
    0x90, 0x15, 0xf8, 0x38, 0x55, 0x6b, 0xc7, 0xfa,
    0xd4, 0x13, 0x8b, 0x23, 0xfd, 0xf9, 0x86, 0xc7,
};
static const uint32_t h1_e[8] = {
    0xdde9d09d, 0x567c03c9, 0x3104fbca, 0x03fbdb93,
    0x923a4ce6, 0x335c3807, 0x96e1d39d, 0x0b5edb73,
};
static const uint32_t h256_e[8] = {
    0x4a0eb022, 0x52b32d05, 0x51d05b7d, 0x3148ba99,
    0x3f568a92, 0x215717d1, 0x60d91a92, 0x4e9d7cca,
};
static const uint32_t h512_e[8] = {
    0xcbdfee5c, 0x1b568e98, 0x7e0c99f2, 0x7831e4b0,
    0x264c477c, 0x9e25d3a9, 0x84368689, 0x186d34e8,
};

/* signature data from RFC 6979 A.2.5 */
static const uint8_t k1[32] = {
    0x88, 0x29, 0x05, 0xf1, 0x22, 0x7f, 0xd6, 0x20,
    0xfb, 0xf2, 0xab, 0xf2, 0x12, 0x44, 0xf0, 0xba,
    0x83, 0xd0, 0xdc, 0x3a, 0x91, 0x03, 0xdb, 0xbe,
    0xe4, 0x3a, 0x1f, 0xb8, 0x58, 0x10, 0x9d, 0xb4,
};
static const uint8_t sig1[64] = {
    0x61, 0x34, 0x0c, 0x88, 0xc3, 0xaa, 0xeb, 0xeb,
    0x4f, 0x6d, 0x66, 0x7f, 0x67, 0x2c, 0xa9, 0x75,
    0x9a, 0x6c, 0xca, 0xa9, 0xfa, 0x88, 0x11, 0x31,
    0x30, 0x39, 0xee, 0x4a, 0x35, 0x47, 0x1d, 0x32,
    0x6d, 0x7f, 0x14, 0x7d, 0xac, 0x08, 0x94, 0x41,
    0xbb, 0x2e, 0x2f, 0xe8, 0xf7, 0xa3, 0xfa, 0x26,
    0x4b, 0x9c, 0x47, 0x50, 0x98, 0xfd, 0xcf, 0x6e,
    0x00, 0xd7, 0xc9, 0x96, 0xe1, 0xb8, 0xb7, 0xeb,
};
static const uint8_t k256[32] = {
    0xa6, 0xe3, 0xc5, 0x7d, 0xd0, 0x1a, 0xbe, 0x90,
    0x08, 0x65, 0x38, 0x39, 0x83, 0x55, 0xdd, 0x4c,
    0x3b, 0x17, 0xaa, 0x87, 0x33, 0x82, 0xb0, 0xf2,
    0x4d, 0x61, 0x29, 0x49, 0x3d, 0x8a, 0xad, 0x60,
};
static const uint8_t sig256[64] = {
    0xef, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd,
    0x11, 0x40, 0xdd, 0x9c, 0xd4, 0x5e, 0x81, 0xd6,
    0x9d, 0x2c, 0x87, 0x7b, 0x56, 0xaa, 0xf9, 0x91,
    0xc3, 0x4d, 0x0e, 0xa8, 0x4e, 0xaf, 0x37, 0x16,
    0xf7, 0xcb, 0x1c, 0x94, 0x2d, 0x65, 0x7c, 0x41,
    0xd4, 0x36, 0xc7, 0xa1, 0xb6, 0xe2, 0x9f, 0x65,
    0xf3, 0xe9, 0x00, 0xdb, 0xb9, 0xaf, 0xf4, 0x06,
    0x4d, 0xc4, 0xab, 0x2f, 0x84, 0x3a, 0xcd, 0xa8,
};
static const uint8_t k512[32] = {
    0x5f, 0xa8, 0x1c, 0x63, 0x10, 0x9b, 0xad, 0xb8,
    0x8c, 0x1f, 0x36, 0x7b, 0x47, 0xda, 0x60, 0x6d,
    0xa2, 0x8c, 0xad, 0x69, 0xaa, 0x22, 0xc4, 0xfe,
    0x6a, 0xd7, 0xdf, 0x73, 0xa7, 0x17, 0x3a, 0xa5,
};
static const uint8_t sig512[64] = {
    0x84, 0x96, 0xa6, 0x0b, 0x5e, 0x9b, 0x47, 0xc8,
    0x25, 0x48, 0x88, 0x27, 0xe0, 0x49, 0x5b, 0x0e,
    0x3f, 0xa1, 0x09, 0xec, 0x45, 0x68, 0xfd, 0x3f,
    0x8d, 0x10, 0x97, 0x67, 0x8e, 0xb9, 0x7f, 0x00,
    0x23, 0x62, 0xab, 0x1a, 0xdb, 0xe2, 0xb8, 0xad,
    0xf9, 0xcb, 0x9e, 0xda, 0xb7, 0x40, 0xea, 0x60,
    0x49, 0xc0, 0x28, 0x11, 0x4f, 0x24, 0x60, 0xf9,
    0x65, 0x54, 0xf6, 0x1f, 0xae, 0x33, 0x02, 0xfe,
};

/* key material from RFC A.2.5 */
static const uint8_t ecdsa_priv[32] = {
    0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16,
    0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6, 0x93,
    0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12,
    0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21,
};
#if 0
static const uint8_t ecdsa_pub[64] = {
    0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31,
    0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68,
    0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c,
    0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6,
    0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99,
    0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc, 0x64,
    0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51,
    0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99,
};
#endif

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
    assert(ret = -1);

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

    ecdsa_m256_from_hash(z, h1, sizeof h1);
    assert(memcmp(z, h1_e, sizeof z) == 0);

    ecdsa_m256_from_hash(z, h256, sizeof h256);
    assert(memcmp(z, h256_e, sizeof z) == 0);

    ecdsa_m256_from_hash(z, h512, sizeof h512);
    assert(memcmp(z, h512_e, sizeof z) == 0);
}

static void assert_ecdsa_sign(void)
{
    int ret;
    uint8_t sig[64];

    /* known values */
    fix_rng(k1, 32, 0);
    ret = p256_ecdsa_sign(sig, ecdsa_priv, h1, sizeof h1);
    assert(ret == 0);
    assert(memcmp(sig, sig1, sizeof sig) == 0);

    fix_rng(k256, 32, 0);
    ret = p256_ecdsa_sign(sig, ecdsa_priv, h256, sizeof h256);
    assert(ret == 0);
    assert(memcmp(sig, sig256, sizeof sig) == 0);

    fix_rng(k512, 32, 0);
    ret = p256_ecdsa_sign(sig, ecdsa_priv, h512, sizeof h512);
    assert(ret == 0);
    assert(memcmp(sig, sig512, sizeof sig) == 0);

    /* TODO: error cases (failing RNG, bad priv) */
}

int main(void)
{
    /* Just to keep the functions used */
    print_u256("p", p256_p, 0);
    print_m256("gx", p256_gx, p256_p);

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
#endif
