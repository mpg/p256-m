#include <stdint.h>

#if !defined(NO_MAIN)
#include <stdio.h>
#include <assert.h>
#include <string.h>
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

    u256_set32(z, 1);
    m256_prep(z, m);

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
STATIC void point_double(uint32_t x[8], uint32_t y[8], uint32_t z[8])
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
 * out: P_out = (x3:y3:z3) = P_in + Q
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

/**********************************************************************
 *
 * Scalar multiplication
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
    u256_set32(rz, 1);
    m256_prep(rz, p256_p);
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

int main(void)
{
    /* Just to keep the function used */
    print_u256("p", p256_p, 0);

    assert_add(r, s, rps, 0u);

    assert_sub(r, s, rms, 0u);
    assert_sub(s, r, smr, 1u);

    assert_cmov();

    assert_madd();
    assert_msub();
    assert_mmul();
    assert_prep_mul_done();
    assert_inv();

    assert_pt_params();
    assert_pt_check();
    assert_pt_affine();
    assert_pt_double();
    assert_pt_add();

    assert_scalar_mult();
}
#endif
