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
STATIC void u256_set32(uint32_t z[8], uint32_t x)
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
 */
STATIC uint32_t u256_add(uint32_t z[8],
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
 */
STATIC uint32_t u256_sub(uint32_t z[8],
                         const uint32_t x[8], const uint32_t y[8])
{
    uint32_t carry = 0;

    for (unsigned i = 0; i < 8; i++) {
        uint64_t diff = (uint64_t) x[i] - y[i] - carry;
        z[i] = (uint32_t) diff;
        carry = - (uint32_t) (diff >> 32);
    }

    return carry;
}

/*
 * 256-bit conditional assignment
 *
 * in: x in [0, 2^256)
 *     c in [0, 1]
 * out: z = x if c == 1, z unchanged otherwise
 */
STATIC void u256_cmov(uint32_t z[8], const uint32_t x[8], uint32_t c)
{
    const uint32_t x_mask = -c;
    for (unsigned i = 0; i < 8; i++) {
        z[i] = (z[i] & ~x_mask) | (x[i] & x_mask);
    }
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
 * This is a helper for Montgomery multiplication.
 */
static uint32_t u288_muladd(uint32_t z[9],
                            uint32_t x, const uint32_t y[8])
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
            z[i] = z[i+1];
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
STATIC const uint32_t p256_p[8] = { /* the curve's p */
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
    0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF,
};
STATIC const uint32_t p256_n[8] = { /* the curve's n */
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
static inline uint32_t m256_mont_idx(const uint32_t m[8]) {
    return m[6]; /* conveniently happens to be 0 for n, 1 for p */
}
static const uint32_t m256_mont_ni[2] = { /* negative inverses or n and p */
    0xee00bc4f, /* -n^-1 mod 32 */
    0x00000001, /* -p^-1 mod 32 */
};
static const uint32_t m256_mont_R2[2][8] = { /* R^2 mod n and p, with R = 2^256 */
    { /* 2^512 mod n */
        0xbe79eea2, 0x83244c95, 0x49bd6fa6, 0x4699799c,
        0x2b6bec59, 0x2845b239, 0xf3d95620, 0x66e12d94,
    },
    { /* 2^512 mod p */
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
 */
STATIC void m256_add(uint32_t z[8],
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
 */
STATIC void m256_sub(uint32_t z[8],
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
 * Algorithm 14.36 in Handbook of Applied Cryptography with:
 * b = 2^32, n = 8, R = 2^256
 */
STATIC void m256_mul(uint32_t z[8],
                     const uint32_t x[8], const uint32_t y[8],
                     const uint32_t m[8])
{
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
    uint32_t carry_add = a[8]; // 0 or 1 since a < 2m, see HAC Note 14.37
    uint32_t carry_sub = u256_sub(z, a, m);
    uint32_t use_sub = carry_add | (1 - carry_sub); // see m256_add()
    u256_cmov(z, a, 1 - use_sub);
}

/*
 * In-place conversion to Montgomery form
 *
 * in: z in [0, m)
 *     m must be either p256_p or p256_n
 * out: z_out = z_in * 2^256 mod m, in [0, m)
 */
STATIC void m256_prep(uint32_t z[8], const uint32_t m[8])
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
 * Caution: z and x must be disjoint memory locations.
 */
STATIC void m256_inv(uint32_t z[8], const uint32_t x[8], const uint32_t m[8])
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
    u256_set32(z, 1);
    m256_prep(z, m);

    uint32_t bitval[8];
    u256_cmov(bitval, x, 1);

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

static void test_add(const char *name,
                     const uint32_t x[8], const uint32_t y[8])
{
    uint32_t z[8];
    uint32_t c = u256_add(z, x, y);
    print_u256(name, z, c);
}

static void test_sub(const char *name,
                     const uint32_t x[8], const uint32_t y[8])
{
    uint32_t z[8];
    uint32_t c = u256_sub(z, x, y);
    print_u256(name, z, c);
}

static void test_madd(const char *name, const uint32_t m[8],
                      const uint32_t x[8], const uint32_t y[8])
{
    uint32_t z[8];
    m256_add(z, x, y, m);
    print_u256(name, z, 0);
}

static void test_msub(const char *name, const uint32_t m[8],
                      const uint32_t x[8], const uint32_t y[8])
{
    uint32_t z[8];
    m256_sub(z, x, y, m);
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

static const uint32_t zero[8] = {0, 0, 0, 0, 0, 0, 0, 0};
static const uint32_t one[8] = {1, 0, 0, 0, 0, 0, 0, 0};
static const uint32_t mone[8] = {-1u, -1u, -1u, -1u, -1u, -1u, -1u, -1u};
static const uint32_t word[8] = {-1u, 0, 0, 0, 0, 0, 0, 0};
static const uint32_t b128[8] = {0, 0, 0, 0, 1, 0, 0, 0};

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

int main(void)
{

#if 0
    test_add("0+0", zero, zero);
    test_add("0+1", zero, one);
    test_add("0+m", zero, mone);
    test_add("0+w", zero, word);

    test_add("1+0", one, zero);
    test_add("1+1", one, one);
    test_add("1+m", one, mone);
    test_add("1+w", one, word);

    test_add("m+0", mone, zero);
    test_add("m+1", mone, one);
    test_add("m+m", mone, mone);
    test_add("m+w", mone, word);

    test_add("w+0", word, zero);
    test_add("w+1", word, one);
    test_add("w+m", word, mone);
    test_add("w+w", word, word);

    printf("\n");

    test_sub("0-0", zero, zero);
    test_sub("0-1", zero, one);
    test_sub("0-m", zero, mone);
    test_sub("0-w", zero, word);

    test_sub("1-0", one, zero);
    test_sub("1-1", one, one);
    test_sub("1-m", one, mone);
    test_sub("1-w", one, word);

    test_sub("m-0", mone, zero);
    test_sub("m-1", mone, one);
    test_sub("m-m", mone, mone);
    test_sub("m-w", mone, word);

    test_sub("w-0", word, zero);
    test_sub("w-1", word, one);
    test_sub("w-m", word, mone);
    test_sub("w-w", word, word);
#else
    /* Just to keep the functions and variables used */
    printf("constants\n");
    print_u256("p", p256_p, 0);
    print_u256("n", p256_n, 0);

    printf("u256\n");
    test_add("w+m", word, mone);
    test_sub("0-1", zero, one);

    printf("m256\n");
    test_madd("n+b", p256_p, p256_n, b128);
    test_msub("w-1", p256_p, word, one);
#endif

    assert_add(r, s, rps, 0u);

    assert_sub(r, s, rms, 0u);
    assert_sub(s, r, smr, 1u);

    assert_cmov();

    assert_madd();
    assert_msub();
    assert_mmul();
    assert_prep_mul_done();
    assert_inv();
}
#endif
