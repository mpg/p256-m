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
 * Operations on 256-bit unsigned integers
 *
 * Represented using 32-bit limbs, least significant limb first.
 * That is: x = x[0] + 2^32 x[1] + ... + 2^224 x[7]
 *
 **********************************************************************/

/*
 * 256-bit addition
 *
 * in: x, y in [0, 2^256)
 * out: z = (x + y) mod 2^256
 *      c = (x + y) div 2^256
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

/**********************************************************************
 *
 * Operations modulo p or n
 *
 **********************************************************************/

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

/* the curve's p */
static const uint32_t cp[8] = {
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
    0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF,
};

/* the curve's n */
static const uint32_t cn[8] = {
    0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD,
    0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF,
};

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
    const uint32_t word[8] = {-1u, 0, 0, 0, 0, 0, 0, 0};
    const uint32_t b128[8] = {0, 0, 0, 0, 1, 0, 0, 0};
    uint32_t z[8];

    /* x + y < p */
    m256_add(z, cn, word, cp);
    assert(memcmp(z, npwmp, sizeof z) == 0);

    /* p <= x + y < 2^256 */
    m256_add(z, cn, b128, cp);
    assert(memcmp(z, npbmp, sizeof z) == 0);

    /* x + y >= 2^256 */
    m256_add(z, cn, cn, cp);
    assert(memcmp(z, npnmp, sizeof z) == 0);
}

int main(void)
{
    const uint32_t zero[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    const uint32_t one[8] = {1, 0, 0, 0, 0, 0, 0, 0};
    const uint32_t mone[8] = {-1u, -1u, -1u, -1u, -1u, -1u, -1u, -1u};
    const uint32_t word[8] = {-1u, 0, 0, 0, 0, 0, 0, 0};
    const uint32_t b128[8] = {0, 0, 0, 0, 1, 0, 0, 0};

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
    test_add("w+m", word, mone);
    test_sub("0-1", zero, one);
    test_madd("n+b", cp, cn, b128);
#endif

    assert_add(r, s, rps, 0u);

    assert_sub(r, s, rms, 0u);
    assert_sub(s, r, smr, 1u);

    assert_cmov();

    assert_madd();
}
#endif
