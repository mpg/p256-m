#include <stdint.h>

#if !defined(NO_MAIN)
#include <stdio.h>
#endif

#if defined(NO_MAIN)
#define STATIC
#else
#define STATIC static
#endif

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

int main(void)
{
    uint32_t zero[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint32_t one[8] = {1, 0, 0, 0, 0, 0, 0, 0};
    uint32_t mone[8] = {-1u, -1u, -1u, -1u, -1u, -1u, -1u, -1u};
    uint32_t word[8] = {-1u, 0, 0, 0, 0, 0, 0, 0};

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
}
#endif
