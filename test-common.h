/*
 * Common macros for both test-closedbox.c and test-openbox.c.
 */
#if defined(TEST_VERBOSE)
#define PUTS    puts
#else
#define PUTS(s)
#endif

#define RUN( code ) \
    PUTS(#code);    \
    code
