/*
 * Common macros for both testing files
 */
#if defined(TEST_VERBOSE)
#define PUTS    puts
#else
#define PUTS(s)
#endif

#define RUN( code ) \
    PUTS(#code);    \
    code
