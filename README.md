p256-m is a minimalistic implementation of ECDH and ECDSA on NIST P-256,
written in standard C with constrained 32-bit environments in mind.

Its design is guided by the following goals in that order:

1. correctness & security;
2. low code size & RAM usage;
3. runtime performance.

Many cryptographic implementations tend to put more emphasis on runtime
performance than on footprint, and sometimes even risk compromising security
or correctness for speed. p256-m was written because I wanted to see what
happened when reversing the usual emphasis.

The result is a full implementation of ECDH and ECDSA in **less than 3KiB of
code, using less than 800 bytes of RAM** (in less than 600 LOC).

## Correctness

**API design:**

- The API is minimal: only 4 public functions.
- Each public function fully validates its inputs and returns specific errors.
- The API uses arrays of octets for all input and output.

**Testing:**

- p256-m is validated against multiple test vectors from various RFCs and
  NIST.
- In addition, crafted inputs are used for negative testing and to reach
  corner cases.
- Two test suites are provided: one for black-box testing (using only the
  public API), one for white-box testing (for unit-testing internal functions,
and reaching more error cases by exploiting knowledge of how the RNG is used).
- The resulting branch coverage is maximal: black-box testing reaches all
  branches except four; three of them are reached by white-box testing using a
rigged RNG; the last branch could only be reached by computing a discrete log
on P-256... See `coverage.sh`.
- Testing also uses dynamic analysis: valgrind, ASan, MemSan, UBSan.

**Code quality:**

- The code is standard C99; it builds without warnings with `clang
  -Weverything` and `gcc -Wall -Wextra -pedantic`.
- The code is small and well documented, including internal APIs: with the
  header file, it's less than 600 lines of code, and more than 600 lines of
comments.
- However it _has not been reviewed_ independently so far, as this is a
  personal project.

**Short Weierstrass pitfalls:**

Its has been [pointed out](https://safecurves.cr.yp.to/) that the NIST curves,
and indeed all Short Weierstrass curves, have a number of pitfalls including
risk for the implementation to:

- "produce incorrect results for some rare curve points" - this is avoided by
  carefully checking the validity domain of formulas used throughout the code;
- "leak secret data when the input isn't a curve point" - this is avoided by
  validating that points lie on the curve every time a point is deserialized.

## Security

In addition to the above correctness claims, p256-m has the following
properties:

- it has no branch depending (even indirectly) on secret data;
- it has no memory access depending (even indirectly) on secret data.

These properties are checked using valgrind and MemSan with the ideas
behind [ctgrind](https://github.com/agl/ctgrind), see `consttime.sh`.

(**TODO:** _clarify the situation with multiplication instructions._)

As a result, p256-m should be secure against the following classes of attackers:

1. attackers who can only manipulate the input and observe the output;
2. attackers who can also measure the total computation time of the operation;
3. attackers who can also observe and manipulate micro-architectural features
   such as the cache or branch predictor with arbitrary precision.

However, p256-m makes no attempt to protect against:

4. passive physical attackers who can record traces of physical emissions
   (power, EM, sound) of the CPU while it manipulates secrets;
5. active physical attackers who can also inject faults in the computation.

(Note: p256-m should actually be secure against SPA, by virtue of being fully
constant-flow, but is not expected to resist any other physical attack.)

**Warning:** p256-m requires an externally-provided RNG function. If that
function is not cryptographically secure, then neither is p256-m's key
generation or ECDSA signature generation.

_Note:_ p256-m also follows best practices such as securely erasing secret
data on the stack before returning.

## Code size

Compiled with
[ARM-GCC 9](https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-rm/downloads),
with `-mthumb -Os -fomit-frame-pointer`, the following sizes of are reached
for selected cores:

- Cortex-M0 core: 3000 bytes
- Cortex-M4 core: 2920 bytes
- Cortex-A5 core: 2928 bytes

Clang was also tried but tends to generate larger code (by about 10%). For
full details see `sizes.sh`.

## RAM usage

p256-m doesn't use any dynamic memory (on the heap), only the stack. Here's
how much stack is used by each of its 4 public functions:

- `p256_gen_keypair`: 664
- `p256_ecdh_shared_secret`: 672
- `p256_ecdsa_sign`: 720
- `p256_ecdsa_verify`: 784

For details of how these numbers were obtained, see `stack.sh`, `wcs.py` and
`libc.msu`.

## Runtime performance

See the table under "Runtime performance" in the next section.

## Comparison with other implementations

The most relevant/convenient implementation for comparisons is
[TinyCrypt](https://github.com/intel/tinycrypt) (version used: 0.2.8), as it's
also a standalone implementation of ECDH and ECDSA on P-256 only, that also
targets constrained devices. Other implementations tend to implement many
curves and build on a shared bignum/MPI module (possibly also supporting RSA),
which makes fair comparisons less convenient.

**Correctness & Security:**

- _API design:_ TinyCrypt seems to provide less systematic input validation
  than p256-m. For example, TinyCrypt's `uECC_shared_secret()` does not seem
to check that the peer's public key is valid, leaving it to the user to
validate it with `uECC_valid_public_key()`. This may open the
door to [invalid curve
attacks](https://link.springer.com/chapter/10.1007/3-540-36288-6_16) if static
ECDH is used and [users forget to
validate](https://link.springer.com/chapter/10.1007/978-3-319-24174-6_21) the
peer-provided data. By contrast, p256-m seems to be less likely to be misused
in that way, as each public function fully validates all of its inputs.
- _Local side channels:_ While TinyCrypt employs a regular scalar
  multiplication algorithm, the underlying multi-precision and modular
arithmetic is not constant-time. Similar characteristics in other libraries
have been exploited by [multiple](https://eprint.iacr.org/2020/055) recent
[attacks](https://eprint.iacr.org/2020/432). This means p256-m has a stronger
argument for being secure against powerful local attackers (for example, an
untrusted OS attacking a secure enclave).
- _Physical side channels:_ On the other hand, TinyCrypt has some facilities
  for using coordinate randomisation, which protects against some,
but not all, passive physical attacks (see Table 3, column C9 of [this
paper](https://www.esat.kuleuven.be/cosic/publications/article-2293.pdf#page=12)).
This means TinyCrypt offers some protection against some attacks that p256-m
doesn't even attempt to mitigate.

**Footprint:**

|  | p256-m| TinyCrypt  |
| --- | --- | --- |
| Code size¹ | 3000 | 6134 |
| Stack used² for key generation | 664 | 824 |
| Stack used² for ECDH shared secret | 672 | 736 |
| Stack used² for ECDSA sign | 720 | 888 |
| Stack used² for ECDSA verify | 784 | 824 |

¹ Targeting a Cortex-M0 core - for p256-m, see `sizes.sh`; for TinyCrypt sum
of the sizes of `ecc.o`, `ecc_dh.o` and `ecc_dsa.o` built with the same
compiler and options.

² For p256-m, see `stack.sh`, `wcs.py` and `libc.msu`; for TinyCrypt similar
scripts were used after lightly editing the source to replace indirect
function calls (`g_rng_function`, function pointers in the `curve` structure)
with direct function calls to allow the scripts to work.

**Runtime performance:**

Timing of various operations in milliseconds, measured using `gettimeofday()`
on a Raspberry Pi Model XXX running Linux distro YYY - **TODO**.

|  | p256-m | TinyCrypt |
| --- | --- | --- |
| key generation | TODO | TODO |
| ECDH shared secret | TODO | TODO |
| ECDSA sign | TODO | TODO |
| ECDSA verify | TODO | TODO |

## Design overview

**TODO**

## What about other curves?

**TODO**
