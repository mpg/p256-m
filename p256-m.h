/*
 * Interface of curve P-256 (ECDH and ECDSA)
 */

#include <stdint.h>
#include <stddef.h>

/*
 * RNG function - must be provided externally
 *
 * in: output - must point to a writable buffer of at least output_size bytes.
 *     output_size - the number of random bytes to write to output.
 * out: output is filled with output_size random bytes.
 *      return 0 on success, non-zero on errors.
 */
extern int p256_generate_random(uint8_t * output, unsigned output_size);

/*
 * ECDH generate pair
 */
int p256_ecdh_gen_pair(uint8_t priv[32], uint8_t pub[64]);

/*
 * ECDH compute shared secret
 */
int p256_ecdh_shared_secret(uint8_t secret[32],
                            const uint8_t priv[32], const uint8_t pub[64]);

/*
 * ECDSA sign
 */
int p256_ecdsa_sign(uint8_t sig[64], const uint8_t priv[32],
                    const uint8_t *hash, size_t hlen);

/*
 * ECDSA verify
 */
int p256_ecdsa_verify(const uint8_t sig[64], const uint8_t pub[64],
                      const uint8_t *hash, size_t hlen);
