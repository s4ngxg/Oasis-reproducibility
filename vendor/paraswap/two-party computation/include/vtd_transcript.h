#ifndef OASIS_VTD_TRANSCRIPT_H
#define OASIS_VTD_TRANSCRIPT_H
#include "vtd_puzzle.h"

/* Requires initialized RELIC. Output is rows*count bytes, each 0 or 1.
 * context is the immutable 32-byte host/VTD context binding. Integers are
 * unsigned minimal big-endian, length-prefixed (zero has length zero).
 * See docs/VTD_IMPLEMENTATION.md for the exact normative transcript. */
int vtd_range_challenge(unsigned char *bits, unsigned rows, unsigned count,
                        const unsigned char context[32], uint64_t squarings,
                        const mpz_t modulus, const mpz_t g, const mpz_t h,
                        const mpz_t limit, const mpz_t *puzzle_u,
                        const mpz_t *puzzle_v, const mpz_t *commitment_u,
                        const mpz_t *commitment_v);
/* Caller supplies validated setup and policy-selected L. Requires >=128 rows.
 * Checks every response; no externally supplied challenge is accepted.
 * Does not validate a VTD cut-and-choose proof or public-key linkage. */
int vtd_range_verify(unsigned rows, unsigned count,
                      const unsigned char context[32], uint64_t squarings,
                      const mpz_t modulus, const mpz_t g, const mpz_t h,
                      const mpz_t limit, const mpz_t *puzzle_u,
                      const mpz_t *puzzle_v, const mpz_t *commitment_u,
                      const mpz_t *commitment_v, const mpz_t *responses,
                      const mpz_t *random_responses);
/* Initializes no mpz objects: all output arrays must be caller-allocated.
 * Original puzzle exponents must be in [1,N^2]. Requires
 * L >= count*B*2^144 and 2L<N. Does not generate or certify the trusted setup.
 * Outputs are zeroed on failure after basic pointer/count validation. */
int vtd_range_prove(unsigned rows, unsigned count,
                     const unsigned char context[32], uint64_t squarings,
                     const mpz_t modulus, const mpz_t g, const mpz_t h,
                     const mpz_t limit, const mpz_t witness_bound,
                     const mpz_t *puzzle_u, const mpz_t *puzzle_v,
                     const mpz_t *messages, const mpz_t *exponents,
                     mpz_t *commitment_u, mpz_t *commitment_v,
                     mpz_t *responses, mpz_t *random_responses);
/* Derive a sorted half-size subset of 1-based share indices. Inputs include
 * fixed-width public point encodings (key then count share points), range
 * challenge bytes, and every range response. Point validation is separate.
 * digest_out is 32 bytes and is useful for independent encoding tests. */
int vtd_opening_challenge(unsigned *indices, unsigned char digest_out[32],
                          unsigned count, unsigned rows,
                          const unsigned char *point_encodings,
                          const unsigned char *range_bits,
                          const mpz_t *responses,
                          const mpz_t *random_responses);
#endif
