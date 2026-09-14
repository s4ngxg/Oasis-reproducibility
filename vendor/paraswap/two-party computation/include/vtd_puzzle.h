#ifndef OASIS_VTD_PUZZLE_H
#define OASIS_VTD_PUZZLE_H
#include <gmp.h>
#include <stdint.h>

/* Uniform integer in [0, bound), sampled by rejection from Linux getrandom.
 * Leaves output unchanged on failure. Bound is limited to 16384 bits. */
int vtd_random_below(mpz_t output, const mpz_t bound);

/* Outputs and inputs are initialized by the caller. Parameters must originate
 * from a separately validated trusted setup. These functions do not prove
 * unknown factorization, the setup delay relation, or a plaintext range. */
int vtd_puzzle_generate(mpz_t u, mpz_t v, const mpz_t modulus,
                        const mpz_t g, const mpz_t h,
                        const mpz_t message, const mpz_t exponent);
int vtd_puzzle_solve(mpz_t message, const mpz_t modulus,
                     const mpz_t u, const mpz_t v, uint64_t squarings);
/* One Figure-5 verifier equation. Challenge bits MUST be supplied by the
 * transcript-bound Fiat-Shamir layer, not selected by an untrusted prover.
 * This is not the complete noninteractive proof verifier. */
int vtd_range_check_row(const mpz_t modulus, const mpz_t g, const mpz_t h,
                        const mpz_t limit, const mpz_t commitment_u,
                        const mpz_t commitment_v, const mpz_t response,
                        const mpz_t random_response, const mpz_t *puzzle_u,
                        const mpz_t *puzzle_v, const unsigned char *challenge,
                        unsigned count);
#endif
