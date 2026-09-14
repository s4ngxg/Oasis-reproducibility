#ifndef OASIS_VTD_OPENINGS_H
#define OASIS_VTD_OPENINGS_H
#include "vtd_sharing.h"
#include "vtd_puzzle.h"

/* Internal Figure-16 checks. indices are the recomputed sorted half-subset,
 * not an untrusted proof field. Open values/exponents have count/2 entries;
 * points and puzzles have count entries. Returns 1 on success, 0 otherwise.
 * Range proof and trusted-setup validation are separate required checks. */
int vtd_verify_openings(const ec_t expected, const ec_t *points, unsigned count,
                        const unsigned *indices, const mpz_t *values,
                        const mpz_t *exponents, const mpz_t modulus,
                        const mpz_t g, const mpz_t h,
                        const mpz_t *puzzle_u, const mpz_t *puzzle_v);
#endif
