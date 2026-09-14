#ifndef OASIS_VTD_COMMIT_H
#define OASIS_VTD_COMMIT_H
#include "vtd_verify.h"

/* All arrays are caller-allocated and initialized, with the corresponding
 * count, rows, or count/2 length. Outputs must not alias inputs or each other. */
typedef struct {
  unsigned count, rows;
  ec_t *points;
  mpz_t *puzzle_u, *puzzle_v, *commitment_u, *commitment_v;
  mpz_t *responses, *random_responses, *opened_values, *opened_exponents;
} vtd_proof_output;

vtd_proof_view vtd_commit_view(const vtd_proof_output *proof);
/* Explicit caller-selected setup and size policy. Secret must match key.
 * Temporary unopened shares/exponents are never returned or persisted.
 * This is an in-memory construction; trusted setup is still required. */
int vtd_commit(vtd_proof_output *proof, const bn_t secret, const ec_t key,
                const unsigned char context[32], uint64_t squarings,
                const mpz_t modulus, const mpz_t g, const mpz_t h,
                const mpz_t limit);
#endif
