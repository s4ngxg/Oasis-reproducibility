#ifndef OASIS_VTD_VERIFY_H
#define OASIS_VTD_VERIFY_H
#include "vtd_openings.h"
#include "vtd_transcript.h"

/* In-memory proof view; all arrays are owned by the caller. The opening
 * arrays contain count/2 entries in the recomputed sorted-subset order. */
typedef struct {
  unsigned count, rows;
  const ec_t *points;
  const mpz_t *puzzle_u, *puzzle_v;
  const mpz_t *commitment_u, *commitment_v;
  const mpz_t *responses, *random_responses;
  const mpz_t *opened_values, *opened_exponents;
} vtd_proof_view;

/* Verifies proof relations, not trusted-setup provenance or timed privacy.
 * expected_count is caller policy, never inferred from an untrusted proof.
 * Small test counts must not be treated as deployment security parameters. */
int vtd_verify_relations(const vtd_proof_view *proof, unsigned expected_count,
                         const ec_t expected_key, const unsigned char context[32],
                         uint64_t squarings, const mpz_t modulus, const mpz_t g,
                         const mpz_t h, const mpz_t limit);
/* Revalidates proof, sequentially solves unopened puzzles until a valid share
 * permits reconstruction. max_squarings bounds total work across attempts.
 * Leaves output unchanged on failure. Solved secrets remain in memory only.
 * Trusted setup and deadline calibration remain caller responsibilities. */
int vtd_force_open(bn_t output, uint64_t *performed_squarings,
                    uint64_t max_squarings, const vtd_proof_view *proof,
                    unsigned expected_count, const ec_t expected_key,
                    const unsigned char context[32], uint64_t squarings,
                    const mpz_t modulus, const mpz_t g, const mpz_t h,
                    const mpz_t limit);
#endif
