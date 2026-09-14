#include <stdlib.h>
#include <string.h>
#include "vtd_verify.h"

int vtd_verify_relations(const vtd_proof_view *proof, unsigned expected_count,
                         const ec_t expected_key, const unsigned char context[32],
                         uint64_t squarings, const mpz_t modulus, const mpz_t g,
                         const mpz_t h, const mpz_t limit) {
  unsigned char *encoding=NULL, *bits=NULL, digest[32];
  unsigned indices[128];
  int valid=0;
  if (!proof || !context || expected_count<2 || expected_count>256 ||
      expected_count%2 || proof->count!=expected_count || proof->rows<128 ||
      proof->rows>256 || !proof->points || !proof->opened_values ||
      !proof->opened_exponents) return 0;
  encoding=calloc((size_t)expected_count+1,33);
  bits=malloc((size_t)proof->rows*expected_count);
  if (!encoding || !bits) goto cleanup;
  RLC_TRY {
    if (ec_is_infty(expected_key) || !ec_on_curve(expected_key)) RLC_THROW(ERR_NO_VALID);
    ec_write_bin(encoding,33,expected_key,1);
    for (unsigned j=0;j<expected_count;j++) {
      /* Unique 33-zero encoding for an identity share (a valid zero scalar).
       * Finite points use the usual 33-byte compressed curve encoding. */
      if (!ec_is_infty(proof->points[j])) {
        if (!ec_on_curve(proof->points[j])) RLC_THROW(ERR_NO_VALID);
        ec_write_bin(encoding+33*((size_t)j+1),33,proof->points[j],1);
      }
    }
    if (!vtd_range_verify(proof->rows,proof->count,context,squarings,modulus,g,h,limit,
        proof->puzzle_u,proof->puzzle_v,proof->commitment_u,proof->commitment_v,
        proof->responses,proof->random_responses)) RLC_THROW(ERR_NO_VALID);
    if (!vtd_range_challenge(bits,proof->rows,proof->count,context,squarings,modulus,g,h,
        limit,proof->puzzle_u,proof->puzzle_v,proof->commitment_u,proof->commitment_v) ||
        !vtd_opening_challenge(indices,digest,proof->count,proof->rows,encoding,bits,
        proof->responses,proof->random_responses)) RLC_THROW(ERR_NO_VALID);
    valid=vtd_verify_openings(expected_key,proof->points,proof->count,indices,
        proof->opened_values,proof->opened_exponents,modulus,g,h,
        proof->puzzle_u,proof->puzzle_v);
  } RLC_CATCH_ANY { valid=0; }
cleanup:
  free(encoding); free(bits);
  return valid;
}
