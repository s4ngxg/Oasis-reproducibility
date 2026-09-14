#ifndef OASIS_VTD_SETUP_H
#define OASIS_VTD_SETUP_H
#include "vtd_puzzle.h"
/* Generate a single-party trusted setup. Outputs must be initialized and
 * distinct. bits is even, 2048..4096. max_candidates bounds primality work
 * across both factors. Outputs stay unchanged on failure. No factors return.
 * Run in a dedicated setup process: GMP does not guarantee secure erasure. */
int vtd_setup_generate(mpz_t modulus, mpz_t g, mpz_t h, unsigned bits,
                        uint64_t squarings, uint64_t max_candidates);
#endif
