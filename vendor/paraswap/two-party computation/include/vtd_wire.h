#ifndef OASIS_VTD_WIRE_H
#define OASIS_VTD_WIRE_H
#include <stddef.h>
#include "vtd_commit.h"
#define VTD_WIRE_MAX_BYTES (8u*1024u*1024u)
/* Public setup transport only. Canonical unsigned integers N,g,h,L. This
 * codec does not attest setup provenance, unknown factorization or time.
 * Decode commits all four initialized distinct outputs only on success. */
int vtd_setup_encode(unsigned char *buffer,size_t capacity,size_t *written,
    const mpz_t n,const mpz_t g,const mpz_t h,const mpz_t limit);
int vtd_setup_decode(mpz_t n,mpz_t g,mpz_t h,mpz_t limit,
    const unsigned char *buffer,size_t length);
/* Encodes public proof material only, including the intentionally opened
 * half-shares. No unopened witness or puzzle exponent is exported.
 * On encode failure written=0 and the caller must discard the buffer.
 * Decode needs initialized arrays with caller-selected counts. On malformed
 * input these arrays are cleared. Neither operation verifies proof validity. */
int vtd_proof_encode(unsigned char *buffer, size_t capacity, size_t *written,
                       const vtd_proof_view *proof);
int vtd_proof_decode(vtd_proof_output *proof, const unsigned char *buffer,
                       size_t length);
#endif
