#include <stdlib.h>
#include "vtd_transcript.h"

int vtd_range_prove(unsigned rows, unsigned count,
                     const unsigned char context[32], uint64_t squarings,
                     const mpz_t modulus, const mpz_t g, const mpz_t h,
                     const mpz_t limit, const mpz_t witness_bound,
                     const mpz_t *puzzle_u, const mpz_t *puzzle_v,
                     const mpz_t *messages, const mpz_t *exponents,
                     mpz_t *commitment_u, mpz_t *commitment_v,
                     mpz_t *responses, mpz_t *random_responses) {
  mpz_t square, required, radius, width, random_width, temp, check_u, check_v;
  unsigned char *bits=NULL;
  int valid=0;
  if (!context || !puzzle_u || !puzzle_v || !messages || !exponents ||
      !commitment_u || !commitment_v || !responses || !random_responses ||
      rows<128 || rows>256 || count==0 || count>256) return 0;
  mpz_inits(square,required,radius,width,random_width,temp,check_u,check_v,NULL);
  if (mpz_sgn(witness_bound)<=0 || mpz_cmp_ui(modulus,3)<=0 ||
      mpz_even_p(modulus) || mpz_sizeinbase(modulus,2)>8000 ||
      mpz_sizeinbase(limit,2)>8000 || mpz_sizeinbase(witness_bound,2)>8000)
    goto cleanup;
  mpz_mul_ui(required,witness_bound,count); mpz_mul_2exp(required,required,144);
  if (mpz_cmp(limit,required)<0) goto cleanup;
  mpz_mul_ui(required,limit,2);
  if (mpz_cmp(required,modulus)>=0) goto cleanup;
  mpz_mul(square,modulus,modulus);
  for (unsigned j=0;j<count;j++) {
    mpz_abs(temp,messages[j]);
    if (mpz_cmp(temp,witness_bound)>0 || mpz_sgn(exponents[j])<=0 ||
        mpz_cmp(exponents[j],square)>0) goto cleanup;
    if (!vtd_puzzle_generate(check_u,check_v,modulus,g,h,messages[j],exponents[j]) ||
        mpz_cmp(check_u,puzzle_u[j]) || mpz_cmp(check_v,puzzle_v[j])) goto cleanup;
  }
  mpz_fdiv_q_2exp(radius,limit,2);
  mpz_mul_ui(width,radius,2); mpz_add_ui(width,width,1);
  /* Integer exponent masks: do not reduce a response modulo N (N is not
   * the group order). Wide masks hide sums of bounded original exponents. */
  mpz_mul_ui(random_width,square,count); mpz_mul_2exp(random_width,random_width,144);
  for (unsigned i=0;i<rows;i++) {
    if (!vtd_random_below(responses[i],width) ||
        !vtd_random_below(random_responses[i],random_width)) goto cleanup;
    mpz_sub(responses[i],responses[i],radius);
    if (!vtd_puzzle_generate(commitment_u[i],commitment_v[i],modulus,g,h,
                             responses[i],random_responses[i])) goto cleanup;
  }
  bits=malloc((size_t)rows*count);
  if (!bits || !vtd_range_challenge(bits,rows,count,context,squarings,modulus,g,h,
      limit,puzzle_u,puzzle_v,(const mpz_t *)commitment_u,
      (const mpz_t *)commitment_v)) goto cleanup;
  for (unsigned i=0;i<rows;i++)
    for (unsigned j=0;j<count;j++) if (bits[(size_t)i*count+j]) {
      mpz_add(responses[i],responses[i],messages[j]);
      mpz_add(random_responses[i],random_responses[i],exponents[j]);
    }
  valid=vtd_range_verify(rows,count,context,squarings,modulus,g,h,limit,puzzle_u,
      puzzle_v,(const mpz_t *)commitment_u,(const mpz_t *)commitment_v,
      (const mpz_t *)responses,(const mpz_t *)random_responses);
cleanup:
  if (!valid) for (unsigned i=0;i<rows;i++) {
    mpz_set_ui(commitment_u[i],0); mpz_set_ui(commitment_v[i],0);
    mpz_set_ui(responses[i],0); mpz_set_ui(random_responses[i],0);
  }
  free(bits);
  mpz_clears(square,required,radius,width,random_width,temp,check_u,check_v,NULL);
  return valid;
}
