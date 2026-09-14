#include <stdio.h>
#include "vtd_puzzle.h"

static int range_rows(void) {
  mpz_t n,g,h,limit,du,dv,y,r,reply,coins,u[2],v[2],x[2],exponents[2];
  unsigned char bits[2];
  int valid=0;
  mpz_inits(n,g,h,limit,du,dv,y,r,reply,coins,NULL);
  for (unsigned i=0;i<2;i++) mpz_inits(u[i],v[i],x[i],exponents[i],NULL);
  mpz_set_ui(n,77); mpz_set_ui(g,4); mpz_set(h,g);
  for (unsigned i=0;i<12;i++) { mpz_mul(h,h,h); mpz_mod(h,h,n); }
  mpz_set_ui(limit,32); mpz_set_si(y,-2); mpz_set_ui(r,57);
  mpz_set_si(x[0],1); mpz_set_si(x[1],-1);
  mpz_set_ui(exponents[0],13); mpz_set_ui(exponents[1],19);
  if (!vtd_puzzle_generate(du,dv,n,g,h,y,r)) goto cleanup;
  for (unsigned i=0;i<2;i++)
    if (!vtd_puzzle_generate(u[i],v[i],n,g,h,x[i],exponents[i])) goto cleanup;
  for (unsigned mask=0;mask<4;mask++) {
    mpz_set(reply,y); mpz_set(coins,r);
    for (unsigned i=0;i<2;i++) {
      bits[i]=(mask>>i)&1;
      if (bits[i]) { mpz_add(reply,reply,x[i]); mpz_add(coins,coins,exponents[i]); }
    }
    if (!vtd_range_check_row(n,g,h,limit,du,dv,reply,coins,
                             (const mpz_t *)u,(const mpz_t *)v,bits,2)) goto cleanup;
    mpz_add_ui(reply,reply,1);
    if (vtd_range_check_row(n,g,h,limit,du,dv,reply,coins,
                            (const mpz_t *)u,(const mpz_t *)v,bits,2)) goto cleanup;
  }
  mpz_set_si(reply,17);
  if (vtd_range_check_row(n,g,h,limit,du,dv,reply,coins,
                          (const mpz_t *)u,(const mpz_t *)v,bits,2)) goto cleanup;
  mpz_set_si(reply,-17);
  if (vtd_range_check_row(n,g,h,limit,du,dv,reply,coins,
                          (const mpz_t *)u,(const mpz_t *)v,bits,2)) goto cleanup;
  mpz_set(reply,y); mpz_set(coins,r); bits[0]=0; bits[1]=0;
  mpz_set_ui(u[1],0);
  if (vtd_range_check_row(n,g,h,limit,du,dv,reply,coins,
                          (const mpz_t *)u,(const mpz_t *)v,bits,2)) goto cleanup;
  if (!vtd_puzzle_generate(u[1],v[1],n,g,h,x[1],exponents[1])) goto cleanup;
  bits[0]=2;
  if (vtd_range_check_row(n,g,h,limit,du,dv,reply,coins,
                          (const mpz_t *)u,(const mpz_t *)v,bits,2)) goto cleanup;
  bits[0]=0; mpz_set_ui(limit,39);
  if (vtd_range_check_row(n,g,h,limit,du,dv,reply,coins,
                          (const mpz_t *)u,(const mpz_t *)v,bits,2)) goto cleanup;
  valid=1;
cleanup:
  for (unsigned i=0;i<2;i++) mpz_clears(u[i],v[i],x[i],exponents[i],NULL);
  mpz_clears(n,g,h,limit,du,dv,y,r,reply,coins,NULL);
  return valid;
}

int main(void) {
  mpz_t n,g,h,x,r,u,v,x2,r2,u2,v2,us,vs,sum,square,recovered;
  int status = 1;
  if (!range_rows()) return 1;
  mpz_inits(n,g,h,x,r,u,v,x2,r2,u2,v2,us,vs,sum,square,recovered,NULL);
  for (unsigned bits=1; bits<=16384; bits*=2) {
    mpz_set_ui(n,1); mpz_mul_2exp(n,n,bits-1); mpz_add_ui(n,n,1);
    for (unsigned trial=0;trial<16;trial++) {
      if (!vtd_random_below(r,n) || mpz_sgn(r)<0 || mpz_cmp(r,n)>=0)
        goto cleanup;
    }
  }
  mpz_set_ui(n,1);
  if (!vtd_random_below(r,n) || mpz_sgn(r)) goto cleanup;
  mpz_set_ui(r,123); mpz_set_ui(n,0);
  if (vtd_random_below(r,n) || mpz_cmp_ui(r,123)) goto cleanup;
  mpz_set_si(n,-1);
  if (vtd_random_below(r,n) || mpz_cmp_ui(r,123)) goto cleanup;
  mpz_set_ui(n,1); mpz_mul_2exp(n,n,16384);
  if (vtd_random_below(r,n) || mpz_cmp_ui(r,123)) goto cleanup;
  /* Tiny public composite and known factors are ONLY an algebra test fixture. */
  mpz_set_ui(n, 77); mpz_set_ui(g, 4); mpz_set(h,g);
  for (unsigned i=0;i<12;i++) { mpz_mul(h,h,h); mpz_mod(h,h,n); }
  mpz_mul(square,n,n);
  for (long a=-30;a<=30;a++) {
    mpz_set_si(x,a); mpz_set_ui(r,91);
    mpz_set_si(x2,7); mpz_set_ui(r2,123);
    if (!vtd_puzzle_generate(u,v,n,g,h,x,r) ||
        !vtd_puzzle_solve(recovered,n,u,v,12)) goto cleanup;
    mpz_mod(sum,x,n); if (mpz_cmp(sum,recovered)) goto cleanup;
    if (!vtd_puzzle_generate(u2,v2,n,g,h,x2,r2)) goto cleanup;
    mpz_add(sum,x,x2); mpz_add(r2,r2,r);
    if (!vtd_puzzle_generate(us,vs,n,g,h,sum,r2)) goto cleanup;
    mpz_mul(u2,u2,u); mpz_mod(u2,u2,n);
    mpz_mul(v2,v2,v); mpz_mod(v2,v2,square);
    if (mpz_cmp(us,u2) || mpz_cmp(vs,v2)) goto cleanup;
  }
  mpz_set_ui(u,0);
  if (vtd_puzzle_solve(recovered,n,u,v,12)) goto cleanup;
  mpz_set_ui(u,7);
  if (vtd_puzzle_solve(recovered,n,u,v,12)) goto cleanup;
  mpz_set_ui(u,1); mpz_set_ui(v,2);
  if (vtd_puzzle_solve(recovered,n,u,v,12)) goto cleanup;
  mpz_set_si(r,-1);
  if (vtd_puzzle_generate(u,v,n,g,h,x,r)) goto cleanup;
  puts("{\"centered_message_cases\":61,\"homomorphic_exponents\":true,"
       "\"malformed_puzzles_rejected\":true,\"secure_setup\":false}");
  status=0;
cleanup:
  mpz_clears(n,g,h,x,r,u,v,x2,r2,u2,v2,us,vs,sum,square,recovered,NULL);
  return status;
}
