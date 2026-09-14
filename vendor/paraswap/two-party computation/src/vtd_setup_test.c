#include <stdio.h>
#include "vtd_setup.h"
int main(void) {
  mpz_t n,g,h,check,message,r,u,v,decoded;
  int status=1;
  mpz_inits(n,g,h,check,message,r,u,v,decoded,NULL);
  mpz_set_ui(n,42);
  mpz_set_ui(g,43); mpz_set_ui(h,44);
  if (vtd_setup_generate(n,g,h,2048,16,0) || mpz_cmp_ui(n,42) ||
      mpz_cmp_ui(g,43) || mpz_cmp_ui(h,44)) goto cleanup;
  if (vtd_setup_generate(n,g,h,512,16,1000) || mpz_cmp_ui(n,42)) goto cleanup;
  if (vtd_setup_generate(n,g,h,2048,0,1000) || mpz_cmp_ui(n,42)) goto cleanup;
  if (!vtd_setup_generate(n,g,h,2048,16,2000000)) goto cleanup;
  if (mpz_sizeinbase(n,2)!=2048 || mpz_jacobi(g,n)!=1) goto cleanup;
  mpz_set(check,g);
  for (unsigned i=0;i<16;i++) { mpz_mul(check,check,check); mpz_mod(check,check,n); }
  if (mpz_cmp(check,h)) goto cleanup;
  mpz_set_ui(message,12345); mpz_set_ui(r,72);
  if (!vtd_puzzle_generate(u,v,n,g,h,message,r) ||
      !vtd_puzzle_solve(decoded,n,u,v,16) || mpz_cmp(decoded,message)) goto cleanup;
  puts("{\"generated_modulus_bits\":2048,\"delay_relation_checked\":true,"
       "\"puzzle_roundtrip\":true,\"timed_privacy_benchmarked\":false}");
  status=0;
cleanup:
  mpz_clears(n,g,h,check,message,r,u,v,decoded,NULL);
  return status;
}
