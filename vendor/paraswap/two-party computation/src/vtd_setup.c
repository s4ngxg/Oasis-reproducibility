#include "vtd_setup.h"

static int safe_prime(mpz_t prime, unsigned bits, uint64_t *budget) {
  mpz_t subprime, bound;
  int valid=0;
  mpz_inits(subprime,bound,NULL);
  mpz_set_ui(bound,1); mpz_mul_2exp(bound,bound,bits-1);
  while (*budget) {
    --*budget;
    if (!vtd_random_below(subprime,bound)) break;
    mpz_setbit(subprime,bits-2); mpz_setbit(subprime,0);
    if (!mpz_probab_prime_p(subprime,64)) continue;
    mpz_mul_2exp(prime,subprime,1); mpz_add_ui(prime,prime,1);
    if (mpz_probab_prime_p(prime,64)) { valid=1; break; }
  }
  mpz_clears(subprime,bound,NULL);
  return valid;
}

int vtd_setup_generate(mpz_t modulus, mpz_t g, mpz_t h, unsigned bits,
                        uint64_t squarings, uint64_t max_candidates) {
  mpz_t p,q,n,base,generator,power,result,phi,half_p,half_q,check,time;
  int valid=0;
  if (bits<2048 || bits>4096 || bits%2 || !squarings || !max_candidates)
    return 0;
  mpz_inits(p,q,n,base,generator,power,result,phi,half_p,half_q,check,time,NULL);
  do {
    /* Resample the pair on a short product. Keeping a near-minimal p can
     * make the acceptable interval for q arbitrarily narrow. */
    if (!safe_prime(p,bits/2,&max_candidates)) goto cleanup;
    if (!safe_prime(q,bits/2,&max_candidates)) goto cleanup;
    mpz_mul(n,p,q);
  } while (mpz_cmp(p,q)==0 || mpz_sizeinbase(n,2)!=bits);
  mpz_sub_ui(half_p,p,1); mpz_fdiv_q_2exp(half_p,half_p,1);
  mpz_sub_ui(half_q,q,1); mpz_fdiv_q_2exp(half_q,half_q,1);
  mpz_mul(phi,half_p,half_q); mpz_mul_2exp(phi,phi,1);
  for (unsigned attempt=0;attempt<1024;attempt++) {
    if (!vtd_random_below(base,n)) goto cleanup;
    mpz_gcd(check,base,n); if (mpz_cmp_ui(check,1)) continue;
    mpz_mul(generator,base,base); mpz_neg(generator,generator); mpz_mod(generator,generator,n);
    /* Reject the negligible small-order cases while the factors are known. */
    mpz_powm(check,generator,half_p,n); mpz_mul(check,check,check); mpz_mod(check,check,n);
    if (mpz_cmp_ui(check,1)==0) continue;
    mpz_powm(check,generator,half_q,n); mpz_mul(check,check,check); mpz_mod(check,check,n);
    if (mpz_cmp_ui(check,1)==0) continue;
    mpz_set_ui(base,2);
    unsigned char encoded[8];
    for (unsigned i=0;i<8;i++) encoded[i]=(unsigned char)(squarings>>(56-8*i));
    mpz_import(time,8,1,1,0,0,encoded);
    mpz_powm(power,base,time,phi); mpz_powm(result,generator,power,n);
    mpz_set(modulus,n); mpz_set(g,generator); mpz_set(h,result);
    valid=1; break;
  }
cleanup:
  mpz_clears(p,q,n,base,generator,power,result,phi,half_p,half_q,check,time,NULL);
  return valid;
}
