#include <stdlib.h>
#include <string.h>
#include "vtd_commit.h"

vtd_proof_view vtd_commit_view(const vtd_proof_output *p) {
  vtd_proof_view view={0};
  if (!p) return view;
  view.count=p->count; view.rows=p->rows; view.points=(const ec_t *)p->points;
  view.puzzle_u=(const mpz_t *)p->puzzle_u; view.puzzle_v=(const mpz_t *)p->puzzle_v;
  view.commitment_u=(const mpz_t *)p->commitment_u; view.commitment_v=(const mpz_t *)p->commitment_v;
  view.responses=(const mpz_t *)p->responses; view.random_responses=(const mpz_t *)p->random_responses;
  view.opened_values=(const mpz_t *)p->opened_values; view.opened_exponents=(const mpz_t *)p->opened_exponents;
  return view;
}

int vtd_commit(vtd_proof_output *proof, const bn_t secret, const ec_t key,
                const unsigned char context[32], uint64_t squarings,
                const mpz_t modulus, const mpz_t g, const mpz_t h,
                const mpz_t limit) {
  bn_t shares[256],order;
  ec_t computed;
  mpz_t messages[256],coins[256],square,bound;
  unsigned indices[128],allocated=0;
  unsigned char scalar[32],digest[32],*encoding=NULL,*bits=NULL;
  int valid=0;
  if (!proof || !context || proof->count<2 || proof->count>256 || proof->count%2 ||
      proof->rows<128 || proof->rows>256 || !proof->points || !proof->puzzle_u ||
      !proof->puzzle_v || !proof->commitment_u || !proof->commitment_v ||
      !proof->responses || !proof->random_responses || !proof->opened_values ||
      !proof->opened_exponents || squarings==0) return 0;
  bn_null(order); ec_null(computed); mpz_inits(square,bound,NULL);
  for (unsigned j=0;j<proof->count;j++) mpz_inits(messages[j],coins[j],NULL);
  RLC_TRY {
    bn_new(order); ec_new(computed); ec_curve_get_ord(order);
    if (bn_is_zero(secret) || bn_sign(secret)==RLC_NEG || bn_cmp(secret,order)!=RLC_LT ||
        ec_is_infty(key) || !ec_on_curve(key)) RLC_THROW(ERR_NO_VALID);
    ec_mul_gen(computed,secret);
    if (ec_cmp(computed,key)!=RLC_EQ) RLC_THROW(ERR_NO_VALID);
    for (unsigned j=0;j<proof->count;j++) {
      bn_null(shares[j]); bn_new(shares[j]); allocated++;
    }
    if (vtd_split(shares,proof->count,proof->count/2+1,secret)!=RLC_OK)
      RLC_THROW(ERR_NO_VALID);
    bn_write_bin(scalar,32,order); mpz_import(bound,32,1,1,0,0,scalar);
    mpz_sub_ui(bound,bound,1); mpz_mul(square,modulus,modulus);
    encoding=calloc((size_t)proof->count+1,33); bits=malloc((size_t)proof->rows*proof->count);
    if (!encoding || !bits) RLC_THROW(ERR_NO_VALID);
    ec_write_bin(encoding,33,key,1);
    for (unsigned j=0;j<proof->count;j++) {
      bn_write_bin(scalar,32,shares[j]); mpz_import(messages[j],32,1,1,0,0,scalar);
      ec_mul_gen(proof->points[j],shares[j]);
      if (!ec_is_infty(proof->points[j])) ec_write_bin(encoding+33*(j+1),33,proof->points[j],1);
      if (!vtd_random_below(coins[j],square)) RLC_THROW(ERR_NO_VALID);
      mpz_add_ui(coins[j],coins[j],1);
      if (!vtd_puzzle_generate(proof->puzzle_u[j],proof->puzzle_v[j],modulus,g,h,messages[j],coins[j]))
        RLC_THROW(ERR_NO_VALID);
    }
    if (!vtd_range_prove(proof->rows,proof->count,context,squarings,modulus,g,h,limit,bound,
        (const mpz_t *)proof->puzzle_u,(const mpz_t *)proof->puzzle_v,
        (const mpz_t *)messages,(const mpz_t *)coins,proof->commitment_u,proof->commitment_v,
        proof->responses,proof->random_responses) ||
        !vtd_range_challenge(bits,proof->rows,proof->count,context,squarings,modulus,g,h,limit,
        (const mpz_t *)proof->puzzle_u,(const mpz_t *)proof->puzzle_v,
        (const mpz_t *)proof->commitment_u,(const mpz_t *)proof->commitment_v) ||
        !vtd_opening_challenge(indices,digest,proof->count,proof->rows,encoding,bits,
        (const mpz_t *)proof->responses,(const mpz_t *)proof->random_responses))
      RLC_THROW(ERR_NO_VALID);
    for (unsigned i=0;i<proof->count/2;i++) {
      mpz_set(proof->opened_values[i],messages[indices[i]-1]);
      mpz_set(proof->opened_exponents[i],coins[indices[i]-1]);
    }
    vtd_proof_view view=vtd_commit_view(proof);
    valid=vtd_verify_relations(&view,proof->count,key,context,squarings,modulus,g,h,limit);
  } RLC_CATCH_ANY { valid=0; }
  RLC_FINALLY {
    for (unsigned j=0;j<allocated;j++) { bn_zero(shares[j]); bn_free(shares[j]); }
    bn_free(order); ec_free(computed);
  }
  if (!valid) {
    for (unsigned j=0;j<proof->count;j++) {
      ec_set_infty(proof->points[j]); mpz_set_ui(proof->puzzle_u[j],0); mpz_set_ui(proof->puzzle_v[j],0);
    }
    for (unsigned i=0;i<proof->rows;i++) {
      mpz_set_ui(proof->commitment_u[i],0); mpz_set_ui(proof->commitment_v[i],0);
      mpz_set_ui(proof->responses[i],0); mpz_set_ui(proof->random_responses[i],0);
    }
    for (unsigned i=0;i<proof->count/2;i++) {
      mpz_set_ui(proof->opened_values[i],0); mpz_set_ui(proof->opened_exponents[i],0);
    }
  }
  for (unsigned j=0;j<proof->count;j++) mpz_clears(messages[j],coins[j],NULL);
  for (unsigned j=0;j<32;j++) ((volatile unsigned char *)scalar)[j]=0;
  mpz_clears(square,bound,NULL); free(encoding); free(bits);
  return valid;
}
