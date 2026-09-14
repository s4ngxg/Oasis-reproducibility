#include <string.h>
#include "vtd_openings.h"

int vtd_verify_openings(const ec_t expected, const ec_t *points, unsigned count,
                        const unsigned *indices, const mpz_t *values,
                        const mpz_t *exponents, const mpz_t modulus,
                        const mpz_t g, const mpz_t h,
                        const mpz_t *puzzle_u, const mpz_t *puzzle_v) {
  bn_t scalar, order;
  ec_t computed, subset[129];
  mpz_t u,v,square;
  unsigned positions[129], allocated=0, half=count/2;
  unsigned char selected[256]={0}, encoded[32];
  int valid=0;
  if (!points || !indices || !values || !exponents || !puzzle_u || !puzzle_v ||
      count<2 || count>256 || count%2) return 0;
  for (unsigned i=0;i<half;i++) {
    if (indices[i]==0 || indices[i]>count || (i && indices[i]<=indices[i-1])) return 0;
    selected[indices[i]-1]=1;
  }
  bn_null(scalar); bn_null(order); ec_null(computed);
  mpz_inits(u,v,square,NULL); mpz_mul(square,modulus,modulus);
  RLC_TRY {
    bn_new(scalar); bn_new(order); ec_new(computed); ec_curve_get_ord(order);
    if (ec_is_infty(expected) || !ec_on_curve(expected)) RLC_THROW(ERR_NO_VALID);
    for (unsigned j=0;j<count;j++)
      if (!ec_is_infty(points[j]) && !ec_on_curve(points[j])) RLC_THROW(ERR_NO_VALID);
    for (unsigned i=0;i<=half;i++) {
      ec_null(subset[i]); ec_new(subset[i]); allocated++;
    }
    for (unsigned i=0;i<half;i++) {
      size_t length=0;
      unsigned j=indices[i]-1;
      if (mpz_sgn(values[i])<0 || mpz_sizeinbase(values[i],2)>256 ||
          mpz_sgn(exponents[i])<=0 || mpz_cmp(exponents[i],square)>0)
        RLC_THROW(ERR_NO_VALID);
      memset(encoded,0,sizeof(encoded));
      size_t bytes=mpz_sgn(values[i]) ? (mpz_sizeinbase(values[i],2)+7)/8 : 0;
      if (bytes) mpz_export(encoded+32-bytes,&length,1,1,0,0,values[i]);
      if (length!=bytes) RLC_THROW(ERR_NO_VALID);
      bn_read_bin(scalar,encoded,32);
      if (bn_cmp(scalar,order)!=RLC_LT) RLC_THROW(ERR_NO_VALID);
      ec_mul_gen(computed,scalar);
      if (ec_cmp(computed,points[j])!=RLC_EQ ||
          !vtd_puzzle_generate(u,v,modulus,g,h,values[i],exponents[i]) ||
          mpz_cmp(u,puzzle_u[j]) || mpz_cmp(v,puzzle_v[j])) RLC_THROW(ERR_NO_VALID);
      positions[i]=indices[i]; ec_copy(subset[i],points[j]);
    }
    for (unsigned j=0;j<count;j++) if (!selected[j]) {
      positions[half]=j+1; ec_copy(subset[half],points[j]);
      if (vtd_check_points(expected,(const ec_t *)subset,positions,half+1)!=RLC_OK)
        RLC_THROW(ERR_NO_VALID);
    }
    valid=1;
  } RLC_CATCH_ANY { valid=0; }
  RLC_FINALLY {
    for (unsigned i=0;i<allocated;i++) ec_free(subset[i]);
    bn_free(scalar); bn_free(order); ec_free(computed);
  }
  mpz_clears(u,v,square,NULL);
  return valid;
}
