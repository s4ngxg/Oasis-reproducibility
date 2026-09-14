#include <stdlib.h>
#include <string.h>
#include "vtd_verify.h"

int vtd_force_open(bn_t output, uint64_t *performed_squarings,
                    uint64_t max_squarings, const vtd_proof_view *proof,
                    unsigned expected_count, const ec_t expected_key,
                    const unsigned char context[32], uint64_t squarings,
                    const mpz_t modulus, const mpz_t g, const mpz_t h,
                    const mpz_t limit) {
  bn_t shares[129], recovered, order;
  ec_t computed;
  mpz_t decoded, q, absolute;
  unsigned indices[129], allocated=0, half;
  unsigned char selected[256]={0}, scalar_bytes[32], digest[32];
  unsigned char *points=NULL, *bits=NULL;
  uint64_t work=0;
  int valid=0;
  if (!performed_squarings) return 0;
  *performed_squarings=0;
  if (squarings==0 || squarings>max_squarings ||
      !vtd_verify_relations(proof,expected_count,expected_key,context,squarings,
                            modulus,g,h,limit)) return 0;
  half=expected_count/2;
  points=calloc((size_t)expected_count+1,33);
  bits=malloc((size_t)proof->rows*expected_count);
  if (!points || !bits) { free(points); free(bits); return 0; }
  bn_null(recovered); bn_null(order); ec_null(computed);
  mpz_inits(decoded,q,absolute,NULL);
  RLC_TRY {
    bn_new(recovered); bn_new(order); ec_new(computed); ec_curve_get_ord(order);
    bn_write_bin(scalar_bytes,32,order); mpz_import(q,32,1,1,0,0,scalar_bytes);
    ec_write_bin(points,33,expected_key,1);
    for (unsigned j=0;j<expected_count;j++)
      if (!ec_is_infty(proof->points[j])) ec_write_bin(points+33*(j+1),33,proof->points[j],1);
    if (!vtd_range_challenge(bits,proof->rows,expected_count,context,squarings,modulus,g,h,
        limit,proof->puzzle_u,proof->puzzle_v,proof->commitment_u,proof->commitment_v) ||
        !vtd_opening_challenge(indices,digest,expected_count,proof->rows,points,bits,
        proof->responses,proof->random_responses)) RLC_THROW(ERR_NO_VALID);
    for (unsigned i=0;i<=half;i++) {
      bn_null(shares[i]); bn_new(shares[i]); allocated++;
      if (i<half) {
        size_t size=0, length=mpz_sgn(proof->opened_values[i]) ?
          (mpz_sizeinbase(proof->opened_values[i],2)+7)/8 : 0;
        memset(scalar_bytes,0,32);
        if (length) mpz_export(scalar_bytes+32-length,&size,1,1,0,0,proof->opened_values[i]);
        if (size!=length) RLC_THROW(ERR_NO_VALID);
        bn_read_bin(shares[i],scalar_bytes,32); selected[indices[i]-1]=1;
      }
    }
    for (unsigned j=0;j<expected_count;j++) if (!selected[j]) {
      if (max_squarings-work<squarings) break;
      work+=squarings;
      if (!vtd_puzzle_solve(decoded,modulus,proof->puzzle_u[j],proof->puzzle_v[j],squarings))
        continue;
      /* A negative centered plaintext is encoded modulo N, not modulo q. */
      mpz_mul_ui(absolute,decoded,2);
      if (mpz_cmp(absolute,modulus)>0) mpz_sub(decoded,decoded,modulus);
      mpz_abs(absolute,decoded);
      if (mpz_cmp(absolute,limit)>0) continue;
      mpz_mod(decoded,decoded,q);
      size_t size=0, length=mpz_sgn(decoded) ? (mpz_sizeinbase(decoded,2)+7)/8 : 0;
      memset(scalar_bytes,0,32);
      if (length) mpz_export(scalar_bytes+32-length,&size,1,1,0,0,decoded);
      if (size!=length) RLC_THROW(ERR_NO_VALID);
      bn_read_bin(shares[half],scalar_bytes,32);
      ec_mul_gen(computed,shares[half]);
      if (ec_cmp(computed,proof->points[j])!=RLC_EQ) continue;
      indices[half]=j+1;
      if (vtd_recover(recovered,(const bn_t *)shares,indices,half+1)!=RLC_OK)
        RLC_THROW(ERR_NO_VALID);
      ec_mul_gen(computed,recovered);
      if (ec_cmp(computed,expected_key)!=RLC_EQ) continue;
      bn_copy(output,recovered); valid=1; break;
    }
  } RLC_CATCH_ANY { valid=0; }
  RLC_FINALLY {
    for (unsigned i=0;i<allocated;i++) { bn_zero(shares[i]); bn_free(shares[i]); }
    if (recovered!=NULL) bn_zero(recovered);
    bn_free(recovered); bn_free(order); ec_free(computed);
  }
  for (unsigned i=0;i<32;i++) ((volatile unsigned char *)scalar_bytes)[i]=0;
  mpz_clears(decoded,q,absolute,NULL); free(points); free(bits);
  *performed_squarings=work;
  return valid;
}
