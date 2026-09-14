#include <stdio.h>
#include "util.h"
#include "vtd_openings.h"
#include "vtd_verify.h"
#include "vtd_commit.h"
#include "vtd_wire.h"

static int setup_codec_test(void) {
  mpz_t source[4],decoded[4];
  unsigned char buffer[128];
  size_t length=0;
  int valid=0;
  for (unsigned i=0;i<4;i++) { mpz_init_set_ui(source[i],17+i); mpz_init_set_ui(decoded[i],99); }
  if (!vtd_setup_encode(buffer,sizeof(buffer),&length,source[0],source[1],source[2],source[3]))
    goto done;
  for (size_t size=0;size<length;size++) {
    if (vtd_setup_decode(decoded[0],decoded[1],decoded[2],decoded[3],buffer,size)) goto done;
    for (unsigned i=0;i<4;i++) if (mpz_cmp_ui(decoded[i],99)) goto done;
  }
  buffer[length]=0;
  if (vtd_setup_decode(decoded[0],decoded[1],decoded[2],decoded[3],buffer,length+1)) goto done;
  if (!vtd_setup_decode(decoded[0],decoded[1],decoded[2],decoded[3],buffer,length)) goto done;
  for (unsigned i=0;i<4;i++) if (mpz_cmp(source[i],decoded[i])) goto done;
  valid=1;
done:
  for (unsigned i=0;i<4;i++) { mpz_clear(source[i]); mpz_clear(decoded[i]); }
  return valid;
}

int main(void) {
  bn_t shares[8],secret,order,recovered;
  ec_t points[8],expected;
  mpz_t n,g,h,u[8],v[8],values[4],exponents[4],message,random;
  mpz_t messages[8],coins[8],du[128],dv[128],a[128],b[128],limit,bound;
  unsigned char encoding[33*9]={0},bits[128*8],digest[32];
  unsigned indices[4]={1,3,6,8};
  unsigned char bytes[32];
  unsigned initialized=0;
  unsigned char *wire=NULL,*again=NULL;
  int status=1;
  if (!setup_codec_test() || init()!=RLC_OK) return 1;
  bn_null(secret); bn_null(order); bn_null(recovered); ec_null(expected);
  mpz_inits(n,g,h,message,random,NULL);
  mpz_inits(limit,bound,NULL);
  for (unsigned i=0;i<8;i++) mpz_inits(messages[i],coins[i],NULL);
  for (unsigned i=0;i<128;i++) mpz_inits(du[i],dv[i],a[i],b[i],NULL);
  for (unsigned i=0;i<8;i++) mpz_inits(u[i],v[i],NULL);
  for (unsigned i=0;i<4;i++) mpz_inits(values[i],exponents[i],NULL);
  /* Known-factor public modulus for correctness, not a security setup. */
  mpz_set_ui(n,1); mpz_mul_2exp(n,n,521); mpz_sub_ui(n,n,1);
  mpz_set_ui(message,1); mpz_mul_2exp(message,message,127); mpz_sub_ui(message,message,1);
  mpz_mul(n,n,message); mpz_set_ui(g,4); mpz_set(h,g);
  for (unsigned i=0;i<12;i++) { mpz_mul(h,h,h); mpz_mod(h,h,n); }
  RLC_TRY {
    bn_new(secret); bn_new(order); bn_new(recovered); ec_new(expected); ec_curve_get_ord(order);
    bn_rand_mod(secret,order); ec_mul_gen(expected,secret);
    for (unsigned i=0;i<8;i++) {
      bn_null(shares[i]); ec_null(points[i]); bn_new(shares[i]); ec_new(points[i]); initialized++;
    }
    if (vtd_split(shares,8,5,secret)!=RLC_OK) RLC_THROW(ERR_NO_VALID);
    for (unsigned i=0;i<8;i++) {
      ec_mul_gen(points[i],shares[i]); bn_write_bin(bytes,32,shares[i]);
      mpz_import(message,32,1,1,0,0,bytes); mpz_set_ui(random,i+20);
      mpz_set(messages[i],message); mpz_set(coins[i],random);
      if (!vtd_puzzle_generate(u[i],v[i],n,g,h,message,random)) RLC_THROW(ERR_NO_VALID);
      for (unsigned j=0;j<4;j++) if (indices[j]==i+1) {
        mpz_set(values[j],message); mpz_set(exponents[j],random);
      }
    }
#define CHECK_OPENINGS() vtd_verify_openings(expected,(const ec_t *)points,8,indices, \
    (const mpz_t *)values,(const mpz_t *)exponents,n,g,h,(const mpz_t *)u,(const mpz_t *)v)
    if (!CHECK_OPENINGS()) RLC_THROW(ERR_NO_VALID);
    mpz_add_ui(values[0],values[0],1);
    if (CHECK_OPENINGS()) RLC_THROW(ERR_NO_VALID);
    mpz_sub_ui(values[0],values[0],1);
    mpz_add_ui(v[0],v[0],1);
    if (CHECK_OPENINGS()) RLC_THROW(ERR_NO_VALID);
    mpz_sub_ui(v[0],v[0],1);
    ec_add(points[1],points[1],expected);
    if (CHECK_OPENINGS()) RLC_THROW(ERR_NO_VALID);
    ec_sub(points[1],points[1],expected);
    if (!CHECK_OPENINGS()) RLC_THROW(ERR_NO_VALID);
    indices[0]=indices[1];
    if (CHECK_OPENINGS()) RLC_THROW(ERR_NO_VALID);
    mpz_set_ui(bound,1); mpz_mul_2exp(bound,bound,256);
    mpz_mul_2exp(limit,bound,148);
    if (!vtd_range_prove(128,8,(const unsigned char[32]){0},12,n,g,h,limit,bound,
        (const mpz_t *)u,(const mpz_t *)v,(const mpz_t *)messages,(const mpz_t *)coins,
        du,dv,a,b)) RLC_THROW(ERR_NO_VALID);
    ec_write_bin(encoding,33,expected,1);
    for (unsigned j=0;j<8;j++) ec_write_bin(encoding+33*(j+1),33,points[j],1);
    if (!vtd_range_challenge(bits,128,8,(const unsigned char[32]){0},12,n,g,h,limit,
        (const mpz_t *)u,(const mpz_t *)v,(const mpz_t *)du,(const mpz_t *)dv) ||
        !vtd_opening_challenge(indices,digest,8,128,encoding,bits,
        (const mpz_t *)a,(const mpz_t *)b)) RLC_THROW(ERR_NO_VALID);
    for (unsigned i=0;i<4;i++) {
      mpz_set(values[i],messages[indices[i]-1]); mpz_set(exponents[i],coins[indices[i]-1]);
    }
    vtd_proof_view proof={8,128,(const ec_t *)points,(const mpz_t *)u,(const mpz_t *)v,
      (const mpz_t *)du,(const mpz_t *)dv,(const mpz_t *)a,(const mpz_t *)b,
      (const mpz_t *)values,(const mpz_t *)exponents};
#define RELATIONS() vtd_verify_relations(&proof,8,expected,(const unsigned char[32]){0},12,n,g,h,limit)
    if (!RELATIONS()) RLC_THROW(ERR_NO_VALID);
    mpz_add_ui(values[0],values[0],1);
    if (RELATIONS()) RLC_THROW(ERR_NO_VALID);
    mpz_sub_ui(values[0],values[0],1);
    mpz_add_ui(a[127],a[127],1);
    if (RELATIONS()) RLC_THROW(ERR_NO_VALID);
    mpz_sub_ui(a[127],a[127],1);
    if (!RELATIONS()) RLC_THROW(ERR_NO_VALID);
    if (vtd_verify_relations(&proof,256,expected,(const unsigned char[32]){0},12,n,g,h,limit))
      RLC_THROW(ERR_NO_VALID);
    uint64_t work=999;
    bn_set_dig(recovered,42);
    if (vtd_force_open(recovered,&work,11,&proof,8,expected,
        (const unsigned char[32]){0},12,n,g,h,limit) || work!=0 ||
        bn_cmp_dig(recovered,42)!=RLC_EQ) RLC_THROW(ERR_NO_VALID);
    if (!vtd_force_open(recovered,&work,48,&proof,8,expected,
        (const unsigned char[32]){0},12,n,g,h,limit) || work!=12 ||
        bn_cmp(recovered,secret)!=RLC_EQ) RLC_THROW(ERR_NO_VALID);
    mpz_add_ui(a[0],a[0],1); bn_set_dig(recovered,42);
    if (vtd_force_open(recovered,&work,48,&proof,8,expected,
        (const unsigned char[32]){0},12,n,g,h,limit) || work!=0 ||
        bn_cmp_dig(recovered,42)!=RLC_EQ) RLC_THROW(ERR_NO_VALID);
    mpz_sub_ui(a[0],a[0],1);
    vtd_proof_output generated={8,128,points,u,v,du,dv,a,b,values,exponents};
    if (!vtd_commit(&generated,secret,expected,(const unsigned char[32]){0},12,n,g,h,limit))
      RLC_THROW(ERR_NO_VALID);
    proof=vtd_commit_view(&generated);
    size_t wire_size=0,again_size=0;
    wire=malloc(1024*1024); again=malloc(1024*1024);
    if (!wire || !again || !vtd_proof_encode(wire,1024*1024,&wire_size,&proof) ||
        !vtd_proof_decode(&generated,wire,wire_size) || !RELATIONS()) RLC_THROW(ERR_NO_VALID);
    if (!vtd_proof_encode(again,1024*1024,&again_size,&proof) || again_size!=wire_size ||
        memcmp(wire,again,wire_size)) RLC_THROW(ERR_NO_VALID);
    if (vtd_proof_decode(&generated,wire,wire_size-1)) RLC_THROW(ERR_NO_VALID);
    if (!ec_is_infty(points[0]) || mpz_sgn(u[0])) RLC_THROW(ERR_NO_VALID);
    if (!vtd_proof_decode(&generated,wire,wire_size)) RLC_THROW(ERR_NO_VALID);
    wire[wire_size]=0;
    if (vtd_proof_decode(&generated,wire,wire_size+1)) RLC_THROW(ERR_NO_VALID);
    wire[16]=4;
    if (vtd_proof_decode(&generated,wire,wire_size)) RLC_THROW(ERR_NO_VALID);
    memcpy(wire,again,wire_size); wire[11]=9;
    if (vtd_proof_decode(&generated,wire,wire_size)) RLC_THROW(ERR_NO_VALID);
    memcpy(wire,again,wire_size);
    if (!vtd_proof_decode(&generated,wire,wire_size)) RLC_THROW(ERR_NO_VALID);
    if (!RELATIONS() || !vtd_force_open(recovered,&work,48,&proof,8,expected,
        (const unsigned char[32]){0},12,n,g,h,limit) ||
        bn_cmp(recovered,secret)!=RLC_EQ) RLC_THROW(ERR_NO_VALID);
    bn_add_dig(secret,secret,1); bn_mod(secret,secret,order);
    if (vtd_commit(&generated,secret,expected,(const unsigned char[32]){0},12,n,g,h,limit))
      RLC_THROW(ERR_NO_VALID);
    for (unsigned i=0;i<8;i++)
      if (!ec_is_infty(points[i]) || mpz_sgn(u[i]) || mpz_sgn(v[i])) RLC_THROW(ERR_NO_VALID);
    puts("{\"opened_share_puzzle_link\":true,\"unopened_point_interpolation\":true,"
         "\"mutations_rejected\":true,\"full_vtd\":false}");
    status=0;
  } RLC_CATCH_ANY { status=1; }
  RLC_FINALLY {
    for (unsigned i=0;i<initialized;i++) { bn_zero(shares[i]); bn_free(shares[i]); ec_free(points[i]); }
    if (secret!=NULL) bn_zero(secret);
    if (recovered!=NULL) bn_zero(recovered);
    bn_free(secret); bn_free(order); bn_free(recovered); ec_free(expected);
  }
  for (unsigned i=0;i<8;i++) mpz_clears(u[i],v[i],NULL);
  for (unsigned i=0;i<4;i++) mpz_clears(values[i],exponents[i],NULL);
  for (unsigned i=0;i<8;i++) mpz_clears(messages[i],coins[i],NULL);
  for (unsigned i=0;i<128;i++) mpz_clears(du[i],dv[i],a[i],b[i],NULL);
  mpz_clears(limit,bound,NULL);
  free(wire); free(again);
  mpz_clears(n,g,h,message,random,NULL); memzero(bytes,sizeof(bytes)); clean();
  return status;
}
