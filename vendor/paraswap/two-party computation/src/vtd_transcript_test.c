#include <stdio.h>
#include <string.h>
#include "util.h"
#include "vtd_transcript.h"

static int opening_encoding(void) {
  static const unsigned char kat[32]={
    0xf9,0x68,0x64,0x0d,0x35,0xb3,0xb2,0x49,0x0b,0xdc,0x07,0x42,0xaf,0xdd,0x43,0xca,
    0xea,0xe6,0x8e,0xa9,0x5d,0xaf,0x82,0xa3,0x82,0xca,0xfe,0xcb,0x01,0xa8,0x13,0x3e};
  unsigned char points[33*9]={0}, bits[128*8]={0}, digest[32];
  mpz_t a[128],b[128];
  unsigned indices[4];
  int valid=0;
  for (unsigned i=0;i<128;i++) mpz_inits(a[i],b[i],NULL);
#define OPENING() vtd_opening_challenge(indices,digest,8,128,points,bits, \
    (const mpz_t *)a,(const mpz_t *)b)
  if (!OPENING() || memcmp(digest,kat,32) || indices[0]!=1 || indices[1]!=2 ||
      indices[2]!=6 || indices[3]!=7) goto cleanup;
  points[0]=1;
  if (!OPENING() || !memcmp(digest,kat,32)) goto cleanup;
  points[0]=0; bits[1023]=1;
  if (!OPENING() || !memcmp(digest,kat,32)) goto cleanup;
  bits[1023]=0; mpz_set_si(a[127],-1);
  if (!OPENING() || !memcmp(digest,kat,32)) goto cleanup;
  mpz_set_ui(a[127],0); mpz_set_ui(b[127],1);
  if (!OPENING() || !memcmp(digest,kat,32)) goto cleanup;
  for (unsigned i=0;i<4;i++)
    if (indices[i]<1 || indices[i]>8 || (i && indices[i]<=indices[i-1])) goto cleanup;
  mpz_set_si(b[127],-1);
  if (OPENING()) goto cleanup;
  mpz_set_ui(b[127],0); bits[0]=2;
  if (OPENING()) goto cleanup;
  valid=1;
cleanup:
  for (unsigned i=0;i<128;i++) mpz_clears(a[i],b[i],NULL);
  return valid;
}

static int proof_equations(void) {
  mpz_t n,g,h,l,u[2],v[2],x[2],r[2],du[128],dv[128],y[128],s[128],a[128],b[128];
  unsigned char context[32]={0},bits[256];
  int valid=0;
  mpz_inits(n,g,h,l,NULL);
  for (unsigned i=0;i<2;i++) mpz_inits(u[i],v[i],x[i],r[i],NULL);
  for (unsigned i=0;i<128;i++) mpz_inits(du[i],dv[i],y[i],s[i],a[i],b[i],NULL);
  mpz_set_ui(n,77); mpz_set_ui(g,4); mpz_set(h,g); mpz_set_ui(l,32);
  for (unsigned i=0;i<12;i++) { mpz_mul(h,h,h); mpz_mod(h,h,n); }
  for (unsigned j=0;j<2;j++) {
    mpz_set_si(x[j],j ? -1 : 1); mpz_set_ui(r[j],13+6*j);
    if (!vtd_puzzle_generate(u[j],v[j],n,g,h,x[j],r[j])) goto cleanup;
  }
  /* Deterministic toy witnesses only test verifier algebra, not ZK sampling. */
  for (unsigned i=0;i<128;i++) {
    mpz_set_si(y[i],(long)(i%5)-2); mpz_set_ui(s[i],50+i);
    if (!vtd_puzzle_generate(du[i],dv[i],n,g,h,y[i],s[i])) goto cleanup;
  }
  if (!vtd_range_challenge(bits,128,2,context,12,n,g,h,l,
      (const mpz_t *)u,(const mpz_t *)v,(const mpz_t *)du,(const mpz_t *)dv)) goto cleanup;
  for (unsigned i=0;i<128;i++) {
    mpz_set(a[i],y[i]); mpz_set(b[i],s[i]);
    for (unsigned j=0;j<2;j++) if (bits[i*2+j]) {
      mpz_add(a[i],a[i],x[j]); mpz_add(b[i],b[i],r[j]);
    }
  }
#define VERIFY() vtd_range_verify(128,2,context,12,n,g,h,l,(const mpz_t *)u, \
    (const mpz_t *)v,(const mpz_t *)du,(const mpz_t *)dv,(const mpz_t *)a,(const mpz_t *)b)
  if (!VERIFY()) goto cleanup;
  for (unsigned i=0;i<128;i++) {
    mpz_add_ui(a[i],a[i],1);
    if (VERIFY()) goto cleanup;
    mpz_sub_ui(a[i],a[i],1);
  }
  context[0]=1;
  if (VERIFY()) goto cleanup;
  context[0]=0;
  mpz_add_ui(du[127],du[127],1);
  if (VERIFY()) goto cleanup;
  mpz_sub_ui(du[127],du[127],1);
  if (!VERIFY()) goto cleanup;
  if (vtd_range_verify(127,2,context,12,n,g,h,l,(const mpz_t *)u,
      (const mpz_t *)v,(const mpz_t *)du,(const mpz_t *)dv,
      (const mpz_t *)a,(const mpz_t *)b)) goto cleanup;
  /* Larger but still PUBLIC, known-factor setup tests the real mask sampler.
   * This fixture is not a trusted production setup or timed-privacy test. */
  mpz_set_ui(n,1); mpz_mul_2exp(n,n,127); mpz_sub_ui(n,n,1);
  mpz_set_ui(l,1); mpz_mul_2exp(l,l,107); mpz_sub_ui(l,l,1); mpz_mul(n,n,l);
  mpz_set_ui(l,1); mpz_mul_2exp(l,l,150);
  mpz_set(h,g);
  for (unsigned i=0;i<12;i++) { mpz_mul(h,h,h); mpz_mod(h,h,n); }
  for (unsigned j=0;j<2;j++)
    if (!vtd_puzzle_generate(u[j],v[j],n,g,h,x[j],r[j])) goto cleanup;
  mpz_set_ui(y[0],2);
#define PROVE() vtd_range_prove(128,2,context,12,n,g,h,l,y[0], \
    (const mpz_t *)u,(const mpz_t *)v,(const mpz_t *)x,(const mpz_t *)r,du,dv,a,b)
  if (!PROVE() || !VERIFY()) goto cleanup;
  mpz_add_ui(x[0],x[0],1);
  if (PROVE()) goto cleanup;
  for (unsigned i=0;i<128;i++)
    if (mpz_sgn(du[i]) || mpz_sgn(dv[i]) || mpz_sgn(a[i]) || mpz_sgn(b[i])) goto cleanup;
  mpz_sub_ui(x[0],x[0],1);
  if (!PROVE() || !VERIFY()) goto cleanup;
  mpz_mul(r[0],n,n);
  if (!vtd_puzzle_generate(u[0],v[0],n,g,h,x[0],r[0]) || !PROVE() || !VERIFY()) goto cleanup;
  mpz_add_ui(r[0],r[0],1);
  if (PROVE()) goto cleanup;
  mpz_set_ui(r[0],0);
  if (!vtd_puzzle_generate(u[0],v[0],n,g,h,x[0],r[0]) || PROVE()) goto cleanup;
  mpz_set_ui(r[0],13);
  if (!vtd_puzzle_generate(u[0],v[0],n,g,h,x[0],r[0])) goto cleanup;
  mpz_set_ui(l,32);
  if (PROVE()) goto cleanup;
  valid=1;
cleanup:
  for (unsigned i=0;i<128;i++) mpz_clears(du[i],dv[i],y[i],s[i],a[i],b[i],NULL);
  for (unsigned i=0;i<2;i++) mpz_clears(u[i],v[i],x[i],r[i],NULL);
  mpz_clears(n,g,h,l,NULL);
  return valid;
}

int main(void) {
  static const unsigned char expected[32]={
    0x96,0xbf,0xa5,0xa0,0xee,0xbc,0x9e,0x4f,0xc4,0xba,0x1e,0xc7,0xdc,0x27,0xe5,0xe9,
    0x06,0x20,0x13,0xa9,0x25,0xcd,0xf9,0xf3,0x02,0x68,0xd7,0xa0,0x19,0x56,0x4e,0x06};
  mpz_t n,g,h,l,u[2],v[2],du[128],dv[128];
  unsigned char context[32]={0}, bits[256], changed[256];
  int status=1;
  if (init()!=RLC_OK) return 1;
  if (!opening_encoding()) { clean(); return 1; }
  if (!proof_equations()) { clean(); return 1; }
  mpz_inits(n,g,h,l,NULL);
  for (unsigned i=0;i<2;i++) { mpz_init_set_ui(u[i],1+2*i); mpz_init_set_ui(v[i],2+2*i); }
  for (unsigned i=0;i<128;i++) { mpz_init_set_ui(du[i],5+2*i); mpz_init_set_ui(dv[i],6+2*i); }
  mpz_set_ui(n,77); mpz_set_ui(g,4); mpz_set_ui(h,16); mpz_set_ui(l,32);
#define CHALLENGE(out,delay) vtd_range_challenge(out,128,2,context,delay,n,g,h,l, \
    (const mpz_t *)u,(const mpz_t *)v,(const mpz_t *)du,(const mpz_t *)dv)
  /* Encoder test values need not be a valid proof. Semantic validation belongs
   * to the proof verifier, not to this deterministic transcript encoder. */
  if (!CHALLENGE(bits,12)) goto cleanup;
  for (unsigned i=0;i<256;i++)
    if (bits[i]!=((expected[i/8]>>(7-i%8))&1)) goto cleanup;
  context[0]=1;
  if (!CHALLENGE(changed,12) || !memcmp(bits,changed,256)) goto cleanup;
  context[0]=0;
  if (!CHALLENGE(changed,13) || !memcmp(bits,changed,256)) goto cleanup;
  mpz_ptr fields[]={n,g,h,l,u[0],v[0],u[1],v[1],du[0],dv[0],du[127],dv[127]};
  for (unsigned i=0;i<sizeof(fields)/sizeof(fields[0]);i++) {
    mpz_add_ui(fields[i],fields[i],1);
    if (!CHALLENGE(changed,12) || !memcmp(bits,changed,256)) goto cleanup;
    mpz_sub_ui(fields[i],fields[i],1);
  }
  mpz_swap(u[0],u[1]);
  if (!CHALLENGE(changed,12) || !memcmp(bits,changed,256)) goto cleanup;
  mpz_swap(u[0],u[1]);
  mpz_set_si(n,-1); memset(changed,0xa5,sizeof(changed));
  if (CHALLENGE(changed,12)) goto cleanup;
  for (unsigned i=0;i<256;i++) if (changed[i]!=0xa5) goto cleanup;
  puts("{\"sha256_known_answer\":true,\"transcript_mutations_bound\":true}");
  status=0;
cleanup:
  for (unsigned i=0;i<128;i++) mpz_clears(du[i],dv[i],NULL);
  for (unsigned i=0;i<2;i++) mpz_clears(u[i],v[i],NULL);
  mpz_clears(n,g,h,l,NULL); clean();
  return status;
}
