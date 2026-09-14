#include <stdlib.h>
#include <string.h>
#include <relic/relic.h>
#include "vtd_transcript.h"

#define MAX_INTEGER_BYTES 4096u

int vtd_range_verify(unsigned rows, unsigned count,
                      const unsigned char context[32], uint64_t squarings,
                      const mpz_t modulus, const mpz_t g, const mpz_t h,
                      const mpz_t limit, const mpz_t *puzzle_u,
                      const mpz_t *puzzle_v, const mpz_t *commitment_u,
                      const mpz_t *commitment_v, const mpz_t *responses,
                      const mpz_t *random_responses) {
  unsigned char *bits;
  int valid=0;
  if (rows<128 || rows>256 || count==0 || count>256 || !responses ||
      !random_responses) return 0;
  for (unsigned i=0;i<rows;i++)
    if (mpz_sizeinbase(responses[i],2)>MAX_INTEGER_BYTES*8 ||
        mpz_sizeinbase(random_responses[i],2)>MAX_INTEGER_BYTES*8) return 0;
  bits=malloc((size_t)rows*count);
  if (!bits) return 0;
  if (!vtd_range_challenge(bits,rows,count,context,squarings,modulus,g,h,limit,
                           puzzle_u,puzzle_v,commitment_u,commitment_v)) goto cleanup;
  for (unsigned i=0;i<rows;i++)
    if (!vtd_range_check_row(modulus,g,h,limit,commitment_u[i],commitment_v[i],
                             responses[i],random_responses[i],puzzle_u,puzzle_v,
                             bits+(size_t)i*count,count)) goto cleanup;
  valid=1;
cleanup:
  free(bits);
  return valid;
}

static void put32(unsigned char *out, uint32_t value) {
  for (unsigned i=0;i<4;i++) out[i]=(unsigned char)(value >> (24-8*i));
}

static int append_integer(unsigned char *buffer, size_t capacity, size_t *used,
                           const mpz_t value) {
  size_t length, written=0;
  if (mpz_sgn(value)<0) return 0;
  length=mpz_sgn(value) ? (mpz_sizeinbase(value,2)+7)/8 : 0;
  if (length>MAX_INTEGER_BYTES || *used>capacity || capacity-*used<length+4)
    return 0;
  put32(buffer+*used,(uint32_t)length); *used+=4;
  if (length) mpz_export(buffer+*used,&written,1,1,0,0,value);
  if (written!=length) return 0;
  *used+=length;
  return 1;
}

int vtd_range_challenge(unsigned char *bits, unsigned rows, unsigned count,
                        const unsigned char context[32], uint64_t squarings,
                        const mpz_t modulus, const mpz_t g, const mpz_t h,
                        const mpz_t limit, const mpz_t *puzzle_u,
                        const mpz_t *puzzle_v, const mpz_t *commitment_u,
                        const mpz_t *commitment_v) {
  static const unsigned char domain[]="OASIS-VTD-RANGE-v1";
  static const unsigned char expansion[]="OASIS-VTD-RANGE-BITS-v1";
  unsigned char digest[32], block[32], input[sizeof(expansion)-1+32+4];
  unsigned char *buffer=NULL, *result=NULL;
  size_t capacity, used=0, total;
  int valid=0;
  if (!bits || !context || !puzzle_u || !puzzle_v || !commitment_u ||
      !commitment_v || rows==0 || rows>256 || count==0 || count>256) return 0;
  total=(size_t)rows*count;
  capacity=sizeof(domain)-1+48+(4+2*(size_t)count+2*(size_t)rows)*(MAX_INTEGER_BYTES+4);
  buffer=malloc(capacity); result=malloc(total);
  if (!buffer || !result) goto cleanup;
  memcpy(buffer,domain,sizeof(domain)-1); used=sizeof(domain)-1;
  memcpy(buffer+used,context,32); used+=32;
  for (unsigned i=0;i<8;i++) buffer[used++]=(unsigned char)(squarings>>(56-8*i));
  put32(buffer+used,count); used+=4; put32(buffer+used,rows); used+=4;
  if (!append_integer(buffer,capacity,&used,modulus) ||
      !append_integer(buffer,capacity,&used,g) ||
      !append_integer(buffer,capacity,&used,h) ||
      !append_integer(buffer,capacity,&used,limit)) goto cleanup;
  for (unsigned j=0;j<count;j++)
    if (!append_integer(buffer,capacity,&used,puzzle_u[j]) ||
        !append_integer(buffer,capacity,&used,puzzle_v[j])) goto cleanup;
  for (unsigned i=0;i<rows;i++)
    if (!append_integer(buffer,capacity,&used,commitment_u[i]) ||
        !append_integer(buffer,capacity,&used,commitment_v[i])) goto cleanup;
  md_map_sh256(digest,buffer,used);
  memcpy(input,expansion,sizeof(expansion)-1);
  memcpy(input+sizeof(expansion)-1,digest,32);
  for (size_t offset=0;offset<total;offset+=256) {
    put32(input+sizeof(expansion)-1+32,(uint32_t)(offset/256));
    md_map_sh256(block,input,sizeof(input));
    for (size_t j=0;j<256 && offset+j<total;j++)
      result[offset+j]=(block[j/8]>>(7-j%8))&1;
  }
  memcpy(bits,result,total); valid=1;
cleanup:
  free(buffer); free(result);
  return valid;
}

int vtd_opening_challenge(unsigned *indices, unsigned char digest_out[32],
                          unsigned count, unsigned rows,
                          const unsigned char *point_encodings,
                          const unsigned char *range_bits,
                          const mpz_t *responses,
                          const mpz_t *random_responses) {
  static const unsigned char domain[]="OASIS-VTD-OPENING-v1";
  static const unsigned char expansion[]="OASIS-VTD-OPENING-DRAW-v1";
  unsigned char input[sizeof(expansion)-1+32+4], digest[32], block[32];
  unsigned char *buffer=NULL;
  unsigned order[256], selected[256]={0};
  size_t used=0, bit_count, point_bytes, capacity;
  uint32_t counter=0;
  unsigned cursor=32;
  mpz_t magnitude;
  int valid=0;
  if (!indices || !digest_out || !point_encodings || !range_bits ||
      !responses || !random_responses || count<2 || count>256 || count%2 ||
      rows<128 || rows>256) return 0;
  bit_count=(size_t)rows*count; point_bytes=33*((size_t)count+1);
  for (size_t i=0;i<bit_count;i++) if (range_bits[i]>1) return 0;
  capacity=sizeof(domain)-1+8+point_bytes+bit_count+(size_t)rows*(1+2*(MAX_INTEGER_BYTES+4));
  buffer=malloc(capacity); if (!buffer) return 0;
  mpz_init(magnitude);
  memcpy(buffer,domain,sizeof(domain)-1); used=sizeof(domain)-1;
  put32(buffer+used,count); used+=4; put32(buffer+used,rows); used+=4;
  memcpy(buffer+used,point_encodings,point_bytes); used+=point_bytes;
  memcpy(buffer+used,range_bits,bit_count); used+=bit_count;
  for (unsigned i=0;i<rows;i++) {
    buffer[used++]=mpz_sgn(responses[i])<0 ? 1 : 0;
    mpz_abs(magnitude,responses[i]);
    if (!append_integer(buffer,capacity,&used,magnitude) ||
        !append_integer(buffer,capacity,&used,random_responses[i])) goto cleanup;
  }
  md_map_sh256(digest,buffer,used);
  memcpy(input,expansion,sizeof(expansion)-1);
  memcpy(input+sizeof(expansion)-1,digest,32);
  for (unsigned i=0;i<count;i++) order[i]=i+1;
  /* Partial Fisher-Yates with rejection: no biased modulo-only draws. */
  for (unsigned i=0;i<count/2;i++) {
    unsigned remaining=count-i, value, draw_limit=65536u-(65536u%remaining);
    do {
      if (cursor==32) {
        if (counter>=65536) goto cleanup;
        put32(input+sizeof(expansion)-1+32,counter++);
        md_map_sh256(block,input,sizeof(input)); cursor=0;
      }
      value=((unsigned)block[cursor]<<8)|block[cursor+1]; cursor+=2;
    } while (value>=draw_limit);
    unsigned at=i+value%remaining, temp=order[i];
    order[i]=order[at]; order[at]=temp; selected[order[i]-1]=1;
  }
  for (unsigned i=0,j=0;i<count;i++) if (selected[i]) indices[j++]=i+1;
  memcpy(digest_out,digest,32); valid=1;
cleanup:
  mpz_clear(magnitude); free(buffer);
  return valid;
}
