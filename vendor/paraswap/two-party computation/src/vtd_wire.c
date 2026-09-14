#include <string.h>
#include "vtd_wire.h"

typedef struct { unsigned char *write; const unsigned char *read; size_t size,pos; } cursor;

static int transfer(cursor *c, unsigned char *value, size_t length) {
  if (c->pos>c->size || length>c->size-c->pos) return 0;
  if (c->write) memcpy(c->write+c->pos,value,length);
  else memcpy(value,c->read+c->pos,length);
  c->pos+=length; return 1;
}

static int number(cursor *c, mpz_t value, int signed_value) {
  unsigned char prefix[4],sign=0,bytes[4096];
  size_t size=0,exported=0;
  if (c->write) {
    sign=mpz_sgn(value)<0;
    if (sign && !signed_value) return 0;
    size=mpz_sgn(value) ? (mpz_sizeinbase(value,2)+7)/8 : 0;
    if (size>sizeof(bytes)) return 0;
    for (unsigned i=0;i<4;i++) prefix[i]=(unsigned char)(size>>(24-8*i));
  }
  if (signed_value && (!transfer(c,&sign,1) || sign>1)) return 0;
  if (!transfer(c,prefix,4)) return 0;
  if (!c->write) {
    for (unsigned i=0;i<4;i++) size=(size<<8)|prefix[i];
    if (size>sizeof(bytes)) return 0;
  }
  if (c->write && size) mpz_export(bytes,&exported,1,1,0,0,value);
  if (c->write && exported!=size) return 0;
  if (!transfer(c,bytes,size)) return 0;
  if (!c->write) {
    if ((size && bytes[0]==0) || (!size && sign)) return 0;
    mpz_import(value,size,1,1,0,0,bytes);
    if (sign) mpz_neg(value,value);
  }
  return 1;
}

int vtd_setup_encode(unsigned char *buffer,size_t capacity,size_t *written,
    const mpz_t n,const mpz_t g,const mpz_t h,const mpz_t limit) {
  unsigned char magic[8]={'O','A','S','I','S','P','A','1'};
  cursor c={buffer,NULL,capacity,0};
  if (!written) return 0;
  *written=0;
  if (!buffer || capacity>VTD_WIRE_MAX_BYTES || !transfer(&c,magic,8) ||
      !number(&c,(mpz_ptr)n,0) || !number(&c,(mpz_ptr)g,0) ||
      !number(&c,(mpz_ptr)h,0) || !number(&c,(mpz_ptr)limit,0)) return 0;
  *written=c.pos; return 1;
}

int vtd_setup_decode(mpz_t n,mpz_t g,mpz_t h,mpz_t limit,
    const unsigned char *buffer,size_t length) {
  unsigned char magic[8];
  cursor c={NULL,buffer,length,0};
  mpz_t values[4];
  int valid=0;
  if (!buffer || length>VTD_WIRE_MAX_BYTES) return 0;
  for (unsigned i=0;i<4;i++) mpz_init(values[i]);
  if (transfer(&c,magic,8) && !memcmp(magic,"OASISPA1",8) &&
      number(&c,values[0],0) && number(&c,values[1],0) &&
      number(&c,values[2],0) && number(&c,values[3],0) && c.pos==length) {
    mpz_set(n,values[0]); mpz_set(g,values[1]);
    mpz_set(h,values[2]); mpz_set(limit,values[3]); valid=1;
  }
  for (unsigned i=0;i<4;i++) mpz_clear(values[i]);
  return valid;
}

static int dimensions(unsigned count, unsigned rows) {
  return count>=2 && count<=256 && count%2==0 && rows>=128 && rows<=256;
}

static int header(cursor *c, unsigned count, unsigned rows) {
  unsigned char expected[16]={'O','A','S','I','S','V','0','1'},actual[16];
  for (unsigned i=0;i<4;i++) {
    expected[8+i]=(unsigned char)(count>>(24-8*i));
    expected[12+i]=(unsigned char)(rows>>(24-8*i));
  }
  memcpy(actual,expected,16);
  return transfer(c,actual,16) && !memcmp(actual,expected,16);
}

int vtd_proof_encode(unsigned char *buffer, size_t capacity, size_t *written,
                       const vtd_proof_view *p) {
  cursor c={buffer,NULL,capacity,0};
  int valid=0;
  if (!written) return 0;
  *written=0;
  if (!buffer || !p || !dimensions(p->count,p->rows) || capacity>VTD_WIRE_MAX_BYTES ||
      !p->points || !p->puzzle_u || !p->puzzle_v || !p->commitment_u || !p->commitment_v ||
      !p->responses || !p->random_responses || !p->opened_values || !p->opened_exponents)
    return 0;
  RLC_TRY {
    if (!header(&c,p->count,p->rows)) RLC_THROW(ERR_NO_VALID);
    for (unsigned i=0;i<p->count;i++) {
      unsigned char point[33]={0};
      if (!ec_is_infty(p->points[i])) {
        if (!ec_on_curve(p->points[i])) RLC_THROW(ERR_NO_VALID);
        ec_write_bin(point,33,p->points[i],1);
      }
      if (!transfer(&c,point,33) || !number(&c,(mpz_ptr)p->puzzle_u[i],0) ||
          !number(&c,(mpz_ptr)p->puzzle_v[i],0)) RLC_THROW(ERR_NO_VALID);
    }
    for (unsigned i=0;i<p->rows;i++)
      if (!number(&c,(mpz_ptr)p->commitment_u[i],0) || !number(&c,(mpz_ptr)p->commitment_v[i],0) ||
          !number(&c,(mpz_ptr)p->responses[i],1) || !number(&c,(mpz_ptr)p->random_responses[i],0))
        RLC_THROW(ERR_NO_VALID);
    for (unsigned i=0;i<p->count/2;i++)
      if (!number(&c,(mpz_ptr)p->opened_values[i],0) || !number(&c,(mpz_ptr)p->opened_exponents[i],0))
        RLC_THROW(ERR_NO_VALID);
    *written=c.pos; valid=1;
  } RLC_CATCH_ANY { valid=0; }
  return valid;
}

int vtd_proof_decode(vtd_proof_output *p, const unsigned char *buffer, size_t length) {
  cursor c={NULL,buffer,length,0};
  int valid=0;
  if (!p || !dimensions(p->count,p->rows) || !p->points || !p->puzzle_u || !p->puzzle_v ||
      !p->commitment_u || !p->commitment_v || !p->responses || !p->random_responses ||
      !p->opened_values || !p->opened_exponents) return 0;
  RLC_TRY {
    if (!buffer || length>VTD_WIRE_MAX_BYTES || !header(&c,p->count,p->rows)) RLC_THROW(ERR_NO_VALID);
    for (unsigned i=0;i<p->count;i++) {
      unsigned char point[33],canonical[33]={0};
      if (!transfer(&c,point,33)) RLC_THROW(ERR_NO_VALID);
      if (!memcmp(point,canonical,33)) ec_set_infty(p->points[i]);
      else {
        if (point[0]!=2 && point[0]!=3) RLC_THROW(ERR_NO_VALID);
        ec_read_bin(p->points[i],point,33);
        if (ec_is_infty(p->points[i]) || !ec_on_curve(p->points[i])) RLC_THROW(ERR_NO_VALID);
        ec_write_bin(canonical,33,p->points[i],1);
        if (memcmp(point,canonical,33)) RLC_THROW(ERR_NO_VALID);
      }
      if (!number(&c,p->puzzle_u[i],0) || !number(&c,p->puzzle_v[i],0)) RLC_THROW(ERR_NO_VALID);
    }
    for (unsigned i=0;i<p->rows;i++)
      if (!number(&c,p->commitment_u[i],0) || !number(&c,p->commitment_v[i],0) ||
          !number(&c,p->responses[i],1) || !number(&c,p->random_responses[i],0)) RLC_THROW(ERR_NO_VALID);
    for (unsigned i=0;i<p->count/2;i++)
      if (!number(&c,p->opened_values[i],0) || !number(&c,p->opened_exponents[i],0)) RLC_THROW(ERR_NO_VALID);
    if (c.pos!=length) RLC_THROW(ERR_NO_VALID);
    valid=1;
  } RLC_CATCH_ANY { valid=0; }
  if (!valid) {
    for (unsigned i=0;i<p->count;i++) {
      ec_set_infty(p->points[i]); mpz_set_ui(p->puzzle_u[i],0); mpz_set_ui(p->puzzle_v[i],0);
    }
    for (unsigned i=0;i<p->rows;i++) {
      mpz_set_ui(p->commitment_u[i],0); mpz_set_ui(p->commitment_v[i],0);
      mpz_set_ui(p->responses[i],0); mpz_set_ui(p->random_responses[i],0);
    }
    for (unsigned i=0;i<p->count/2;i++) {
      mpz_set_ui(p->opened_values[i],0); mpz_set_ui(p->opened_exponents[i],0);
    }
  }
  return valid;
}
