#include <stdlib.h>
#include <string.h>
#include "util.h"
#include "host_ledger.h"

struct host_ledger {
  unsigned n,level,initialized;
  host_asset_state state;
  int timed;
  host_schedule schedule;
  unsigned char withdrawal_signature[64];
  unsigned char lock_digest[32],owner[33];
  unsigned char digests[255*32],refund_digest[32];
  ec_t keys[128];
};

#define HOST_LEDGER_SNAPSHOT_FIXED 249u

static void put_u32(unsigned char *p,uint32_t value) {
  p[0]=(unsigned char)(value>>24); p[1]=(unsigned char)(value>>16);
  p[2]=(unsigned char)(value>>8); p[3]=(unsigned char)value;
}
static uint32_t get_u32(const unsigned char *p) {
  return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}
static void put_u64(unsigned char *p,uint64_t value) {
  for (unsigned i=0;i<8;i++) p[i]=(unsigned char)(value>>(56-8*i));
}
static uint64_t get_u64(const unsigned char *p) {
  uint64_t value=0;
  for (unsigned i=0;i<8;i++) value=(value<<8)|p[i];
  return value;
}

void host_ledger_destroy(host_ledger *ledger) {
  if (!ledger) return;
  for (unsigned i=0;i<ledger->initialized;i++) ec_free(ledger->keys[i]);
  free(ledger);
}

host_ledger *host_ledger_create(unsigned n, const unsigned char *digests,
    const ec_t *keys, const unsigned char refund_digest[32]) {
  host_ledger *ledger;
  int valid=0;
  if (n<3 || n>128 || !digests || !keys || !refund_digest) return NULL;
  ledger=calloc(1,sizeof(*ledger)); if (!ledger) return NULL;
  ledger->n=n; memcpy(ledger->digests,digests,(2*n-1)*32); memcpy(ledger->refund_digest,refund_digest,32);
  RLC_TRY {
    for (unsigned i=0;i<2*n-1;i++) {
      if (ec_is_infty(keys[i]) || !ec_on_curve(keys[i])) RLC_THROW(ERR_NO_VALID);
      for (unsigned j=0;j<i;j++)
        if (!memcmp(digests+32*i,digests+32*j,32)) RLC_THROW(ERR_NO_VALID);
      if (!memcmp(digests+32*i,refund_digest,32)) RLC_THROW(ERR_NO_VALID);
      if (i<n) {
        ec_null(ledger->keys[i]); ec_new(ledger->keys[i]); ledger->initialized++;
        ec_copy(ledger->keys[i],keys[i]);
      } else if (ec_cmp(keys[i],keys[i-n])!=RLC_EQ) RLC_THROW(ERR_NO_VALID);
    }
    valid=1;
  } RLC_CATCH_ANY { valid=0; }
  if (!valid) { host_ledger_destroy(ledger); return NULL; }
  return ledger;
}

static int verify_key(const ec_t public_key, unsigned char digest[32], schnorr_signature_t signature) {
  ec_public_key_t key;
  ec_t infinity;
  bn_t order;
  int valid=0;
  ec_public_key_null(key); ec_null(infinity); bn_null(order);
  RLC_TRY {
    ec_public_key_new(key); ec_new(infinity); ec_set_infty(infinity);
    bn_new(order); ec_curve_get_ord(order);
    if (bn_sign(signature->e)==RLC_NEG || bn_sign(signature->s)==RLC_NEG ||
        bn_cmp(signature->e,order)!=RLC_LT || bn_cmp(signature->s,order)!=RLC_LT)
      RLC_THROW(ERR_NO_VALID);
    ec_copy(key->pk,public_key);
    valid=adaptor_schnorr_preverify(signature,digest,32,infinity,key)==1;
  } RLC_CATCH_ANY { valid=0; }
  RLC_FINALLY { if (key!=NULL) ec_public_key_free(key); ec_free(infinity); bn_free(order); }
  return valid;
}

static int verify(host_ledger *ledger,unsigned char digest[32],schnorr_signature_t signature) {
  return verify_key(ledger->keys[ledger->level],digest,signature);
}

int host_ledger_lock_digest(unsigned char output[32],const unsigned char context[32],
    const ec_t owner,const ec_t destination,const unsigned char amount[32]) {
  static const unsigned char domain[]="OASIS-FIXTURE-LOCK-v1";
  unsigned char bytes[sizeof(domain)-1+32+33+33+32];
  unsigned nonzero=0;
  int valid=0;
  if (!output || !context || !amount) return 0;
  for (unsigned i=0;i<32;i++) nonzero|=amount[i];
  if (!nonzero) return 0;
  RLC_TRY {
    if (ec_is_infty(owner) || !ec_on_curve(owner) ||
        ec_is_infty(destination) || !ec_on_curve(destination)) RLC_THROW(ERR_NO_VALID);
    size_t offset=sizeof(domain)-1;
    memcpy(bytes,domain,offset); memcpy(bytes+offset,context,32); offset+=32;
    ec_write_bin(bytes+offset,33,owner,1); offset+=33;
    ec_write_bin(bytes+offset,33,destination,1); offset+=33;
    memcpy(bytes+offset,amount,32);
    md_map_sh256(output,bytes,sizeof(bytes)); valid=1;
  } RLC_CATCH_ANY { valid=0; }
  return valid;
}

host_ledger *host_ledger_create_unfunded(unsigned n,const unsigned char *digests,
    const ec_t *keys,const unsigned char refund_digest[32],
    uint64_t origin_ns,uint64_t delta_ns,uint64_t epsilon_ns,
    const unsigned char context[32],const ec_t owner,const unsigned char amount[32]) {
  host_ledger *ledger=host_ledger_create_timed(n,digests,keys,refund_digest,
      origin_ns,delta_ns,epsilon_ns);
  if (!ledger) return NULL;
  if (!host_ledger_lock_digest(ledger->lock_digest,context,owner,keys[0],amount)) {
    host_ledger_destroy(ledger); return NULL;
  }
  ec_write_bin(ledger->owner,33,owner,1);
  ledger->state=HOST_UNFUNDED;
  return ledger;
}

int host_ledger_lock_at(host_ledger *ledger,schnorr_signature_t signature,uint64_t now_ns) {
  ec_t owner;
  int valid=0;
  if (!ledger || !signature || !ledger->timed || ledger->state!=HOST_UNFUNDED ||
      !host_preswap_live(&ledger->schedule,now_ns)) return 0;
  ec_null(owner);
  RLC_TRY {
    ec_new(owner); ec_read_bin(owner,ledger->owner,33);
    valid=verify_key(owner,ledger->lock_digest,signature);
    if (valid) ledger->state=HOST_LOCKED;
  } RLC_CATCH_ANY { valid=0; }
  RLC_FINALLY { ec_free(owner); }
  return valid;
}

static int spend(host_ledger *ledger, unsigned ordinal, schnorr_signature_t signature) {
  if (!ledger || !signature || ledger->state!=HOST_LOCKED || ordinal>=2*ledger->n-1)
    return 0;
  unsigned level=ordinal<ledger->n ? ordinal : ordinal-ledger->n;
  if (level!=ledger->level || !verify(ledger,ledger->digests+32*ordinal,signature)) return 0;
  if (ordinal<ledger->n) {
    bn_write_bin(ledger->withdrawal_signature,32,signature->e);
    bn_write_bin(ledger->withdrawal_signature+32,32,signature->s);
    ledger->state=HOST_WITHDRAWN;
  }
  else ledger->level++;
  return 1;
}

static int refund(host_ledger *ledger, schnorr_signature_t signature) {
  if (!ledger || !signature || ledger->state!=HOST_LOCKED || ledger->level!=ledger->n-1 ||
      !verify(ledger,ledger->refund_digest,signature)) return 0;
  ledger->state=HOST_REFUNDED; return 1;
}

host_ledger *host_ledger_create_timed(unsigned n,const unsigned char *digests,
    const ec_t *keys,const unsigned char refund_digest[32],
    uint64_t origin_ns,uint64_t delta_ns,uint64_t epsilon_ns) {
  host_schedule schedule;
  if (!host_schedule_init(&schedule,n,origin_ns,delta_ns,epsilon_ns)) return NULL;
  host_ledger *ledger=host_ledger_create(n,digests,keys,refund_digest);
  if (ledger) { ledger->timed=1; ledger->schedule=schedule; }
  return ledger;
}

size_t host_ledger_snapshot_size(const host_ledger *ledger) {
  if (!ledger || ledger->n<3 || ledger->n>128) return 0;
  return HOST_LEDGER_SNAPSHOT_FIXED+(size_t)(2*ledger->n-1)*32u+(size_t)ledger->n*33u;
}

int host_ledger_snapshot_encode(const host_ledger *ledger,
    unsigned char *output,size_t output_size) {
  size_t expected=host_ledger_snapshot_size(ledger),offset=0;
  unsigned char digest[32];
  if (!expected || !output || output_size!=expected) return 0;
  memset(output,0,output_size);
  memcpy(output+offset,"OASISL01",8); offset+=8;
  put_u32(output+offset,ledger->n); offset+=4;
  put_u32(output+offset,ledger->level); offset+=4;
  output[offset++]=(unsigned char)ledger->state;
  output[offset++]=(unsigned char)(ledger->timed ? 1 : 0);
  offset+=6;
  put_u64(output+offset,ledger->schedule.origin_ns); offset+=8;
  put_u64(output+offset,ledger->schedule.delta_ns); offset+=8;
  put_u64(output+offset,ledger->schedule.preswap_window_ns); offset+=8;
  put_u64(output+offset,ledger->schedule.refund_ns); offset+=8;
  memcpy(output+offset,ledger->withdrawal_signature,64); offset+=64;
  memcpy(output+offset,ledger->lock_digest,32); offset+=32;
  memcpy(output+offset,ledger->owner,33); offset+=33;
  memcpy(output+offset,ledger->refund_digest,32); offset+=32;
  memcpy(output+offset,ledger->digests,(2*ledger->n-1)*32u); offset+=(2*ledger->n-1)*32u;
  for (unsigned i=0;i<ledger->n;i++) {
    ec_write_bin(output+offset,33,ledger->keys[i],1); offset+=33;
  }
  if (offset+32!=output_size) return 0;
  md_map_sh256(digest,output,offset); memcpy(output+offset,digest,32);
  memzero(digest,sizeof(digest));
  return 1;
}

host_ledger *host_ledger_snapshot_decode(const unsigned char *input,size_t input_size) {
  host_ledger *ledger=NULL;
  schnorr_signature_t signature;
  ec_t keys[255];
  unsigned initialized=0,n,level;
  host_asset_state state;
  int timed,valid=0;
  size_t offset=0,expected;
  unsigned char digest[32];
  if (!input || input_size<HOST_LEDGER_SNAPSHOT_FIXED || memcmp(input,"OASISL01",8)) return NULL;
  offset=8; n=get_u32(input+offset); offset+=4; level=get_u32(input+offset); offset+=4;
  state=(host_asset_state)input[offset++]; timed=input[offset++];
  for (unsigned i=0;i<6;i++) if (input[offset+i]!=0) return NULL;
  offset+=6;
  expected=HOST_LEDGER_SNAPSHOT_FIXED+(size_t)(2*n-1)*32u+(size_t)n*33u;
  if (n<3 || n>128 || input_size!=expected || level>=n ||
      state<HOST_LOCKED || state>HOST_UNFUNDED || (timed!=0 && timed!=1)) return NULL;
  md_map_sh256(digest,input,input_size-32);
  if (memcmp(digest,input+input_size-32,32)) { memzero(digest,sizeof(digest)); return NULL; }
  memzero(digest,sizeof(digest));
  uint64_t origin=get_u64(input+offset); offset+=8;
  uint64_t delta=get_u64(input+offset); offset+=8;
  uint64_t preswap=get_u64(input+offset); offset+=8;
  uint64_t refund_ns=get_u64(input+offset); offset+=8;
  const unsigned char *withdrawal=input+offset; offset+=64;
  const unsigned char *lock=input+offset; offset+=32;
  const unsigned char *owner=input+offset; offset+=33;
  const unsigned char *refund_digest=input+offset; offset+=32;
  const unsigned char *digests=input+offset; offset+=(2*n-1)*32u;
  schnorr_signature_null(signature);
  RLC_TRY {
    for (unsigned i=0;i<2*n-1;i++) {
      ec_null(keys[i]); ec_new(keys[i]); initialized++;
      unsigned source=i<n ? i : i-n;
      ec_read_bin(keys[i],input+offset+33u*source,33);
    }
    ledger=host_ledger_create(n,digests,keys,refund_digest);
    if (!ledger) RLC_THROW(ERR_NO_VALID);
    ledger->level=level; ledger->state=state; ledger->timed=timed;
    ledger->schedule.participants=n;
    ledger->schedule.origin_ns=origin; ledger->schedule.delta_ns=delta;
    ledger->schedule.preswap_window_ns=preswap; ledger->schedule.refund_ns=refund_ns;
    memcpy(ledger->withdrawal_signature,withdrawal,64);
    memcpy(ledger->lock_digest,lock,32); memcpy(ledger->owner,owner,33);
    if (state==HOST_WITHDRAWN) {
      schnorr_signature_new(signature);
      bn_read_bin(signature->e,withdrawal,32);
      bn_read_bin(signature->s,withdrawal+32,32);
      if (!verify(ledger,ledger->digests+32*level,signature)) RLC_THROW(ERR_NO_VALID);
    } else {
      for (unsigned i=0;i<64;i++) if (withdrawal[i]) RLC_THROW(ERR_NO_VALID);
    }
    if ((state==HOST_UNFUNDED && level!=0) ||
        (state==HOST_REFUNDED && level!=n-1)) RLC_THROW(ERR_NO_VALID);
    if (timed) {
      host_schedule check;
      uint64_t epsilon;
      if (preswap<delta || (preswap-delta)%3u) RLC_THROW(ERR_NO_VALID);
      epsilon=(preswap-delta)/3u;
      if (!host_schedule_init(&check,n,origin,delta,epsilon) ||
          check.preswap_window_ns!=preswap || check.refund_ns!=refund_ns)
        RLC_THROW(ERR_NO_VALID);
    }
    valid=1;
  } RLC_CATCH_ANY { valid=0; }
  RLC_FINALLY {
    if (signature!=NULL) schnorr_signature_free(signature);
    for (unsigned i=0;i<initialized;i++) ec_free(keys[i]);
  }
  if (!valid) { host_ledger_destroy(ledger); return NULL; }
  return ledger;
}

int host_ledger_spend(host_ledger *ledger,unsigned ordinal,schnorr_signature_t signature) {
  return ledger && !ledger->timed && spend(ledger,ordinal,signature);
}

int host_ledger_refund(host_ledger *ledger,schnorr_signature_t signature) {
  return ledger && !ledger->timed && refund(ledger,signature);
}

int host_ledger_spend_at(host_ledger *ledger,unsigned ordinal,
    schnorr_signature_t signature,uint64_t now_ns) {
  if (!ledger || !ledger->timed || ordinal>=2*ledger->n-1 ||
      now_ns<ledger->schedule.origin_ns) return 0;
  if (ordinal>=ledger->n &&
      !host_relock_ready(&ledger->schedule,ordinal-ledger->n+1,now_ns)) return 0;
  return spend(ledger,ordinal,signature);
}

int host_ledger_refund_at(host_ledger *ledger,schnorr_signature_t signature,uint64_t now_ns) {
  return ledger && ledger->timed && host_refund_ready(&ledger->schedule,now_ns) &&
         refund(ledger,signature);
}

host_asset_state host_ledger_state(const host_ledger *ledger) { return ledger->state; }
unsigned host_ledger_level(const host_ledger *ledger) { return ledger->level; }

int host_ledger_extract_withdrawal(const host_ledger *ledger,
    schnorr_signature_t presignature,const ec_t statement,bn_t output) {
  bn_t order,challenge,scalar,witness;
  ec_t point;
  ec_public_key_t key;
  unsigned char digest[32];
  int valid=0;
  if (!ledger || ledger->state!=HOST_WITHDRAWN || !presignature) return 0;
  bn_null(order); bn_null(challenge); bn_null(scalar); bn_null(witness);
  ec_null(point); ec_public_key_null(key);
  RLC_TRY {
    bn_new(order); bn_new(challenge); bn_new(scalar); bn_new(witness);
    ec_new(point); ec_public_key_new(key); ec_curve_get_ord(order);
    if (bn_sign(presignature->e)==RLC_NEG || bn_sign(presignature->s)==RLC_NEG ||
        bn_cmp(presignature->e,order)!=RLC_LT || bn_cmp(presignature->s,order)!=RLC_LT ||
        ec_is_infty(statement) || !ec_on_curve(statement)) RLC_THROW(ERR_NO_VALID);
    bn_read_bin(challenge,ledger->withdrawal_signature,32);
    bn_read_bin(scalar,ledger->withdrawal_signature+32,32);
    if (bn_cmp(challenge,presignature->e)!=RLC_EQ) RLC_THROW(ERR_NO_VALID);
    memcpy(digest,ledger->digests+32*ledger->level,32);
    ec_copy(key->pk,ledger->keys[ledger->level]);
    if (adaptor_schnorr_preverify(presignature,digest,32,statement,key)!=1)
      RLC_THROW(ERR_NO_VALID);
    bn_sub(witness,scalar,presignature->s); bn_mod(witness,witness,order);
    ec_mul_gen(point,witness);
    if (bn_is_zero(witness) || ec_cmp(point,statement)!=RLC_EQ) RLC_THROW(ERR_NO_VALID);
    bn_copy(output,witness); valid=1;
  } RLC_CATCH_ANY { valid=0; }
  RLC_FINALLY {
    if (witness!=NULL) bn_zero(witness);
    bn_free(order); bn_free(challenge); bn_free(scalar); bn_free(witness);
    ec_free(point); if (key!=NULL) ec_public_key_free(key);
  }
  return valid;
}
