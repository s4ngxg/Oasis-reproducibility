#include <stdlib.h>
#include <string.h>
#include "host_witness.h"

struct host_witness_state {
  unsigned count,initialized,received;
  unsigned char context[32],present[128];
  ec_t expected[128];
  bn_t values[128];
};

void host_witness_destroy(host_witness_state *state) {
  if (!state) return;
  for (unsigned i=0;i<state->initialized;i++) {
    if (state->values[i]!=NULL) bn_zero(state->values[i]);
    bn_free(state->values[i]); ec_free(state->expected[i]);
  }
  free(state);
}

host_witness_state *host_witness_create(unsigned participants,
    const ec_t *public_witnesses, const unsigned char context[32]) {
  host_witness_state *state;
  int valid=0;
  if (!public_witnesses || !context || participants<3 || participants>128) return NULL;
  state=calloc(1,sizeof(*state)); if (!state) return NULL;
  state->count=participants; memcpy(state->context,context,32);
  RLC_TRY {
    for (unsigned i=0;i<participants;i++) {
      ec_null(state->expected[i]); bn_null(state->values[i]); state->initialized++;
      ec_new(state->expected[i]); bn_new(state->values[i]);
      if (ec_is_infty(public_witnesses[i]) || !ec_on_curve(public_witnesses[i]))
        RLC_THROW(ERR_NO_VALID);
      ec_copy(state->expected[i],public_witnesses[i]);
    }
    valid=1;
  } RLC_CATCH_ANY { valid=0; }
  if (!valid) { host_witness_destroy(state); return NULL; }
  return state;
}

int host_witness_receive(host_witness_state *state, unsigned participant,
    const unsigned char context[32], const bn_t witness) {
  bn_t order;
  ec_t computed;
  int valid=0;
  if (!state || !context || participant>=state->count || memcmp(state->context,context,32))
    return 0;
  bn_null(order); ec_null(computed);
  RLC_TRY {
    bn_new(order); ec_new(computed); ec_curve_get_ord(order);
    if (bn_sign(witness)==RLC_NEG || bn_is_zero(witness) || bn_cmp(witness,order)!=RLC_LT)
      RLC_THROW(ERR_NO_VALID);
    ec_mul_gen(computed,witness);
    if (ec_cmp(computed,state->expected[participant])!=RLC_EQ) RLC_THROW(ERR_NO_VALID);
    if (state->present[participant]) valid=bn_cmp(witness,state->values[participant])==RLC_EQ;
    else {
      bn_copy(state->values[participant],witness);
      state->present[participant]=1; state->received++; valid=1;
    }
  } RLC_CATCH_ANY { valid=0; }
  RLC_FINALLY { bn_free(order); ec_free(computed); }
  return valid;
}

int host_witness_global(const host_witness_state *state, bn_t output) {
  bn_t order,sum;
  int valid=0;
  if (!state || state->received!=state->count) return 0;
  bn_null(order); bn_null(sum);
  RLC_TRY {
    bn_new(order); bn_new(sum); ec_curve_get_ord(order); bn_zero(sum);
    for (unsigned i=0;i<state->count;i++) {
      if (!state->present[i]) RLC_THROW(ERR_NO_VALID);
      bn_add(sum,sum,state->values[i]); bn_mod(sum,sum,order);
    }
    bn_copy(output,sum); valid=1;
  } RLC_CATCH_ANY { valid=0; }
  RLC_FINALLY {
    if (sum!=NULL) bn_zero(sum);
    bn_free(order); bn_free(sum);
  }
  return valid;
}

int host_witness_withdraw(const host_witness_state *state,
    const bn_t *identifiers,unsigned prefix_count,const ec_t expected,bn_t output) {
  bn_t sum,order;
  ec_t point;
  int valid=0;
  if (!state || !identifiers || !prefix_count || prefix_count>state->count) return 0;
  bn_null(sum); bn_null(order); ec_null(point);
  RLC_TRY {
    bn_new(sum); bn_new(order); ec_new(point); ec_curve_get_ord(order);
    if (!host_witness_global(state,sum) || ec_is_infty(expected) || !ec_on_curve(expected))
      RLC_THROW(ERR_NO_VALID);
    for (unsigned i=0;i<prefix_count;i++) {
      if (bn_sign(identifiers[i])==RLC_NEG || bn_is_zero(identifiers[i]) ||
          bn_cmp(identifiers[i],order)!=RLC_LT) RLC_THROW(ERR_NO_VALID);
      bn_add(sum,sum,identifiers[i]); bn_mod(sum,sum,order);
    }
    if (bn_is_zero(sum)) RLC_THROW(ERR_NO_VALID);
    ec_mul_gen(point,sum);
    if (ec_cmp(point,expected)!=RLC_EQ) RLC_THROW(ERR_NO_VALID);
    bn_copy(output,sum); valid=1;
  } RLC_CATCH_ANY { valid=0; }
  RLC_FINALLY {
    if (sum!=NULL) bn_zero(sum);
    bn_free(sum); bn_free(order); ec_free(point);
  }
  return valid;
}

int host_witness_advance(const bn_t extracted,const ec_t source_statement,
    const bn_t local_identifier,const ec_t destination_statement,bn_t output) {
  bn_t order,sum;
  ec_t point;
  int valid=0;
  bn_null(order); bn_null(sum); ec_null(point);
  RLC_TRY {
    bn_new(order); bn_new(sum); ec_new(point); ec_curve_get_ord(order);
    if (bn_sign(extracted)==RLC_NEG || bn_is_zero(extracted) || bn_cmp(extracted,order)!=RLC_LT ||
        bn_sign(local_identifier)==RLC_NEG || bn_is_zero(local_identifier) ||
        bn_cmp(local_identifier,order)!=RLC_LT || ec_is_infty(source_statement) ||
        ec_is_infty(destination_statement) || !ec_on_curve(source_statement) ||
        !ec_on_curve(destination_statement)) RLC_THROW(ERR_NO_VALID);
    ec_mul_gen(point,extracted);
    if (ec_cmp(point,source_statement)!=RLC_EQ) RLC_THROW(ERR_NO_VALID);
    bn_add(sum,extracted,local_identifier); bn_mod(sum,sum,order);
    if (bn_is_zero(sum)) RLC_THROW(ERR_NO_VALID);
    ec_mul_gen(point,sum);
    if (ec_cmp(point,destination_statement)!=RLC_EQ) RLC_THROW(ERR_NO_VALID);
    bn_copy(output,sum); valid=1;
  } RLC_CATCH_ANY { valid=0; }
  RLC_FINALLY {
    if (sum!=NULL) bn_zero(sum);
    bn_free(sum); bn_free(order); ec_free(point);
  }
  return valid;
}

int host_witness_encode(unsigned char *output, size_t length, unsigned participant,
    const unsigned char context[32], const bn_t witness) {
  bn_t order;
  unsigned char encoded[HOST_WITNESS_FRAME_BYTES] = {0};
  int valid=0;
  if (!output || !context || length!=sizeof(encoded) || participant>=128) return 0;
  bn_null(order);
  RLC_TRY {
    bn_new(order); ec_curve_get_ord(order);
    if (bn_sign(witness)==RLC_NEG || bn_is_zero(witness) || bn_cmp(witness,order)!=RLC_LT)
      RLC_THROW(ERR_NO_VALID);
    memcpy(encoded,"OASISY01",8); memcpy(encoded+8,context,32);
    encoded[43]=(unsigned char)participant;
    bn_write_bin(encoded+44,32,witness);
    memcpy(output,encoded,sizeof(encoded)); valid=1;
  } RLC_CATCH_ANY { valid=0; }
  RLC_FINALLY {
    volatile unsigned char *wipe=encoded;
    for (size_t i=0;i<sizeof(encoded);i++) wipe[i]=0;
    bn_free(order);
  }
  return valid;
}

int host_witness_receive_authenticated(host_witness_state *state,const char *identity,
    const unsigned char *frame,size_t length) {
  static const char prefix[]="participant:";
  unsigned index=0,digits=0;
  if (!state || !identity || strncmp(identity,prefix,sizeof(prefix)-1)) return 0;
  const char *number=identity+sizeof(prefix)-1;
  if (!*number || (*number=='0' && number[1])) return 0;
  for (const char *p=number;*p;p++) {
    if (++digits>3 || *p<'0' || *p>'9') return 0;
    index=10*index+(unsigned)(*p-'0');
  }
  return host_witness_receive_frame(state,index,frame,length);
}

int host_witness_receive_frame(host_witness_state *state,
    unsigned authenticated_participant, const unsigned char *frame, size_t length) {
  bn_t witness;
  int valid=0;
  if (!state || !frame || length!=HOST_WITNESS_FRAME_BYTES ||
      authenticated_participant>=state->count || memcmp(frame,"OASISY01",8) ||
      frame[40] || frame[41] || frame[42] || frame[43]!=authenticated_participant ||
      memcmp(frame+8,state->context,32)) return 0;
  bn_null(witness);
  RLC_TRY {
    bn_new(witness); bn_read_bin(witness,frame+44,32);
    valid=host_witness_receive(state,authenticated_participant,frame+8,witness);
  } RLC_CATCH_ANY { valid=0; }
  RLC_FINALLY {
    if (witness!=NULL) bn_zero(witness);
    bn_free(witness);
  }
  return valid;
}
