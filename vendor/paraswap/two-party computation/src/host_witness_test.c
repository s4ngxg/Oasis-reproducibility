#include <stdio.h>
#include <string.h>
#include "util.h"
#include "host_witness.h"
int main(void) {
  bn_t witnesses[3],result,bad;
  ec_t points[3],withdrawal;
  host_witness_state *state=NULL;
  host_witness_state *wire_state=NULL;
  unsigned char frame[HOST_WITNESS_FRAME_BYTES+1]={0};
  unsigned char context[32]={0},wrong[32]={1};
  unsigned initialized=0;
  int status=1;
  if (init()!=RLC_OK) return 1;
  bn_null(result); bn_null(bad); ec_null(withdrawal);
  RLC_TRY {
    bn_new(result); bn_new(bad); bn_set_dig(result,42); bn_set_dig(bad,99);
    ec_new(withdrawal); bn_set_dig(bad,9); ec_mul_gen(withdrawal,bad); bn_set_dig(bad,99);
    for (unsigned i=0;i<3;i++) {
      bn_null(witnesses[i]); ec_null(points[i]); bn_new(witnesses[i]); ec_new(points[i]); initialized++;
      bn_set_dig(witnesses[i],i+1); ec_mul_gen(points[i],witnesses[i]);
    }
    state=host_witness_create(3,(const ec_t *)points,context);
    if (!state || host_witness_global(state,result) || bn_cmp_dig(result,42)!=RLC_EQ)
      RLC_THROW(ERR_NO_VALID);
    if (host_witness_withdraw(state,(const bn_t *)witnesses,2,withdrawal,result) ||
        bn_cmp_dig(result,42)!=RLC_EQ) RLC_THROW(ERR_NO_VALID);
    if (host_witness_receive(state,0,wrong,witnesses[0]) ||
        host_witness_receive(state,3,context,witnesses[0]) ||
        host_witness_receive(state,0,context,bad)) RLC_THROW(ERR_NO_VALID);
    if (!host_witness_receive(state,2,context,witnesses[2]) ||
        !host_witness_receive(state,0,context,witnesses[0]) ||
        !host_witness_receive(state,0,context,witnesses[0])) RLC_THROW(ERR_NO_VALID);
    if (host_witness_global(state,result) || bn_cmp_dig(result,42)!=RLC_EQ)
      RLC_THROW(ERR_NO_VALID);
    if (!host_witness_receive(state,1,context,witnesses[1]) ||
        !host_witness_global(state,result) || bn_cmp_dig(result,6)!=RLC_EQ) RLC_THROW(ERR_NO_VALID);
    if (host_witness_receive(state,1,context,bad) || !host_witness_global(state,result) ||
        bn_cmp_dig(result,6)!=RLC_EQ) RLC_THROW(ERR_NO_VALID);
    wire_state=host_witness_create(3,(const ec_t *)points,context);
    if (!wire_state || !host_witness_encode(frame,HOST_WITNESS_FRAME_BYTES,0,context,witnesses[0]))
      RLC_THROW(ERR_NO_VALID);
    if (memcmp(frame,"OASISY01",8) || memcmp(frame+8,context,32) || frame[75]!=1)
      RLC_THROW(ERR_NO_VALID);
    const char *bad_identities[]={NULL,"","participant:","participant:00",
      "participant:+0","participant:-0","participant:0x0","participant:0 ",
      "participant:128","participant:999999999999999999","participant:1","initiator"};
    for (unsigned i=0;i<sizeof(bad_identities)/sizeof(bad_identities[0]);i++)
      if (host_witness_receive_authenticated(wire_state,bad_identities[i],frame,
                                            HOST_WITNESS_FRAME_BYTES)) RLC_THROW(ERR_NO_VALID);
    if (!host_witness_receive_authenticated(wire_state,"participant:0",frame,
                                           HOST_WITNESS_FRAME_BYTES)) RLC_THROW(ERR_NO_VALID);
    for (unsigned i=40;i<75;i++) if (frame[i]) RLC_THROW(ERR_NO_VALID);
    for (unsigned size=0;size<HOST_WITNESS_FRAME_BYTES;size++)
      if (host_witness_receive_frame(wire_state,0,frame,size)) RLC_THROW(ERR_NO_VALID);
    if (host_witness_receive_frame(wire_state,0,frame,sizeof(frame)) ||
        host_witness_receive_frame(wire_state,1,frame,HOST_WITNESS_FRAME_BYTES))
      RLC_THROW(ERR_NO_VALID);
    for (unsigned i=0;i<HOST_WITNESS_FRAME_BYTES;i++) {
      frame[i]^=1;
      if (host_witness_receive_frame(wire_state,0,frame,HOST_WITNESS_FRAME_BYTES))
        RLC_THROW(ERR_NO_VALID);
      frame[i]^=1;
    }
    if (host_witness_global(wire_state,result)) RLC_THROW(ERR_NO_VALID);
    for (unsigned i=0;i<3;i++) {
      if (!host_witness_encode(frame,HOST_WITNESS_FRAME_BYTES,i,context,witnesses[i]) ||
          !host_witness_receive_frame(wire_state,i,frame,HOST_WITNESS_FRAME_BYTES) ||
          !host_witness_receive_frame(wire_state,i,frame,HOST_WITNESS_FRAME_BYTES))
        RLC_THROW(ERR_NO_VALID);
      if (i<2 && host_witness_global(wire_state,result)) RLC_THROW(ERR_NO_VALID);
    }
    if (!host_witness_global(wire_state,result) || bn_cmp_dig(result,6)!=RLC_EQ)
      RLC_THROW(ERR_NO_VALID);
    /* Extracted 1 plus local identifier 2 yields the next statement 3G.
     * No complete witness state is passed to this recovery operation. */
    bn_set_dig(result,42);
    if (!host_witness_advance(witnesses[0],points[0],witnesses[1],points[2],result) ||
        bn_cmp_dig(result,3)!=RLC_EQ ||
        host_witness_advance(witnesses[0],points[1],witnesses[1],points[2],result) ||
        host_witness_advance(witnesses[0],points[0],witnesses[1],points[1],result) ||
        bn_cmp_dig(result,3)!=RLC_EQ) RLC_THROW(ERR_NO_VALID);
    if (!host_witness_withdraw(wire_state,(const bn_t *)witnesses,2,withdrawal,result) ||
        bn_cmp_dig(result,9)!=RLC_EQ ||
        host_witness_withdraw(wire_state,(const bn_t *)witnesses,1,withdrawal,result) ||
        host_witness_withdraw(wire_state,(const bn_t *)witnesses,0,withdrawal,result) ||
        host_witness_withdraw(wire_state,(const bn_t *)witnesses,4,withdrawal,result) ||
        host_witness_withdraw(wire_state,(const bn_t *)witnesses,2,points[0],result) ||
        bn_cmp_dig(result,9)!=RLC_EQ) RLC_THROW(ERR_NO_VALID);
    puts("{\"witness_points_verified\":true,\"incomplete_export_rejected\":true,"
         "\"duplicate_idempotent\":true,\"context_bound\":true,"
         "\"canonical_frames_and_peer_binding\":true,\"withdrawal_composition\":true,"
         "\"extracted_witness_advancement\":true}"); status=0;
  } RLC_CATCH_ANY { status=1; }
  RLC_FINALLY {
    host_witness_destroy(state);
    host_witness_destroy(wire_state); memzero(frame,sizeof(frame));
    for (unsigned i=0;i<initialized;i++) { bn_zero(witnesses[i]); bn_free(witnesses[i]); ec_free(points[i]); }
    if (result!=NULL) bn_zero(result);
    bn_free(result); bn_free(bad); ec_free(withdrawal);
  }
  clean(); return status;
}
