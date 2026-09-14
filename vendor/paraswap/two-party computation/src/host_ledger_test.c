#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"
#include "host_ledger.h"
#include "host_refund.h"

static host_ledger *roundtrip(host_ledger *ledger,int corrupt_test) {
  size_t size=host_ledger_snapshot_size(ledger);
  unsigned char *snapshot=size ? malloc(size) : NULL;
  host_ledger *restored=NULL;
  if (!snapshot || !host_ledger_snapshot_encode(ledger,snapshot,size)) {
    free(snapshot); return NULL;
  }
  if (corrupt_test) {
    snapshot[20]^=1;
    host_ledger *bad=host_ledger_snapshot_decode(snapshot,size);
    snapshot[20]^=1;
    if (bad) { host_ledger_destroy(bad); free(snapshot); return NULL; }
    /* A valid checksum must not make reserved-byte variants canonical. */
    for (unsigned i=18;i<24;i++) {
      snapshot[i]=1;
      md_map_sh256(snapshot+size-32,snapshot,size-32);
      bad=host_ledger_snapshot_decode(snapshot,size);
      snapshot[i]=0;
      if (bad) { host_ledger_destroy(bad); free(snapshot); return NULL; }
    }
    md_map_sh256(snapshot+size-32,snapshot,size-32);
    unsigned char old_state=snapshot[16];
    snapshot[16]=(unsigned char)HOST_WITHDRAWN;
    md_map_sh256(snapshot+size-32,snapshot,size-32);
    bad=host_ledger_snapshot_decode(snapshot,size);
    snapshot[16]=old_state;
    if (bad) { host_ledger_destroy(bad); free(snapshot); return NULL; }
    md_map_sh256(snapshot+size-32,snapshot,size-32);
  }
  restored=host_ledger_snapshot_decode(snapshot,size);
  memset(snapshot,0,size); free(snapshot);
  return restored;
}

int main(void) {
  ec_secret_key_t secret;
  schnorr_signature_t signature;
  ec_t keys[5],infinity,recipient;
  bn_t sender,recovered;
  unsigned char digests[5*32]={0},refund[32]={99};
  host_ledger *ledger=NULL,*happy=NULL,*timed=NULL,*funded=NULL,*restored=NULL;
  unsigned initialized=0;
  int status=1;
  if (init()!=RLC_OK) return 1;
  ec_secret_key_null(secret); schnorr_signature_null(signature); ec_null(infinity);
  bn_null(sender); bn_null(recovered); ec_null(recipient);
  RLC_TRY {
    ec_secret_key_new(secret); schnorr_signature_new(signature); ec_new(infinity); ec_set_infty(infinity);
    bn_new(sender); bn_new(recovered); ec_new(recipient);
    for (unsigned i=0;i<5;i++) {
      ec_null(keys[i]); ec_new(keys[i]); initialized++;
      bn_set_dig(secret->sk,5+(i<3 ? i : i-3)); ec_mul_gen(keys[i],secret->sk); digests[32*i]=i+1;
    }
    ledger=host_ledger_create(3,digests,(const ec_t *)keys,refund);
    happy=host_ledger_create(3,digests,(const ec_t *)keys,refund);
    timed=host_ledger_create_timed(3,digests,(const ec_t *)keys,refund,100,15,2);
    if (!ledger || !happy || !timed) RLC_THROW(ERR_NO_VALID);
    unsigned char context[32]={17},amount[32]={0},lock_digest[32],wrong_digest[32];
    amount[31]=1;
    bn_set_dig(secret->sk,19); ec_mul_gen(recipient,secret->sk);
    funded=host_ledger_create_unfunded(3,digests,(const ec_t *)keys,refund,
        100,15,2,context,recipient,amount);
    if (!funded || host_ledger_state(funded)!=HOST_UNFUNDED ||
        !host_ledger_lock_digest(lock_digest,context,recipient,keys[0],amount))
      RLC_THROW(ERR_NO_VALID);
    bn_set_dig(secret->sk,5);
    if (adaptor_schnorr_sign(signature,digests,32,infinity,secret)!=RLC_OK ||
        host_ledger_spend_at(funded,0,signature,100) ||
        host_ledger_refund_at(funded,signature,166)) RLC_THROW(ERR_NO_VALID);
    for (unsigned field=0;field<4;field++) {
      unsigned char changed_context[32],changed_amount[32];
      memcpy(changed_context,context,32); memcpy(changed_amount,amount,32);
      if (field==0) changed_context[0]^=1;
      if (field==1) changed_amount[31]=2;
      if (!host_ledger_lock_digest(wrong_digest,changed_context,recipient,
          keys[field==2 ? 1 : 0],changed_amount)) RLC_THROW(ERR_NO_VALID);
      bn_set_dig(secret->sk,field==3 ? 20 : 19);
      if (adaptor_schnorr_sign(signature,wrong_digest,32,infinity,secret)!=RLC_OK ||
          host_ledger_lock_at(funded,signature,100) ||
          host_ledger_state(funded)!=HOST_UNFUNDED) RLC_THROW(ERR_NO_VALID);
    }
    bn_set_dig(secret->sk,19);
    if (adaptor_schnorr_sign(signature,lock_digest,32,infinity,secret)!=RLC_OK ||
        host_ledger_lock_at(funded,signature,99) || host_ledger_lock_at(funded,signature,121) ||
        !host_ledger_lock_at(funded,signature,100) ||
        host_ledger_state(funded)!=HOST_LOCKED || host_ledger_lock_at(funded,signature,100))
      RLC_THROW(ERR_NO_VALID);
    /* Simulate a helper restart immediately after funding. The decoded ledger
     * must retain the exact state/schedule while a one-byte corruption fails. */
    restored=roundtrip(funded,1);
    if (!restored || host_ledger_state(restored)!=HOST_LOCKED || host_ledger_level(restored)!=0)
      RLC_THROW(ERR_NO_VALID);
    host_ledger_destroy(funded); funded=restored; restored=NULL;
    bn_set_dig(secret->sk,5);
    if (adaptor_schnorr_sign(signature,digests,32,infinity,secret)!=RLC_OK ||
        !host_ledger_spend_at(funded,0,signature,101) ||
        host_ledger_state(funded)!=HOST_WITHDRAWN) RLC_THROW(ERR_NO_VALID);
    bn_set_dig(secret->sk,5);
    if (adaptor_schnorr_sign(signature,digests,32,infinity,secret)!=RLC_OK ||
        !host_ledger_spend(happy,0,signature) || host_ledger_state(happy)!=HOST_WITHDRAWN ||
        host_ledger_spend(happy,0,signature) || host_ledger_refund(happy,signature))
      RLC_THROW(ERR_NO_VALID);
    if (host_ledger_refund(ledger,signature) || host_ledger_spend(ledger,1,signature))
      RLC_THROW(ERR_NO_VALID);
    /* Reconstruct the corresponding pre-signature for witness 4, then consume
     * the immutable accepted withdrawal rather than a caller-supplied final. */
    bn_set_dig(recovered,4); ec_mul_gen(recipient,recovered);
    bn_sub_dig(signature->s,signature->s,4);
    ec_curve_get_ord(sender); bn_mod(signature->s,signature->s,sender);
    bn_set_dig(recovered,42);
    if (host_ledger_extract_withdrawal(ledger,signature,recipient,recovered) ||
        bn_cmp_dig(recovered,42)!=RLC_EQ ||
        !host_ledger_extract_withdrawal(happy,signature,recipient,recovered) ||
        bn_cmp_dig(recovered,4)!=RLC_EQ) RLC_THROW(ERR_NO_VALID);
    bn_add_dig(signature->e,signature->e,1);
    if (host_ledger_extract_withdrawal(happy,signature,recipient,recovered) ||
        bn_cmp_dig(recovered,4)!=RLC_EQ) RLC_THROW(ERR_NO_VALID);
    for (unsigned i=0;i<2;i++) {
      bn_set_dig(secret->sk,5+i);
      if (adaptor_schnorr_sign(signature,digests+32*(3+i),32,infinity,secret)!=RLC_OK)
        RLC_THROW(ERR_NO_VALID);
      ec_curve_get_ord(sender); bn_add(signature->s,signature->s,sender);
      if (host_ledger_spend(ledger,3+i,signature) || host_ledger_level(ledger)!=i)
        RLC_THROW(ERR_NO_VALID);
      bn_sub(signature->s,signature->s,sender);
      bn_add_dig(signature->s,signature->s,1);
      if (host_ledger_spend(ledger,3+i,signature) || host_ledger_level(ledger)!=i)
        RLC_THROW(ERR_NO_VALID);
      bn_sub_dig(signature->s,signature->s,1);
      uint64_t due=136+15*i;
      if (host_ledger_spend(timed,3+i,signature) ||
          host_ledger_spend_at(timed,3+i,signature,due-1) ||
          host_ledger_level(timed)!=i ||
          !host_ledger_spend_at(timed,3+i,signature,due) ||
          host_ledger_spend_at(timed,3+i,signature,due)) RLC_THROW(ERR_NO_VALID);
      if (!host_ledger_spend(ledger,3+i,signature) || host_ledger_level(ledger)!=i+1 ||
          host_ledger_spend(ledger,3+i,signature)) RLC_THROW(ERR_NO_VALID);
    }
    /* Persist/restore after every re-lock level, then take the refund on the
     * restored object. This covers state/level continuity across a restart. */
    restored=roundtrip(timed,0);
    if (!restored || host_ledger_state(restored)!=HOST_LOCKED || host_ledger_level(restored)!=2)
      RLC_THROW(ERR_NO_VALID);
    host_ledger_destroy(timed); timed=restored; restored=NULL;
    bn_set_dig(sender,3); bn_set_dig(recovered,4); ec_mul_gen(recipient,recovered);
    bn_set_dig(signature->e,42); bn_set_dig(signature->s,43);
    bn_set_dig(recovered,5);
    if (host_refund_sign(signature,refund,sender,recovered,recipient,keys[2]) ||
        bn_cmp_dig(signature->e,42)!=RLC_EQ || bn_cmp_dig(signature->s,43)!=RLC_EQ)
      RLC_THROW(ERR_NO_VALID);
    bn_set_dig(recovered,4);
    if (host_refund_sign(signature,refund,sender,recovered,recipient,keys[1]) ||
        bn_cmp_dig(signature->s,43)!=RLC_EQ) RLC_THROW(ERR_NO_VALID);
    if (!host_refund_sign(signature,refund,sender,recovered,recipient,keys[2]) ||
        !host_ledger_refund(ledger,signature) || host_ledger_state(ledger)!=HOST_REFUNDED ||
        host_ledger_refund(ledger,signature)) RLC_THROW(ERR_NO_VALID);
    bn_add_dig(signature->s,signature->s,1);
    if (host_ledger_refund_at(timed,signature,166) ||
        host_ledger_state(timed)!=HOST_LOCKED || host_ledger_level(timed)!=2)
      RLC_THROW(ERR_NO_VALID);
    bn_sub_dig(signature->s,signature->s,1);
    if (host_ledger_refund(timed,signature) ||
        host_ledger_refund_at(timed,signature,165) ||
        host_ledger_state(timed)!=HOST_LOCKED ||
        !host_ledger_refund_at(timed,signature,166) ||
        host_ledger_state(timed)!=HOST_REFUNDED ||
        host_ledger_refund_at(timed,signature,167)) RLC_THROW(ERR_NO_VALID);
    restored=roundtrip(happy,0);
    if (!restored || host_ledger_state(restored)!=HOST_WITHDRAWN)
      RLC_THROW(ERR_NO_VALID);
    host_ledger_destroy(restored); restored=NULL;
    puts("{\"signed_withdrawal\":true,\"signed_relocks\":true,\"signed_refund\":true,"
         "\"invalid_signature_and_double_spend_rejected\":true,"
         "\"accepted_withdrawal_extraction\":true,"
         "\"signed_lock_admission_and_binding\":true,"
         "\"timed_relock_refund_and_bypass_rejection\":true,"
         "\"invalid_refund_preserves_locked_level\":true,"
         "\"restart_snapshot_roundtrip\":true,\"snapshot_corruption_rejected\":true}"); status=0;
  } RLC_CATCH_ANY { status=1; }
  RLC_FINALLY {
    host_ledger_destroy(ledger); host_ledger_destroy(happy);
    host_ledger_destroy(timed); host_ledger_destroy(funded); host_ledger_destroy(restored);
    for (unsigned i=0;i<initialized;i++) ec_free(keys[i]);
    if (secret!=NULL) { bn_zero(secret->sk); ec_secret_key_free(secret); }
    if (signature!=NULL) schnorr_signature_free(signature);
    if (sender!=NULL) bn_zero(sender);
    if (recovered!=NULL) bn_zero(recovered);
    bn_free(sender); bn_free(recovered); ec_free(recipient); ec_free(infinity);
  }
  clean(); return status;
}
