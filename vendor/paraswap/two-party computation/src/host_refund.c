#include <string.h>
#include "host_refund.h"

int host_refund_sign(schnorr_signature_t output,
    const unsigned char refund_digest[32], const bn_t sender_share,
    const bn_t recovered_share, const ec_t recipient_key, const ec_t joint_key) {
  bn_t order;
  ec_t computed,infinity;
  ec_secret_key_t secret;
  ec_public_key_t public_key;
  schnorr_signature_t signature;
  unsigned char digest[32];
  int valid=0;
  if (!output || !refund_digest) return 0;
  memcpy(digest,refund_digest,sizeof(digest));
  bn_null(order); ec_null(computed); ec_null(infinity);
  ec_secret_key_null(secret); ec_public_key_null(public_key);
  schnorr_signature_null(signature);
  RLC_TRY {
    bn_new(order); ec_new(computed); ec_new(infinity);
    ec_secret_key_new(secret); ec_public_key_new(public_key);
    schnorr_signature_new(signature); ec_curve_get_ord(order);
    if (bn_sign(sender_share)==RLC_NEG || bn_is_zero(sender_share) ||
        bn_cmp(sender_share,order)!=RLC_LT || bn_sign(recovered_share)==RLC_NEG ||
        bn_is_zero(recovered_share) || bn_cmp(recovered_share,order)!=RLC_LT ||
        ec_is_infty(recipient_key) || !ec_on_curve(recipient_key) ||
        ec_is_infty(joint_key) || !ec_on_curve(joint_key)) RLC_THROW(ERR_NO_VALID);
    ec_mul_gen(computed,recovered_share);
    if (ec_cmp(computed,recipient_key)!=RLC_EQ) RLC_THROW(ERR_NO_VALID);
    bn_add(secret->sk,sender_share,recovered_share); bn_mod(secret->sk,secret->sk,order);
    ec_mul_gen(computed,secret->sk);
    if (bn_is_zero(secret->sk) || ec_cmp(computed,joint_key)!=RLC_EQ) RLC_THROW(ERR_NO_VALID);
    ec_set_infty(infinity); ec_copy(public_key->pk,joint_key);
    if (adaptor_schnorr_sign(signature,digest,32,infinity,secret)!=RLC_OK ||
        adaptor_schnorr_preverify(signature,digest,32,infinity,public_key)!=1)
      RLC_THROW(ERR_NO_VALID);
    bn_copy(output->e,signature->e); bn_copy(output->s,signature->s); valid=1;
  } RLC_CATCH_ANY { valid=0; }
  RLC_FINALLY {
    if (secret!=NULL) { bn_zero(secret->sk); ec_secret_key_free(secret); }
    if (public_key!=NULL) ec_public_key_free(public_key);
    if (signature!=NULL) { bn_zero(signature->s); schnorr_signature_free(signature); }
    bn_free(order); ec_free(computed); ec_free(infinity);
  }
  return valid;
}
