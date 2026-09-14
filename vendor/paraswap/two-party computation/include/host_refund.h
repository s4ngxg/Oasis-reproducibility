#ifndef OASIS_HOST_REFUND_H
#define OASIS_HOST_REFUND_H
#include "util.h"

/* Wallet-side refund signing after VTD recovery. The caller supplies the
 * validated final-address keys and prepared refund digest, and enforces host
 * deadlines. This routine checks both recovered and joint key bindings; it
 * does not itself prove that the recovered scalar came from ForceOp.
 * Signature output is unchanged on failure. Secret shares stay in memory. */
int host_refund_sign(schnorr_signature_t output,
    const unsigned char refund_digest[32], const bn_t sender_share,
    const bn_t recovered_share, const ec_t recipient_key, const ec_t joint_key);
#endif
