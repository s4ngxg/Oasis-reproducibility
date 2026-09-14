#ifndef OASIS_HOST_WITNESS_H
#define OASIS_HOST_WITNESS_H
#include <stddef.h>
#include <relic/relic.h>

typedef struct host_witness_state host_witness_state;
/* One receiver's in-memory state, created after successful Pre-swap export.
 * Peer identity and delivery authentication are the transport's responsibility.
 * Public witness points come from the validated Preparation context.
 * These functions are single-threaded; no secret is logged or persisted. */
host_witness_state *host_witness_create(unsigned participants,
    const ec_t *public_witnesses, const unsigned char context[32]);
void host_witness_destroy(host_witness_state *state);
int host_witness_receive(host_witness_state *state, unsigned participant,
    const unsigned char context[32], const bn_t witness);
/* Export sum mod q only when every distinct participant has a valid receipt.
 * Failure leaves output unchanged. Duplicate valid receipts are idempotent. */
int host_witness_global(const host_witness_state *state, bn_t output);
/* Eq. 10/11: verified global witness plus the host-validated cyclic prefix.
 * The caller owns prefix identity/order validation and the expected statement
 * from admitted Preparation. Addition alone cannot authenticate prefix order.
 * No output until all receipts arrive and the result matches the statement.
 * Failure preserves output. This does not disclose identifiers to any peer. */
int host_witness_withdraw(const host_witness_state *state,
    const bn_t *identifiers,unsigned prefix_count,const ec_t expected,bn_t output);
/* Recovery path (Eq. 16/17): an extracted outgoing witness plus the local
 * identifier. Caller verifies the observed transaction/signature and Extract,
 * and selects the source/destination statements from validated arc topology.
 * Does not require all y_i receipts. Validates both point relations; leaves
 * output unchanged on rejection. This alone is not transaction validation. */
int host_witness_advance(const bn_t extracted,const ec_t source_statement,
    const bn_t local_identifier,const ec_t destination_statement,bn_t output);
/* OASISY01 || context[32] || participant_u32_be || scalar_u256_be.
 * Buffers contain secret material: use only authenticated confidential transport,
 * disable core dumps, and wipe them after sending. Never write them to results.
 * Receive's authenticated_participant must come from the channel identity map,
 * not from this payload. The state was admitted after successful Pre-swap.
 * Invalid encodings leave the state/output unchanged. */
#define HOST_WITNESS_FRAME_BYTES 76u
int host_witness_encode(unsigned char *output, size_t length, unsigned participant,
    const unsigned char context[32], const bn_t witness);
int host_witness_receive_frame(host_witness_state *state,
    unsigned authenticated_participant, const unsigned char *frame, size_t length);
/* identity must be ZAP-authenticated User-Id metadata (participant:N), never
 * an application field. Strict canonical decimal parsing; no receive-order
 * assumption. Transport retains ownership of identity/frame during this call. */
int host_witness_receive_authenticated(host_witness_state *state,const char *identity,
    const unsigned char *frame,size_t length);
#endif
