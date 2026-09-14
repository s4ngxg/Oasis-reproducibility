#ifndef OASIS_HOST_LEDGER_H
#define OASIS_HOST_LEDGER_H
#include <stddef.h>
#include "types.h"
#include "host_schedule.h"

typedef struct host_ledger host_ledger;
typedef enum { HOST_LOCKED=0, HOST_WITHDRAWN=1, HOST_REFUNDED=2, HOST_UNFUNDED=3 } host_asset_state;
/* One arc, n source-address levels. Prepared withdrawal digests occupy [0,n),
 * re-locks [n,2n-1). Each re-lock must share its source key with withdrawal
 * at the same level. Registry inputs must come from validated Preparation.
 * This is a signature-checking ledger adapter, not a blockchain implementation. */
host_ledger *host_ledger_create(unsigned n, const unsigned char *digests,
    const ec_t *keys, const unsigned char refund_digest[32]);
/* Host-local timed adapter, not blockchain consensus. Copies a validated
 * schedule; now_ns must come from the trusted host, never the peer. */
host_ledger *host_ledger_create_timed(unsigned n,const unsigned char *digests,
    const ec_t *keys,const unsigned char refund_digest[32],
    uint64_t origin_ns,uint64_t delta_ns,uint64_t epsilon_ns);
/* Signature-checked funding path. Context identifies an admitted swap/arc;
 * amount is a nonzero unsigned 256-bit big-endian value. Digest encoding is
 * fixture-domain || context[32] || owner[33] || destination[33] || amount[32].
 * This is a ledger-adapter transaction, not a chain transaction serialization.
 * The legacy create functions above assume funding for isolated tests only. */
int host_ledger_lock_digest(unsigned char output[32],const unsigned char context[32],
    const ec_t owner,const ec_t destination,const unsigned char amount[32]);
host_ledger *host_ledger_create_unfunded(unsigned n,const unsigned char *digests,
    const ec_t *keys,const unsigned char refund_digest[32],
    uint64_t origin_ns,uint64_t delta_ns,uint64_t epsilon_ns,
    const unsigned char context[32],const ec_t owner,const unsigned char amount[32]);
int host_ledger_lock_at(host_ledger *ledger,schnorr_signature_t signature,uint64_t now_ns);
int host_ledger_spend_at(host_ledger *ledger,unsigned ordinal,
    schnorr_signature_t signature,uint64_t now_ns);
int host_ledger_refund_at(host_ledger *ledger,schnorr_signature_t signature,
    uint64_t now_ns);
/* Extract only from the withdrawal actually accepted by this ledger instance.
 * Caller supplies the admitted pre-signature and adaptor statement. Checks
 * canonical scalars, matching challenge, PreVf and the extracted point.
 * Failure preserves output. Not a substitute for a real chain observation. */
int host_ledger_extract_withdrawal(const host_ledger *ledger,
    schnorr_signature_t presignature,const ec_t statement,bn_t output);

/* Snapshot codec for the trusted host adapter, not a durable recovery service.
 * The encoding contains the
 * complete admitted digest/key set, schedule, state/level, accepted withdrawal
 * signature (if any), and a SHA-256 corruption check. It deliberately contains
 * no private signing key or witness. The snapshot is host state, not consensus
 * state. SHA-256 detects corruption, not hostile replacement or rollback.
 * Decode does not authenticate Preparation provenance, prove prior transitions,
 * or establish freshness. A recovery caller must independently anchor those
 * properties and durably preserve state before acknowledging transitions.
 * The lifecycle coordinator does not currently use this codec for recovery. */
size_t host_ledger_snapshot_size(const host_ledger *ledger);
int host_ledger_snapshot_encode(const host_ledger *ledger,
    unsigned char *output,size_t output_size);
host_ledger *host_ledger_snapshot_decode(const unsigned char *input,size_t input_size);

void host_ledger_destroy(host_ledger *ledger);
int host_ledger_spend(host_ledger *ledger, unsigned ordinal, schnorr_signature_t signature);
int host_ledger_refund(host_ledger *ledger, schnorr_signature_t signature);
host_asset_state host_ledger_state(const host_ledger *ledger);
unsigned host_ledger_level(const host_ledger *ledger);
#endif
