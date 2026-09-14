#ifndef OASIS_HOST_HANDOFF_H
#define OASIS_HOST_HANDOFF_H
#include "preswap_protocol.h"

/* Public vector: eight-byte magic, then count compressed secp256k1 points.
 * The expected count comes from the validated host options. The separate
 * handoff writer accepts only anonymous memory descriptors, never disk paths. */
#define HOST_PUBLIC_MAGIC "OASISP01"

int host_read_statement(ec_t point, const char *path, unsigned count,
                        unsigned ordinal);
#define HOST_HANDOFF_MAGIC "OASISH02"
#define HOST_REGISTRY_MAGIC "OASISRG2"
#define HOST_REGISTRY_RECORD_BYTES 130u
#define HOST_RECORD_BYTES 194u
#define HOST_HEADER_BYTES 104u
#define HOST_TX_DIGEST_OFFSET 0u
#define HOST_ITEM_DIGEST_OFFSET 32u
#define HOST_STATEMENT_OFFSET 64u
#define HOST_JOINT_KEY_OFFSET 97u
#define HOST_CHALLENGE_OFFSET 130u
#define HOST_SCALAR_OFFSET 162u
/* Synthetic ledger refund identifier only; not a chain transaction hash.
 * Caller supplies the already validated, completed handoff header. */
int host_fixture_refund_digest(uint8_t output[32],const uint8_t header[HOST_HEADER_BYTES]);
static inline unsigned host_key_ordinal(const bench_options_t *options,
                                        unsigned ordinal) {
  return options->host_statements[0] && ordinal >= options->context_participants
      ? ordinal - options->context_participants : ordinal;
}
int host_memory_fd(int fd);
int host_item_secret(bn_t output,const bn_t base,const bench_options_t *options,
                     unsigned ordinal,bench_key_role_t role);
int host_item_public(ec_t output,const ec_t base,const bench_options_t *options,
                     unsigned ordinal,bench_key_role_t role);
/* Admission owns a copy of all verified address keys for one immutable session
 * context. Call before measuring Pre-swap, release before RELIC cleanup.
 * Options copies must not independently free this owned pointer. */
int host_admit_address_keys(bench_options_t *options,bench_key_role_t local_role);
void host_release_address_keys(bench_options_t *options);
/* OASISK01 || canonical nonzero scalar[32], in a write/grow/shrink-sealed
 * anonymous memory file. Host retains ownership; no secret output is logged. */
int host_read_key(int fd, bn_t secret, ec_t public_key);
/* Independent address shares: OASISA01 || count_u32_be || count scalars[32].
 * Entire vector is validated, including duplicate rejection. Count is trusted
 * host policy; the ordinal is an address level, not a transaction ordinal.
 * Caller generates independent random scalars; uniqueness alone cannot prove
 * independence. Sealing/anonymous-memory requirements match host_read_key. */
int host_read_address_key(int fd, unsigned count, unsigned ordinal,
                          bn_t secret, ec_t public_key);
int host_address_key_prove(uint8_t proof[BENCH_KEY_OWNERSHIP_PROOF_BYTES],
    const bn_t secret, const ec_t public_key, const uint8_t preparation[32],
    unsigned count, unsigned ordinal, bench_key_role_t role,
    uint64_t pair_id, uint64_t epoch);
int host_address_key_verify(const uint8_t proof[BENCH_KEY_OWNERSHIP_PROOF_BYTES],
    const ec_t public_key, const uint8_t preparation[32],
    unsigned count, unsigned ordinal, bench_key_role_t role,
    uint64_t pair_id, uint64_t epoch);
/* Public preparation bundle: OASISAP1 || count_u32_be ||
 * repeated(point[33] || ownership_proof). Uses anonymous sealed descriptors
 * for immutable host import. No trust is placed in bundle-supplied context:
 * role, pair, epoch and preparation digest are validated host arguments.
 * Verify every entry, not just the requested address. */
int host_write_address_public(int output_fd,int secret_fd,unsigned count,
    const uint8_t preparation[32],bench_key_role_t role,uint64_t pair_id,uint64_t epoch);
int host_read_address_public(int fd,unsigned count,unsigned ordinal,ec_t point,
    const uint8_t preparation[32],bench_key_role_t role,uint64_t pair_id,uint64_t epoch);
int host_write_handoff(int fd, const bench_transcript_t *transcript,
                       const bn_t *challenges, const bn_t *scalars);
/* Trusted local CLOCK_MONOTONIC cutoff. The host waits for writer completion
 * before consuming the buffer. Expiry clears any partial export; the outer
 * host must recheck its own deadline at admission. Zero disables this gate
 * only for legacy correctness fixtures. No fair/simultaneous-output claim. */
int host_write_handoff_until(int fd,const bench_transcript_t *transcript,
    const bn_t *challenges,const bn_t *scalars,uint64_t deadline_ns);
#endif
