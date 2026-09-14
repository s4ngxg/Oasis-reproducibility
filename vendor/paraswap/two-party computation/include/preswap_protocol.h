#ifndef OASIS_PRESWAP_PROTOCOL_H
#define OASIS_PRESWAP_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#include "util.h"

#define BENCH_MAGIC 0x50424a50u
#define BENCH_VERSION 4u
#define BENCH_DIGEST_BYTES 32u
#define BENCH_SALT_BYTES 32u
#define BENCH_ITEM_SESSION_BYTES 32u
#define BENCH_CONTEXT_SEED_BYTES 32u
#define BENCH_POINT_BYTES ((size_t) RLC_EC_SIZE_COMPRESSED)
#define BENCH_SCALAR_BYTES ((size_t) RLC_BN_SIZE)
#define BENCH_KEY_OWNERSHIP_PROOF_BYTES \
  (BENCH_POINT_BYTES + BENCH_SCALAR_BYTES)
#define BENCH_MAX_ITEMS 4096u
#define BENCH_ENDPOINT_HOST_BYTES 128u
#define BENCH_ENDPOINT_BYTES 512u
#define BENCH_AUTH_PATH_BYTES 512u
#define BENCH_ZAP_DOMAIN_BYTES 96u

typedef enum {
  BENCH_MODE_ORIGINAL_ITEMWISE = 0,
  BENCH_MODE_PHASE_COALESCED_ITEMWISE = 1,
  BENCH_MODE_BJP_ITEMWISE = 2,
  BENCH_MODE_PHASE_COALESCED_MSM = 3,
  BENCH_MODE_BJP_MSM = 4
} bench_mode_t;

typedef enum {
  BENCH_MSG_BATCH_INIT = 1,
  BENCH_MSG_SERVER_COMMIT = 2,
  BENCH_MSG_CLIENT_NONCE = 3,
  BENCH_MSG_SERVER_OPEN = 4,
  BENCH_MSG_CLIENT_FINAL = 5,
  BENCH_MSG_DONE = 6,
  BENCH_MSG_ABORT = 7,
  BENCH_MSG_FINAL_STATUS = 8,
  BENCH_MSG_COMPLETION_QUERY = 9,
  BENCH_MSG_GATEWAY_REGISTER = 100,
  BENCH_MSG_GATEWAY_ASSIGN = 101,
  BENCH_MSG_GATEWAY_SHUTDOWN = 102,
  BENCH_MSG_GATEWAY_COMPLETION_ACK = 103
} bench_msg_type_t;

typedef struct {
  uint32_t magic;
  uint32_t version;
  uint32_t type;
  uint32_t count;
  uint32_t pair_id;
  uint32_t first_ordinal;
  uint64_t execution_id;
  uint8_t sid[BENCH_DIGEST_BYTES];
} bench_header_t;

typedef struct {
  bench_mode_t mode;
  unsigned count;
  unsigned pair_id;
  unsigned port;
  unsigned io_timeout_ms;
  unsigned completion_ack_timeout_ms;
  unsigned completion_retries;
  unsigned completion_retry_delay_ms;
  uint64_t execution_id;
  unsigned context_participants;
  uint64_t context_epoch;
  uint64_t context_expiry;
  uint64_t context_arc_index;
  uint8_t context_seed[BENCH_CONTEXT_SEED_BYTES];
  int context_seed_set;
  char host_statements[BENCH_AUTH_PATH_BYTES];
  int host_output_fd;
  uint64_t host_export_deadline_ns;
  int host_key_fd;
  int host_address_keys_fd;
  int host_client_keys_fd;
  int host_server_keys_fd;
  struct host_admitted_keys *host_admitted_keys;
  char host_peer_key[BENCH_AUTH_PATH_BYTES];
  int inject_bad_preparation_proof;
  int inject_bad_open;
  int inject_bad_server_partial;
  int inject_bad_final;
  int use_tcp;
  int use_gateway;
  int pool_worker;
  unsigned pool_worker_index;
  char host[BENCH_ENDPOINT_HOST_BYTES];
  char bind[BENCH_ENDPOINT_HOST_BYTES];
  char gateway_backend[BENCH_ENDPOINT_BYTES];
  char curve_public_key_file[BENCH_AUTH_PATH_BYTES];
  char curve_secret_key_file[BENCH_AUTH_PATH_BYTES];
  char curve_server_key_file[BENCH_AUTH_PATH_BYTES];
  char curve_allowed_client_key_file[BENCH_AUTH_PATH_BYTES];
  char zap_domain[BENCH_ZAP_DOMAIN_BYTES];
} bench_options_t;

typedef struct {
  unsigned count;
  uint8_t context_digest[BENCH_DIGEST_BYTES];
  uint8_t batch_digest[BENCH_DIGEST_BYTES];
  uint8_t parent_sid[BENCH_DIGEST_BYTES];
  uint8_t *message_digests;
  uint8_t *item_digests;
  uint8_t *item_sids;
  ec_t *statements;
  ec_t *client_public_keys;
  ec_t *server_public_keys;
  ec_t *joint_public_keys;
} bench_transcript_t;

typedef enum {
  BENCH_EQUATION_SERVER_PARTIAL = 1,
  BENCH_EQUATION_CLIENT_PARTIAL = 2,
  BENCH_EQUATION_FULL_PRESIGNATURE = 3
} bench_equation_t;

typedef enum {
  BENCH_KEY_ROLE_INITIATOR = 1,
  BENCH_KEY_ROLE_RESPONDER = 2
} bench_key_role_t;

typedef struct {
  bench_mode_t mode;
  unsigned pair_id;
  unsigned item_count;
  unsigned sent_frames;
  unsigned received_frames;
  size_t bytes_sent;
  size_t bytes_received;
  long long total_time_ns;
  long long request_sign_ns;
  long long response_preverify_ns;
  long long final_sign_ns;
  long long total_crypto_ns;
  long long verifier_challenge_ns;
  long long verifier_msm_ns;
  unsigned verifier_equations;
  unsigned verifier_msm_calls;
  unsigned verifier_fallbacks;
  long long setup_ns;
  long long user_cpu_ns;
  long long system_cpu_ns;
  long max_rss_kb;
  long voluntary_context_switches;
  long involuntary_context_switches;
  long long scheduler_wait_ns;
  long long scheduler_slices;
  unsigned send_calls;
  unsigned receive_calls;
} bench_result_t;

typedef struct {
  long long user_cpu_ns;
  long long system_cpu_ns;
  long max_rss_kb;
  long voluntary_context_switches;
  long involuntary_context_switches;
  long long scheduler_wait_ns;
  long long scheduler_slices;
} bench_resource_mark_t;

typedef struct {
  long long challenge_ns;
  long long equation_ns;
  long long msm_ns;
  unsigned equations;
  unsigned msm_calls;
  unsigned fallbacks;
} bench_verify_metrics_t;

#define BENCH_HEADER_SIZE ((size_t) 64)
#define BENCH_COMPLETION_FRAME_BYTES \
  (BENCH_HEADER_SIZE + BENCH_DIGEST_BYTES)
#define BENCH_SIG_BYTES ((size_t) (2 * RLC_BN_SIZE))
#define BENCH_NONCE_SIG_BYTES \
  ((size_t) RLC_EC_SIZE_COMPRESSED + BENCH_SIG_BYTES)
#define BENCH_LEGACY_REQUEST_BYTES \
  ((size_t) BENCH_DIGEST_BYTES + BENCH_SIG_BYTES)
#define BENCH_EXPLICIT_REQUEST_BYTES \
  ((size_t) BENCH_DIGEST_BYTES + BENCH_NONCE_SIG_BYTES)
#define BENCH_LEGACY_RESPONSE_BYTES \
  ((size_t) RLC_EC_SIZE_COMPRESSED + BENCH_SIG_BYTES)
#define BENCH_EXPLICIT_RESPONSE_BYTES \
  ((size_t) (2 * RLC_EC_SIZE_COMPRESSED) + BENCH_SIG_BYTES)
#define BENCH_EXPLICIT_FINAL_BYTES BENCH_NONCE_SIG_BYTES

const char *bench_mode_name(bench_mode_t mode);
int bench_mode_is_coalesced(bench_mode_t mode);
int bench_mode_is_bjp(bench_mode_t mode);
int bench_mode_has_item_sessions(bench_mode_t mode);
int bench_mode_uses_msm(bench_mode_t mode);
int bench_mode_uses_explicit_nonce(bench_mode_t mode);
size_t bench_request_bytes(bench_mode_t mode);
size_t bench_response_bytes(bench_mode_t mode);
size_t bench_final_bytes(bench_mode_t mode);
size_t bench_open_prefix_bytes(bench_mode_t mode);
size_t bench_done_bytes(bench_mode_t mode);
long long bench_monotonic_ns(void);
int bench_resource_mark(bench_resource_mark_t *mark);
void bench_resource_delta(const bench_resource_mark_t *before,
                          const bench_resource_mark_t *after,
                          bench_resource_mark_t *delta);
int bench_parse_options(int argc, char **argv, bench_options_t *options);
void bench_write_header(uint8_t *buffer, bench_msg_type_t type, uint32_t count,
                        uint32_t pair_id, uint32_t first_ordinal,
                        uint64_t execution_id);
void bench_write_header_sid(uint8_t *buffer, bench_msg_type_t type,
                            uint32_t count, uint32_t pair_id,
                            uint32_t first_ordinal, uint64_t execution_id,
                            const uint8_t sid[BENCH_DIGEST_BYTES]);
int bench_read_header(const uint8_t *buffer, size_t length,
                      bench_header_t *header);
int bench_make_client_endpoint(char *buffer, size_t buffer_size,
                               const bench_options_t *options);
int bench_make_server_endpoint(char *buffer, size_t buffer_size,
                               const bench_options_t *options);
void bench_cleanup_endpoint(const char *endpoint);
int bench_send_frame(void *socket, const uint8_t *buffer, size_t length);
int bench_recv_frame(void *socket, uint8_t **buffer, size_t *length);
void bench_item_digest(bench_mode_t mode, uint32_t pair_id, uint32_t ordinal,
                       uint32_t total_items, uint64_t execution_id,
                       uint8_t out[BENCH_DIGEST_BYTES]);
void bench_item_session_digest(uint32_t pair_id, uint32_t ordinal,
                               uint32_t total_items, uint64_t execution_id,
                               uint8_t out[BENCH_ITEM_SESSION_BYTES]);
void bench_commitment_digest(const uint8_t *open_payload, size_t payload_length,
                             uint8_t out[BENCH_DIGEST_BYTES]);
int bench_independent_completion_digest(
    const uint8_t *ordered_commitments, unsigned count, uint32_t pair_id,
    uint64_t execution_id, uint8_t out[BENCH_DIGEST_BYTES]);
int bench_digest_equal(const uint8_t left[BENCH_DIGEST_BYTES],
                       const uint8_t right[BENCH_DIGEST_BYTES]);
int bench_random_salt(uint8_t salt[BENCH_SALT_BYTES]);
int bench_validate_secp256k1(void);
int bench_validate_joint_public_key(const ec_t client_public_key,
                                    const ec_t server_public_key,
                                    const ec_t joint_public_key);
int bench_key_ownership_prove(
    uint8_t proof[BENCH_KEY_OWNERSHIP_PROOF_BYTES],
    const bn_t secret_key, const ec_t public_key,
    const uint8_t preparation_digest[BENCH_CONTEXT_SEED_BYTES],
    bench_key_role_t role, uint64_t pair_id, uint64_t key_epoch);
int bench_key_ownership_verify(
    const uint8_t proof[BENCH_KEY_OWNERSHIP_PROOF_BYTES],
    const ec_t public_key,
    const uint8_t preparation_digest[BENCH_CONTEXT_SEED_BYTES],
    bench_key_role_t role, uint64_t pair_id, uint64_t key_epoch);
int bench_validate_preparation_key_ownership(
    const uint8_t client_proof[BENCH_KEY_OWNERSHIP_PROOF_BYTES],
    const uint8_t server_proof[BENCH_KEY_OWNERSHIP_PROOF_BYTES],
    const ec_t client_public_key, const ec_t server_public_key,
    const uint8_t preparation_digest[BENCH_CONTEXT_SEED_BYTES],
    uint64_t pair_id, uint64_t key_epoch);
int bench_decode_invalid_indices(const uint8_t *encoded,
                                 size_t encoded_length,
                                 unsigned item_count,
                                 uint32_t *indices,
                                 unsigned capacity,
                                 unsigned *invalid_count);
int bench_transcript_init(bench_transcript_t *transcript,
                          const bench_options_t *options,
                          const ec_t base_client_public,
                          const ec_t base_server_public);
void bench_transcript_free(bench_transcript_t *transcript);
const uint8_t *bench_active_sid(const bench_transcript_t *transcript,
                                bench_mode_t mode, unsigned ordinal);
int bench_pedersen_commit(ec_t commitment, bn_t opening,
                          const uint8_t sid[BENCH_DIGEST_BYTES],
                          const uint8_t item_digest[BENCH_DIGEST_BYTES],
                          const ec_t nonce);
int bench_pedersen_verify(const ec_t commitment, const bn_t opening,
                          const uint8_t sid[BENCH_DIGEST_BYTES],
                          const uint8_t item_digest[BENCH_DIGEST_BYTES],
                          const ec_t nonce);
int bench_joint_challenge(bn_t challenge,
                          const uint8_t transaction_digest[BENCH_DIGEST_BYTES],
                          const ec_t client_nonce, const ec_t server_nonce,
                          const ec_t statement);
int bench_joint_partial_sign(bn_t partial, const bn_t nonce_scalar,
                             const bn_t secret_scalar,
                             const bn_t challenge);
int bench_joint_partial_verify(const bn_t partial, const ec_t nonce,
                               const ec_t public_key, const bn_t challenge,
                               bench_verify_metrics_t *metrics);
int bench_joint_full_verify(const bn_t full_scalar, const ec_t client_nonce,
                            const ec_t server_nonce, const ec_t statement,
                            const ec_t joint_public_key,
                            const bn_t challenge,
                            bench_verify_metrics_t *metrics);
int bench_derive_verifier_salt(
    uint8_t verifier_salt[BENCH_SALT_BYTES],
    const char *purpose, const uint8_t sid[BENCH_DIGEST_BYTES],
    const uint8_t batch_digest[BENCH_DIGEST_BYTES],
    const uint8_t fresh_random[BENCH_SALT_BYTES]);
int bench_joint_batch_verify(
    bench_equation_t equation, const bench_transcript_t *transcript,
    bench_mode_t mode, unsigned first_ordinal, unsigned count,
    const ec_t client_nonces[], const ec_t server_nonces[],
    const bn_t challenges[], const bn_t server_partials[],
    const bn_t client_partials[], const bn_t full_scalars[],
    const uint8_t salt[BENCH_SALT_BYTES],
    bench_verify_metrics_t *metrics);
int bench_completion_digest(
    const bench_transcript_t *transcript,
    const uint8_t status_digest[BENCH_DIGEST_BYTES],
    uint8_t out[BENCH_DIGEST_BYTES]);
int bench_status_digest(const uint8_t *payload, size_t payload_length,
                        uint8_t out[BENCH_DIGEST_BYTES]);
int bench_derive_item_secret(bn_t derived, const bn_t base_secret,
                             const char *key_domain, uint32_t pair_id,
                             uint32_t ordinal, uint32_t total_items);
int bench_derive_item_public(ec_t derived, const ec_t base_public,
                             const char *key_domain, uint32_t pair_id,
                             uint32_t ordinal, uint32_t total_items);
int bench_schnorr_sign_explicit(schnorr_signature_t signature, ec_t nonce,
                                const uint8_t *message, size_t message_length,
                                const ec_t adaptor, int has_adaptor,
                                const bn_t secret_scalar);
int bench_schnorr_verify_explicit(const schnorr_signature_t signature,
                                  const ec_t nonce,
                                  const uint8_t *message,
                                  size_t message_length,
                                  const ec_t adaptor, int has_adaptor,
                                  const ec_t public_key,
                                  bench_verify_metrics_t *metrics);
int bench_schnorr_batch_verify(schnorr_signature_t const signatures[],
                               const ec_t nonces[], const uint8_t *messages,
                               size_t message_stride, const ec_t adaptors[],
                               int has_adaptor, const ec_t public_keys[],
                               unsigned count,
                               const uint8_t salt[BENCH_SALT_BYTES],
                               const char *equation_domain,
                               bench_verify_metrics_t *metrics);
void bench_print_result(const bench_result_t *result);

#endif
