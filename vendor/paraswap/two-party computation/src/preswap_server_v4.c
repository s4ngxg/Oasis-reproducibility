#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zmq.h"
#include "tumbler.h"
#include "preswap_protocol.h"
#include "transport_auth.h"
#include "host_handoff.h"
#ifdef BENCH_ALLOCATION_PROFILE
#include "allocation_counter.h"
#endif

#define INIT_PREFIX_BYTES (2u * BENCH_DIGEST_BYTES)
#define COMMIT_CORE_BYTES BENCH_POINT_BYTES
#define NONCE_CORE_BYTES BENCH_POINT_BYTES
#define OPEN_CORE_BYTES (BENCH_POINT_BYTES + 2u * BENCH_SCALAR_BYTES)
#define FINAL_CORE_BYTES BENCH_SCALAR_BYTES
#define STATUS_CORE_BYTES (2u * BENCH_SALT_BYTES + 4u)
#define ASSIGNMENT_BYTES (BENCH_HEADER_SIZE + 64u)

typedef struct {
  long long verify_request_ns;
  long long generate_response_ns;
  long long verify_final_ns;
  unsigned sessions;
  bench_verify_metrics_t verifier;
  long long protocol_wall_ns;
  long long setup_ns;
  long long user_cpu_ns;
  long long system_cpu_ns;
  long max_rss_kb;
  long voluntary_context_switches;
  long involuntary_context_switches;
  long long scheduler_wait_ns;
  long long scheduler_slices;
  size_t bytes_sent;
  size_t bytes_received;
  unsigned sent_frames;
  unsigned received_frames;
  unsigned send_calls;
  unsigned receive_calls;
} server_metrics_t;

typedef struct {
  bench_transcript_t transcript;
  uint8_t server_key_proof[BENCH_KEY_OWNERSHIP_PROOF_BYTES];
  ec_t *commitments;
  ec_t *client_nonces;
  ec_t *server_nonces;
  bn_t *server_nonce_scalars;
  bn_t *openings;
  bn_t *challenges;
  bn_t *server_partials;
  bn_t *client_partials;
  bn_t *full_scalars;
} server_session_t;

#ifdef BENCH_ALLOCATION_PROFILE
static bench_allocation_metrics_t server_allocation_previous;

static void reset_server_allocation_baseline(void) {
  bench_allocation_metrics_read(&server_allocation_previous);
}
#endif

static uint32_t read_u32_be(const uint8_t in[4]) {
  return ((uint32_t) in[0] << 24) | ((uint32_t) in[1] << 16) |
         ((uint32_t) in[2] << 8) | (uint32_t) in[3];
}

static uint64_t read_u64_be(const uint8_t in[8]) {
  return ((uint64_t) read_u32_be(in) << 32) | read_u32_be(in + 4);
}

static int receive_assignment(void *socket, bench_options_t *options,
                              int *shutdown) {
  uint8_t *frame = NULL;
  size_t length = 0;
  bench_header_t header;
  const uint8_t *cursor;
  *shutdown = 0;
  if (bench_recv_frame(socket, &frame, &length) != RLC_OK ||
      bench_read_header(frame, length, &header) != RLC_OK) {
    free(frame);
    return RLC_ERR;
  }
  if (header.type == BENCH_MSG_GATEWAY_SHUTDOWN) {
    *shutdown = 1;
    free(frame);
    return RLC_OK;
  }
  if (header.type != BENCH_MSG_GATEWAY_ASSIGN ||
      length != ASSIGNMENT_BYTES || header.count == 0 ||
      header.count > BENCH_MAX_ITEMS) {
    free(frame);
    return RLC_ERR;
  }
  cursor = frame + BENCH_HEADER_SIZE;
  /* Validate before updating the reusable worker context; bound n before the
   * unsigned 2*n-1 calculation so a wrapped value cannot match header.count. */
  uint32_t mode=read_u32_be(cursor),participants=read_u32_be(cursor+4);
  uint64_t expiry=read_u64_be(cursor+16),arc=read_u64_be(cursor+24);
  if (mode<BENCH_MODE_ORIGINAL_ITEMWISE || mode>BENCH_MODE_BJP_MSM ||
      participants<2 || participants>(BENCH_MAX_ITEMS+1u)/2u ||
      header.count!=2u*participants-1u || !expiry || !arc) {
    free(frame);
    return RLC_ERR;
  }
  options->mode=(bench_mode_t)mode;
  options->context_participants=participants;
  options->context_epoch=read_u64_be(cursor+8);
  options->context_expiry=expiry;
  options->context_arc_index=arc;
  memcpy(options->context_seed,cursor+32,BENCH_CONTEXT_SEED_BYTES);
  options->context_seed_set=1;
  options->count=header.count;
  options->pair_id=header.pair_id;
  options->execution_id=header.execution_id;
  free(frame);
  return RLC_OK;
}

static void write_u32(uint8_t out[4], uint32_t value) {
  out[0] = (uint8_t) (value >> 24);
  out[1] = (uint8_t) (value >> 16);
  out[2] = (uint8_t) (value >> 8);
  out[3] = (uint8_t) value;
}

static void print_hex(const uint8_t *value, size_t length) {
  size_t i;
  for (i = 0; i < length; i++) printf("%02x", value[i]);
}

static int send_frame(void *socket, const uint8_t *frame, size_t length,
                      server_metrics_t *metrics) {
  if (bench_send_frame(socket, frame, length) != RLC_OK) return RLC_ERR;
  metrics->sent_frames++;
  metrics->send_calls++;
  metrics->bytes_sent += length;
  return RLC_OK;
}

static void send_abort(void *socket, const bench_options_t *options,
                       const uint8_t sid[BENCH_DIGEST_BYTES],
                       server_metrics_t *metrics) {
  uint8_t frame[BENCH_HEADER_SIZE];
  bench_write_header_sid(frame, BENCH_MSG_ABORT, options->count,
                         options->pair_id, 0, options->execution_id, sid);
  (void) send_frame(socket, frame, sizeof(frame), metrics);
}

static int receive_expected(
    void *socket, bench_msg_type_t type, unsigned count, unsigned pair_id,
    unsigned first, uint64_t execution_id,
    const uint8_t sid[BENCH_DIGEST_BYTES], uint8_t **frame, size_t *length,
    server_metrics_t *metrics) {
  bench_header_t header;
  if (bench_recv_frame(socket, frame, length) != RLC_OK) return RLC_ERR;
  metrics->received_frames++;
  metrics->receive_calls++;
  metrics->bytes_received += *length;
  if (bench_read_header(*frame, *length, &header) != RLC_OK ||
      header.type != (uint32_t) type || header.count != count ||
      header.pair_id != pair_id || header.first_ordinal != first ||
      header.execution_id != execution_id ||
      !bench_digest_equal(header.sid, sid)) {
    free(*frame);
    *frame = NULL;
    return RLC_ERR;
  }
  return RLC_OK;
}

static int allocate_session(server_session_t *session,
                            const bench_options_t *options,
                            const ec_t client_public,
                            const ec_t server_public,
                            const uint8_t server_key_proof[
                                BENCH_KEY_OWNERSHIP_PROOF_BYTES]) {
  unsigned i;
  memset(session, 0, sizeof(*session));
  if (server_key_proof == NULL) return RLC_ERR;
  if (bench_transcript_init(&session->transcript, options, client_public,
                            server_public) != RLC_OK) return RLC_ERR;
  memcpy(session->server_key_proof, server_key_proof,
         BENCH_KEY_OWNERSHIP_PROOF_BYTES);
  session->commitments = calloc(options->count, sizeof(ec_t));
  session->client_nonces = calloc(options->count, sizeof(ec_t));
  session->server_nonces = calloc(options->count, sizeof(ec_t));
  session->server_nonce_scalars = calloc(options->count, sizeof(bn_t));
  session->openings = calloc(options->count, sizeof(bn_t));
  session->challenges = calloc(options->count, sizeof(bn_t));
  session->server_partials = calloc(options->count, sizeof(bn_t));
  session->client_partials = calloc(options->count, sizeof(bn_t));
  session->full_scalars = calloc(options->count, sizeof(bn_t));
  if (session->commitments == NULL || session->client_nonces == NULL ||
      session->server_nonces == NULL ||
      session->server_nonce_scalars == NULL || session->openings == NULL ||
      session->challenges == NULL || session->server_partials == NULL ||
      session->client_partials == NULL || session->full_scalars == NULL) {
    return RLC_ERR;
  }
  for (i = 0; i < options->count; i++) {
    ec_null(session->commitments[i]);
    ec_null(session->client_nonces[i]);
    ec_null(session->server_nonces[i]);
    bn_null(session->server_nonce_scalars[i]);
    bn_null(session->openings[i]);
    bn_null(session->challenges[i]);
    bn_null(session->server_partials[i]);
    bn_null(session->client_partials[i]);
    bn_null(session->full_scalars[i]);
    ec_new(session->commitments[i]);
    ec_new(session->client_nonces[i]);
    ec_new(session->server_nonces[i]);
    bn_new(session->server_nonce_scalars[i]);
    bn_new(session->openings[i]);
    bn_new(session->challenges[i]);
    bn_new(session->server_partials[i]);
    bn_new(session->client_partials[i]);
    bn_new(session->full_scalars[i]);
  }
  return RLC_OK;
}

static void free_session(server_session_t *session) {
  unsigned i;
  if (session == NULL) return;
  for (i = 0; i < session->transcript.count; i++) {
    ec_free(session->commitments[i]);
    ec_free(session->client_nonces[i]);
    ec_free(session->server_nonces[i]);
    bn_free(session->server_nonce_scalars[i]);
    bn_free(session->openings[i]);
    bn_free(session->challenges[i]);
    bn_free(session->server_partials[i]);
    bn_free(session->client_partials[i]);
    bn_free(session->full_scalars[i]);
  }
  free(session->commitments);
  free(session->client_nonces);
  free(session->server_nonces);
  free(session->server_nonce_scalars);
  free(session->openings);
  free(session->challenges);
  free(session->server_partials);
  free(session->client_partials);
  free(session->full_scalars);
  bench_transcript_free(&session->transcript);
  memset(session, 0, sizeof(*session));
}

static size_t item_sid_prefix(bench_mode_t mode) {
  return bench_mode_has_item_sessions(mode) ? BENCH_ITEM_SESSION_BYTES : 0;
}

static const uint8_t *active_sid(const server_session_t *session,
                                 bench_mode_t mode, unsigned ordinal) {
  return mode == BENCH_MODE_ORIGINAL_ITEMWISE
             ? bench_active_sid(&session->transcript, mode, ordinal)
             : session->transcript.parent_sid;
}

static void write_item_sid(uint8_t **cursor, bench_mode_t mode,
                           const bench_transcript_t *transcript,
                           unsigned ordinal) {
  if (bench_mode_has_item_sessions(mode)) {
    memcpy(*cursor, bench_active_sid(transcript, mode, ordinal),
           BENCH_ITEM_SESSION_BYTES);
    *cursor += BENCH_ITEM_SESSION_BYTES;
  }
}

static int check_item_sid(const uint8_t **cursor, bench_mode_t mode,
                          const bench_transcript_t *transcript,
                          unsigned ordinal) {
  if (bench_mode_has_item_sessions(mode)) {
    if (!bench_digest_equal(*cursor,
                            bench_active_sid(transcript, mode, ordinal))) {
      return RLC_ERR;
    }
    *cursor += BENCH_ITEM_SESSION_BYTES;
  }
  return RLC_OK;
}

static int parse_init(const bench_options_t *options,
                      const server_session_t *session, unsigned first,
                      unsigned count, const uint8_t *frame, size_t length,
                      const ec_t base_client_public) {
  const size_t stride = item_sid_prefix(options->mode) + BENCH_DIGEST_BYTES;
  const size_t proof_bytes =
      first == 0 ? BENCH_KEY_OWNERSHIP_PROOF_BYTES : 0;
  const uint8_t *cursor = frame + BENCH_HEADER_SIZE;
  unsigned i;
  if (length != BENCH_HEADER_SIZE + INIT_PREFIX_BYTES + proof_bytes +
                    (size_t) count * stride ||
      !bench_digest_equal(cursor, session->transcript.context_digest) ||
      !bench_digest_equal(cursor + BENCH_DIGEST_BYTES,
                          session->transcript.batch_digest)) return RLC_ERR;
  cursor += INIT_PREFIX_BYTES;
  if (proof_bytes != 0) {
    if (bench_key_ownership_verify(
            cursor, base_client_public, options->context_seed,
            BENCH_KEY_ROLE_INITIATOR, options->pair_id,
            options->context_epoch) != RLC_OK) {
      return RLC_ERR;
    }
    cursor += BENCH_KEY_OWNERSHIP_PROOF_BYTES;
  }
  for (i = 0; i < count; i++) {
    unsigned ordinal = first + i;
    if (check_item_sid(&cursor, options->mode, &session->transcript,
                    ordinal) != RLC_OK ||
        !bench_digest_equal(cursor,
                            session->transcript.item_digests +
                                (size_t) ordinal * BENCH_DIGEST_BYTES)) {
      return RLC_ERR;
    }
    cursor += BENCH_DIGEST_BYTES;
  }
  return RLC_OK;
}

static int receive_init(void *socket, const bench_options_t *options,
                        server_session_t *session, unsigned first,
                        unsigned count, const ec_t base_client_public,
                        server_metrics_t *metrics) {
  uint8_t *frame = NULL;
  size_t length = 0;
  int status = RLC_ERR;
  if (receive_expected(socket, BENCH_MSG_BATCH_INIT, count, options->pair_id,
                       first, options->execution_id,
                       active_sid(session, options->mode, first), &frame,
                       &length, metrics) == RLC_OK &&
      parse_init(options, session, first, count, frame, length,
                 base_client_public) == RLC_OK) {
    status = RLC_OK;
  }
  free(frame);
  return status;
}

static int prepare_commitment(const bench_options_t *options,
                              server_session_t *session, unsigned ordinal) {
  bn_t order;
  int status;
  bn_null(order);
  bn_new(order);
  ec_curve_get_ord(order);
  do {
    bn_rand_mod(session->server_nonce_scalars[ordinal], order);
  } while (bn_is_zero(session->server_nonce_scalars[ordinal]));
  ec_mul_gen(session->server_nonces[ordinal],
             session->server_nonce_scalars[ordinal]);
  status = bench_pedersen_commit(
      session->commitments[ordinal], session->openings[ordinal],
      bench_active_sid(&session->transcript, options->mode, ordinal),
      session->transcript.item_digests +
          (size_t) ordinal * BENCH_DIGEST_BYTES,
      session->server_nonces[ordinal]);
  bn_free(order);
  return status;
}

static uint8_t *build_commit(const bench_options_t *options,
                             server_session_t *session, unsigned first,
                             unsigned count, size_t *length) {
  const size_t stride = item_sid_prefix(options->mode) + COMMIT_CORE_BYTES;
  const size_t proof_bytes =
      first == 0 ? BENCH_KEY_OWNERSHIP_PROOF_BYTES : 0;
  uint8_t *frame = NULL;
  uint8_t *cursor;
  unsigned i;
  *length = BENCH_HEADER_SIZE + proof_bytes + (size_t) count * stride;
  frame = calloc(1, *length);
  if (frame == NULL) return NULL;
  bench_write_header_sid(frame, BENCH_MSG_SERVER_COMMIT, count,
                         options->pair_id, first, options->execution_id,
                         active_sid(session, options->mode, first));
  cursor = frame + BENCH_HEADER_SIZE;
  if (proof_bytes != 0) {
    memcpy(cursor, session->server_key_proof,
           BENCH_KEY_OWNERSHIP_PROOF_BYTES);
    cursor += BENCH_KEY_OWNERSHIP_PROOF_BYTES;
  }
  for (i = 0; i < count; i++) {
    unsigned ordinal = first + i;
    if (prepare_commitment(options, session, ordinal) != RLC_OK) {
      free(frame);
      return NULL;
    }
    write_item_sid(&cursor, options->mode, &session->transcript, ordinal);
    ec_write_bin(cursor, BENCH_POINT_BYTES, session->commitments[ordinal], 1);
    cursor += BENCH_POINT_BYTES;
  }
  return frame;
}

static int parse_nonce(const bench_options_t *options,
                       server_session_t *session, unsigned first,
                       unsigned count, const uint8_t *frame, size_t length) {
  const size_t stride = item_sid_prefix(options->mode) + NONCE_CORE_BYTES;
  const uint8_t *cursor = frame + BENCH_HEADER_SIZE;
  unsigned i;
  if (length != BENCH_HEADER_SIZE + (size_t) count * stride) return RLC_ERR;
  for (i = 0; i < count; i++) {
    unsigned ordinal = first + i;
    if (check_item_sid(&cursor, options->mode, &session->transcript,
                    ordinal) != RLC_OK) return RLC_ERR;
    ec_read_bin(session->client_nonces[ordinal], cursor, BENCH_POINT_BYTES);
    cursor += BENCH_POINT_BYTES;
  }
  return RLC_OK;
}

static int prepare_open(tumbler_state_t state,
                        const bench_options_t *options,
                        server_session_t *session, unsigned ordinal) {
  bn_t secret;
  int status = RLC_ERR;
  bn_null(secret);
  bn_new(secret);
  if (host_item_secret(secret,state->tumbler_ec_sk->sk,options,ordinal,
                       BENCH_KEY_ROLE_RESPONDER)==RLC_OK &&
      bench_joint_challenge(
          session->challenges[ordinal],
          session->transcript.message_digests +
              (size_t) ordinal * BENCH_DIGEST_BYTES,
          session->client_nonces[ordinal], session->server_nonces[ordinal],
          session->transcript.statements[ordinal]) == RLC_OK &&
      bench_joint_partial_sign(session->server_partials[ordinal],
                               session->server_nonce_scalars[ordinal], secret,
                               session->challenges[ordinal]) == RLC_OK) {
    status = RLC_OK;
  }
  bn_free(secret);
  return status;
}

static uint8_t *build_open(tumbler_state_t state,
                           const bench_options_t *options,
                           server_session_t *session, unsigned first,
                           unsigned count, size_t *length) {
  const size_t stride = item_sid_prefix(options->mode) + OPEN_CORE_BYTES;
  uint8_t *frame = NULL;
  uint8_t *cursor;
  unsigned i;
  *length = BENCH_HEADER_SIZE + (size_t) count * stride;
  frame = calloc(1, *length);
  if (frame == NULL) return NULL;
  bench_write_header_sid(frame, BENCH_MSG_SERVER_OPEN, count,
                         options->pair_id, first, options->execution_id,
                         active_sid(session, options->mode, first));
  cursor = frame + BENCH_HEADER_SIZE;
  for (i = 0; i < count; i++) {
    unsigned ordinal = first + i;
    if (prepare_open(state, options, session, ordinal) != RLC_OK) {
      free(frame);
      return NULL;
    }
    write_item_sid(&cursor, options->mode, &session->transcript, ordinal);
    ec_write_bin(cursor, BENCH_POINT_BYTES, session->server_nonces[ordinal], 1);
    cursor += BENCH_POINT_BYTES;
    bn_write_bin(cursor, BENCH_SCALAR_BYTES, session->openings[ordinal]);
    cursor += BENCH_SCALAR_BYTES;
    bn_write_bin(cursor, BENCH_SCALAR_BYTES,
                 session->server_partials[ordinal]);
    cursor += BENCH_SCALAR_BYTES;
  }
  if (options->inject_bad_open) {
    size_t opening_last = BENCH_HEADER_SIZE + item_sid_prefix(options->mode) +
        BENCH_POINT_BYTES + BENCH_SCALAR_BYTES - 1;
    frame[opening_last] ^= 1;
  }
  if (options->inject_bad_server_partial) {
    size_t partial_last = BENCH_HEADER_SIZE +
        item_sid_prefix(options->mode) + OPEN_CORE_BYTES - 1;
    frame[partial_last] ^= 1;
  }
  return frame;
}

static int parse_final(const bench_options_t *options,
                       server_session_t *session, unsigned first,
                       unsigned count, const uint8_t *frame, size_t length) {
  const size_t stride = item_sid_prefix(options->mode) + FINAL_CORE_BYTES;
  const uint8_t *cursor = frame + BENCH_HEADER_SIZE;
  bn_t order;
  unsigned i;
  bn_null(order);
  bn_new(order);
  ec_curve_get_ord(order);
  if (length != BENCH_HEADER_SIZE + (size_t) count * stride) {
    bn_free(order);
    return RLC_ERR;
  }
  for (i = 0; i < count; i++) {
    unsigned ordinal = first + i;
    if (check_item_sid(&cursor, options->mode, &session->transcript,
                    ordinal) != RLC_OK) {
      bn_free(order);
      return RLC_ERR;
    }
    bn_read_bin(session->client_partials[ordinal], cursor,
                BENCH_SCALAR_BYTES);
    if (bn_cmp(session->client_partials[ordinal], order) != RLC_LT) {
      bn_free(order);
      return RLC_ERR;
    }
    cursor += BENCH_SCALAR_BYTES;
    bn_add(session->full_scalars[ordinal],
           session->client_partials[ordinal],
           session->server_partials[ordinal]);
    bn_mod(session->full_scalars[ordinal],
           session->full_scalars[ordinal], order);
  }
  bn_free(order);
  return RLC_OK;
}

static void add_verify_metrics(server_metrics_t *server,
                               const bench_verify_metrics_t *metrics) {
  server->verifier.challenge_ns += metrics->challenge_ns;
  server->verifier.equation_ns += metrics->equation_ns;
  server->verifier.msm_ns += metrics->msm_ns;
  server->verifier.equations += metrics->equations;
  server->verifier.msm_calls += metrics->msm_calls;
  server->verifier.fallbacks += metrics->fallbacks;
}

static int verify_itemwise(server_session_t *session, unsigned first,
                           unsigned count, server_metrics_t *metrics,
                           uint32_t *invalid, unsigned *invalid_count) {
  unsigned i;
  *invalid_count = 0;
  for (i = 0; i < count; i++) {
    unsigned ordinal = first + i;
    bench_verify_metrics_t item = {0};
    int client_ok = bench_joint_partial_verify(
        session->client_partials[ordinal], session->client_nonces[ordinal],
        session->transcript.client_public_keys[ordinal],
        session->challenges[ordinal], &item);
    int full_ok = bench_joint_full_verify(
        session->full_scalars[ordinal], session->client_nonces[ordinal],
        session->server_nonces[ordinal],
        session->transcript.statements[ordinal],
        session->transcript.joint_public_keys[ordinal],
        session->challenges[ordinal], &item);
    add_verify_metrics(metrics, &item);
    if (!client_ok || !full_ok) invalid[(*invalid_count)++] = ordinal;
  }
  return *invalid_count == 0 ? RLC_OK : RLC_ERR;
}

static int verify_aggregate(server_session_t *session,
                            const bench_options_t *options,
                            server_metrics_t *metrics,
                            uint8_t client_salt[BENCH_SALT_BYTES],
                            uint8_t full_salt[BENCH_SALT_BYTES],
                            uint32_t *invalid, unsigned *invalid_count) {
  uint8_t random[BENCH_SALT_BYTES];
  bench_verify_metrics_t aggregate = {0};
  int client_ok;
  int full_ok;
  if (bench_random_salt(random) != RLC_OK ||
      bench_derive_verifier_salt(
          client_salt, "CLIENT-PARTIAL", session->transcript.parent_sid,
          session->transcript.batch_digest, random) != RLC_OK ||
      bench_random_salt(random) != RLC_OK ||
      bench_derive_verifier_salt(
          full_salt, "FULL-PRESIGNATURE", session->transcript.parent_sid,
          session->transcript.batch_digest, random) != RLC_OK) return RLC_ERR;
  client_ok = bench_joint_batch_verify(
      BENCH_EQUATION_CLIENT_PARTIAL, &session->transcript, options->mode,
      0, options->count, session->client_nonces, session->server_nonces,
      session->challenges, session->server_partials,
      session->client_partials, session->full_scalars, client_salt,
      &aggregate);
  full_ok = bench_joint_batch_verify(
      BENCH_EQUATION_FULL_PRESIGNATURE, &session->transcript, options->mode,
      0, options->count, session->client_nonces, session->server_nonces,
      session->challenges, session->server_partials,
      session->client_partials, session->full_scalars, full_salt,
      &aggregate);
  add_verify_metrics(metrics, &aggregate);
  if (client_ok && full_ok) {
    *invalid_count = 0;
    return RLC_OK;
  }
  metrics->verifier.fallbacks++;
  return verify_itemwise(session, 0, options->count, metrics,
                         invalid, invalid_count);
}

static uint8_t *build_status(const bench_options_t *options,
                             const server_session_t *session,
                             const uint8_t client_salt[BENCH_SALT_BYTES],
                             const uint8_t full_salt[BENCH_SALT_BYTES],
                             const uint32_t *invalid,
                             unsigned invalid_count, size_t *length) {
  uint8_t *frame;
  uint8_t *cursor;
  unsigned i;
  *length = BENCH_HEADER_SIZE + STATUS_CORE_BYTES +
            (size_t) invalid_count * 4;
  frame = calloc(1, *length);
  if (frame == NULL) return NULL;
  bench_write_header_sid(frame, BENCH_MSG_FINAL_STATUS, options->count,
                         options->pair_id, 0, options->execution_id,
                         session->transcript.parent_sid);
  cursor = frame + BENCH_HEADER_SIZE;
  memcpy(cursor, client_salt, BENCH_SALT_BYTES);
  cursor += BENCH_SALT_BYTES;
  memcpy(cursor, full_salt, BENCH_SALT_BYTES);
  cursor += BENCH_SALT_BYTES;
  write_u32(cursor, invalid_count);
  cursor += 4;
  for (i = 0; i < invalid_count; i++) {
    write_u32(cursor, invalid[i]);
    cursor += 4;
  }
  {
    uint32_t decoded[BENCH_MAX_ITEMS];
    unsigned decoded_count = 0;
    if (bench_decode_invalid_indices(
            frame + BENCH_HEADER_SIZE + 2 * BENCH_SALT_BYTES,
            *length - BENCH_HEADER_SIZE - 2 * BENCH_SALT_BYTES,
            options->count, decoded, BENCH_MAX_ITEMS,
            &decoded_count) != RLC_OK || decoded_count != invalid_count) {
      free(frame);
      return NULL;
    }
  }
  return frame;
}

static int send_done(void *socket, const bench_options_t *options,
                     const server_session_t *session,
                     const uint8_t status_digest[BENCH_DIGEST_BYTES],
                     server_metrics_t *metrics) {
  uint8_t frame[BENCH_HEADER_SIZE + BENCH_DIGEST_BYTES];
  uint8_t completion[BENCH_DIGEST_BYTES];
  uint8_t *ack = NULL;
  size_t ack_length = 0;
  bench_header_t ack_header;
  if (bench_completion_digest(&session->transcript, status_digest,
                              completion) != RLC_OK) return RLC_ERR;
  bench_write_header_sid(frame, BENCH_MSG_DONE, options->count,
                         options->pair_id, 0, options->execution_id,
                         session->transcript.parent_sid);
  memcpy(frame + BENCH_HEADER_SIZE, completion, BENCH_DIGEST_BYTES);
  if (send_frame(socket, frame, sizeof(frame), metrics) != RLC_OK) {
    return RLC_ERR;
  }
  if (!options->pool_worker) return RLC_OK;

  if (bench_recv_frame(socket, &ack, &ack_length) != RLC_OK ||
      ack_length != BENCH_COMPLETION_FRAME_BYTES ||
      bench_read_header(ack, ack_length, &ack_header) != RLC_OK ||
      ack_header.type != BENCH_MSG_GATEWAY_COMPLETION_ACK ||
      ack_header.count != options->count ||
      ack_header.pair_id != options->pair_id ||
      ack_header.first_ordinal != 0 ||
      ack_header.execution_id != options->execution_id ||
      !bench_digest_equal(ack_header.sid, session->transcript.parent_sid) ||
      !bench_digest_equal(ack + BENCH_HEADER_SIZE, completion)) {
    free(ack);
    return RLC_ERR;
  }
  free(ack);
  return RLC_OK;
}

static int run_coalesced(tumbler_state_t state, void *socket,
                         const bench_options_t *options,
                         server_metrics_t *metrics,
                         const uint8_t server_key_proof[
                             BENCH_KEY_OWNERSHIP_PROOF_BYTES]) {
  server_session_t session;
  uint8_t *frame = NULL;
  uint8_t *received = NULL;
  uint8_t client_salt[BENCH_SALT_BYTES] = {0};
  uint8_t full_salt[BENCH_SALT_BYTES] = {0};
  uint8_t status_digest[BENCH_DIGEST_BYTES];
  uint32_t *invalid = NULL;
  unsigned invalid_count = 0;
  size_t length = 0;
  size_t received_length = 0;
  int verify_status;
  int status = RLC_ERR;
  long long started = bench_monotonic_ns();
  long long phase;
  memset(&session, 0, sizeof(session));
  if (allocate_session(&session, options, state->bob_ec_pk->pk,
                       state->tumbler_ec_pk->pk,
                       server_key_proof) != RLC_OK) goto cleanup;
  invalid = calloc(options->count, sizeof(*invalid));
  if (invalid == NULL) goto cleanup;

  phase = bench_monotonic_ns();
  if (receive_init(socket, options, &session, 0, options->count,
                   state->bob_ec_pk->pk, metrics) != RLC_OK) {
    goto abort_session;
  }
  metrics->verify_request_ns += bench_monotonic_ns() - phase;

  phase = bench_monotonic_ns();
  frame = build_commit(options, &session, 0, options->count, &length);
  if (frame == NULL || send_frame(socket, frame, length, metrics) != RLC_OK) {
    goto cleanup;
  }
  free(frame);
  frame = NULL;
  if (receive_expected(socket, BENCH_MSG_CLIENT_NONCE, options->count,
                       options->pair_id, 0, options->execution_id,
                       session.transcript.parent_sid, &received,
                       &received_length, metrics) != RLC_OK ||
      parse_nonce(options, &session, 0, options->count, received,
                  received_length) != RLC_OK) goto abort_session;
  free(received);
  received = NULL;
  frame = build_open(state, options, &session, 0, options->count, &length);
  if (frame == NULL || send_frame(socket, frame, length, metrics) != RLC_OK) {
    goto cleanup;
  }
  free(frame);
  frame = NULL;
  metrics->generate_response_ns += bench_monotonic_ns() - phase;

  phase = bench_monotonic_ns();
  if (receive_expected(socket, BENCH_MSG_CLIENT_FINAL, options->count,
                       options->pair_id, 0, options->execution_id,
                       session.transcript.parent_sid, &received,
                       &received_length, metrics) != RLC_OK ||
      parse_final(options, &session, 0, options->count, received,
                  received_length) != RLC_OK) goto abort_session;
  free(received);
  received = NULL;
  if (bench_mode_uses_msm(options->mode)) {
    verify_status = verify_aggregate(&session, options, metrics,
                                     client_salt, full_salt, invalid,
                                     &invalid_count);
    frame = build_status(options, &session, client_salt, full_salt,
                         invalid, invalid_count, &length);
    if (frame == NULL || send_frame(socket, frame, length, metrics) != RLC_OK ||
        bench_status_digest(frame + BENCH_HEADER_SIZE,
                            length - BENCH_HEADER_SIZE,
                            status_digest) != RLC_OK) goto cleanup;
    free(frame);
    frame = NULL;
    if (verify_status != RLC_OK) goto cleanup;
    printf("SERVER_VERIFIER_AUDIT\t%s\t%u\t%u\t",
           bench_mode_name(options->mode), options->pair_id, options->count);
    print_hex(client_salt, BENCH_SALT_BYTES);
    printf("\t");
    print_hex(full_salt, BENCH_SALT_BYTES);
    printf("\t");
    print_hex(session.transcript.batch_digest, BENCH_DIGEST_BYTES);
    printf("\n");
  } else {
    if (verify_itemwise(&session, 0, options->count, metrics,
                        invalid, &invalid_count) != RLC_OK ||
        bench_status_digest(NULL, 0, status_digest) != RLC_OK) {
      goto abort_session;
    }
  }
  metrics->verify_final_ns += bench_monotonic_ns() - phase;
  if (send_done(socket, options, &session, status_digest, metrics) != RLC_OK) {
    goto cleanup;
  }
  metrics->sessions++;
  metrics->protocol_wall_ns += bench_monotonic_ns() - started;
  status = RLC_OK;
  goto cleanup;

abort_session:
  send_abort(socket, options, session.transcript.parent_sid, metrics);
cleanup:
  free(frame);
  free(received);
  free(invalid);
  free_session(&session);
  return status;
}

static int run_pipelined(tumbler_state_t state, void *socket,
                         const bench_options_t *options,
                         server_metrics_t *metrics,
                         const uint8_t server_key_proof[
                             BENCH_KEY_OWNERSHIP_PROOF_BYTES]) {
  server_session_t session;
  uint8_t **frames = NULL;
  uint8_t status_digest[BENCH_DIGEST_BYTES];
  uint32_t invalid[1];
  unsigned invalid_count;
  unsigned i;
  int status = RLC_ERR;
  long long started = bench_monotonic_ns();
  long long phase;
  memset(&session, 0, sizeof(session));
  if (allocate_session(&session, options, state->bob_ec_pk->pk,
                       state->tumbler_ec_pk->pk,
                       server_key_proof) != RLC_OK) goto cleanup;
  frames = calloc(options->count, sizeof(*frames));
  if (frames == NULL) goto cleanup;

  phase = bench_monotonic_ns();
  for (i = 0; i < options->count; i++) {
    if (receive_init(socket, options, &session, i, 1,
                     state->bob_ec_pk->pk, metrics) != RLC_OK) {
      goto abort_session;
    }
  }
  metrics->verify_request_ns += bench_monotonic_ns() - phase;
  phase = bench_monotonic_ns();
  for (i = 0; i < options->count; i++) {
    size_t length;
    frames[i] = build_commit(options, &session, i, 1, &length);
    if (frames[i] == NULL ||
        send_frame(socket, frames[i], length, metrics) != RLC_OK) goto cleanup;
    free(frames[i]);
    frames[i] = NULL;
  }
  for (i = 0; i < options->count; i++) {
    size_t length = 0;
    if (receive_expected(
            socket, BENCH_MSG_CLIENT_NONCE, 1, options->pair_id, i,
            options->execution_id,
            bench_active_sid(&session.transcript, options->mode, i),
            &frames[i], &length, metrics) != RLC_OK ||
        parse_nonce(options, &session, i, 1, frames[i], length) != RLC_OK) {
      goto abort_session;
    }
    free(frames[i]);
    frames[i] = NULL;
  }
  for (i = 0; i < options->count; i++) {
    size_t length;
    frames[i] = build_open(state, options, &session, i, 1, &length);
    if (frames[i] == NULL ||
        send_frame(socket, frames[i], length, metrics) != RLC_OK) goto cleanup;
    free(frames[i]);
    frames[i] = NULL;
  }
  metrics->generate_response_ns += bench_monotonic_ns() - phase;
  phase = bench_monotonic_ns();
  for (i = 0; i < options->count; i++) {
    size_t length = 0;
    if (receive_expected(
            socket, BENCH_MSG_CLIENT_FINAL, 1, options->pair_id, i,
            options->execution_id,
            bench_active_sid(&session.transcript, options->mode, i),
            &frames[i], &length, metrics) != RLC_OK ||
        parse_final(options, &session, i, 1, frames[i], length) != RLC_OK ||
        verify_itemwise(&session, i, 1, metrics,
                        invalid, &invalid_count) != RLC_OK) {
      goto abort_session;
    }
    free(frames[i]);
    frames[i] = NULL;
  }
  if (bench_status_digest(NULL, 0, status_digest) != RLC_OK ||
      send_done(socket, options, &session, status_digest, metrics) != RLC_OK) {
    goto cleanup;
  }
  metrics->verify_final_ns += bench_monotonic_ns() - phase;
  metrics->sessions += options->count;
  metrics->protocol_wall_ns += bench_monotonic_ns() - started;
  status = RLC_OK;
  goto cleanup;

abort_session:
  send_abort(socket, options, session.transcript.parent_sid, metrics);
cleanup:
  if (frames != NULL) {
    for (i = 0; i < options->count; i++) free(frames[i]);
  }
  free(frames);
  free_session(&session);
  return status;
}

static void print_server_metrics(const bench_options_t *options,
                                 const server_metrics_t *metrics) {
  printf("SERVER_RESULT\t%s\t%u\t%u\t%u\t%lld\t%lld\t%lld\n",
         bench_mode_name(options->mode), options->pair_id, options->count,
         metrics->sessions, metrics->verify_request_ns,
         metrics->generate_response_ns, metrics->verify_final_ns);
  printf("SERVER_VERIFIER_RESULT\t%s\t%u\t%u\t%lld\t%lld\t%u\t%u\t%u\n",
         bench_mode_name(options->mode), options->pair_id, options->count,
         metrics->verifier.challenge_ns, metrics->verifier.msm_ns,
         metrics->verifier.equations, metrics->verifier.msm_calls,
         metrics->verifier.fallbacks);
  printf("SERVER_RESOURCE_RESULT\t%s\t%u\t%u\t%lld\t%lld\t%lld\t%lld\t%ld\t%ld\t%ld\t%lld\t%lld\n",
         bench_mode_name(options->mode), options->pair_id, options->count,
         metrics->protocol_wall_ns, metrics->setup_ns, metrics->user_cpu_ns,
         metrics->system_cpu_ns, metrics->max_rss_kb,
         metrics->voluntary_context_switches,
         metrics->involuntary_context_switches, metrics->scheduler_wait_ns,
         metrics->scheduler_slices);
  printf("SERVER_TRANSPORT_RESULT\t%s\t%u\t%u\t%zu\t%zu\t%u\t%u\t%u\t%u\n",
         bench_mode_name(options->mode), options->pair_id, options->count,
         metrics->bytes_sent, metrics->bytes_received, metrics->sent_frames,
         metrics->received_frames, metrics->send_calls, metrics->receive_calls);
#ifdef BENCH_ALLOCATION_PROFILE
  {
    bench_allocation_metrics_t current;
    bench_allocation_metrics_read(&current);
    printf("SERVER_ALLOCATION_RESULT\t%s\t%u\t%u\t%llu\t%llu\t%llu\t%llu\t%llu\n",
           bench_mode_name(options->mode), options->pair_id, options->count,
           current.malloc_calls - server_allocation_previous.malloc_calls,
           current.calloc_calls - server_allocation_previous.calloc_calls,
           current.realloc_calls - server_allocation_previous.realloc_calls,
           current.free_calls - server_allocation_previous.free_calls,
           current.requested_bytes - server_allocation_previous.requested_bytes);
    server_allocation_previous = current;
  }
#endif
  fflush(stdout);
}

int main(int argc, char **argv) {
  int result_status = RLC_OK;
  void *context = NULL;
  void *socket = NULL;
  tumbler_state_t state;
  bench_options_t options;
  bench_zap_service_t zap_service;
  server_metrics_t metrics;
  char endpoint[256] = {0};
  long long process_started = bench_monotonic_ns();
  int linger = 0;
  int timeout_ms;
  char routing_id[96] = {0};
  bench_resource_mark_t before;
  bench_resource_mark_t after;
  bench_resource_mark_t delta;
  bench_resource_mark_t pool_before;
  bench_resource_mark_t pool_after;
  bench_resource_mark_t pool_delta;
  unsigned pool_sessions = 0;
  long long pool_setup_ns = 0;
  uint8_t server_key_proof[BENCH_KEY_OWNERSHIP_PROOF_BYTES] = {0};

  memset(&metrics, 0, sizeof(metrics));
  memset(&zap_service, 0, sizeof(zap_service));
  tumbler_state_null(state);
  if (bench_resource_mark(&pool_before) != RLC_OK ||
      bench_parse_options(argc, argv, &options) != RLC_OK || init() != RLC_OK) {
    return 1;
  }
  context = zmq_ctx_new();
  if (context == NULL ||
      (options.use_tcp && !options.use_gateway &&
       bench_zap_start(&zap_service, context, &options) != RLC_OK)) {
    result_status = RLC_ERR;
    goto cleanup;
  }
  socket = zmq_socket(context, ZMQ_DEALER);
  timeout_ms = (int) options.io_timeout_ms;
  if (socket != NULL && options.use_gateway) {
    int written = options.pool_worker
                      ? snprintf(routing_id, sizeof(routing_id), "worker:%u",
                                 options.pool_worker_index)
                      : snprintf(routing_id, sizeof(routing_id), "pair:%u:%llu",
                                 options.pair_id,
                                 (unsigned long long) options.execution_id);
    if (written <= 0 || (size_t) written >= sizeof(routing_id) ||
        zmq_setsockopt(socket, ZMQ_ROUTING_ID, routing_id,
                       (size_t) written) != 0) {
      result_status = RLC_ERR;
      goto cleanup;
    }
  }
  if (socket == NULL ||
      zmq_setsockopt(socket, ZMQ_LINGER, &linger, sizeof(linger)) != 0 ||
      zmq_setsockopt(socket, ZMQ_RCVTIMEO, &timeout_ms, sizeof(timeout_ms)) != 0 ||
      zmq_setsockopt(socket, ZMQ_SNDTIMEO, &timeout_ms, sizeof(timeout_ms)) != 0 ||
      (options.use_tcp && !options.use_gateway &&
       bench_curve_configure_server(socket, &options) != RLC_OK) ||
      (!options.use_gateway &&
       bench_make_server_endpoint(endpoint, sizeof(endpoint), &options) != RLC_OK)) {
    result_status = RLC_ERR;
    goto cleanup;
  }
  if (options.use_gateway) {
    memcpy(endpoint, options.gateway_backend,
           strlen(options.gateway_backend) + 1);
  } else {
    bench_cleanup_endpoint(endpoint);
  }
  if ((options.use_gateway ? zmq_connect(socket, endpoint)
                           : zmq_bind(socket, endpoint)) != 0) {
    perror(options.use_gateway ? "zmq_connect gateway" : "zmq_bind");
    result_status = RLC_ERR;
    goto cleanup;
  }
  RLC_TRY {
    tumbler_state_new(state);
    if (generate_cl_params(state->cl_params) != RLC_OK ||
        read_keys_from_file_tumbler(state->tumbler_ec_sk,
                                    state->tumbler_ec_pk,
                                    state->tumbler_ps_sk,
                                    state->tumbler_ps_pk,
                                    state->tumbler_cl_sk,
                                    state->tumbler_cl_pk,
                                    state->alice_ec_pk,
                                    state->bob_ec_pk) != RLC_OK ||
        (options.host_key_fd >= 0 &&
         host_read_key(options.host_key_fd,state->tumbler_ec_sk->sk,
                       state->tumbler_ec_pk->pk) != RLC_OK) ||
        ((options.host_key_fd>=0) != (options.host_peer_key[0]!=0)) ||
        (options.host_peer_key[0] &&
         host_read_statement(state->bob_ec_pk->pk,options.host_peer_key,1,0)!=RLC_OK) ||
        bench_validate_secp256k1() != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    if (host_admit_address_keys(&options,BENCH_KEY_ROLE_RESPONDER)!=RLC_OK) RLC_THROW(ERR_NO_VALID);
    pool_setup_ns = bench_monotonic_ns() - process_started;
    metrics.setup_ns = pool_setup_ns;
#ifdef BENCH_ALLOCATION_PROFILE
    if (options.pool_worker) reset_server_allocation_baseline();
#endif
    if (options.use_gateway) {
      uint8_t registration[BENCH_HEADER_SIZE];
      bench_write_header(registration, BENCH_MSG_GATEWAY_REGISTER,
                         options.pool_worker ? 0 : options.count,
                         options.pool_worker ? options.pool_worker_index
                                             : options.pair_id,
                         0, options.pool_worker ? 0 : options.execution_id);
      if (bench_send_frame(socket, registration,
                           sizeof(registration)) != RLC_OK) {
        RLC_THROW(ERR_CAUGHT);
      }
    }
    if (options.pool_worker) {
      int shutdown = 0;
      int pool_failed = 0;
      while (!shutdown) {
        memset(&metrics, 0, sizeof(metrics));
        if (receive_assignment(socket, &options, &shutdown) != RLC_OK) {
          RLC_THROW(ERR_CAUGHT);
        }
        if (shutdown) break;
        if (bench_key_ownership_prove(
                server_key_proof, state->tumbler_ec_sk->sk,
                state->tumbler_ec_pk->pk, options.context_seed,
                BENCH_KEY_ROLE_RESPONDER, options.pair_id,
                options.context_epoch) != RLC_OK) {
          RLC_THROW(ERR_CAUGHT);
        }
        if (bench_resource_mark(&before) != RLC_OK) RLC_THROW(ERR_CAUGHT);
        if ((options.mode == BENCH_MODE_ORIGINAL_ITEMWISE
                 ? run_pipelined(state, socket, &options, &metrics,
                                 server_key_proof)
                 : run_coalesced(state, socket, &options, &metrics,
                                 server_key_proof)) != RLC_OK) {
          pool_failed = 1;
        }
        if (bench_resource_mark(&after) != RLC_OK) RLC_THROW(ERR_CAUGHT);
        bench_resource_delta(&before, &after, &delta);
        metrics.user_cpu_ns = delta.user_cpu_ns;
        metrics.system_cpu_ns = delta.system_cpu_ns;
        metrics.max_rss_kb = delta.max_rss_kb;
        metrics.voluntary_context_switches = delta.voluntary_context_switches;
        metrics.involuntary_context_switches =
            delta.involuntary_context_switches;
        metrics.scheduler_wait_ns = delta.scheduler_wait_ns;
        metrics.scheduler_slices = delta.scheduler_slices;
        metrics.setup_ns = 0;
        print_server_metrics(&options, &metrics);
        pool_sessions++;
      }
      if (bench_resource_mark(&pool_after) != RLC_OK) RLC_THROW(ERR_CAUGHT);
      bench_resource_delta(&pool_before, &pool_after, &pool_delta);
      printf("SERVER_POOL_RESULT\t%u\t%u\t%lld\t%lld\t%lld\t%ld\t%ld\t%ld\t%lld\t%lld\n",
             options.pool_worker_index, pool_sessions, pool_setup_ns,
             pool_delta.user_cpu_ns, pool_delta.system_cpu_ns,
             pool_delta.max_rss_kb, pool_delta.voluntary_context_switches,
             pool_delta.involuntary_context_switches,
             pool_delta.scheduler_wait_ns, pool_delta.scheduler_slices);
      fflush(stdout);
      if (pool_failed) result_status = RLC_ERR;
    } else {
      if (bench_key_ownership_prove(
              server_key_proof, state->tumbler_ec_sk->sk,
              state->tumbler_ec_pk->pk, options.context_seed,
              BENCH_KEY_ROLE_RESPONDER, options.pair_id,
              options.context_epoch) != RLC_OK) {
        RLC_THROW(ERR_CAUGHT);
      }
      if (bench_resource_mark(&before) != RLC_OK) RLC_THROW(ERR_CAUGHT);
      if ((options.mode == BENCH_MODE_ORIGINAL_ITEMWISE
               ? run_pipelined(state, socket, &options, &metrics,
                               server_key_proof)
               : run_coalesced(state, socket, &options, &metrics,
                               server_key_proof)) != RLC_OK) {
        result_status = RLC_ERR;
      }
      if (bench_resource_mark(&after) != RLC_OK) {
        result_status = RLC_ERR;
      } else {
        bench_resource_delta(&before, &after, &delta);
        metrics.user_cpu_ns = delta.user_cpu_ns;
        metrics.system_cpu_ns = delta.system_cpu_ns;
        metrics.max_rss_kb = delta.max_rss_kb;
        metrics.voluntary_context_switches = delta.voluntary_context_switches;
        metrics.involuntary_context_switches =
            delta.involuntary_context_switches;
        metrics.scheduler_wait_ns = delta.scheduler_wait_ns;
        metrics.scheduler_slices = delta.scheduler_slices;
      }
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    if (state != NULL) tumbler_state_free(state);
  }

cleanup:
  if (socket != NULL) zmq_close(socket);
  if (!options.use_gateway) bench_cleanup_endpoint(endpoint);
  if (options.use_tcp && !options.use_gateway) bench_zap_stop(&zap_service);
  if (context != NULL) zmq_ctx_destroy(context);
  host_release_address_keys(&options);
  clean();
  if (result_status != RLC_OK) return 1;
  if (!options.pool_worker) print_server_metrics(&options, &metrics);
  return 0;
}
