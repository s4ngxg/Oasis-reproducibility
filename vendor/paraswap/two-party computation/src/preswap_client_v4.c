#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "zmq.h"
#include "bob.h"
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

typedef struct {
  bench_transcript_t transcript;
  uint8_t client_key_proof[BENCH_KEY_OWNERSHIP_PROOF_BYTES];
  ec_t *commitments;
  ec_t *client_nonces;
  ec_t *server_nonces;
  bn_t *client_nonce_scalars;
  bn_t *openings;
  bn_t *challenges;
  bn_t *server_partials;
  bn_t *client_partials;
  bn_t *full_scalars;
} client_session_t;

typedef struct {
  uint8_t *commit;
  uint8_t *open;
} pipeline_item_t;

static void print_hex(const uint8_t *value, size_t length) {
  size_t i;
  for (i = 0; i < length; i++) printf("%02x", value[i]);
}

static int send_frame(void *socket, const uint8_t *frame, size_t length,
                      bench_result_t *result) {
  if (bench_send_frame(socket, frame, length) != RLC_OK) return RLC_ERR;
  result->sent_frames++;
  result->send_calls++;
  result->bytes_sent += length;
  return RLC_OK;
}

static int receive_expected(
    void *socket, bench_msg_type_t type, unsigned count, unsigned pair_id,
    unsigned first_ordinal, uint64_t execution_id,
    const uint8_t sid[BENCH_DIGEST_BYTES], uint8_t **frame, size_t *length,
    bench_result_t *result) {
  bench_header_t header;
  if (bench_recv_frame(socket, frame, length) != RLC_OK) return RLC_ERR;
  result->received_frames++;
  result->receive_calls++;
  result->bytes_received += *length;
  if (bench_read_header(*frame, *length, &header) != RLC_OK ||
      header.type != (uint32_t) type || header.count != count ||
      header.pair_id != pair_id || header.first_ordinal != first_ordinal ||
      header.execution_id != execution_id ||
      !bench_digest_equal(header.sid, sid)) {
    free(*frame);
    *frame = NULL;
    return RLC_ERR;
  }
  return RLC_OK;
}

static int receive_done(void *socket, const bench_options_t *options,
                        const bench_transcript_t *transcript,
                        const uint8_t expected[BENCH_DIGEST_BYTES],
                        bench_result_t *result) {
  uint8_t *frame = NULL;
  size_t length = 0;
  unsigned attempt;
  int acknowledgement_timeout;
  int original_timeout;
  int status = RLC_ERR;
  size_t timeout_length = sizeof(original_timeout);
  acknowledgement_timeout = (int) options->completion_ack_timeout_ms;
  if (zmq_getsockopt(socket, ZMQ_RCVTIMEO, &original_timeout,
                     &timeout_length) != 0 ||
      zmq_setsockopt(socket, ZMQ_RCVTIMEO, &acknowledgement_timeout,
                     sizeof(acknowledgement_timeout)) != 0) return RLC_ERR;

  for (attempt = 0; attempt <= options->completion_retries; attempt++) {
    if (attempt != 0) {
      uint8_t query[BENCH_COMPLETION_FRAME_BYTES];
      struct timespec delay;
      bench_write_header_sid(query, BENCH_MSG_COMPLETION_QUERY, options->count,
                             options->pair_id, 0, options->execution_id,
                             transcript->parent_sid);
      memcpy(query + BENCH_HEADER_SIZE, expected, BENCH_DIGEST_BYTES);
      if (options->completion_retry_delay_ms != 0) {
        delay.tv_sec = options->completion_retry_delay_ms / 1000;
        delay.tv_nsec = (long) (options->completion_retry_delay_ms % 1000) *
                        1000000L;
        while (nanosleep(&delay, &delay) != 0) {
          if (errno != EINTR) break;
        }
      }
      if (send_frame(socket, query, sizeof(query), result) != RLC_OK) break;
    }
    if (receive_expected(socket, BENCH_MSG_DONE, options->count,
                         options->pair_id, 0, options->execution_id,
                         transcript->parent_sid, &frame, &length,
                         result) == RLC_OK &&
        length == BENCH_COMPLETION_FRAME_BYTES &&
        bench_digest_equal(frame + BENCH_HEADER_SIZE, expected)) {
      status = RLC_OK;
      free(frame);
      frame = NULL;
      break;
    }
    free(frame);
    frame = NULL;
  }
  free(frame);
  (void) zmq_setsockopt(socket, ZMQ_RCVTIMEO, &original_timeout,
                        sizeof(original_timeout));
  return status;
}

static void abort_and_wait(void *socket, const bench_options_t *options,
                           const uint8_t sid[BENCH_DIGEST_BYTES],
                           bench_result_t *result) {
  uint8_t frame[BENCH_HEADER_SIZE];
  uint8_t *acknowledgement = NULL;
  size_t acknowledgement_length = 0;
  bench_write_header_sid(frame, BENCH_MSG_ABORT, options->count,
                         options->pair_id, 0, options->execution_id, sid);
  if (send_frame(socket, frame, sizeof(frame), result) == RLC_OK) {
    (void) receive_expected(
        socket, BENCH_MSG_ABORT, options->count, options->pair_id, 0,
        options->execution_id, sid, &acknowledgement,
        &acknowledgement_length, result);
  }
  free(acknowledgement);
}

static int allocate_session(client_session_t *session,
                            const bench_options_t *options,
                            const ec_t base_client_public,
                            const ec_t base_server_public,
                            const uint8_t client_key_proof[
                                BENCH_KEY_OWNERSHIP_PROOF_BYTES]) {
  unsigned i;
  if (session == NULL) return RLC_ERR;
  memset(session, 0, sizeof(*session));
  if (client_key_proof == NULL) return RLC_ERR;
  if (bench_transcript_init(&session->transcript, options, base_client_public,
                            base_server_public) != RLC_OK) return RLC_ERR;
  memcpy(session->client_key_proof, client_key_proof,
         BENCH_KEY_OWNERSHIP_PROOF_BYTES);
  session->commitments = calloc(options->count, sizeof(ec_t));
  session->client_nonces = calloc(options->count, sizeof(ec_t));
  session->server_nonces = calloc(options->count, sizeof(ec_t));
  session->client_nonce_scalars = calloc(options->count, sizeof(bn_t));
  session->openings = calloc(options->count, sizeof(bn_t));
  session->challenges = calloc(options->count, sizeof(bn_t));
  session->server_partials = calloc(options->count, sizeof(bn_t));
  session->client_partials = calloc(options->count, sizeof(bn_t));
  session->full_scalars = calloc(options->count, sizeof(bn_t));
  if (session->commitments == NULL || session->client_nonces == NULL ||
      session->server_nonces == NULL || session->client_nonce_scalars == NULL ||
      session->openings == NULL || session->challenges == NULL ||
      session->server_partials == NULL || session->client_partials == NULL ||
      session->full_scalars == NULL) return RLC_ERR;
  for (i = 0; i < options->count; i++) {
    ec_null(session->commitments[i]);
    ec_null(session->client_nonces[i]);
    ec_null(session->server_nonces[i]);
    bn_null(session->client_nonce_scalars[i]);
    bn_null(session->openings[i]);
    bn_null(session->challenges[i]);
    bn_null(session->server_partials[i]);
    bn_null(session->client_partials[i]);
    bn_null(session->full_scalars[i]);
    ec_new(session->commitments[i]);
    ec_new(session->client_nonces[i]);
    ec_new(session->server_nonces[i]);
    bn_new(session->client_nonce_scalars[i]);
    bn_new(session->openings[i]);
    bn_new(session->challenges[i]);
    bn_new(session->server_partials[i]);
    bn_new(session->client_partials[i]);
    bn_new(session->full_scalars[i]);
  }
  return RLC_OK;
}

static void free_session(client_session_t *session) {
  unsigned i;
  if (session == NULL) return;
  for (i = 0; i < session->transcript.count; i++) {
    ec_free(session->commitments[i]);
    ec_free(session->client_nonces[i]);
    ec_free(session->server_nonces[i]);
    bn_free(session->client_nonce_scalars[i]);
    bn_free(session->openings[i]);
    bn_free(session->challenges[i]);
    bn_free(session->server_partials[i]);
    bn_free(session->client_partials[i]);
    bn_free(session->full_scalars[i]);
  }
  free(session->commitments);
  free(session->client_nonces);
  free(session->server_nonces);
  free(session->client_nonce_scalars);
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

static void write_item_sid_prefix(uint8_t **cursor, bench_mode_t mode,
                                  const bench_transcript_t *transcript,
                                  unsigned ordinal) {
  if (bench_mode_has_item_sessions(mode)) {
    memcpy(*cursor, bench_active_sid(transcript, mode, ordinal),
           BENCH_ITEM_SESSION_BYTES);
    *cursor += BENCH_ITEM_SESSION_BYTES;
  }
}

static int check_item_sid_prefix(const uint8_t **cursor, bench_mode_t mode,
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

static const uint8_t *envelope_sid(const client_session_t *session,
                                   bench_mode_t mode, unsigned ordinal) {
  return mode == BENCH_MODE_ORIGINAL_ITEMWISE
             ? bench_active_sid(&session->transcript, mode, ordinal)
             : session->transcript.parent_sid;
}

static uint8_t *build_init(const bench_options_t *options,
                           const client_session_t *session,
                           unsigned first, unsigned count, size_t *length) {
  size_t stride = BENCH_DIGEST_BYTES + item_sid_prefix(options->mode);
  size_t proof_bytes = first == 0 ? BENCH_KEY_OWNERSHIP_PROOF_BYTES : 0;
  uint8_t *frame;
  uint8_t *cursor;
  unsigned i;
  *length = BENCH_HEADER_SIZE + INIT_PREFIX_BYTES + proof_bytes +
            (size_t) count * stride;
  frame = calloc(1, *length);
  if (frame == NULL) return NULL;
  bench_write_header_sid(frame, BENCH_MSG_BATCH_INIT, count, options->pair_id,
                         first, options->execution_id,
                         envelope_sid(session, options->mode, first));
  cursor = frame + BENCH_HEADER_SIZE;
  memcpy(cursor, session->transcript.context_digest, BENCH_DIGEST_BYTES);
  cursor += BENCH_DIGEST_BYTES;
  memcpy(cursor, session->transcript.batch_digest, BENCH_DIGEST_BYTES);
  cursor += BENCH_DIGEST_BYTES;
  if (proof_bytes != 0) {
    memcpy(cursor, session->client_key_proof,
           BENCH_KEY_OWNERSHIP_PROOF_BYTES);
    if (options->inject_bad_preparation_proof) cursor[0] ^= 1u;
    cursor += BENCH_KEY_OWNERSHIP_PROOF_BYTES;
  }
  for (i = 0; i < count; i++) {
    unsigned ordinal = first + i;
    write_item_sid_prefix(&cursor, options->mode, &session->transcript,
                          ordinal);
    memcpy(cursor, session->transcript.item_digests +
                       (size_t) ordinal * BENCH_DIGEST_BYTES,
           BENCH_DIGEST_BYTES);
    cursor += BENCH_DIGEST_BYTES;
  }
  return frame;
}

static int parse_commit(const bench_options_t *options,
                        client_session_t *session, unsigned first,
                        unsigned count, const uint8_t *frame, size_t length,
                        const ec_t base_server_public) {
  size_t stride = item_sid_prefix(options->mode) + COMMIT_CORE_BYTES;
  size_t proof_bytes = first == 0 ? BENCH_KEY_OWNERSHIP_PROOF_BYTES : 0;
  const uint8_t *cursor = frame + BENCH_HEADER_SIZE;
  unsigned i;
  if (length != BENCH_HEADER_SIZE + proof_bytes +
                    (size_t) count * stride) return RLC_ERR;
  if (proof_bytes != 0) {
    if (bench_key_ownership_verify(
            cursor, base_server_public, options->context_seed,
            BENCH_KEY_ROLE_RESPONDER, options->pair_id,
            options->context_epoch) != RLC_OK) {
      return RLC_ERR;
    }
    cursor += BENCH_KEY_OWNERSHIP_PROOF_BYTES;
  }
  for (i = 0; i < count; i++) {
    unsigned ordinal = first + i;
    if (check_item_sid_prefix(&cursor, options->mode, &session->transcript,
                           ordinal) != RLC_OK) return RLC_ERR;
    ec_read_bin(session->commitments[ordinal], cursor, BENCH_POINT_BYTES);
    cursor += BENCH_POINT_BYTES;
  }
  return RLC_OK;
}

static uint8_t *build_client_nonce(const bench_options_t *options,
                                   client_session_t *session, unsigned first,
                                   unsigned count, bench_result_t *result,
                                   size_t *length) {
  size_t stride = item_sid_prefix(options->mode) + NONCE_CORE_BYTES;
  uint8_t *frame;
  uint8_t *cursor;
  bn_t order;
  unsigned i;
  long long started = bench_monotonic_ns();
  bn_null(order);
  bn_new(order);
  ec_curve_get_ord(order);
  *length = BENCH_HEADER_SIZE + (size_t) count * stride;
  frame = calloc(1, *length);
  if (frame == NULL) {
    bn_free(order);
    return NULL;
  }
  bench_write_header_sid(frame, BENCH_MSG_CLIENT_NONCE, count,
                         options->pair_id, first, options->execution_id,
                         envelope_sid(session, options->mode, first));
  cursor = frame + BENCH_HEADER_SIZE;
  for (i = 0; i < count; i++) {
    unsigned ordinal = first + i;
    do {
      bn_rand_mod(session->client_nonce_scalars[ordinal], order);
    } while (bn_is_zero(session->client_nonce_scalars[ordinal]));
    ec_mul_gen(session->client_nonces[ordinal],
               session->client_nonce_scalars[ordinal]);
    write_item_sid_prefix(&cursor, options->mode, &session->transcript,
                          ordinal);
    ec_write_bin(cursor, BENCH_POINT_BYTES, session->client_nonces[ordinal], 1);
    cursor += BENCH_POINT_BYTES;
  }
  bn_free(order);
  result->request_sign_ns += bench_monotonic_ns() - started;
  return frame;
}

static int prepare_final_item(bob_state_t state,
                              const bench_options_t *options,
                              client_session_t *session, unsigned ordinal,
                              bench_result_t *result) {
  bn_t client_secret;
  bn_t order;
  long long started;
  int status = RLC_ERR;
  bn_null(client_secret);
  bn_null(order);
  bn_new(client_secret);
  bn_new(order);
  ec_curve_get_ord(order);
  if (host_item_secret(client_secret,state->bob_ec_sk->sk,options,ordinal,
                       BENCH_KEY_ROLE_INITIATOR)!=RLC_OK) goto cleanup;
  started = bench_monotonic_ns();
  if (bench_joint_partial_sign(session->client_partials[ordinal],
                               session->client_nonce_scalars[ordinal],
                               client_secret,
                               session->challenges[ordinal]) != RLC_OK) {
    goto cleanup;
  }
  bn_add(session->full_scalars[ordinal],
         session->client_partials[ordinal],
         session->server_partials[ordinal]);
  bn_mod(session->full_scalars[ordinal],
         session->full_scalars[ordinal], order);
  result->final_sign_ns += bench_monotonic_ns() - started;
  status = RLC_OK;
cleanup:
  bn_free(client_secret);
  bn_free(order);
  return status;
}

static int parse_open_and_prepare(
    bob_state_t state, const bench_options_t *options,
    client_session_t *session, unsigned first, unsigned count,
    const uint8_t *frame, size_t length, bench_result_t *result) {
  size_t stride = item_sid_prefix(options->mode) + OPEN_CORE_BYTES;
  const uint8_t *cursor = frame + BENCH_HEADER_SIZE;
  unsigned i;
  if (length != BENCH_HEADER_SIZE + (size_t) count * stride) return RLC_ERR;
  for (i = 0; i < count; i++) {
    unsigned ordinal = first + i;
    long long started;
    if (check_item_sid_prefix(&cursor, options->mode, &session->transcript,
                           ordinal) != RLC_OK) return RLC_ERR;
    ec_read_bin(session->server_nonces[ordinal], cursor, BENCH_POINT_BYTES);
    cursor += BENCH_POINT_BYTES;
    bn_read_bin(session->openings[ordinal], cursor, BENCH_SCALAR_BYTES);
    cursor += BENCH_SCALAR_BYTES;
    bn_read_bin(session->server_partials[ordinal], cursor, BENCH_SCALAR_BYTES);
    cursor += BENCH_SCALAR_BYTES;
    started = bench_monotonic_ns();
    if (!bench_pedersen_verify(
            session->commitments[ordinal], session->openings[ordinal],
            bench_active_sid(&session->transcript, options->mode, ordinal),
            session->transcript.item_digests +
                (size_t) ordinal * BENCH_DIGEST_BYTES,
            session->server_nonces[ordinal]) ||
        bench_joint_challenge(
            session->challenges[ordinal],
            session->transcript.message_digests +
                (size_t) ordinal * BENCH_DIGEST_BYTES,
            session->client_nonces[ordinal], session->server_nonces[ordinal],
            session->transcript.statements[ordinal]) != RLC_OK) {
      return RLC_ERR;
    }
    result->response_preverify_ns += bench_monotonic_ns() - started;
    if (prepare_final_item(state, options, session, ordinal, result) != RLC_OK) {
      return RLC_ERR;
    }
  }
  return RLC_OK;
}

static void add_verify_metrics(bench_result_t *result,
                               const bench_verify_metrics_t *metrics) {
  result->verifier_challenge_ns += metrics->challenge_ns;
  result->verifier_msm_ns += metrics->msm_ns;
  result->verifier_equations += metrics->equations;
  result->verifier_msm_calls += metrics->msm_calls;
  result->verifier_fallbacks += metrics->fallbacks;
}

static int verify_server_vector(const bench_options_t *options,
                                client_session_t *session,
                                bench_result_t *result,
                                uint8_t verifier_salt[BENCH_SALT_BYTES]) {
  bench_verify_metrics_t metrics = {0};
  unsigned i;
  long long started = bench_monotonic_ns();
  if (bench_mode_uses_msm(options->mode)) {
    uint8_t random[BENCH_SALT_BYTES];
    if (bench_random_salt(random) != RLC_OK ||
        bench_derive_verifier_salt(
            verifier_salt, "SERVER-PARTIAL", session->transcript.parent_sid,
            session->transcript.batch_digest, random) != RLC_OK ||
        !bench_joint_batch_verify(
            BENCH_EQUATION_SERVER_PARTIAL, &session->transcript,
            options->mode, 0, options->count, session->client_nonces,
            session->server_nonces, session->challenges,
            session->server_partials, session->client_partials,
            session->full_scalars, verifier_salt, &metrics)) {
      metrics.fallbacks++;
      for (i = 0; i < options->count; i++) {
        if (!bench_joint_partial_verify(
                session->server_partials[i], session->server_nonces[i],
                session->transcript.server_public_keys[i],
                session->challenges[i], NULL)) break;
      }
      add_verify_metrics(result, &metrics);
      return RLC_ERR;
    }
  } else {
    for (i = 0; i < options->count; i++) {
      if (!bench_joint_partial_verify(
              session->server_partials[i], session->server_nonces[i],
              session->transcript.server_public_keys[i],
              session->challenges[i], &metrics)) return RLC_ERR;
    }
  }
  add_verify_metrics(result, &metrics);
  result->response_preverify_ns += bench_monotonic_ns() - started;
  return RLC_OK;
}

static uint8_t *build_final(const bench_options_t *options,
                            const client_session_t *session,
                            unsigned first, unsigned count, size_t *length) {
  size_t stride = item_sid_prefix(options->mode) + FINAL_CORE_BYTES;
  uint8_t *frame;
  uint8_t *cursor;
  unsigned i;
  *length = BENCH_HEADER_SIZE + (size_t) count * stride;
  frame = calloc(1, *length);
  if (frame == NULL) return NULL;
  bench_write_header_sid(frame, BENCH_MSG_CLIENT_FINAL, count,
                         options->pair_id, first, options->execution_id,
                         envelope_sid(session, options->mode, first));
  cursor = frame + BENCH_HEADER_SIZE;
  for (i = 0; i < count; i++) {
    unsigned ordinal = first + i;
    write_item_sid_prefix(&cursor, options->mode, &session->transcript,
                          ordinal);
    bn_write_bin(cursor, BENCH_SCALAR_BYTES,
                 session->client_partials[ordinal]);
    cursor += BENCH_SCALAR_BYTES;
  }
  return frame;
}

static int parse_status(const uint8_t *frame, size_t length,
                        unsigned item_count,
                        uint8_t status_digest[BENCH_DIGEST_BYTES],
                        unsigned *invalid_count) {
  const uint8_t *payload = frame + BENCH_HEADER_SIZE;
  uint32_t *invalid = NULL;
  int status = RLC_ERR;
  if (length < BENCH_HEADER_SIZE + STATUS_CORE_BYTES) return RLC_ERR;
  invalid = calloc(item_count, sizeof(*invalid));
  if (invalid == NULL) return RLC_ERR;
  if (bench_decode_invalid_indices(
          payload + 2 * BENCH_SALT_BYTES,
          length - BENCH_HEADER_SIZE - 2 * BENCH_SALT_BYTES,
          item_count, invalid, item_count, invalid_count) == RLC_OK &&
      bench_status_digest(payload, length - BENCH_HEADER_SIZE,
                          status_digest) == RLC_OK) {
    status = RLC_OK;
  }
  free(invalid);
  return status;
}

static int run_coalesced(bob_state_t state, void *socket,
                         const bench_options_t *options,
                         bench_result_t *result,
                         client_session_t *completed,
                         const uint8_t client_key_proof[
                             BENCH_KEY_OWNERSHIP_PROOF_BYTES]) {
  client_session_t session;
  uint8_t *frame = NULL;
  uint8_t *received = NULL;
  uint8_t verifier_salt[BENCH_SALT_BYTES] = {0};
  uint8_t status_digest[BENCH_DIGEST_BYTES];
  uint8_t completion[BENCH_DIGEST_BYTES];
  unsigned invalid_count = 0;
  size_t length = 0;
  size_t received_length = 0;
  int status = RLC_ERR;
  memset(&session, 0, sizeof(session));
  if (allocate_session(&session, options, state->bob_ec_pk->pk,
                       state->tumbler_ec_pk->pk,
                       client_key_proof) != RLC_OK) goto cleanup;
  frame = build_init(options, &session, 0, options->count, &length);
  if (frame == NULL || send_frame(socket, frame, length, result) != RLC_OK) {
    goto cleanup;
  }
  free(frame);
  frame = NULL;
  if (receive_expected(socket, BENCH_MSG_SERVER_COMMIT, options->count,
                       options->pair_id, 0, options->execution_id,
                       session.transcript.parent_sid, &received,
                       &received_length, result) != RLC_OK ||
      parse_commit(options, &session, 0, options->count, received,
                   received_length, state->tumbler_ec_pk->pk) != RLC_OK) {
    goto cleanup;
  }
  free(received);
  received = NULL;
  frame = build_client_nonce(options, &session, 0, options->count, result,
                             &length);
  if (frame == NULL || send_frame(socket, frame, length, result) != RLC_OK) {
    goto cleanup;
  }
  free(frame);
  frame = NULL;
  if (receive_expected(socket, BENCH_MSG_SERVER_OPEN, options->count,
                       options->pair_id, 0, options->execution_id,
                       session.transcript.parent_sid, &received,
                       &received_length, result) != RLC_OK) {
    goto cleanup;
  }
  if (parse_open_and_prepare(state, options, &session, 0, options->count,
                             received, received_length, result) != RLC_OK ||
      verify_server_vector(options, &session, result, verifier_salt) != RLC_OK) {
    abort_and_wait(socket, options, session.transcript.parent_sid, result);
    goto cleanup;
  }
  free(received);
  received = NULL;
  frame = build_final(options, &session, 0, options->count, &length);
  if (frame == NULL) goto cleanup;
  if (options->inject_bad_final) frame[length - 1] ^= 1;
  if (send_frame(socket, frame, length, result) != RLC_OK) goto cleanup;
  free(frame);
  frame = NULL;
  if (bench_mode_uses_msm(options->mode)) {
    if (receive_expected(socket, BENCH_MSG_FINAL_STATUS, options->count,
                         options->pair_id, 0, options->execution_id,
                         session.transcript.parent_sid, &received,
                         &received_length, result) != RLC_OK ||
        parse_status(received, received_length, options->count, status_digest,
                     &invalid_count) != RLC_OK ||
        invalid_count != 0) {
      goto cleanup;
    }
    free(received);
    received = NULL;
  } else if (bench_status_digest(NULL, 0, status_digest) != RLC_OK) {
    goto cleanup;
  }
  if (bench_completion_digest(&session.transcript, status_digest,
                              completion) != RLC_OK ||
      receive_done(socket, options, &session.transcript, completion,
                   result) != RLC_OK) goto cleanup;
  if (bench_mode_uses_msm(options->mode)) {
    printf("CLIENT_VERIFIER_AUDIT\t%s\t%u\t%u\t",
           bench_mode_name(options->mode), options->pair_id, options->count);
    print_hex(verifier_salt, BENCH_SALT_BYTES);
    printf("\t");
    print_hex(session.transcript.batch_digest, BENCH_DIGEST_BYTES);
    printf("\n");
  }
  if (options->host_output_fd >= 0) {
    *completed = session;
    memset(&session, 0, sizeof(session));
  }
  status = RLC_OK;
cleanup:
  free(frame);
  free(received);
  free_session(&session);
  return status;
}

static int run_pipelined(bob_state_t state, void *socket,
                         const bench_options_t *options,
                         bench_result_t *result,
                         client_session_t *completed,
                         const uint8_t client_key_proof[
                             BENCH_KEY_OWNERSHIP_PROOF_BYTES]) {
  client_session_t session;
  pipeline_item_t *items = NULL;
  uint8_t status_digest[BENCH_DIGEST_BYTES];
  uint8_t completion[BENCH_DIGEST_BYTES];
  unsigned i;
  int status = RLC_ERR;
  memset(&session, 0, sizeof(session));
  if (allocate_session(&session, options, state->bob_ec_pk->pk,
                       state->tumbler_ec_pk->pk,
                       client_key_proof) != RLC_OK) goto cleanup;
  items = calloc(options->count, sizeof(*items));
  if (items == NULL) goto cleanup;
  for (i = 0; i < options->count; i++) {
    uint8_t *frame;
    size_t length;
    frame = build_init(options, &session, i, 1, &length);
    if (frame == NULL || send_frame(socket, frame, length, result) != RLC_OK) {
      free(frame);
      goto cleanup;
    }
    free(frame);
  }
  for (i = 0; i < options->count; i++) {
    size_t length = 0;
    if (receive_expected(socket, BENCH_MSG_SERVER_COMMIT, 1,
                         options->pair_id, i, options->execution_id,
                         bench_active_sid(&session.transcript, options->mode, i),
                         &items[i].commit, &length, result) != RLC_OK ||
        parse_commit(options, &session, i, 1, items[i].commit, length,
                     state->tumbler_ec_pk->pk) != RLC_OK) goto cleanup;
  }
  for (i = 0; i < options->count; i++) {
    uint8_t *frame;
    size_t length;
    frame = build_client_nonce(options, &session, i, 1, result, &length);
    if (frame == NULL || send_frame(socket, frame, length, result) != RLC_OK) {
      free(frame);
      goto cleanup;
    }
    free(frame);
  }
  for (i = 0; i < options->count; i++) {
    size_t length = 0;
    bench_verify_metrics_t metrics = {0};
    if (receive_expected(socket, BENCH_MSG_SERVER_OPEN, 1, options->pair_id,
                         i, options->execution_id,
                         bench_active_sid(&session.transcript, options->mode, i),
                         &items[i].open, &length, result) != RLC_OK) goto cleanup;
    if (parse_open_and_prepare(state, options, &session, i, 1,
                               items[i].open, length, result) != RLC_OK ||
        !bench_joint_partial_verify(
            session.server_partials[i], session.server_nonces[i],
            session.transcript.server_public_keys[i], session.challenges[i],
            &metrics)) {
      abort_and_wait(socket, options, session.transcript.parent_sid, result);
      goto cleanup;
    }
    add_verify_metrics(result, &metrics);
  }
  for (i = 0; i < options->count; i++) {
    uint8_t *frame;
    size_t length;
    frame = build_final(options, &session, i, 1, &length);
    if (frame == NULL) goto cleanup;
    if (options->inject_bad_final && i == 0) frame[length - 1] ^= 1;
    if (send_frame(socket, frame, length, result) != RLC_OK) {
      free(frame);
      goto cleanup;
    }
    free(frame);
  }
  if (bench_status_digest(NULL, 0, status_digest) != RLC_OK ||
      bench_completion_digest(&session.transcript, status_digest,
                              completion) != RLC_OK ||
      receive_done(socket, options, &session.transcript, completion,
                   result) != RLC_OK) goto cleanup;
  if (options->host_output_fd >= 0) {
    *completed = session;
    memset(&session, 0, sizeof(session));
  }
  status = RLC_OK;
cleanup:
  if (items != NULL) {
    for (i = 0; i < options->count; i++) {
      free(items[i].commit);
      free(items[i].open);
    }
  }
  free(items);
  free_session(&session);
  return status;
}

int main(int argc, char **argv) {
  int result_status = RLC_OK;
  void *context = NULL;
  void *socket = NULL;
  bob_state_t state;
  bench_options_t options;
  bench_result_t result;
  client_session_t completed = {0};
  uint8_t client_key_proof[BENCH_KEY_OWNERSHIP_PROOF_BYTES] = {0};
  char endpoint[256] = {0};
  long long started;
  long long process_started = bench_monotonic_ns();
  int linger = 0;
  int timeout_ms;
  bench_resource_mark_t resource_before;
  bench_resource_mark_t resource_after;
  bench_resource_mark_t resource_delta;

  memset(&result, 0, sizeof(result));
  bob_state_null(state);
  if (bench_parse_options(argc, argv, &options) != RLC_OK ||
      (options.host_output_fd >= 0 && !host_memory_fd(options.host_output_fd)) ||
      init() != RLC_OK) {
    return 1;
  }
  context = zmq_ctx_new();
  socket = context == NULL ? NULL : zmq_socket(context, ZMQ_DEALER);
  timeout_ms = (int) options.io_timeout_ms;
  if (socket == NULL ||
      zmq_setsockopt(socket, ZMQ_LINGER, &linger, sizeof(linger)) != 0 ||
      zmq_setsockopt(socket, ZMQ_RCVTIMEO, &timeout_ms, sizeof(timeout_ms)) != 0 ||
      zmq_setsockopt(socket, ZMQ_SNDTIMEO, &timeout_ms, sizeof(timeout_ms)) != 0 ||
      (options.use_tcp &&
       bench_curve_configure_client(socket, &options) != RLC_OK) ||
      bench_make_client_endpoint(endpoint, sizeof(endpoint), &options) != RLC_OK ||
      zmq_connect(socket, endpoint) != 0) {
    result_status = RLC_ERR;
    goto cleanup;
  }
  RLC_TRY {
    bob_state_new(state);
    if (generate_cl_params(state->cl_params) != RLC_OK ||
        read_keys_from_file_alice_bob(
            BOB_KEY_FILE_PREFIX, state->bob_ec_sk, state->bob_ec_pk,
            state->tumbler_ec_pk, state->tumbler_ps_pk,
            state->tumbler_cl_pk) != RLC_OK ||
        (options.host_key_fd >= 0 &&
         host_read_key(options.host_key_fd,state->bob_ec_sk->sk,
                       state->bob_ec_pk->pk) != RLC_OK) ||
        ((options.host_key_fd>=0) != (options.host_peer_key[0]!=0)) ||
        (options.host_peer_key[0] &&
         host_read_statement(state->tumbler_ec_pk->pk,options.host_peer_key,1,0)!=RLC_OK) ||
        bench_validate_secp256k1() != RLC_OK ||
        bench_key_ownership_prove(
            client_key_proof, state->bob_ec_sk->sk, state->bob_ec_pk->pk,
            options.context_seed, BENCH_KEY_ROLE_INITIATOR, options.pair_id,
            options.context_epoch) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    if (host_admit_address_keys(&options,BENCH_KEY_ROLE_INITIATOR)!=RLC_OK) RLC_THROW(ERR_NO_VALID);
    result.setup_ns = bench_monotonic_ns() - process_started;
    if (bench_resource_mark(&resource_before) != RLC_OK) RLC_THROW(ERR_CAUGHT);
    started = bench_monotonic_ns();
    if ((options.mode == BENCH_MODE_ORIGINAL_ITEMWISE
             ? run_pipelined(state, socket, &options, &result,
                             &completed, client_key_proof)
             : run_coalesced(state, socket, &options, &result,
                             &completed, client_key_proof)) != RLC_OK) {
      result_status = RLC_ERR;
    }
    if (result_status == RLC_OK) {
      result.total_time_ns = bench_monotonic_ns() - started;
      if (bench_resource_mark(&resource_after) != RLC_OK) {
        result_status = RLC_ERR;
      } else {
        bench_resource_delta(&resource_before, &resource_after, &resource_delta);
        result.user_cpu_ns = resource_delta.user_cpu_ns;
        result.system_cpu_ns = resource_delta.system_cpu_ns;
        result.max_rss_kb = resource_delta.max_rss_kb;
        result.voluntary_context_switches =
            resource_delta.voluntary_context_switches;
        result.involuntary_context_switches =
            resource_delta.involuntary_context_switches;
        result.scheduler_wait_ns = resource_delta.scheduler_wait_ns;
        result.scheduler_slices = resource_delta.scheduler_slices;
      }
    }
    /* Handoff is after the Pre-swap wall/CPU interval and verified DONE. */
    if (result_status == RLC_OK && options.host_output_fd >= 0 &&
        host_write_handoff_until(options.host_output_fd, &completed.transcript,
                           completed.challenges, completed.full_scalars,
                           options.host_export_deadline_ns) != RLC_OK)
      result_status = RLC_ERR;
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    free_session(&completed);
    if (state != NULL) bob_state_free(state);
  }
cleanup:
  if (socket != NULL) zmq_close(socket);
  if (context != NULL) zmq_ctx_destroy(context);
  host_release_address_keys(&options);
  clean();
  if (result_status != RLC_OK) return 1;
  result.mode = options.mode;
  result.pair_id = options.pair_id;
  result.item_count = options.count;
  result.total_crypto_ns = result.request_sign_ns +
                           result.response_preverify_ns + result.final_sign_ns;
  bench_print_result(&result);
#ifdef BENCH_ALLOCATION_PROFILE
  {
    bench_allocation_metrics_t allocations;
    bench_allocation_metrics_read(&allocations);
    printf("ALLOCATION_RESULT\t%s\t%u\t%u\t%llu\t%llu\t%llu\t%llu\t%llu\n",
           bench_mode_name(options.mode), options.pair_id, options.count,
           allocations.malloc_calls, allocations.calloc_calls,
           allocations.realloc_calls, allocations.free_calls,
           allocations.requested_bytes);
  }
#endif
  return 0;
}
