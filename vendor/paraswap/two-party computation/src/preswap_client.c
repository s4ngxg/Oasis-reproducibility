#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zmq.h"
#include "bob.h"
#include "preswap_protocol.h"
#include "transport_auth.h"
#ifdef BENCH_ALLOCATION_PROFILE
#include "allocation_counter.h"
#endif

static int send_frame(void *socket, const uint8_t *frame, size_t length,
                      bench_result_t *result) {
  if (bench_send_frame(socket, frame, length) != RLC_OK) return RLC_ERR;
  result->sent_frames++;
  result->send_calls++;
  result->bytes_sent += length;
  return RLC_OK;
}

static int receive_expected(void *socket, bench_msg_type_t type,
                            unsigned count, unsigned pair_id,
                            unsigned first_ordinal, uint64_t execution_id,
                            uint8_t **frame, size_t *length,
                            bench_result_t *result) {
  bench_header_t header;
  if (bench_recv_frame(socket, frame, length) != RLC_OK) return RLC_ERR;
  result->received_frames++;
  result->receive_calls++;
  result->bytes_received += *length;
  if (bench_read_header(*frame, *length, &header) != RLC_OK ||
      header.type != (uint32_t) type || header.count != count ||
      header.pair_id != pair_id || header.first_ordinal != first_ordinal ||
      header.execution_id != execution_id) {
    free(*frame);
    *frame = NULL;
    return RLC_ERR;
  }
  return RLC_OK;
}

static int receive_done(void *socket, unsigned count, unsigned pair_id,
                        unsigned first_ordinal, uint64_t execution_id,
                        const uint8_t commitment[BENCH_DIGEST_BYTES],
                        size_t expected_payload, bench_result_t *result) {
  bench_header_t header;
  uint8_t *frame = NULL;
  size_t length = 0;
  int status = RLC_ERR;
  if (bench_recv_frame(socket, &frame, &length) != RLC_OK) return RLC_ERR;
  result->received_frames++;
  result->receive_calls++;
  result->bytes_received += length;
  if (bench_read_header(frame, length, &header) != RLC_OK ||
      header.count != count || header.pair_id != pair_id ||
      header.first_ordinal != first_ordinal ||
      header.execution_id != execution_id) {
    goto cleanup;
  }
  if (header.type == BENCH_MSG_ABORT) {
    fprintf(stderr, "server aborted invalid final vector\n");
    goto cleanup;
  }
  if (header.type == BENCH_MSG_DONE &&
      length == BENCH_HEADER_SIZE + expected_payload &&
      bench_digest_equal(frame + BENCH_HEADER_SIZE, commitment)) {
    status = RLC_OK;
  }
cleanup:
  free(frame);
  return status;
}

static int allocate_verification_batch(unsigned count,
                                       schnorr_signature_t **signatures_out,
                                       ec_t **nonces_out,
                                       ec_t **adaptors_out,
                                       ec_t **public_keys_out) {
  schnorr_signature_t *signatures = calloc(count, sizeof(*signatures));
  ec_t *nonces = calloc(count, sizeof(*nonces));
  ec_t *adaptors = calloc(count, sizeof(*adaptors));
  ec_t *public_keys = calloc(count, sizeof(*public_keys));
  unsigned i;
  if (signatures == NULL || nonces == NULL || adaptors == NULL ||
      public_keys == NULL) {
    free(signatures);
    free(nonces);
    free(adaptors);
    free(public_keys);
    return RLC_ERR;
  }
  for (i = 0; i < count; i++) {
    schnorr_signature_null(signatures[i]);
    ec_null(nonces[i]);
    ec_null(adaptors[i]);
    ec_null(public_keys[i]);
    schnorr_signature_new(signatures[i]);
    ec_new(nonces[i]);
    ec_new(adaptors[i]);
    ec_new(public_keys[i]);
  }
  *signatures_out = signatures;
  *nonces_out = nonces;
  *adaptors_out = adaptors;
  *public_keys_out = public_keys;
  return RLC_OK;
}

static void free_verification_batch(unsigned count,
                                    schnorr_signature_t *signatures,
                                    ec_t *nonces, ec_t *adaptors,
                                    ec_t *public_keys) {
  unsigned i;
  if (signatures != NULL && nonces != NULL && adaptors != NULL &&
      public_keys != NULL) {
    for (i = 0; i < count; i++) {
      schnorr_signature_free(signatures[i]);
      ec_free(nonces[i]);
      ec_free(adaptors[i]);
      ec_free(public_keys[i]);
    }
  }
  free(signatures);
  free(nonces);
  free(adaptors);
  free(public_keys);
}

static int verify_responses(const bench_options_t *options,
                            const uint8_t *request, size_t request_stride,
                            schnorr_signature_t *signatures,
                            ec_t *nonces, ec_t *adaptors,
                            ec_t *server_keys,
                            const uint8_t salt[BENCH_SALT_BYTES],
                            unsigned count,
                            bench_verify_metrics_t *metrics) {
  unsigned i;
  if (bench_mode_uses_msm(options->mode)) {
    if (bench_schnorr_batch_verify(signatures, nonces,
                                   request + BENCH_HEADER_SIZE,
                                   request_stride, adaptors, 1, server_keys,
                                   count, salt, "SERVER-PARTIAL-v1", metrics)) {
      return RLC_OK;
    }
    metrics->fallbacks++;
    for (i = 0; i < count; i++) {
      const uint8_t *message = request + BENCH_HEADER_SIZE +
                               (size_t) i * request_stride;
      if (!bench_schnorr_verify_explicit(signatures[i], nonces[i], message,
                                         BENCH_DIGEST_BYTES, adaptors[i], 1,
                                         server_keys[i], metrics)) {
        return RLC_ERR;
      }
    }
    return RLC_ERR;
  }
  for (i = 0; i < count; i++) {
    const uint8_t *message = request + BENCH_HEADER_SIZE +
                             (size_t) i * request_stride;
    if (!bench_schnorr_verify_explicit(signatures[i], nonces[i], message,
                                       BENCH_DIGEST_BYTES, adaptors[i], 1,
                                       server_keys[i], metrics)) {
      return RLC_ERR;
    }
  }
  return RLC_OK;
}

typedef struct {
  uint8_t *request;
  uint8_t *commit;
  uint8_t *open;
  uint8_t *final_frame;
} reference_client_item_t;

static void free_reference_client_items(reference_client_item_t *items,
                                        unsigned count) {
  unsigned i;
  if (items == NULL) return;
  for (i = 0; i < count; i++) {
    free(items[i].request);
    free(items[i].commit);
    free(items[i].open);
    free(items[i].final_frame);
  }
  free(items);
}

/*
 * Pipeline independent item sessions by protocol phase. Each item keeps its
 * own SID/header and frame; only the causal waits are shared across the k
 * sessions. This is the persistent asynchronous comparison baseline.
 */
static int run_reference_pipelined(bob_state_t state, void *socket,
                                   const bench_options_t *options,
                                   bench_result_t *result) {
  const size_t request_length = BENCH_HEADER_SIZE + BENCH_LEGACY_REQUEST_BYTES;
  const size_t open_length = BENCH_HEADER_SIZE + BENCH_SALT_BYTES +
                             BENCH_LEGACY_RESPONSE_BYTES;
  const size_t final_length = BENCH_HEADER_SIZE + BENCH_SIG_BYTES;
  reference_client_item_t *items = NULL;
  ec_public_key_t verification_key;
  ec_secret_key_t signing_key;
  bn_t signing_secret;
  uint8_t ready[BENCH_HEADER_SIZE];
  uint8_t completion_digest[BENCH_DIGEST_BYTES];
  uint8_t *ordered_commitments = NULL;
  unsigned i;
  int status = RLC_ERR;

  ec_public_key_null(verification_key);
  ec_secret_key_null(signing_key);
  bn_null(signing_secret);
  items = calloc(options->count, sizeof(*items));
  ordered_commitments = malloc((size_t) options->count * BENCH_DIGEST_BYTES);
  if (items == NULL || ordered_commitments == NULL) goto cleanup;
  ec_public_key_new(verification_key);
  ec_secret_key_new(signing_key);
  bn_new(signing_secret);

  /* Phase 1: construct and enqueue every independent INIT frame. */
  for (i = 0; i < options->count; i++) {
    uint8_t *item;
    long long started;
    items[i].request = calloc(1, request_length);
    items[i].final_frame = calloc(1, final_length);
    if (items[i].request == NULL || items[i].final_frame == NULL) goto cleanup;
    bench_write_header(items[i].request, BENCH_MSG_BATCH_INIT, 1,
                       options->pair_id, i, options->execution_id);
    bench_write_header(items[i].final_frame, BENCH_MSG_CLIENT_FINAL, 1,
                       options->pair_id, i, options->execution_id);
    item = items[i].request + BENCH_HEADER_SIZE;
    bench_item_digest(options->mode, options->pair_id, i, options->count,
                      options->execution_id, item);
    started = bench_monotonic_ns();
    if (bench_derive_item_secret(signing_secret, state->bob_ec_sk->sk,
                                 "CLIENT-SIGNING-KEY-v1", options->pair_id,
                                 i, options->count) != RLC_OK ||
        cp_ecss_sig(state->sigma_r->e, state->sigma_r->s, item,
                    BENCH_DIGEST_BYTES, signing_secret) != RLC_OK) {
      goto cleanup;
    }
    result->request_sign_ns += bench_monotonic_ns() - started;
    bn_write_bin(item + BENCH_DIGEST_BYTES, RLC_BN_SIZE, state->sigma_r->e);
    bn_write_bin(item + BENCH_DIGEST_BYTES + RLC_BN_SIZE, RLC_BN_SIZE,
                 state->sigma_r->s);
    if (send_frame(socket, items[i].request, request_length, result) != RLC_OK) {
      goto cleanup;
    }
  }

  /* Phase 2: collect every commitment before releasing any READY frame. */
  for (i = 0; i < options->count; i++) {
    size_t length = 0;
    if (receive_expected(socket, BENCH_MSG_SERVER_COMMIT, 1,
                         options->pair_id, i, options->execution_id,
                         &items[i].commit, &length, result) != RLC_OK ||
        length != BENCH_HEADER_SIZE + BENCH_DIGEST_BYTES) {
      goto cleanup;
    }
  }
  for (i = 0; i < options->count; i++) {
    bench_write_header(ready, BENCH_MSG_CLIENT_NONCE, 1, options->pair_id, i,
                       options->execution_id);
    if (send_frame(socket, ready, sizeof(ready), result) != RLC_OK) goto cleanup;
  }

  /* Phase 3: verify every opening and prepare the independent final frames. */
  for (i = 0; i < options->count; i++) {
    uint8_t calculated_commitment[BENCH_DIGEST_BYTES];
    const uint8_t *message;
    const uint8_t *response;
    uint8_t *final_item;
    size_t length = 0;
    long long started;
    if (receive_expected(socket, BENCH_MSG_SERVER_OPEN, 1, options->pair_id,
                         i, options->execution_id, &items[i].open, &length,
                         result) != RLC_OK || length != open_length) {
      goto cleanup;
    }
    bench_commitment_digest(items[i].open + BENCH_HEADER_SIZE,
                            length - BENCH_HEADER_SIZE,
                            calculated_commitment);
    if (!bench_digest_equal(calculated_commitment,
                            items[i].commit + BENCH_HEADER_SIZE)) {
      goto cleanup;
    }
    message = items[i].request + BENCH_HEADER_SIZE;
    response = items[i].open + BENCH_HEADER_SIZE + BENCH_SALT_BYTES;
    if (bench_derive_item_public(verification_key->pk,
                                 state->tumbler_ec_pk->pk,
                                 "SERVER-SIGNING-KEY-v1", options->pair_id,
                                 i, options->count) != RLC_OK) {
      goto cleanup;
    }
    ec_read_bin(state->g_to_the_alpha, response, RLC_EC_SIZE_COMPRESSED);
    bn_read_bin(state->sigma_t->e, response + RLC_EC_SIZE_COMPRESSED,
                RLC_BN_SIZE);
    bn_read_bin(state->sigma_t->s,
                response + RLC_EC_SIZE_COMPRESSED + RLC_BN_SIZE,
                RLC_BN_SIZE);
    started = bench_monotonic_ns();
    if (adaptor_schnorr_preverify(state->sigma_t, (uint8_t *) message,
                                  BENCH_DIGEST_BYTES, state->g_to_the_alpha,
                                  verification_key) != 1) {
      goto cleanup;
    }
    result->response_preverify_ns += bench_monotonic_ns() - started;

    if (bench_derive_item_secret(signing_secret, state->bob_ec_sk->sk,
                                 "CLIENT-SIGNING-KEY-v1", options->pair_id,
                                 i, options->count) != RLC_OK) {
      goto cleanup;
    }
    bn_copy(signing_key->sk, signing_secret);
    started = bench_monotonic_ns();
    if (adaptor_schnorr_sign(state->sigma_f, (uint8_t *) message,
                             BENCH_DIGEST_BYTES, state->g_to_the_alpha,
                             signing_key) != RLC_OK) {
      goto cleanup;
    }
    result->final_sign_ns += bench_monotonic_ns() - started;
    final_item = items[i].final_frame + BENCH_HEADER_SIZE;
    bn_write_bin(final_item, RLC_BN_SIZE, state->sigma_f->e);
    bn_write_bin(final_item + RLC_BN_SIZE, RLC_BN_SIZE, state->sigma_f->s);
  }
  if (options->inject_bad_final) {
    items[0].final_frame[final_length - 1] ^= 0x01;
  }
  for (i = 0; i < options->count; i++) {
    if (send_frame(socket, items[i].final_frame, final_length, result) !=
        RLC_OK) {
      goto cleanup;
    }
  }

  /* Phase 4: one receipt binds the ordered set of independent item SIDs. */
  for (i = 0; i < options->count; i++) {
    memcpy(ordered_commitments + (size_t) i * BENCH_DIGEST_BYTES,
           items[i].commit + BENCH_HEADER_SIZE, BENCH_DIGEST_BYTES);
  }
  if (bench_independent_completion_digest(
          ordered_commitments, options->count, options->pair_id,
          options->execution_id, completion_digest) != RLC_OK ||
      receive_done(socket, options->count, options->pair_id, 0,
                   options->execution_id, completion_digest,
                   BENCH_DIGEST_BYTES, result) != RLC_OK) {
    goto cleanup;
  }
  status = RLC_OK;

cleanup:
  free(ordered_commitments);
  free_reference_client_items(items, options->count);
  if (verification_key != NULL) ec_public_key_free(verification_key);
  if (signing_key != NULL) ec_secret_key_free(signing_key);
  bn_free(signing_secret);
  return status;
}

static int run_session(bob_state_t state, void *socket,
                       const bench_options_t *options, unsigned first_ordinal,
                       unsigned session_count, bench_result_t *result) {
  const int explicit_nonce = bench_mode_uses_explicit_nonce(options->mode);
  const size_t child_bytes = bench_mode_has_child_sessions(options->mode)
                                 ? BENCH_CHILD_SESSION_BYTES : 0;
  const size_t request_stride = bench_request_bytes(options->mode);
  const size_t response_stride = bench_response_bytes(options->mode);
  const size_t final_stride = bench_final_bytes(options->mode);
  const size_t open_prefix = bench_open_prefix_bytes(options->mode);
  const size_t done_payload = bench_done_bytes(options->mode);
  const size_t request_length = BENCH_HEADER_SIZE +
                                (size_t) session_count * request_stride;
  const size_t ready_length = BENCH_HEADER_SIZE +
                              (explicit_nonce ? BENCH_SALT_BYTES : 0);
  const size_t final_length = BENCH_HEADER_SIZE +
                              (size_t) session_count * final_stride;
  uint8_t *request = calloc(1, request_length);
  uint8_t *ready = calloc(1, ready_length);
  uint8_t *final_frame = calloc(1, final_length);
  uint8_t *commit_frame = NULL;
  uint8_t *open_frame = NULL;
  uint8_t client_salt[BENCH_SALT_BYTES] = {0};
  uint8_t calculated_commitment[BENCH_DIGEST_BYTES];
  schnorr_signature_t *response_signatures = NULL;
  ec_t *response_nonces = NULL;
  ec_t *adaptors = NULL;
  ec_t *server_public_keys = NULL;
  ec_t signing_nonce;
  ec_t base_server_public;
  ec_secret_key_t signing_key;
  ec_public_key_t verification_key;
  bn_t base_client_secret;
  bn_t signing_secret;
  bench_verify_metrics_t verify_metrics;
  size_t frame_length = 0;
  unsigned i;
  int status = RLC_ERR;

  ec_null(signing_nonce);
  ec_null(base_server_public);
  ec_secret_key_null(signing_key);
  ec_public_key_null(verification_key);
  bn_null(base_client_secret);
  bn_null(signing_secret);
  memset(&verify_metrics, 0, sizeof(verify_metrics));
  if (request == NULL || ready == NULL || final_frame == NULL) goto cleanup;
  ec_new(signing_nonce);
  ec_new(base_server_public);
  ec_secret_key_new(signing_key);
  ec_public_key_new(verification_key);
  bn_new(base_client_secret);
  bn_new(signing_secret);
  ec_copy(base_server_public, state->tumbler_ec_pk->pk);
  bn_copy(base_client_secret, state->bob_ec_sk->sk);
  if (explicit_nonce &&
      allocate_verification_batch(session_count, &response_signatures,
                                  &response_nonces, &adaptors,
                                  &server_public_keys) != RLC_OK) {
    goto cleanup;
  }

  bench_write_header(request, BENCH_MSG_BATCH_INIT, session_count,
                     options->pair_id, first_ordinal, options->execution_id);
  bench_write_header(ready, BENCH_MSG_CLIENT_NONCE, session_count,
                     options->pair_id, first_ordinal, options->execution_id);
  bench_write_header(final_frame, BENCH_MSG_CLIENT_FINAL, session_count,
                     options->pair_id, first_ordinal, options->execution_id);

  for (i = 0; i < session_count; i++) {
    uint8_t *item = request + BENCH_HEADER_SIZE + (size_t) i * request_stride;
    long long started;
    bench_item_digest(options->mode, options->pair_id, first_ordinal + i,
                      options->count, options->execution_id, item);
    if (child_bytes != 0) {
      bench_child_session_digest(options->pair_id, first_ordinal + i,
                                 options->count, options->execution_id,
                                 item + BENCH_DIGEST_BYTES);
    }
    started = bench_monotonic_ns();
    if (explicit_nonce) {
      if (bench_derive_item_secret(
              signing_secret, base_client_secret, "CLIENT-SIGNING-KEY-v1",
              options->pair_id, first_ordinal + i, options->count) != RLC_OK) {
        goto cleanup;
      }
      if (bench_schnorr_sign_explicit(state->sigma_r, signing_nonce, item,
                                      BENCH_DIGEST_BYTES, signing_nonce, 0,
                                      signing_secret) != RLC_OK) {
        goto cleanup;
      }
      ec_write_bin(item + BENCH_DIGEST_BYTES + child_bytes,
                   RLC_EC_SIZE_COMPRESSED,
                   signing_nonce, 1);
      bn_write_bin(item + BENCH_DIGEST_BYTES + child_bytes +
                       RLC_EC_SIZE_COMPRESSED,
                   RLC_BN_SIZE, state->sigma_r->e);
      bn_write_bin(item + BENCH_DIGEST_BYTES + child_bytes +
                       RLC_EC_SIZE_COMPRESSED +
                       RLC_BN_SIZE,
                   RLC_BN_SIZE, state->sigma_r->s);
    } else {
      if (bench_derive_item_secret(
              signing_secret, base_client_secret, "CLIENT-SIGNING-KEY-v1",
              options->pair_id, first_ordinal + i, options->count) != RLC_OK) {
        goto cleanup;
      }
      if (cp_ecss_sig(state->sigma_r->e, state->sigma_r->s, item,
                      BENCH_DIGEST_BYTES, signing_secret) != RLC_OK) {
        goto cleanup;
      }
      bn_write_bin(item + BENCH_DIGEST_BYTES, RLC_BN_SIZE, state->sigma_r->e);
      bn_write_bin(item + BENCH_DIGEST_BYTES + RLC_BN_SIZE,
                   RLC_BN_SIZE, state->sigma_r->s);
    }
    result->request_sign_ns += bench_monotonic_ns() - started;
  }

  if (send_frame(socket, request, request_length, result) != RLC_OK) goto cleanup;
  if (receive_expected(socket, BENCH_MSG_SERVER_COMMIT, session_count,
                       options->pair_id, first_ordinal, options->execution_id,
                       &commit_frame, &frame_length, result) != RLC_OK ||
      frame_length != BENCH_HEADER_SIZE + BENCH_DIGEST_BYTES) {
    goto cleanup;
  }
  if (explicit_nonce) {
    if (bench_random_salt(client_salt) != RLC_OK) goto cleanup;
    memcpy(ready + BENCH_HEADER_SIZE, client_salt, BENCH_SALT_BYTES);
  }
  if (send_frame(socket, ready, ready_length, result) != RLC_OK) goto cleanup;

  if (receive_expected(socket, BENCH_MSG_SERVER_OPEN, session_count,
                       options->pair_id, first_ordinal, options->execution_id,
                       &open_frame, &frame_length, result) != RLC_OK ||
      frame_length != BENCH_HEADER_SIZE + open_prefix +
                          (size_t) session_count * response_stride) {
    goto cleanup;
  }
  bench_commitment_digest(open_frame + BENCH_HEADER_SIZE,
                          frame_length - BENCH_HEADER_SIZE,
                          calculated_commitment);
  if (!bench_digest_equal(calculated_commitment,
                          commit_frame + BENCH_HEADER_SIZE)) {
    fprintf(stderr, "server commitment mismatch\n");
    goto cleanup;
  }

  if (explicit_nonce) {
    long long started;
    for (i = 0; i < session_count; i++) {
      const uint8_t *response = open_frame + BENCH_HEADER_SIZE +
                                open_prefix +
                                (size_t) i * response_stride;
      const uint8_t *request_item = request + BENCH_HEADER_SIZE +
                                    (size_t) i * request_stride;
      if (child_bytes != 0 &&
          !bench_digest_equal(response,
                              request_item + BENCH_DIGEST_BYTES)) {
        goto cleanup;
      }
      response += child_bytes;
      ec_read_bin(adaptors[i], response, RLC_EC_SIZE_COMPRESSED);
      ec_read_bin(response_nonces[i], response + RLC_EC_SIZE_COMPRESSED,
                  RLC_EC_SIZE_COMPRESSED);
      bn_read_bin(response_signatures[i]->e,
                  response + 2 * RLC_EC_SIZE_COMPRESSED, RLC_BN_SIZE);
      bn_read_bin(response_signatures[i]->s,
                  response + 2 * RLC_EC_SIZE_COMPRESSED + RLC_BN_SIZE,
                  RLC_BN_SIZE);
      if (bench_derive_item_public(
              server_public_keys[i], base_server_public,
              "SERVER-SIGNING-KEY-v1", options->pair_id,
              first_ordinal + i, options->count) != RLC_OK) {
        goto cleanup;
      }
    }
    started = bench_monotonic_ns();
    if (verify_responses(options, request, request_stride, response_signatures,
                         response_nonces, adaptors, server_public_keys,
                         client_salt, session_count,
                         &verify_metrics) != RLC_OK) {
      goto cleanup;
    }
    result->response_preverify_ns += bench_monotonic_ns() - started;
  }

  for (i = 0; i < session_count; i++) {
    const uint8_t *message = request + BENCH_HEADER_SIZE +
                             (size_t) i * request_stride;
    const uint8_t *response = open_frame + BENCH_HEADER_SIZE +
                              open_prefix +
                              (size_t) i * response_stride;
    uint8_t *final_item = final_frame + BENCH_HEADER_SIZE +
                          (size_t) i * final_stride;
    long long started;

    if (!explicit_nonce) {
      if (bench_derive_item_public(
              verification_key->pk, base_server_public,
              "SERVER-SIGNING-KEY-v1", options->pair_id,
              first_ordinal + i, options->count) != RLC_OK) {
        goto cleanup;
      }
      ec_read_bin(state->g_to_the_alpha, response, RLC_EC_SIZE_COMPRESSED);
      bn_read_bin(state->sigma_t->e, response + RLC_EC_SIZE_COMPRESSED,
                  RLC_BN_SIZE);
      bn_read_bin(state->sigma_t->s,
                  response + RLC_EC_SIZE_COMPRESSED + RLC_BN_SIZE,
                  RLC_BN_SIZE);
      started = bench_monotonic_ns();
      if (adaptor_schnorr_preverify(state->sigma_t,
                                    (uint8_t *) message,
                                    BENCH_DIGEST_BYTES,
                                    state->g_to_the_alpha,
                                    verification_key) != 1) {
        goto cleanup;
      }
      result->response_preverify_ns += bench_monotonic_ns() - started;
    } else {
      ec_copy(state->g_to_the_alpha, adaptors[i]);
      if (child_bytes != 0) {
        memcpy(final_item, message + BENCH_DIGEST_BYTES, child_bytes);
      }
    }

    started = bench_monotonic_ns();
    if (explicit_nonce) {
      if (bench_derive_item_secret(
              signing_secret, base_client_secret, "CLIENT-SIGNING-KEY-v1",
              options->pair_id, first_ordinal + i, options->count) != RLC_OK) {
        goto cleanup;
      }
      if (bench_schnorr_sign_explicit(state->sigma_f, signing_nonce,
                                      message, BENCH_DIGEST_BYTES,
                                      state->g_to_the_alpha, 1,
                                      signing_secret) != RLC_OK) {
        goto cleanup;
      }
      final_item += child_bytes;
      ec_write_bin(final_item, RLC_EC_SIZE_COMPRESSED, signing_nonce, 1);
      bn_write_bin(final_item + RLC_EC_SIZE_COMPRESSED,
                   RLC_BN_SIZE, state->sigma_f->e);
      bn_write_bin(final_item + RLC_EC_SIZE_COMPRESSED + RLC_BN_SIZE,
                   RLC_BN_SIZE, state->sigma_f->s);
    } else {
      if (bench_derive_item_secret(
              signing_secret, base_client_secret, "CLIENT-SIGNING-KEY-v1",
              options->pair_id, first_ordinal + i, options->count) != RLC_OK) {
        goto cleanup;
      }
      bn_copy(signing_key->sk, signing_secret);
      if (adaptor_schnorr_sign(state->sigma_f, (uint8_t *) message,
                               BENCH_DIGEST_BYTES, state->g_to_the_alpha,
                               signing_key) != RLC_OK) {
        goto cleanup;
      }
      bn_write_bin(final_item, RLC_BN_SIZE, state->sigma_f->e);
      bn_write_bin(final_item + RLC_BN_SIZE, RLC_BN_SIZE, state->sigma_f->s);
    }
    result->final_sign_ns += bench_monotonic_ns() - started;
  }

  if (options->inject_bad_final && first_ordinal == 0) {
    final_frame[final_length - 1] ^= 0x01;
  }

  if (send_frame(socket, final_frame, final_length, result) != RLC_OK) goto cleanup;
  if (bench_mode_uses_msm(options->mode)) {
    uint8_t *status_frame = NULL;
    size_t status_length = 0;
    if (receive_expected(socket, BENCH_MSG_FINAL_STATUS, session_count,
                         options->pair_id, first_ordinal,
                         options->execution_id, &status_frame,
                         &status_length, result) != RLC_OK ||
        status_length != BENCH_HEADER_SIZE + BENCH_SALT_BYTES) {
      free(status_frame);
      goto cleanup;
    }
    free(status_frame);
  }
  if (receive_done(socket, session_count, options->pair_id, first_ordinal,
                   options->execution_id, commit_frame + BENCH_HEADER_SIZE,
                   done_payload, result) != RLC_OK) {
    goto cleanup;
  }
  result->verifier_challenge_ns += verify_metrics.challenge_ns;
  result->verifier_msm_ns += verify_metrics.msm_ns;
  result->verifier_equations += verify_metrics.equations;
  result->verifier_msm_calls += verify_metrics.msm_calls;
  result->verifier_fallbacks += verify_metrics.fallbacks;
  status = RLC_OK;

cleanup:
  free(request);
  free(ready);
  free(final_frame);
  free(commit_frame);
  free(open_frame);
  free_verification_batch(session_count, response_signatures,
                          response_nonces, adaptors, server_public_keys);
  ec_free(signing_nonce);
  ec_free(base_server_public);
  if (signing_key != NULL) ec_secret_key_free(signing_key);
  if (verification_key != NULL) ec_public_key_free(verification_key);
  bn_free(base_client_secret);
  bn_free(signing_secret);
  return status;
}

int main(int argc, char **argv) {
  int result_status = RLC_OK;
  void *context = NULL;
  void *socket = NULL;
  bob_state_t state;
  bench_options_t options;
  bench_result_t result;
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
  if (bench_parse_options(argc, argv, &options) != RLC_OK || init() != RLC_OK) {
    return 1;
  }
  context = zmq_ctx_new();
  socket = context == NULL ? NULL :
      zmq_socket(context,
                 options.mode == BENCH_MODE_ORIGINAL_ITEMWISE ||
                         bench_mode_uses_msm(options.mode)
                     ? ZMQ_DEALER : ZMQ_REQ);
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
        read_keys_from_file_alice_bob(BOB_KEY_FILE_PREFIX,
                                      state->bob_ec_sk, state->bob_ec_pk,
                                      state->tumbler_ec_pk, state->tumbler_ps_pk,
                                      state->tumbler_cl_pk) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    result.setup_ns = bench_monotonic_ns() - process_started;
    if (bench_resource_mark(&resource_before) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    started = bench_monotonic_ns();
    if (options.mode == BENCH_MODE_ORIGINAL_ITEMWISE) {
      if (run_reference_pipelined(state, socket, &options, &result) != RLC_OK) {
        result_status = RLC_ERR;
      }
    } else if (bench_mode_is_coalesced(options.mode)) {
      if (run_session(state, socket, &options, 0, options.count,
                      &result) != RLC_OK) {
        result_status = RLC_ERR;
      }
    }
    if (result_status == RLC_OK) {
      result.total_time_ns = bench_monotonic_ns() - started;
      if (bench_resource_mark(&resource_after) != RLC_OK) {
        result_status = RLC_ERR;
      } else {
        bench_resource_delta(&resource_before, &resource_after,
                             &resource_delta);
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
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    if (state != NULL) bob_state_free(state);
  }

cleanup:
  if (socket != NULL) zmq_close(socket);
  if (context != NULL) zmq_ctx_destroy(context);
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
