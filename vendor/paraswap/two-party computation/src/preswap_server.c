#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zmq.h"
#include "tumbler.h"
#include "preswap_protocol.h"
#include "transport_auth.h"
#ifdef BENCH_ALLOCATION_PROFILE
#include "allocation_counter.h"
#endif

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

static void send_abort(void *socket, const bench_options_t *options,
                       unsigned ordinal, unsigned count,
                       server_metrics_t *metrics) {
  uint8_t frame[BENCH_HEADER_SIZE];
  bench_write_header(frame, BENCH_MSG_ABORT, count, options->pair_id,
                     ordinal, options->execution_id);
  if (bench_send_frame(socket, frame, sizeof(frame)) == RLC_OK) {
    metrics->sent_frames++;
    metrics->send_calls++;
    metrics->bytes_sent += sizeof(frame);
  }
}

static int send_frame(void *socket, const uint8_t *frame, size_t length,
                      server_metrics_t *metrics) {
  if (bench_send_frame(socket, frame, length) != RLC_OK) return RLC_ERR;
  metrics->sent_frames++;
  metrics->send_calls++;
  metrics->bytes_sent += length;
  return RLC_OK;
}

static int receive_expected(void *socket, bench_msg_type_t type,
                            unsigned expected_pair, unsigned expected_count,
                            unsigned expected_ordinal,
                            uint64_t expected_execution_id, uint8_t **frame,
                            size_t *length, server_metrics_t *metrics) {
  bench_header_t header;
  if (bench_recv_frame(socket, frame, length) != RLC_OK ||
      bench_read_header(*frame, *length, &header) != RLC_OK ||
      header.type != (uint32_t) type || header.pair_id != expected_pair ||
      header.count != expected_count ||
      header.first_ordinal != expected_ordinal ||
      header.execution_id != expected_execution_id) {
    free(*frame);
    *frame = NULL;
    return RLC_ERR;
  }
  metrics->received_frames++;
  metrics->receive_calls++;
  metrics->bytes_received += *length;
  return RLC_OK;
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

static int verify_explicit_set(const bench_options_t *options,
                               const uint8_t *request,
                               size_t request_stride,
                               schnorr_signature_t *signatures,
                               ec_t *nonces, ec_t *adaptors,
                               int has_adaptor,
                               ec_t *public_keys,
                               unsigned count,
                               const uint8_t salt[BENCH_SALT_BYTES],
                               const char *domain,
                               bench_verify_metrics_t *metrics) {
  unsigned i;
  if (bench_mode_uses_msm(options->mode)) {
    if (bench_schnorr_batch_verify(signatures, nonces,
                                   request + BENCH_HEADER_SIZE,
                                   request_stride, adaptors, has_adaptor,
                                   public_keys, count, salt, domain, metrics)) {
      return RLC_OK;
    }
    metrics->fallbacks++;
    for (i = 0; i < count; i++) {
      const uint8_t *message = request + BENCH_HEADER_SIZE +
                               (size_t) i * request_stride;
      if (!bench_schnorr_verify_explicit(signatures[i], nonces[i], message,
                                         BENCH_DIGEST_BYTES, adaptors[i],
                                         has_adaptor, public_keys[i], metrics)) {
        return RLC_ERR;
      }
    }
    return RLC_ERR;
  }
  for (i = 0; i < count; i++) {
    const uint8_t *message = request + BENCH_HEADER_SIZE +
                             (size_t) i * request_stride;
    if (!bench_schnorr_verify_explicit(signatures[i], nonces[i], message,
                                       BENCH_DIGEST_BYTES, adaptors[i],
                                       has_adaptor, public_keys[i], metrics)) {
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
} reference_server_item_t;

static void free_reference_server_items(reference_server_item_t *items,
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

/* Server half of the persistent phase-pipelined independent-session baseline. */
static int run_reference_pipelined(tumbler_state_t state, void *socket,
                                   const bench_options_t *options,
                                   server_metrics_t *metrics) {
  const size_t request_length = BENCH_HEADER_SIZE + BENCH_LEGACY_REQUEST_BYTES;
  const size_t open_length = BENCH_HEADER_SIZE + BENCH_SALT_BYTES +
                             BENCH_LEGACY_RESPONSE_BYTES;
  const size_t final_length = BENCH_HEADER_SIZE + BENCH_SIG_BYTES;
  reference_server_item_t *items = NULL;
  ec_public_key_t verification_key;
  ec_secret_key_t signing_key;
  bn_t order;
  bn_t signing_secret;
  uint8_t completion_digest[BENCH_DIGEST_BYTES];
  uint8_t *ordered_commitments = NULL;
  long long active_started = 0;
  unsigned i;
  int status = RLC_ERR;

  ec_public_key_null(verification_key);
  ec_secret_key_null(signing_key);
  bn_null(order);
  bn_null(signing_secret);
  items = calloc(options->count, sizeof(*items));
  ordered_commitments = malloc((size_t) options->count * BENCH_DIGEST_BYTES);
  if (items == NULL || ordered_commitments == NULL) goto cleanup;
  ec_public_key_new(verification_key);
  ec_secret_key_new(signing_key);
  bn_new(order);
  bn_new(signing_secret);
  ec_curve_get_ord(order);

  /* Phase 1: receive all independent INIT frames before replying. */
  for (i = 0; i < options->count; i++) {
    uint8_t expected_digest[BENCH_DIGEST_BYTES];
    const uint8_t *request_item;
    uint8_t *response;
    size_t length = 0;
    long long started;
    if (receive_expected(socket, BENCH_MSG_BATCH_INIT, options->pair_id, 1, i,
                         options->execution_id, &items[i].request, &length,
                         metrics) != RLC_OK || length != request_length) {
      goto cleanup;
    }
    if (i == 0) active_started = bench_monotonic_ns();
    request_item = items[i].request + BENCH_HEADER_SIZE;
    bench_item_digest(options->mode, options->pair_id, i, options->count,
                      options->execution_id, expected_digest);
    if (!bench_digest_equal(request_item, expected_digest)) goto cleanup;
    if (bench_derive_item_public(verification_key->pk,
                                 state->bob_ec_pk->pk,
                                 "CLIENT-SIGNING-KEY-v1", options->pair_id,
                                 i, options->count) != RLC_OK) {
      goto cleanup;
    }
    bn_read_bin(state->sigma_r->e, request_item + BENCH_DIGEST_BYTES,
                RLC_BN_SIZE);
    bn_read_bin(state->sigma_r->s,
                request_item + BENCH_DIGEST_BYTES + RLC_BN_SIZE,
                RLC_BN_SIZE);
    started = bench_monotonic_ns();
    if (cp_ecss_ver(state->sigma_r->e, state->sigma_r->s,
                    (uint8_t *) request_item, BENCH_DIGEST_BYTES,
                    verification_key->pk) != 1) {
      goto cleanup;
    }
    metrics->verify_request_ns += bench_monotonic_ns() - started;

    items[i].open = calloc(1, open_length);
    items[i].commit = calloc(1, BENCH_HEADER_SIZE + BENCH_DIGEST_BYTES);
    if (items[i].open == NULL || items[i].commit == NULL) goto cleanup;
    bench_write_header(items[i].open, BENCH_MSG_SERVER_OPEN, 1,
                       options->pair_id, i, options->execution_id);
    bench_write_header(items[i].commit, BENCH_MSG_SERVER_COMMIT, 1,
                       options->pair_id, i, options->execution_id);
    if (bench_random_salt(items[i].open + BENCH_HEADER_SIZE) != RLC_OK) {
      goto cleanup;
    }
    response = items[i].open + BENCH_HEADER_SIZE + BENCH_SALT_BYTES;
    started = bench_monotonic_ns();
    bn_rand_mod(state->alpha, order);
    ec_mul_gen(state->g_to_the_alpha, state->alpha);
    if (bench_derive_item_secret(signing_secret, state->tumbler_ec_sk->sk,
                                 "SERVER-SIGNING-KEY-v1", options->pair_id,
                                 i, options->count) != RLC_OK) {
      goto cleanup;
    }
    bn_copy(signing_key->sk, signing_secret);
    if (adaptor_schnorr_sign(state->sigma_tr, (uint8_t *) request_item,
                             BENCH_DIGEST_BYTES, state->g_to_the_alpha,
                             signing_key) != RLC_OK) {
      goto cleanup;
    }
    metrics->generate_response_ns += bench_monotonic_ns() - started;
    ec_write_bin(response, RLC_EC_SIZE_COMPRESSED, state->g_to_the_alpha, 1);
    bn_write_bin(response + RLC_EC_SIZE_COMPRESSED, RLC_BN_SIZE,
                 state->sigma_tr->e);
    bn_write_bin(response + RLC_EC_SIZE_COMPRESSED + RLC_BN_SIZE,
                 RLC_BN_SIZE, state->sigma_tr->s);
    bench_commitment_digest(items[i].open + BENCH_HEADER_SIZE,
                            open_length - BENCH_HEADER_SIZE,
                            items[i].commit + BENCH_HEADER_SIZE);
  }
  for (i = 0; i < options->count; i++) {
    if (send_frame(socket, items[i].commit,
                   BENCH_HEADER_SIZE + BENCH_DIGEST_BYTES, metrics) != RLC_OK) {
      goto cleanup;
    }
  }

  /* Phase 2: collect all READY frames, then release every opening. */
  for (i = 0; i < options->count; i++) {
    uint8_t *ready = NULL;
    size_t length = 0;
    if (receive_expected(socket, BENCH_MSG_CLIENT_NONCE, options->pair_id, 1,
                         i, options->execution_id, &ready, &length,
                         metrics) != RLC_OK || length != BENCH_HEADER_SIZE) {
      free(ready);
      goto cleanup;
    }
    free(ready);
  }
  if (options->inject_bad_open) {
    items[0].open[open_length - 1] ^= 0x01;
  }
  for (i = 0; i < options->count; i++) {
    if (send_frame(socket, items[i].open, open_length, metrics) != RLC_OK) {
      goto cleanup;
    }
  }

  /* Phase 3: verify all independent finals before acknowledging any item. */
  for (i = 0; i < options->count; i++) {
    const uint8_t *message;
    const uint8_t *response;
    const uint8_t *final_item;
    size_t length = 0;
    long long started;
    if (receive_expected(socket, BENCH_MSG_CLIENT_FINAL, options->pair_id, 1,
                         i, options->execution_id, &items[i].final_frame,
                         &length, metrics) != RLC_OK || length != final_length) {
      goto cleanup;
    }
    message = items[i].request + BENCH_HEADER_SIZE;
    response = items[i].open + BENCH_HEADER_SIZE + BENCH_SALT_BYTES;
    final_item = items[i].final_frame + BENCH_HEADER_SIZE;
    if (bench_derive_item_public(verification_key->pk,
                                 state->bob_ec_pk->pk,
                                 "CLIENT-SIGNING-KEY-v1", options->pair_id,
                                 i, options->count) != RLC_OK) {
      goto cleanup;
    }
    ec_read_bin(state->g_to_the_alpha, response, RLC_EC_SIZE_COMPRESSED);
    bn_read_bin(state->sigma_f->e, final_item, RLC_BN_SIZE);
    bn_read_bin(state->sigma_f->s, final_item + RLC_BN_SIZE, RLC_BN_SIZE);
    started = bench_monotonic_ns();
    if (adaptor_schnorr_preverify(state->sigma_f, (uint8_t *) message,
                                  BENCH_DIGEST_BYTES, state->g_to_the_alpha,
                                  verification_key) != 1) {
      send_abort(socket, options, i, 1, metrics);
      goto cleanup;
    }
    metrics->verify_final_ns += bench_monotonic_ns() - started;
  }
  for (i = 0; i < options->count; i++) {
    memcpy(ordered_commitments + (size_t) i * BENCH_DIGEST_BYTES,
           items[i].commit + BENCH_HEADER_SIZE, BENCH_DIGEST_BYTES);
  }
  if (bench_independent_completion_digest(
          ordered_commitments, options->count, options->pair_id,
          options->execution_id, completion_digest) != RLC_OK) {
    goto cleanup;
  }
  {
    uint8_t done[BENCH_HEADER_SIZE + BENCH_DIGEST_BYTES];
    bench_write_header(done, BENCH_MSG_DONE, options->count, options->pair_id,
                       0, options->execution_id);
    memcpy(done + BENCH_HEADER_SIZE, completion_digest, BENCH_DIGEST_BYTES);
    if (send_frame(socket, done, sizeof(done), metrics) != RLC_OK) goto cleanup;
  }
  metrics->sessions += options->count;
  metrics->protocol_wall_ns += bench_monotonic_ns() - active_started;
  status = RLC_OK;

cleanup:
  free(ordered_commitments);
  free_reference_server_items(items, options->count);
  if (verification_key != NULL) ec_public_key_free(verification_key);
  if (signing_key != NULL) ec_secret_key_free(signing_key);
  bn_free(order);
  bn_free(signing_secret);
  return status;
}

static int run_session(tumbler_state_t state, void *socket,
                       const bench_options_t *options,
                       unsigned expected_ordinal, unsigned expected_count,
                       server_metrics_t *metrics) {
  const int explicit_nonce = bench_mode_uses_explicit_nonce(options->mode);
  const size_t child_bytes = bench_mode_has_child_sessions(options->mode)
                                 ? BENCH_CHILD_SESSION_BYTES : 0;
  const size_t request_stride = bench_request_bytes(options->mode);
  const size_t response_stride = bench_response_bytes(options->mode);
  const size_t final_stride = bench_final_bytes(options->mode);
  const size_t open_prefix = bench_open_prefix_bytes(options->mode);
  const size_t done_payload = bench_done_bytes(options->mode);
  const size_t ready_expected = BENCH_HEADER_SIZE +
                                (explicit_nonce ? BENCH_SALT_BYTES : 0);
  const size_t open_length = BENCH_HEADER_SIZE + open_prefix +
                             (size_t) expected_count * response_stride;
  uint8_t *request = NULL;
  uint8_t *ready = NULL;
  uint8_t *final_frame = NULL;
  uint8_t *open_frame = NULL;
  uint8_t commit_frame[BENCH_HEADER_SIZE + BENCH_DIGEST_BYTES];
  uint8_t done_frame[BENCH_HEADER_SIZE + 2 * BENCH_DIGEST_BYTES];
  uint8_t request_salt[BENCH_SALT_BYTES] = {0};
  uint8_t server_salt[BENCH_SALT_BYTES] = {0};
  schnorr_signature_t *signatures = NULL;
  ec_t *nonces = NULL;
  ec_t *adaptors = NULL;
  ec_t *client_public_keys = NULL;
  ec_t signing_nonce;
  ec_t base_client_public;
  ec_secret_key_t signing_key;
  ec_public_key_t verification_key;
  bn_t order;
  bn_t base_server_secret;
  bn_t signing_secret;
  size_t request_length = 0;
  size_t ready_length = 0;
  size_t final_length = 0;
  long long active_started = 0;
  unsigned i;
  int status = RLC_ERR;

  ec_null(signing_nonce);
  ec_null(base_client_public);
  ec_secret_key_null(signing_key);
  ec_public_key_null(verification_key);
  bn_null(order);
  bn_null(base_server_secret);
  bn_null(signing_secret);
  if (explicit_nonce &&
      allocate_verification_batch(expected_count, &signatures,
                                  &nonces, &adaptors,
                                  &client_public_keys) != RLC_OK) {
    goto cleanup;
  }
  ec_new(signing_nonce);
  ec_new(base_client_public);
  ec_secret_key_new(signing_key);
  ec_public_key_new(verification_key);
  bn_new(order);
  bn_new(base_server_secret);
  bn_new(signing_secret);
  ec_curve_get_ord(order);
  ec_copy(base_client_public, state->bob_ec_pk->pk);
  bn_copy(base_server_secret, state->tumbler_ec_sk->sk);

  if (receive_expected(socket, BENCH_MSG_BATCH_INIT, options->pair_id,
                       expected_count, expected_ordinal, options->execution_id,
                       &request, &request_length, metrics) != RLC_OK ||
      request_length != BENCH_HEADER_SIZE +
                            (size_t) expected_count * request_stride) {
    goto cleanup;
  }
  active_started = bench_monotonic_ns();

  for (i = 0; i < expected_count; i++) {
    const uint8_t *request_item = request + BENCH_HEADER_SIZE +
                                  (size_t) i * request_stride;
    uint8_t expected_digest[BENCH_DIGEST_BYTES];
    bench_item_digest(options->mode, options->pair_id, expected_ordinal + i,
                      options->count, options->execution_id, expected_digest);
    if (!bench_digest_equal(request_item, expected_digest)) goto cleanup;
    if (child_bytes != 0) {
      uint8_t expected_child[BENCH_CHILD_SESSION_BYTES];
      bench_child_session_digest(options->pair_id, expected_ordinal + i,
                                 options->count, options->execution_id,
                                 expected_child);
      if (!bench_digest_equal(request_item + BENCH_DIGEST_BYTES,
                              expected_child)) {
        goto cleanup;
      }
    }
    if (explicit_nonce) {
      ec_read_bin(nonces[i], request_item + BENCH_DIGEST_BYTES + child_bytes,
                  RLC_EC_SIZE_COMPRESSED);
      bn_read_bin(signatures[i]->e,
                  request_item + BENCH_DIGEST_BYTES + child_bytes +
                      RLC_EC_SIZE_COMPRESSED,
                  RLC_BN_SIZE);
      bn_read_bin(signatures[i]->s,
                  request_item + BENCH_DIGEST_BYTES + child_bytes +
                      RLC_EC_SIZE_COMPRESSED +
                      RLC_BN_SIZE,
                  RLC_BN_SIZE);
      if (bench_derive_item_public(
              client_public_keys[i], base_client_public,
              "CLIENT-SIGNING-KEY-v1", options->pair_id,
              expected_ordinal + i, options->count) != RLC_OK) {
        goto cleanup;
      }
    }
  }

  if (explicit_nonce) {
    long long started;
    if (bench_random_salt(request_salt) != RLC_OK) goto cleanup;
    started = bench_monotonic_ns();
    if (verify_explicit_set(options, request, request_stride, signatures,
                            nonces, adaptors, 0, client_public_keys,
                            expected_count, request_salt,
                            "CLIENT-REQUEST-v1", &metrics->verifier) != RLC_OK) {
      goto cleanup;
    }
    metrics->verify_request_ns += bench_monotonic_ns() - started;
  } else {
    for (i = 0; i < expected_count; i++) {
      const uint8_t *request_item = request + BENCH_HEADER_SIZE +
                                    (size_t) i * request_stride;
      long long started;
      if (bench_derive_item_public(
              verification_key->pk, base_client_public,
              "CLIENT-SIGNING-KEY-v1", options->pair_id,
              expected_ordinal + i, options->count) != RLC_OK) {
        goto cleanup;
      }
      bn_read_bin(state->sigma_r->e, request_item + BENCH_DIGEST_BYTES,
                  RLC_BN_SIZE);
      bn_read_bin(state->sigma_r->s,
                  request_item + BENCH_DIGEST_BYTES + RLC_BN_SIZE,
                  RLC_BN_SIZE);
      started = bench_monotonic_ns();
      if (cp_ecss_ver(state->sigma_r->e, state->sigma_r->s,
                      (uint8_t *) request_item, BENCH_DIGEST_BYTES,
                      verification_key->pk) != 1) {
        goto cleanup;
      }
      metrics->verify_request_ns += bench_monotonic_ns() - started;
    }
  }

  open_frame = calloc(1, open_length);
  if (open_frame == NULL) goto cleanup;
  bench_write_header(open_frame, BENCH_MSG_SERVER_OPEN, expected_count,
                     options->pair_id, expected_ordinal,
                     options->execution_id);
  if (!explicit_nonce && bench_random_salt(server_salt) != RLC_OK) goto cleanup;
  if (!explicit_nonce) {
    memcpy(open_frame + BENCH_HEADER_SIZE, server_salt, BENCH_SALT_BYTES);
  }

  for (i = 0; i < expected_count; i++) {
    const uint8_t *request_item = request + BENCH_HEADER_SIZE +
                                  (size_t) i * request_stride;
    uint8_t *response_item = open_frame + BENCH_HEADER_SIZE + open_prefix +
                             (size_t) i * response_stride;
    long long started;
    started = bench_monotonic_ns();
    bn_rand_mod(state->alpha, order);
    ec_mul_gen(state->g_to_the_alpha, state->alpha);
    if (explicit_nonce) {
      if (bench_derive_item_secret(
              signing_secret, base_server_secret, "SERVER-SIGNING-KEY-v1",
              options->pair_id, expected_ordinal + i, options->count) != RLC_OK) {
        goto cleanup;
      }
      ec_copy(adaptors[i], state->g_to_the_alpha);
      if (child_bytes != 0) {
        memcpy(response_item, request_item + BENCH_DIGEST_BYTES, child_bytes);
        response_item += child_bytes;
      }
      if (bench_schnorr_sign_explicit(state->sigma_tr, signing_nonce,
                                      request_item, BENCH_DIGEST_BYTES,
                                      state->g_to_the_alpha, 1,
                                      signing_secret) != RLC_OK) {
        goto cleanup;
      }
      ec_write_bin(response_item, RLC_EC_SIZE_COMPRESSED,
                   state->g_to_the_alpha, 1);
      ec_write_bin(response_item + RLC_EC_SIZE_COMPRESSED,
                   RLC_EC_SIZE_COMPRESSED, signing_nonce, 1);
      bn_write_bin(response_item + 2 * RLC_EC_SIZE_COMPRESSED,
                   RLC_BN_SIZE, state->sigma_tr->e);
      bn_write_bin(response_item + 2 * RLC_EC_SIZE_COMPRESSED + RLC_BN_SIZE,
                   RLC_BN_SIZE, state->sigma_tr->s);
    } else {
      if (bench_derive_item_secret(
              signing_secret, base_server_secret, "SERVER-SIGNING-KEY-v1",
              options->pair_id, expected_ordinal + i, options->count) != RLC_OK) {
        goto cleanup;
      }
      bn_copy(signing_key->sk, signing_secret);
      if (adaptor_schnorr_sign(state->sigma_tr,
                               (uint8_t *) request_item, BENCH_DIGEST_BYTES,
                               state->g_to_the_alpha,
                               signing_key) != RLC_OK) {
        goto cleanup;
      }
      ec_write_bin(response_item, RLC_EC_SIZE_COMPRESSED,
                   state->g_to_the_alpha, 1);
      bn_write_bin(response_item + RLC_EC_SIZE_COMPRESSED,
                   RLC_BN_SIZE, state->sigma_tr->e);
      bn_write_bin(response_item + RLC_EC_SIZE_COMPRESSED + RLC_BN_SIZE,
                   RLC_BN_SIZE, state->sigma_tr->s);
    }
    metrics->generate_response_ns += bench_monotonic_ns() - started;
  }

  bench_write_header(commit_frame, BENCH_MSG_SERVER_COMMIT, expected_count,
                     options->pair_id, expected_ordinal,
                     options->execution_id);
  bench_commitment_digest(open_frame + BENCH_HEADER_SIZE,
                          open_length - BENCH_HEADER_SIZE,
                          commit_frame + BENCH_HEADER_SIZE);
  if (send_frame(socket, commit_frame, sizeof(commit_frame), metrics) != RLC_OK ||
      receive_expected(socket, BENCH_MSG_CLIENT_NONCE, options->pair_id,
                       expected_count, expected_ordinal, options->execution_id,
                       &ready, &ready_length, metrics) != RLC_OK ||
      ready_length != ready_expected) {
    goto cleanup;
  }
  if (options->inject_bad_open && expected_ordinal == 0) {
    open_frame[open_length - 1] ^= 1;
  }
  if (send_frame(socket, open_frame, open_length, metrics) != RLC_OK ||
      receive_expected(socket, BENCH_MSG_CLIENT_FINAL, options->pair_id,
                       expected_count, expected_ordinal, options->execution_id,
                       &final_frame, &final_length, metrics) != RLC_OK ||
      final_length != BENCH_HEADER_SIZE +
                          (size_t) expected_count * final_stride) {
    goto cleanup;
  }

  if (explicit_nonce) {
    long long started;
    for (i = 0; i < expected_count; i++) {
      const uint8_t *final_item = final_frame + BENCH_HEADER_SIZE +
                                  (size_t) i * final_stride;
      const uint8_t *request_item = request + BENCH_HEADER_SIZE +
                                    (size_t) i * request_stride;
      if (child_bytes != 0) {
        if (!bench_digest_equal(final_item,
                                request_item + BENCH_DIGEST_BYTES)) {
          goto cleanup;
        }
        final_item += child_bytes;
      }
      ec_read_bin(nonces[i], final_item, RLC_EC_SIZE_COMPRESSED);
      bn_read_bin(signatures[i]->e,
                  final_item + RLC_EC_SIZE_COMPRESSED, RLC_BN_SIZE);
      bn_read_bin(signatures[i]->s,
                  final_item + RLC_EC_SIZE_COMPRESSED + RLC_BN_SIZE,
                  RLC_BN_SIZE);
    }
    if (bench_random_salt(server_salt) != RLC_OK) goto cleanup;
    started = bench_monotonic_ns();
    if (verify_explicit_set(options, request, request_stride, signatures,
                            nonces, adaptors, 1, client_public_keys,
                            expected_count, server_salt,
                            "CLIENT-FINAL-v1", &metrics->verifier) != RLC_OK) {
      send_abort(socket, options, expected_ordinal, expected_count, metrics);
      goto cleanup;
    }
    metrics->verify_final_ns += bench_monotonic_ns() - started;
  } else {
    for (i = 0; i < expected_count; i++) {
      const uint8_t *message = request + BENCH_HEADER_SIZE +
                               (size_t) i * request_stride;
      const uint8_t *response = open_frame + BENCH_HEADER_SIZE +
                                open_prefix +
                                (size_t) i * response_stride;
      const uint8_t *final_item = final_frame + BENCH_HEADER_SIZE +
                                  (size_t) i * final_stride;
      long long started;
      if (bench_derive_item_public(
              verification_key->pk, base_client_public,
              "CLIENT-SIGNING-KEY-v1", options->pair_id,
              expected_ordinal + i, options->count) != RLC_OK) {
        goto cleanup;
      }
      ec_read_bin(state->g_to_the_alpha, response, RLC_EC_SIZE_COMPRESSED);
      bn_read_bin(state->sigma_f->e, final_item, RLC_BN_SIZE);
      bn_read_bin(state->sigma_f->s, final_item + RLC_BN_SIZE, RLC_BN_SIZE);
      started = bench_monotonic_ns();
      if (adaptor_schnorr_preverify(state->sigma_f,
                                    (uint8_t *) message,
                                    BENCH_DIGEST_BYTES,
                                    state->g_to_the_alpha,
                                    verification_key) != 1) {
        send_abort(socket, options, expected_ordinal, expected_count, metrics);
        goto cleanup;
      }
      metrics->verify_final_ns += bench_monotonic_ns() - started;
    }
  }

  bench_write_header(done_frame, BENCH_MSG_DONE, expected_count,
                     options->pair_id, expected_ordinal,
                     options->execution_id);
  memcpy(done_frame + BENCH_HEADER_SIZE,
         commit_frame + BENCH_HEADER_SIZE, BENCH_DIGEST_BYTES);
  if (bench_mode_uses_msm(options->mode)) {
    uint8_t status_frame[BENCH_HEADER_SIZE + BENCH_SALT_BYTES];
    bench_write_header(status_frame, BENCH_MSG_FINAL_STATUS, expected_count,
                       options->pair_id, expected_ordinal,
                       options->execution_id);
    memcpy(status_frame + BENCH_HEADER_SIZE, server_salt, BENCH_SALT_BYTES);
    if (send_frame(socket, status_frame, sizeof(status_frame), metrics) !=
        RLC_OK) {
      goto cleanup;
    }
  } else if (explicit_nonce) {
    memcpy(done_frame + BENCH_HEADER_SIZE + BENCH_DIGEST_BYTES,
           server_salt, BENCH_SALT_BYTES);
  }
  if (send_frame(socket, done_frame, BENCH_HEADER_SIZE + done_payload,
                 metrics) != RLC_OK) {
    goto cleanup;
  }
  metrics->sessions++;
  metrics->protocol_wall_ns += bench_monotonic_ns() - active_started;
  status = RLC_OK;

cleanup:
  free(request);
  free(ready);
  free(final_frame);
  free(open_frame);
  free_verification_batch(expected_count, signatures, nonces, adaptors,
                          client_public_keys);
  ec_free(signing_nonce);
  ec_free(base_client_public);
  if (signing_key != NULL) ec_secret_key_free(signing_key);
  if (verification_key != NULL) ec_public_key_free(verification_key);
  bn_free(order);
  bn_free(base_server_secret);
  bn_free(signing_secret);
  return status;
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
  bench_resource_mark_t resource_before;
  bench_resource_mark_t resource_after;
  bench_resource_mark_t resource_delta;

  memset(&metrics, 0, sizeof(metrics));
  memset(&zap_service, 0, sizeof(zap_service));
  tumbler_state_null(state);
  if (bench_parse_options(argc, argv, &options) != RLC_OK || init() != RLC_OK) {
    return 1;
  }
  context = zmq_ctx_new();
  if (context == NULL ||
      (options.use_tcp &&
       bench_zap_start(&zap_service, context, &options) != RLC_OK)) {
    result_status = RLC_ERR;
    goto cleanup;
  }
  socket = context == NULL ? NULL :
      zmq_socket(context,
                 options.mode == BENCH_MODE_ORIGINAL_ITEMWISE ||
                         bench_mode_uses_msm(options.mode)
                     ? ZMQ_DEALER : ZMQ_REP);
  timeout_ms = (int) options.io_timeout_ms;
  if (socket == NULL ||
      zmq_setsockopt(socket, ZMQ_LINGER, &linger, sizeof(linger)) != 0 ||
      zmq_setsockopt(socket, ZMQ_RCVTIMEO, &timeout_ms, sizeof(timeout_ms)) != 0 ||
      zmq_setsockopt(socket, ZMQ_SNDTIMEO, &timeout_ms, sizeof(timeout_ms)) != 0 ||
      (options.use_tcp &&
       bench_curve_configure_server(socket, &options) != RLC_OK) ||
      bench_make_server_endpoint(endpoint, sizeof(endpoint), &options) != RLC_OK) {
    result_status = RLC_ERR;
    goto cleanup;
  }
  bench_cleanup_endpoint(endpoint);
  if (zmq_bind(socket, endpoint) != 0) {
    perror("zmq_bind");
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
                                    state->bob_ec_pk) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    metrics.setup_ns = bench_monotonic_ns() - process_started;
    if (bench_resource_mark(&resource_before) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    if (options.mode == BENCH_MODE_ORIGINAL_ITEMWISE) {
      if (run_reference_pipelined(state, socket, &options, &metrics) !=
          RLC_OK) {
        result_status = RLC_ERR;
      }
    } else if (bench_mode_is_coalesced(options.mode)) {
      if (run_session(state, socket, &options, 0, options.count,
                      &metrics) != RLC_OK) {
        result_status = RLC_ERR;
      }
    }
    if (bench_resource_mark(&resource_after) != RLC_OK) {
      result_status = RLC_ERR;
    } else {
      bench_resource_delta(&resource_before, &resource_after, &resource_delta);
      metrics.user_cpu_ns = resource_delta.user_cpu_ns;
      metrics.system_cpu_ns = resource_delta.system_cpu_ns;
      metrics.max_rss_kb = resource_delta.max_rss_kb;
      metrics.voluntary_context_switches =
          resource_delta.voluntary_context_switches;
      metrics.involuntary_context_switches =
          resource_delta.involuntary_context_switches;
      metrics.scheduler_wait_ns = resource_delta.scheduler_wait_ns;
      metrics.scheduler_slices = resource_delta.scheduler_slices;
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    if (state != NULL) tumbler_state_free(state);
  }

cleanup:
  if (socket != NULL) zmq_close(socket);
  bench_cleanup_endpoint(endpoint);
  if (options.use_tcp) bench_zap_stop(&zap_service);
  if (context != NULL) zmq_ctx_destroy(context);
  clean();
  if (result_status != RLC_OK) return 1;
  printf("SERVER_RESULT\t%s\t%u\t%u\t%u\t%lld\t%lld\t%lld\n",
         bench_mode_name(options.mode), options.pair_id, options.count,
         metrics.sessions, metrics.verify_request_ns,
         metrics.generate_response_ns, metrics.verify_final_ns);
  printf("SERVER_VERIFIER_RESULT\t%s\t%u\t%u\t%lld\t%lld\t%u\t%u\t%u\n",
         bench_mode_name(options.mode), options.pair_id, options.count,
         metrics.verifier.challenge_ns, metrics.verifier.msm_ns,
         metrics.verifier.equations, metrics.verifier.msm_calls,
         metrics.verifier.fallbacks);
  printf("SERVER_RESOURCE_RESULT\t%s\t%u\t%u\t%lld\t%lld\t%lld\t%lld\t%ld\t%ld\t%ld\t%lld\t%lld\n",
         bench_mode_name(options.mode), options.pair_id, options.count,
         metrics.protocol_wall_ns, metrics.setup_ns, metrics.user_cpu_ns,
         metrics.system_cpu_ns, metrics.max_rss_kb,
         metrics.voluntary_context_switches,
         metrics.involuntary_context_switches, metrics.scheduler_wait_ns,
         metrics.scheduler_slices);
  printf("SERVER_TRANSPORT_RESULT\t%s\t%u\t%u\t%zu\t%zu\t%u\t%u\t%u\t%u\n",
         bench_mode_name(options.mode), options.pair_id, options.count,
         metrics.bytes_sent, metrics.bytes_received, metrics.sent_frames,
         metrics.received_frames, metrics.send_calls, metrics.receive_calls);
#ifdef BENCH_ALLOCATION_PROFILE
  {
    bench_allocation_metrics_t allocations;
    bench_allocation_metrics_read(&allocations);
    printf("SERVER_ALLOCATION_RESULT\t%s\t%u\t%u\t%llu\t%llu\t%llu\t%llu\t%llu\n",
           bench_mode_name(options.mode), options.pair_id, options.count,
           allocations.malloc_calls, allocations.calloc_calls,
           allocations.realloc_calls, allocations.free_calls,
           allocations.requested_bytes);
  }
#endif
  return 0;
}
