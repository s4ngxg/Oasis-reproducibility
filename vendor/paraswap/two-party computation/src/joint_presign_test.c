#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "preswap_protocol.h"

#define TEST_ITEMS 7u

static void write_u32_be_test(uint8_t out[4], uint32_t value) {
  out[0] = (uint8_t) (value >> 24);
  out[1] = (uint8_t) (value >> 16);
  out[2] = (uint8_t) (value >> 8);
  out[3] = (uint8_t) value;
}

static int test_invalid_index_encoding(void) {
  uint8_t encoded[4 + 3 * 4];
  uint32_t decoded[TEST_ITEMS];
  unsigned count = 99;
  write_u32_be_test(encoded, 0);
  if (bench_decode_invalid_indices(encoded, 4, TEST_ITEMS, decoded,
                                   TEST_ITEMS, &count) != RLC_OK || count != 0) {
    return RLC_ERR;
  }

  write_u32_be_test(encoded, 3);
  write_u32_be_test(encoded + 4, 0);
  write_u32_be_test(encoded + 8, 2);
  write_u32_be_test(encoded + 12, 6);
  if (bench_decode_invalid_indices(encoded, sizeof(encoded), TEST_ITEMS,
                                   decoded, TEST_ITEMS, &count) != RLC_OK ||
      count != 3 || decoded[0] != 0 || decoded[1] != 2 || decoded[2] != 6) {
    return RLC_ERR;
  }
  write_u32_be_test(encoded + 8, 0);
  if (bench_decode_invalid_indices(encoded, sizeof(encoded), TEST_ITEMS,
                                   decoded, TEST_ITEMS, &count) == RLC_OK) {
    return RLC_ERR;
  }
  write_u32_be_test(encoded + 4, 2);
  write_u32_be_test(encoded + 8, 1);
  if (bench_decode_invalid_indices(encoded, sizeof(encoded), TEST_ITEMS,
                                   decoded, TEST_ITEMS, &count) == RLC_OK) {
    return RLC_ERR;
  }
  write_u32_be_test(encoded + 4, 0);
  write_u32_be_test(encoded + 8, 2);
  write_u32_be_test(encoded + 12, TEST_ITEMS);
  if (bench_decode_invalid_indices(encoded, sizeof(encoded), TEST_ITEMS,
                                   decoded, TEST_ITEMS, &count) == RLC_OK ||
      bench_decode_invalid_indices(encoded, sizeof(encoded) - 1, TEST_ITEMS,
                                   decoded, TEST_ITEMS, &count) == RLC_OK ||
      bench_decode_invalid_indices(encoded, sizeof(encoded), TEST_ITEMS,
                                   decoded, 2, &count) == RLC_OK) {
    return RLC_ERR;
  }
  return RLC_OK;
}

static void fprint_hex(FILE *stream, const uint8_t *value, size_t length) {
  size_t i;
  for (i = 0; i < length; i++) fprintf(stream, "%02x", value[i]);
}

static void print_hex(const uint8_t *value, size_t length) {
  fprint_hex(stdout, value, length);
}

static void print_point_hex(const ec_t point) {
  uint8_t encoded[BENCH_POINT_BYTES];
  ec_write_bin(encoded, (int) sizeof(encoded), point, 1);
  print_hex(encoded, sizeof(encoded));
}

static void print_transcript_diagnostic(const bench_transcript_t *transcript) {
  unsigned i;
  for (i = 0; i < transcript->count; i++) {
    printf("JOINT_TRANSCRIPT_ITEM\tordinal=%u\tmessage=", i);
    print_hex(transcript->message_digests +
                  (size_t) i * BENCH_DIGEST_BYTES,
              BENCH_DIGEST_BYTES);
    printf("\tstatement=");
    print_point_hex(transcript->statements[i]);
    printf("\tclient_key=");
    print_point_hex(transcript->client_public_keys[i]);
    printf("\tserver_key=");
    print_point_hex(transcript->server_public_keys[i]);
    printf("\tjoint_key=");
    print_point_hex(transcript->joint_public_keys[i]);
    printf("\titem=");
    print_hex(transcript->item_digests +
                  (size_t) i * BENCH_DIGEST_BYTES,
              BENCH_DIGEST_BYTES);
    printf("\n");
  }
}

static void print_signature_diagnostic(unsigned ordinal,
                                       const uint8_t *message,
                                       const ec_t statement,
                                       const ec_t joint_key,
                                       const bn_t challenge,
                                       const bn_t scalar) {
  uint8_t value[BENCH_SCALAR_BYTES];
  printf("JOINT_SIGNATURE\tordinal=%u\tmessage=", ordinal);
  print_hex(message, BENCH_DIGEST_BYTES);
  printf("\tstatement=");
  print_point_hex(statement);
  printf("\tjoint_key=");
  print_point_hex(joint_key);
  printf("\te=");
  bn_write_bin(value, (int) sizeof(value), challenge);
  print_hex(value, sizeof(value));
  printf("\ts=");
  bn_write_bin(value, (int) sizeof(value), scalar);
  print_hex(value, sizeof(value));
  printf("\n");
}

static int digest_matches_hex(const uint8_t digest[BENCH_DIGEST_BYTES],
                              const char expected[65]) {
  static const char hex[] = "0123456789abcdef";
  unsigned i;
  for (i = 0; i < BENCH_DIGEST_BYTES; i++) {
    if (hex[digest[i] >> 4] != expected[2 * i] ||
        hex[digest[i] & 0x0f] != expected[2 * i + 1]) return 0;
  }
  return expected[64] == '\0';
}

static int allocate_points(ec_t **values, unsigned count) {
  unsigned i;
  *values = calloc(count, sizeof(**values));
  if (*values == NULL) return RLC_ERR;
  for (i = 0; i < count; i++) {
    ec_null((*values)[i]);
    ec_new((*values)[i]);
  }
  return RLC_OK;
}

static int allocate_scalars(bn_t **values, unsigned count) {
  unsigned i;
  *values = calloc(count, sizeof(**values));
  if (*values == NULL) return RLC_ERR;
  for (i = 0; i < count; i++) {
    bn_null((*values)[i]);
    bn_new((*values)[i]);
  }
  return RLC_OK;
}

static void free_points(ec_t *values, unsigned count) {
  unsigned i;
  if (values != NULL) {
    for (i = 0; i < count; i++) ec_free(values[i]);
  }
  free(values);
}

static void free_scalars(bn_t *values, unsigned count) {
  unsigned i;
  if (values != NULL) {
    for (i = 0; i < count; i++) bn_free(values[i]);
  }
  free(values);
}

static uint64_t vector_word(uint64_t vector_id, uint64_t stream) {
  uint64_t value = vector_id + UINT64_C(0x9e3779b97f4a7c15) * (stream + 1);
  value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
  value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
  return value ^ (value >> 31);
}

static int localizes_exactly_one_invalid_item(
    bench_equation_t equation, const bench_transcript_t *transcript,
    bench_mode_t mode, unsigned invalid_ordinal,
    ec_t *client_nonces, ec_t *server_nonces, bn_t *challenges,
    bn_t *server_partials, bn_t *client_partials, bn_t *full_scalars,
    const uint8_t salt[BENCH_SALT_BYTES]) {
  unsigned ordinal;
  unsigned rejected = 0;
  for (ordinal = 0; ordinal < TEST_ITEMS; ordinal++) {
    int valid = bench_joint_batch_verify(
        equation, transcript, mode, ordinal, 1,
        client_nonces + ordinal, server_nonces + ordinal,
        challenges + ordinal, server_partials + ordinal,
        client_partials + ordinal, full_scalars + ordinal, salt, NULL);
    if (!valid) {
      if (ordinal != invalid_ordinal) return 0;
      rejected++;
    }
  }
  return rejected == 1;
}

static int run_joint_test(uint64_t vector_id, int verbose) {
  bench_options_t options;
  bench_options_t changed_options;
  bench_transcript_t transcript;
  bench_transcript_t changed_transcript;
  ec_t client_base_public;
  ec_t server_base_public;
  ec_t *client_nonces = NULL;
  ec_t *server_nonces = NULL;
  ec_t commitment;
  bn_t client_base_secret;
  bn_t server_base_secret;
  bn_t client_secret;
  bn_t server_secret;
  bn_t client_nonce_scalar;
  bn_t server_nonce_scalar;
  bn_t opening;
  bn_t order;
  bn_t saved;
  bn_t *challenges = NULL;
  bn_t *server_partials = NULL;
  bn_t *client_partials = NULL;
  bn_t *full_scalars = NULL;
  ec_public_key_t joint_public;
  schnorr_signature_t signature;
  uint8_t random[BENCH_SALT_BYTES];
  uint8_t server_salt[BENCH_SALT_BYTES];
  uint8_t client_salt[BENCH_SALT_BYTES];
  uint8_t full_salt[BENCH_SALT_BYTES];
  uint8_t client_proof[BENCH_KEY_OWNERSHIP_PROOF_BYTES];
  uint8_t server_proof[BENCH_KEY_OWNERSHIP_PROOF_BYTES];
  uint8_t tampered_proof[BENCH_KEY_OWNERSHIP_PROOF_BYTES];
  uint8_t changed_preparation_digest[BENCH_CONTEXT_SEED_BYTES];
  bench_verify_metrics_t metrics = {0};
  unsigned i;
  int status = RLC_ERR;

  memset(&options, 0, sizeof(options));
  options.host_key_fd = -1;
  options.host_output_fd = -1;
  options.host_address_keys_fd = -1;
  options.host_client_keys_fd = -1;
  options.host_server_keys_fd = -1;
  memset(&transcript, 0, sizeof(transcript));
  memset(&changed_transcript, 0, sizeof(changed_transcript));
  options.mode = BENCH_MODE_BJP_MSM;
  options.count = TEST_ITEMS;
  options.pair_id = vector_id == 0 ? 3u :
      (unsigned) (1u + vector_word(vector_id, 0) % 1000000u);
  options.execution_id = vector_id == 0 ? 19u : vector_word(vector_id, 1);
  options.context_participants = 4;
  options.context_epoch = vector_id == 0 ? 9u : vector_word(vector_id, 2);
  options.context_expiry = vector_id == 0 ? 7200u :
      1u + vector_word(vector_id, 3);
  options.context_arc_index = vector_id == 0 ? 4u :
      vector_word(vector_id, 4) % 1000000u;
  options.context_seed_set = 1;
  for (i = 0; i < BENCH_CONTEXT_SEED_BYTES; i++) {
    options.context_seed[i] = vector_id == 0 ? (uint8_t) (i + 1) :
        (uint8_t) (vector_word(vector_id, 5 + i / 8) >> (8 * (i % 8)));
    random[i] = vector_id == 0 ? (uint8_t) (0xa0u + i) :
        (uint8_t) (vector_word(vector_id, 9 + i / 8) >> (8 * (i % 8)));
  }

  ec_null(client_base_public);
  ec_null(server_base_public);
  ec_null(commitment);
  bn_null(client_base_secret);
  bn_null(server_base_secret);
  bn_null(client_secret);
  bn_null(server_secret);
  bn_null(client_nonce_scalar);
  bn_null(server_nonce_scalar);
  bn_null(opening);
  bn_null(order);
  bn_null(saved);
  ec_public_key_null(joint_public);
  schnorr_signature_null(signature);

  RLC_TRY {
    ec_new(client_base_public);
    ec_new(server_base_public);
    ec_new(commitment);
    bn_new(client_base_secret);
    bn_new(server_base_secret);
    bn_new(client_secret);
    bn_new(server_secret);
    bn_new(client_nonce_scalar);
    bn_new(server_nonce_scalar);
    bn_new(opening);
    bn_new(order);
    bn_new(saved);
    ec_public_key_new(joint_public);
    schnorr_signature_new(signature);
    ec_curve_get_ord(order);
    bn_set_dig(client_base_secret, vector_id == 0 ? 11u :
               1u + vector_word(vector_id, 13) % 0xfffffffeu);
    bn_set_dig(server_base_secret, vector_id == 0 ? 17u :
               1u + vector_word(vector_id, 14) % 0xfffffffeu);
    ec_mul_gen(client_base_public, client_base_secret);
    ec_mul_gen(server_base_public, server_base_secret);
    if (bench_validate_secp256k1() != RLC_OK) {
      fprintf(stderr, "joint KAT: active curve is not secp256k1\n");
      RLC_THROW(ERR_NO_VALID);
    }
    memcpy(changed_preparation_digest, options.context_seed,
           sizeof(changed_preparation_digest));
    changed_preparation_digest[0] ^= 1u;
    if (bench_key_ownership_prove(
            client_proof, client_base_secret, client_base_public,
            options.context_seed, BENCH_KEY_ROLE_INITIATOR, options.pair_id,
            options.context_epoch) != RLC_OK ||
        bench_key_ownership_prove(
            server_proof, server_base_secret, server_base_public,
            options.context_seed, BENCH_KEY_ROLE_RESPONDER, options.pair_id,
            options.context_epoch) != RLC_OK ||
        bench_validate_preparation_key_ownership(
            client_proof, server_proof, client_base_public,
            server_base_public, options.context_seed, options.pair_id,
            options.context_epoch) != RLC_OK ||
        bench_key_ownership_verify(
            client_proof, client_base_public, changed_preparation_digest,
            BENCH_KEY_ROLE_INITIATOR, options.pair_id,
            options.context_epoch) == RLC_OK ||
        bench_key_ownership_verify(
            client_proof, client_base_public, options.context_seed,
            BENCH_KEY_ROLE_RESPONDER, options.pair_id,
            options.context_epoch) == RLC_OK ||
        bench_key_ownership_verify(
            client_proof, client_base_public, options.context_seed,
            BENCH_KEY_ROLE_INITIATOR, options.pair_id + 1,
            options.context_epoch) == RLC_OK ||
        bench_key_ownership_verify(
            client_proof, client_base_public, options.context_seed,
            BENCH_KEY_ROLE_INITIATOR, options.pair_id,
            options.context_epoch + 1) == RLC_OK ||
        bench_key_ownership_verify(
            client_proof, server_base_public, options.context_seed,
            BENCH_KEY_ROLE_INITIATOR, options.pair_id,
            options.context_epoch) == RLC_OK ||
        bench_key_ownership_prove(
            tampered_proof, client_base_secret, server_base_public,
            options.context_seed, BENCH_KEY_ROLE_INITIATOR, options.pair_id,
            options.context_epoch) == RLC_OK) {
      fprintf(stderr, "joint KAT: Preparation key ownership gate failed\n");
      RLC_THROW(ERR_NO_VALID);
    }
    memcpy(tampered_proof, client_proof, sizeof(tampered_proof));
    tampered_proof[sizeof(tampered_proof) - 1] ^= 1u;
    if (bench_key_ownership_verify(
            tampered_proof, client_base_public, options.context_seed,
            BENCH_KEY_ROLE_INITIATOR, options.pair_id,
            options.context_epoch) == RLC_OK) {
      fprintf(stderr, "joint KAT: mutated key ownership proof accepted\n");
      RLC_THROW(ERR_NO_VALID);
    }
    ec_set_infty(commitment);
    if (bench_key_ownership_verify(
            client_proof, commitment, options.context_seed,
            BENCH_KEY_ROLE_INITIATOR, options.pair_id,
            options.context_epoch) == RLC_OK) {
      fprintf(stderr, "joint KAT: identity ownership key accepted\n");
      RLC_THROW(ERR_NO_VALID);
    }
    if (bench_transcript_init(&transcript, &options, client_base_public,
                              server_base_public) != RLC_OK) {
      fprintf(stderr, "joint KAT: transcript initialization failed\n");
      RLC_THROW(ERR_NO_VALID);
    }
    for (i = 0; i < TEST_ITEMS; i++) {
      if (bench_validate_joint_public_key(
              transcript.client_public_keys[i],
              transcript.server_public_keys[i],
              transcript.joint_public_keys[i]) != RLC_OK) {
        fprintf(stderr, "joint KAT: valid joint key rejected\n");
        RLC_THROW(ERR_NO_VALID);
      }
    }
    ec_add(commitment, transcript.joint_public_keys[0], client_base_public);
    ec_norm(commitment, commitment);
    if (bench_validate_joint_public_key(
            transcript.client_public_keys[0], transcript.server_public_keys[0],
            commitment) == RLC_OK) {
      fprintf(stderr, "joint KAT: inconsistent joint key accepted\n");
      RLC_THROW(ERR_NO_VALID);
    }
    if (verbose && getenv("OASIS_KAT_DIAGNOSTIC") != NULL) {
      print_transcript_diagnostic(&transcript);
    }
    if (vector_id == 0 && !digest_matches_hex(
            transcript.context_digest,
            "f6f15bb4ad810d2d516454edc3d3f486108a47a6caf5d17f05b0bfafd50e9bd1")) {
      fprintf(stderr, "joint KAT: context digest mismatch: ");
      fprint_hex(stderr, transcript.context_digest, BENCH_DIGEST_BYTES);
      fprintf(stderr, "\n");
      RLC_THROW(ERR_NO_VALID);
    }
    if (vector_id == 0 && !digest_matches_hex(
            transcript.batch_digest,
            "9089e577fac5c410d97143d66044a02aa14abd70c0fba1072d48a138d6c247da")) {
      fprintf(stderr, "joint KAT: batch digest mismatch: ");
      fprint_hex(stderr, transcript.batch_digest, BENCH_DIGEST_BYTES);
      fprintf(stderr, "\n");
      RLC_THROW(ERR_NO_VALID);
    }
    if (vector_id == 0 && !digest_matches_hex(
            transcript.parent_sid,
            "f9be66888cc55de6687613e52d6d984161c8524b6930c1ed852acccecdf56ead")) {
      fprintf(stderr, "joint KAT: parent SID mismatch: ");
      fprint_hex(stderr, transcript.parent_sid, BENCH_DIGEST_BYTES);
      fprintf(stderr, "\n");
      RLC_THROW(ERR_NO_VALID);
    }
    if (allocate_points(&client_nonces, TEST_ITEMS) != RLC_OK ||
        allocate_points(&server_nonces, TEST_ITEMS) != RLC_OK ||
        allocate_scalars(&challenges, TEST_ITEMS) != RLC_OK ||
        allocate_scalars(&server_partials, TEST_ITEMS) != RLC_OK ||
        allocate_scalars(&client_partials, TEST_ITEMS) != RLC_OK ||
        allocate_scalars(&full_scalars, TEST_ITEMS) != RLC_OK) {
      fprintf(stderr, "joint KAT: test-vector allocation failed\n");
      RLC_THROW(ERR_NO_VALID);
    }

    for (i = 0; i < TEST_ITEMS; i++) {
      bn_set_dig(client_nonce_scalar, vector_id == 0 ? 101u + i :
                 1u + vector_word(vector_id, 15 + 2 * i) % 0xfffffffeu);
      bn_set_dig(server_nonce_scalar, vector_id == 0 ? 211u + i :
                 1u + vector_word(vector_id, 16 + 2 * i) % 0xfffffffeu);
      ec_mul_gen(client_nonces[i], client_nonce_scalar);
      ec_mul_gen(server_nonces[i], server_nonce_scalar);
      if (bench_derive_item_secret(
              client_secret, client_base_secret, "CLIENT-SIGNING-KEY-v1",
              options.pair_id,
              i, TEST_ITEMS) != RLC_OK ||
          bench_derive_item_secret(
              server_secret, server_base_secret, "SERVER-SIGNING-KEY-v1",
              options.pair_id,
              i, TEST_ITEMS) != RLC_OK ||
          bench_pedersen_commit(
              commitment, opening,
              bench_active_sid(&transcript, options.mode, i),
              transcript.item_digests + (size_t) i * BENCH_DIGEST_BYTES,
              server_nonces[i]) != RLC_OK ||
          !bench_pedersen_verify(
              commitment, opening,
              bench_active_sid(&transcript, options.mode, i),
              transcript.item_digests + (size_t) i * BENCH_DIGEST_BYTES,
              server_nonces[i]) ||
          bench_joint_challenge(
              challenges[i],
              transcript.message_digests + (size_t) i * BENCH_DIGEST_BYTES,
              client_nonces[i], server_nonces[i],
              transcript.statements[i]) != RLC_OK ||
          bench_joint_partial_sign(server_partials[i], server_nonce_scalar,
                                   server_secret, challenges[i]) != RLC_OK ||
          bench_joint_partial_sign(client_partials[i], client_nonce_scalar,
                                   client_secret, challenges[i]) != RLC_OK) {
        RLC_THROW(ERR_NO_VALID);
      }
      bn_add(full_scalars[i], server_partials[i], client_partials[i]);
      bn_mod(full_scalars[i], full_scalars[i], order);
      if (!bench_joint_partial_verify(
              server_partials[i], server_nonces[i],
              transcript.server_public_keys[i], challenges[i], NULL) ||
          !bench_joint_partial_verify(
              client_partials[i], client_nonces[i],
              transcript.client_public_keys[i], challenges[i], NULL) ||
          !bench_joint_full_verify(
              full_scalars[i], client_nonces[i], server_nonces[i],
              transcript.statements[i], transcript.joint_public_keys[i],
              challenges[i], NULL)) {
        RLC_THROW(ERR_NO_VALID);
      }
      bn_copy(signature->e, challenges[i]);
      bn_copy(signature->s, full_scalars[i]);
      ec_copy(joint_public->pk, transcript.joint_public_keys[i]);
      if (adaptor_schnorr_preverify(
              signature,
              transcript.message_digests + (size_t) i * BENCH_DIGEST_BYTES,
              BENCH_DIGEST_BYTES, transcript.statements[i],
              joint_public) != 1) {
        RLC_THROW(ERR_NO_VALID);
      }
      if (verbose && getenv("OASIS_KAT_DIAGNOSTIC") != NULL) {
        print_signature_diagnostic(
            i, transcript.message_digests + (size_t) i * BENCH_DIGEST_BYTES,
            transcript.statements[i], transcript.joint_public_keys[i],
            challenges[i], full_scalars[i]);
      }
      if (adaptor_schnorr_preverify(
              signature,
              transcript.item_digests + (size_t) i * BENCH_DIGEST_BYTES,
              BENCH_DIGEST_BYTES, transcript.statements[i],
              joint_public) == 1) {
        fprintf(stderr, "joint KAT: item digest incorrectly accepted as signature message\n");
        RLC_THROW(ERR_NO_VALID);
      }
    }

    if (bench_derive_verifier_salt(
            server_salt, "SERVER-PARTIAL", transcript.parent_sid,
            transcript.batch_digest, random) != RLC_OK ||
        bench_derive_verifier_salt(
            client_salt, "CLIENT-PARTIAL", transcript.parent_sid,
            transcript.batch_digest, random) != RLC_OK ||
        bench_derive_verifier_salt(
            full_salt, "FULL-PRESIGNATURE", transcript.parent_sid,
            transcript.batch_digest, random) != RLC_OK ||
        bench_digest_equal(server_salt, client_salt) ||
        bench_digest_equal(client_salt, full_salt) ||
        !bench_joint_batch_verify(
            BENCH_EQUATION_SERVER_PARTIAL, &transcript, options.mode, 0,
            TEST_ITEMS, client_nonces, server_nonces, challenges,
            server_partials, client_partials, full_scalars, server_salt,
            &metrics) ||
        !bench_joint_batch_verify(
            BENCH_EQUATION_CLIENT_PARTIAL, &transcript, options.mode, 0,
            TEST_ITEMS, client_nonces, server_nonces, challenges,
            server_partials, client_partials, full_scalars, client_salt,
            &metrics) ||
        !bench_joint_batch_verify(
            BENCH_EQUATION_FULL_PRESIGNATURE, &transcript, options.mode, 0,
            TEST_ITEMS, client_nonces, server_nonces, challenges,
            server_partials, client_partials, full_scalars, full_salt,
            &metrics)) {
      RLC_THROW(ERR_NO_VALID);
    }

    /* Subrange inputs are slices whose element zero maps to first_ordinal. */
    if (!bench_joint_batch_verify(
            BENCH_EQUATION_SERVER_PARTIAL, &transcript, options.mode, 2,
            TEST_ITEMS - 2, client_nonces + 2, server_nonces + 2,
            challenges + 2, server_partials + 2, client_partials + 2,
            full_scalars + 2, server_salt, NULL) ||
        !bench_joint_batch_verify(
            BENCH_EQUATION_CLIENT_PARTIAL, &transcript, options.mode, 2,
            TEST_ITEMS - 2, client_nonces + 2, server_nonces + 2,
            challenges + 2, server_partials + 2, client_partials + 2,
            full_scalars + 2, client_salt, NULL) ||
        !bench_joint_batch_verify(
            BENCH_EQUATION_FULL_PRESIGNATURE, &transcript, options.mode, 2,
            TEST_ITEMS - 2, client_nonces + 2, server_nonces + 2,
            challenges + 2, server_partials + 2, client_partials + 2,
            full_scalars + 2, full_salt, NULL)) {
      fprintf(stderr, "joint KAT: non-zero batch subrange rejected\n");
      RLC_THROW(ERR_NO_VALID);
    }

    bn_copy(saved, server_partials[2]);
    bn_add_dig(server_partials[2], server_partials[2], 1);
    bn_mod(server_partials[2], server_partials[2], order);
    if (bench_joint_batch_verify(
            BENCH_EQUATION_SERVER_PARTIAL, &transcript, options.mode, 0,
            TEST_ITEMS, client_nonces, server_nonces, challenges,
            server_partials, client_partials, full_scalars, server_salt,
            NULL) ||
        !localizes_exactly_one_invalid_item(
            BENCH_EQUATION_SERVER_PARTIAL, &transcript, options.mode, 2,
            client_nonces, server_nonces, challenges, server_partials,
            client_partials, full_scalars, server_salt)) {
      fprintf(stderr, "joint KAT: server-partial localization failed\n");
      RLC_THROW(ERR_NO_VALID);
    }
    bn_copy(server_partials[2], saved);

    bn_copy(saved, client_partials[3]);
    bn_add_dig(client_partials[3], client_partials[3], 1);
    bn_mod(client_partials[3], client_partials[3], order);
    if (bench_joint_batch_verify(
            BENCH_EQUATION_CLIENT_PARTIAL, &transcript, options.mode, 0,
            TEST_ITEMS, client_nonces, server_nonces, challenges,
            server_partials, client_partials, full_scalars, client_salt,
            NULL) ||
        !localizes_exactly_one_invalid_item(
            BENCH_EQUATION_CLIENT_PARTIAL, &transcript, options.mode, 3,
            client_nonces, server_nonces, challenges, server_partials,
            client_partials, full_scalars, client_salt)) {
      fprintf(stderr, "joint KAT: client-partial localization failed\n");
      RLC_THROW(ERR_NO_VALID);
    }
    bn_copy(client_partials[3], saved);

    bn_copy(saved, full_scalars[4]);
    bn_add_dig(full_scalars[4], full_scalars[4], 1);
    bn_mod(full_scalars[4], full_scalars[4], order);
    if (bench_joint_batch_verify(
            BENCH_EQUATION_FULL_PRESIGNATURE, &transcript, options.mode, 0,
            TEST_ITEMS, client_nonces, server_nonces, challenges,
            server_partials, client_partials, full_scalars, full_salt,
            NULL) ||
        !localizes_exactly_one_invalid_item(
            BENCH_EQUATION_FULL_PRESIGNATURE, &transcript, options.mode, 4,
            client_nonces, server_nonces, challenges, server_partials,
            client_partials, full_scalars, full_salt)) {
      fprintf(stderr, "joint KAT: full-presignature localization failed\n");
      RLC_THROW(ERR_NO_VALID);
    }
    bn_copy(full_scalars[4], saved);

    changed_options = options;
    changed_options.context_epoch++;
    if (bench_transcript_init(&changed_transcript, &changed_options,
                              client_base_public,
                              server_base_public) != RLC_OK ||
        bench_digest_equal(transcript.context_digest,
                           changed_transcript.context_digest) ||
        bench_digest_equal(transcript.parent_sid,
                           changed_transcript.parent_sid)) {
      RLC_THROW(ERR_NO_VALID);
    }
    bench_transcript_free(&changed_transcript);
    memset(&changed_transcript, 0, sizeof(changed_transcript));
    changed_options = options;
    changed_options.execution_id++;
    if (bench_transcript_init(&changed_transcript, &changed_options,
                              client_base_public,
                              server_base_public) != RLC_OK ||
        bench_digest_equal(transcript.context_digest,
                           changed_transcript.context_digest) ||
        !bench_digest_equal(transcript.message_digests,
                            changed_transcript.message_digests) ||
        ec_cmp(transcript.statements[0], changed_transcript.statements[0]) !=
            RLC_EQ ||
        bench_digest_equal(transcript.item_digests,
                           changed_transcript.item_digests) ||
        bench_digest_equal(transcript.batch_digest,
                           changed_transcript.batch_digest) ||
        bench_digest_equal(transcript.parent_sid,
                           changed_transcript.parent_sid)) {
      RLC_THROW(ERR_NO_VALID);
    }
    bench_transcript_free(&changed_transcript);
    memset(&changed_transcript, 0, sizeof(changed_transcript));
    bn_set_dig(client_base_secret, 12);
    ec_mul_gen(client_base_public, client_base_secret);
    if (bench_transcript_init(&changed_transcript, &options,
                              client_base_public,
                              server_base_public) != RLC_OK ||
        !bench_digest_equal(transcript.context_digest,
                            changed_transcript.context_digest) ||
        bench_digest_equal(transcript.item_digests,
                           changed_transcript.item_digests) ||
        bench_digest_equal(transcript.batch_digest,
                           changed_transcript.batch_digest) ||
        bench_digest_equal(transcript.parent_sid,
                           changed_transcript.parent_sid)) {
      RLC_THROW(ERR_NO_VALID);
    }
    if (verbose) {
      printf("JOINT_TRANSCRIPT_KAT\tcontext=");
      print_hex(transcript.context_digest, BENCH_DIGEST_BYTES);
      printf("\tbatch=");
      print_hex(transcript.batch_digest, BENCH_DIGEST_BYTES);
      printf("\tparent_sid=");
      print_hex(transcript.parent_sid, BENCH_DIGEST_BYTES);
      printf("\n");
    }
    status = RLC_OK;
  } RLC_CATCH_ANY {
    status = RLC_ERR;
  } RLC_FINALLY {
    bench_transcript_free(&changed_transcript);
    bench_transcript_free(&transcript);
    free_points(client_nonces, TEST_ITEMS);
    free_points(server_nonces, TEST_ITEMS);
    free_scalars(challenges, TEST_ITEMS);
    free_scalars(server_partials, TEST_ITEMS);
    free_scalars(client_partials, TEST_ITEMS);
    free_scalars(full_scalars, TEST_ITEMS);
    ec_free(client_base_public);
    ec_free(server_base_public);
    ec_free(commitment);
    bn_free(client_base_secret);
    bn_free(server_base_secret);
    bn_free(client_secret);
    bn_free(server_secret);
    bn_free(client_nonce_scalar);
    bn_free(server_nonce_scalar);
    bn_free(opening);
    bn_free(order);
    bn_free(saved);
    if (joint_public != NULL) ec_public_key_free(joint_public);
    if (signature != NULL) schnorr_signature_free(signature);
  }
  return status;
}

static int parse_u64(const char *text, uint64_t *value) {
  char *end = NULL;
  unsigned long long parsed;
  errno = 0;
  parsed = strtoull(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0') return RLC_ERR;
  *value = (uint64_t) parsed;
  return RLC_OK;
}

static int write_stress_report(const char *path, uint64_t offset,
                               uint64_t vectors) {
  FILE *stream = fopen(path, "w");
  if (stream == NULL) return RLC_ERR;
  fprintf(stream,
          "{\n"
          "  \"schema\": \"oasis-native-differential-v1\",\n"
          "  \"status\": \"pass\",\n"
          "  \"backend\": \"native-c11-relic\",\n"
          "  \"generator\": \"splitmix64-domain-separated\",\n"
          "  \"vector_offset\": %" PRIu64 ",\n"
          "  \"differential_vectors\": %" PRIu64 ",\n"
          "  \"valid_server_partial_checks\": %" PRIu64 ",\n"
          "  \"valid_client_partial_checks\": %" PRIu64 ",\n"
          "  \"valid_full_presignature_checks\": %" PRIu64 ",\n"
          "  \"mutated_server_partial_rejections\": %" PRIu64 ",\n"
          "  \"mutated_client_partial_rejections\": %" PRIu64 ",\n"
          "  \"mutated_full_presignature_rejections\": %" PRIu64 ",\n"
          "  \"subrange_checks\": %" PRIu64 ",\n"
          "  \"exact_localization_checks\": %" PRIu64 "\n"
          "}\n",
          offset, vectors, vectors, vectors, vectors, vectors, vectors,
          vectors, 3 * vectors, 3 * TEST_ITEMS * vectors);
  if (fclose(stream) != 0) return RLC_ERR;
  return RLC_OK;
}

int main(int argc, char **argv) {
  uint64_t vectors = 1;
  uint64_t offset = 0;
  const char *output = NULL;
  uint64_t i;
  int stress = 0;
  int status = RLC_OK;
  for (i = 1; i < (uint64_t) argc; i++) {
    if (strcmp(argv[i], "--vectors") == 0 && i + 1 < (uint64_t) argc) {
      if (parse_u64(argv[++i], &vectors) != RLC_OK || vectors == 0) {
        fprintf(stderr, "invalid --vectors value\n");
        return 2;
      }
      stress = 1;
    } else if (strcmp(argv[i], "--vector-offset") == 0 &&
               i + 1 < (uint64_t) argc) {
      if (parse_u64(argv[++i], &offset) != RLC_OK) {
        fprintf(stderr, "invalid --vector-offset value\n");
        return 2;
      }
      stress = 1;
    } else if (strcmp(argv[i], "--out") == 0 &&
               i + 1 < (uint64_t) argc) {
      output = argv[++i];
      stress = 1;
    } else {
      fprintf(stderr,
              "usage: %s [--vectors N --vector-offset N --out PATH]\n",
              argv[0]);
      return 2;
    }
  }
  if (stress && output == NULL) {
    fprintf(stderr, "--out is required for differential stress mode\n");
    return 2;
  }
  if (UINT64_MAX - offset < vectors) {
    fprintf(stderr, "vector range overflows uint64\n");
    return 2;
  }
  if (test_invalid_index_encoding() != RLC_OK) {
    fprintf(stderr, "canonical invalid-index regression failed\n");
    return 1;
  }
  if (init() != RLC_OK) return 1;
  for (i = 0; i < vectors; i++) {
    status = run_joint_test(offset + i, !stress && i == 0);
    if (status != RLC_OK) {
      fprintf(stderr, "joint differential vector %" PRIu64 " failed\n",
              offset + i);
      break;
    }
  }
  clean();
  if (status != RLC_OK) {
    fprintf(stderr, "joint pre-sign regression failed\n");
    return 1;
  }
  if (stress) {
    if (write_stress_report(output, offset, vectors) != RLC_OK) {
      fprintf(stderr, "cannot write differential report: %s\n", output);
      return 1;
    }
    printf("NATIVE_DIFFERENTIAL_TEST\tvectors=%" PRIu64
           "\toffset=%" PRIu64 "\tstatus=pass\n", vectors, offset);
    return 0;
  }
  printf("JOINT_PRESIGN_TEST\tpartials=pass\tfull=pass\tupstream=pass\t"
         "pedersen=pass\tmsm=pass\tmutation=reject\tcontext=bound\t"
         "joint_key=validated\tkey_ownership=preparation-bound\t"
         "rogue_key=reject\tinvalid_indices=canonical\t"
         "fault_localization=exact\n");
  return 0;
}
