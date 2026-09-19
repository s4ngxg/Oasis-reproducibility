#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "preswap_protocol.h"
#ifdef BENCH_ALLOCATION_PROFILE
#include "allocation_counter.h"
#endif

typedef struct {
  uint8_t *data;
  size_t length;
  size_t capacity;
} canonical_buffer_t;

static void write_u32_be(uint8_t out[4], uint32_t value) {
  out[0] = (uint8_t) (value >> 24);
  out[1] = (uint8_t) (value >> 16);
  out[2] = (uint8_t) (value >> 8);
  out[3] = (uint8_t) value;
}

static uint32_t read_u32_be(const uint8_t in[4]) {
  return ((uint32_t) in[0] << 24) | ((uint32_t) in[1] << 16) |
         ((uint32_t) in[2] << 8) | (uint32_t) in[3];
}

static void write_u64_be(uint8_t out[8], uint64_t value) {
  write_u32_be(out, (uint32_t) (value >> 32));
  write_u32_be(out + 4, (uint32_t) value);
}

static int append_bytes(canonical_buffer_t *buffer, const uint8_t *data,
                        size_t length) {
  size_t needed;
  size_t capacity;
  uint8_t *resized;
  if (buffer == NULL || (length != 0 && data == NULL) ||
      length > SIZE_MAX - buffer->length) {
    return RLC_ERR;
  }
  needed = buffer->length + length;
  if (needed > buffer->capacity) {
    capacity = buffer->capacity == 0 ? 256 : buffer->capacity;
    while (capacity < needed) {
      if (capacity > SIZE_MAX / 2) return RLC_ERR;
      capacity *= 2;
    }
    resized = realloc(buffer->data, capacity);
    if (resized == NULL) return RLC_ERR;
    buffer->data = resized;
    buffer->capacity = capacity;
  }
  if (length != 0) memcpy(buffer->data + buffer->length, data, length);
  buffer->length = needed;
  return RLC_OK;
}

static int append_field(canonical_buffer_t *buffer, const uint8_t *field,
                        size_t length) {
  uint8_t encoded_length[8];
  write_u64_be(encoded_length, (uint64_t) length);
  return append_bytes(buffer, encoded_length, sizeof(encoded_length)) == RLC_OK &&
                 append_bytes(buffer, field, length) == RLC_OK
             ? RLC_OK
             : RLC_ERR;
}

static int canonical_hash(const char *domain, const uint8_t *const fields[],
                          const size_t lengths[], size_t field_count,
                          uint8_t out[BENCH_DIGEST_BYTES]) {
  canonical_buffer_t buffer = {0};
  size_t i;
  int status = RLC_ERR;
  if (domain == NULL || domain[0] == '\0' || fields == NULL ||
      lengths == NULL || out == NULL) {
    return RLC_ERR;
  }
  if (append_field(&buffer, (const uint8_t *) domain, strlen(domain)) != RLC_OK) {
    goto cleanup;
  }
  for (i = 0; i < field_count; i++) {
    if (append_field(&buffer, fields[i], lengths[i]) != RLC_OK) goto cleanup;
  }
  md_map(out, buffer.data, buffer.length);
  status = RLC_OK;
cleanup:
  free(buffer.data);
  return status;
}

static int hash_to_scalar(bn_t scalar, const uint8_t hash[BENCH_DIGEST_BYTES],
                          const bn_t order, int nonzero) {
  bn_read_bin(scalar, hash, BENCH_DIGEST_BYTES);
  bn_mod(scalar, scalar, order);
  if (nonzero && bn_is_zero(scalar)) bn_set_dig(scalar, 1);
  return RLC_OK;
}

static int scalar_valid(const bn_t scalar, const bn_t order) {
  return scalar != NULL && bn_sign(scalar) == RLC_POS &&
         !bn_is_zero(scalar) && bn_cmp(scalar, order) == RLC_LT;
}

static int point_bytes(uint8_t out[BENCH_POINT_BYTES], const ec_t point) {
  if (ec_is_infty(point) || !ec_on_curve(point)) return RLC_ERR;
  ec_write_bin(out, (int) BENCH_POINT_BYTES, point, 1);
  return RLC_OK;
}

static int deterministic_point_map(ec_t point, const char *domain,
                                   const uint8_t *message,
                                   size_t message_length) {
  bn_t candidate;
  bn_t order;
  fp_t rhs;
  uint8_t counter[4];
  uint8_t digest[BENCH_DIGEST_BYTES];
  const uint8_t *fields[] = {message, counter};
  const size_t lengths[] = {message_length, sizeof(counter)};
  uint32_t attempt;
  int status = RLC_ERR;
  bn_null(candidate);
  bn_null(order);
  fp_null(rhs);
  RLC_TRY {
    bn_new(candidate);
    bn_new(order);
    fp_new(rhs);
    ec_curve_get_ord(order);
    for (attempt = 0; attempt < 4096; attempt++) {
      write_u32_be(counter, attempt);
      if (canonical_hash(domain, fields, lengths, 2, digest) != RLC_OK) {
        RLC_THROW(ERR_NO_VALID);
      }
      bn_read_bin(candidate, digest, sizeof(digest));
      /* Restricting x below the group order also guarantees x < field prime. */
      if (bn_cmp(candidate, order) != RLC_LT) continue;
      fp_read_bin(point->x, digest, sizeof(digest));
      ep_rhs(rhs, point->x);
      if (!fp_srt(point->y, rhs)) continue;
      if (fp_get_bit(point->y, 0) != (digest[BENCH_DIGEST_BYTES - 1] & 1u)) {
        fp_neg(point->y, point->y);
      }
      fp_set_dig(point->z, 1);
      point->coord = BASIC;
      if (!ec_is_infty(point) && ec_on_curve(point)) {
        status = RLC_OK;
        break;
      }
    }
  } RLC_CATCH_ANY {
    status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(candidate);
    bn_free(order);
    fp_free(rhs);
  }
  return status;
}

int bench_validate_secp256k1(void) {
  static const char order_hex[] =
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
  bn_t expected;
  bn_t actual;
  int status = RLC_ERR;
  bn_null(expected);
  bn_null(actual);
  RLC_TRY {
    bn_new(expected);
    bn_new(actual);
    bn_read_str(expected, order_hex, sizeof(order_hex) - 1, 16);
    ec_curve_get_ord(actual);
    status = bn_cmp(expected, actual) == RLC_EQ ? RLC_OK : RLC_ERR;
  } RLC_CATCH_ANY {
    status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(expected);
    bn_free(actual);
  }
  return status;
}

static const char *key_role_domain(bench_key_role_t role) {
  switch (role) {
    case BENCH_KEY_ROLE_INITIATOR:
      return "INITIATOR";
    case BENCH_KEY_ROLE_RESPONDER:
      return "RESPONDER";
    default:
      return NULL;
  }
}

static int point_in_prime_subgroup(const ec_t point, const bn_t order) {
  ec_t check;
  int valid = 0;
  ec_null(check);
  RLC_TRY {
    ec_new(check);
    if (point != NULL && !ec_is_infty(point) && ec_on_curve(point)) {
      ec_mul(check, point, order);
      valid = ec_is_infty(check);
    }
  } RLC_CATCH_ANY {
    valid = 0;
  } RLC_FINALLY {
    ec_free(check);
  }
  return valid;
}

static int key_ownership_challenge(
    bn_t challenge, const ec_t public_key, const ec_t commitment,
    const uint8_t preparation_digest[BENCH_CONTEXT_SEED_BYTES],
    bench_key_role_t role, uint64_t pair_id, uint64_t key_epoch,
    const bn_t order) {
  const char *role_name = key_role_domain(role);
  uint8_t pair[8];
  uint8_t epoch[8];
  uint8_t public_encoded[BENCH_POINT_BYTES];
  uint8_t commitment_encoded[BENCH_POINT_BYTES];
  uint8_t digest[BENCH_DIGEST_BYTES];
  const uint8_t *fields[] = {
      preparation_digest, (const uint8_t *) role_name, pair, epoch,
      public_encoded, commitment_encoded};
  size_t lengths[] = {
      BENCH_CONTEXT_SEED_BYTES, role_name == NULL ? 0 : strlen(role_name),
      sizeof(pair), sizeof(epoch), BENCH_POINT_BYTES, BENCH_POINT_BYTES};
  if (preparation_digest == NULL || role_name == NULL ||
      point_bytes(public_encoded, public_key) != RLC_OK ||
      point_bytes(commitment_encoded, commitment) != RLC_OK) {
    return RLC_ERR;
  }
  write_u64_be(pair, pair_id);
  write_u64_be(epoch, key_epoch);
  if (canonical_hash("OASIS-PREPARATION-KEY-OWNERSHIP-v1", fields, lengths,
                     6, digest) != RLC_OK) {
    return RLC_ERR;
  }
  return hash_to_scalar(challenge, digest, order, 1);
}

int bench_key_ownership_prove(
    uint8_t proof[BENCH_KEY_OWNERSHIP_PROOF_BYTES],
    const bn_t secret_key, const ec_t public_key,
    const uint8_t preparation_digest[BENCH_CONTEXT_SEED_BYTES],
    bench_key_role_t role, uint64_t pair_id, uint64_t key_epoch) {
  bn_t order;
  bn_t nonce;
  bn_t challenge;
  bn_t response;
  bn_t product;
  ec_t expected_public;
  ec_t commitment;
  int status = RLC_ERR;
  bn_null(order);
  bn_null(nonce);
  bn_null(challenge);
  bn_null(response);
  bn_null(product);
  ec_null(expected_public);
  ec_null(commitment);
  if (proof == NULL || preparation_digest == NULL ||
      key_role_domain(role) == NULL) {
    return RLC_ERR;
  }
  RLC_TRY {
    bn_new(order);
    bn_new(nonce);
    bn_new(challenge);
    bn_new(response);
    bn_new(product);
    ec_new(expected_public);
    ec_new(commitment);
    ec_curve_get_ord(order);
    if (scalar_valid(secret_key, order) &&
        point_in_prime_subgroup(public_key, order)) {
      ec_mul_gen(expected_public, secret_key);
      ec_norm(expected_public, expected_public);
      if (ec_cmp(expected_public, public_key) == RLC_EQ) {
        do {
          do {
            bn_rand_mod(nonce, order);
          } while (bn_is_zero(nonce));
          ec_mul_gen(commitment, nonce);
          if (key_ownership_challenge(
                  challenge, public_key, commitment, preparation_digest, role,
                  pair_id, key_epoch, order) != RLC_OK) {
            break;
          }
          bn_mul(product, challenge, secret_key);
          bn_mod(product, product, order);
          bn_add(response, nonce, product);
          bn_mod(response, response, order);
        } while (bn_is_zero(response));
        if (!bn_is_zero(response)) {
          ec_write_bin(proof, (int) BENCH_POINT_BYTES, commitment, 1);
          bn_write_bin(proof + BENCH_POINT_BYTES, (int) BENCH_SCALAR_BYTES,
                       response);
          status = RLC_OK;
        }
      }
    }
  } RLC_CATCH_ANY {
    status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(order);
    bn_free(nonce);
    bn_free(challenge);
    bn_free(response);
    bn_free(product);
    ec_free(expected_public);
    ec_free(commitment);
  }
  return status;
}

int bench_key_ownership_verify(
    const uint8_t proof[BENCH_KEY_OWNERSHIP_PROOF_BYTES],
    const ec_t public_key,
    const uint8_t preparation_digest[BENCH_CONTEXT_SEED_BYTES],
    bench_key_role_t role, uint64_t pair_id, uint64_t key_epoch) {
  bn_t order;
  bn_t response;
  bn_t challenge;
  ec_t commitment;
  ec_t left;
  ec_t right;
  ec_t product;
  uint8_t canonical_commitment[BENCH_POINT_BYTES];
  int status = RLC_ERR;
  bn_null(order);
  bn_null(response);
  bn_null(challenge);
  ec_null(commitment);
  ec_null(left);
  ec_null(right);
  ec_null(product);
  if (proof == NULL || preparation_digest == NULL ||
      key_role_domain(role) == NULL) {
    return RLC_ERR;
  }
  RLC_TRY {
    bn_new(order);
    bn_new(response);
    bn_new(challenge);
    ec_new(commitment);
    ec_new(left);
    ec_new(right);
    ec_new(product);
    ec_curve_get_ord(order);
    if (point_in_prime_subgroup(public_key, order)) {
      ec_read_bin(commitment, proof, (int) BENCH_POINT_BYTES);
      if (point_in_prime_subgroup(commitment, order) &&
          point_bytes(canonical_commitment, commitment) == RLC_OK &&
          memcmp(canonical_commitment, proof, BENCH_POINT_BYTES) == 0) {
        bn_read_bin(response, proof + BENCH_POINT_BYTES,
                    (int) BENCH_SCALAR_BYTES);
        if (scalar_valid(response, order) &&
            key_ownership_challenge(
                challenge, public_key, commitment, preparation_digest, role,
                pair_id, key_epoch, order) == RLC_OK) {
          ec_mul_gen(left, response);
          ec_mul(product, public_key, challenge);
          ec_add(right, commitment, product);
          ec_norm(left, left);
          ec_norm(right, right);
          status = ec_cmp(left, right) == RLC_EQ ? RLC_OK : RLC_ERR;
        }
      }
    }
  } RLC_CATCH_ANY {
    status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(order);
    bn_free(response);
    bn_free(challenge);
    ec_free(commitment);
    ec_free(left);
    ec_free(right);
    ec_free(product);
  }
  return status;
}

int bench_validate_preparation_key_ownership(
    const uint8_t client_proof[BENCH_KEY_OWNERSHIP_PROOF_BYTES],
    const uint8_t server_proof[BENCH_KEY_OWNERSHIP_PROOF_BYTES],
    const ec_t client_public_key, const ec_t server_public_key,
    const uint8_t preparation_digest[BENCH_CONTEXT_SEED_BYTES],
    uint64_t pair_id, uint64_t key_epoch) {
  if (bench_key_ownership_verify(
          client_proof, client_public_key, preparation_digest,
          BENCH_KEY_ROLE_INITIATOR, pair_id, key_epoch) != RLC_OK) {
    return RLC_ERR;
  }
  return bench_key_ownership_verify(
      server_proof, server_public_key, preparation_digest,
      BENCH_KEY_ROLE_RESPONDER, pair_id, key_epoch);
}

int bench_validate_joint_public_key(const ec_t client_public_key,
                                    const ec_t server_public_key,
                                    const ec_t joint_public_key) {
  ec_t expected;
  int status = RLC_ERR;
  ec_null(expected);
  RLC_TRY {
    ec_new(expected);
    if (ec_is_infty(client_public_key) || !ec_on_curve(client_public_key) ||
        ec_is_infty(server_public_key) || !ec_on_curve(server_public_key) ||
        ec_is_infty(joint_public_key) || !ec_on_curve(joint_public_key)) {
      RLC_THROW(ERR_NO_VALID);
    }
    ec_add(expected, client_public_key, server_public_key);
    ec_norm(expected, expected);
    if (ec_is_infty(expected) || !ec_on_curve(expected)) {
      RLC_THROW(ERR_NO_VALID);
    }
    status = ec_cmp(expected, joint_public_key) == RLC_EQ ? RLC_OK : RLC_ERR;
  } RLC_CATCH_ANY {
    status = RLC_ERR;
  } RLC_FINALLY {
    ec_free(expected);
  }
  return status;
}

int bench_decode_invalid_indices(const uint8_t *encoded,
                                 size_t encoded_length,
                                 unsigned item_count,
                                 uint32_t *indices,
                                 unsigned capacity,
                                 unsigned *invalid_count) {
  uint32_t count;
  uint32_t previous = 0;
  unsigned i;
  size_t expected_length;
  if (encoded == NULL || invalid_count == NULL || encoded_length < 4 ||
      item_count == 0 || item_count > BENCH_MAX_ITEMS) {
    return RLC_ERR;
  }
  count = read_u32_be(encoded);
  if (count > item_count || count > capacity ||
      (count != 0 && indices == NULL)) {
    return RLC_ERR;
  }
  expected_length = 4u + (size_t) count * 4u;
  if (encoded_length != expected_length) return RLC_ERR;
  for (i = 0; i < count; i++) {
    uint32_t value = read_u32_be(encoded + 4u + (size_t) i * 4u);
    if (value >= item_count || (i != 0 && value <= previous)) return RLC_ERR;
    previous = value;
  }
  for (i = 0; i < count; i++) {
    indices[i] = read_u32_be(encoded + 4u + (size_t) i * 4u);
  }
  *invalid_count = count;
  return RLC_OK;
}

static int message_digest(const bench_options_t *options, unsigned ordinal,
                          uint8_t out[BENCH_DIGEST_BYTES]) {
  uint8_t pair[8];
  uint8_t item[4];
  uint8_t type = ordinal < options->context_participants ? 1 : 2;
  const uint8_t *fields[] = {options->context_seed, pair, item, &type};
  const size_t lengths[] = {
      BENCH_CONTEXT_SEED_BYTES, sizeof(pair), sizeof(item), 1};
  write_u64_be(pair, options->pair_id);
  write_u32_be(item, ordinal);
  return canonical_hash("OASIS-BENCH-MESSAGE-v2", fields, lengths, 4, out);
}

#include "host_handoff.h"

static int statement_from_digest(ec_t statement,
                                 const uint8_t digest[BENCH_DIGEST_BYTES]) {
  return deterministic_point_map(statement,
                                 "OASIS-ADAPTOR-STATEMENT-POINT-v2",
                                 digest, BENCH_DIGEST_BYTES);
}

static int context_digest(const bench_options_t *options,
                          uint8_t out[BENCH_DIGEST_BYTES]) {
  static const uint8_t protocol[] = "ParaSwap";
  uint8_t participants[4];
  uint8_t epoch[8];
  uint8_t expiry[8];
  uint8_t pair[8];
  uint8_t execution[8];
  uint8_t arc[8];
  const uint8_t *fields[] = {
      protocol, participants, epoch, expiry, pair, execution, arc,
      options->context_seed};
  const size_t lengths[] = {
      sizeof(protocol) - 1, sizeof(participants), sizeof(epoch), sizeof(expiry),
      sizeof(pair), sizeof(execution), sizeof(arc), BENCH_CONTEXT_SEED_BYTES};
  write_u32_be(participants, options->context_participants);
  write_u64_be(epoch, options->context_epoch);
  write_u64_be(expiry, options->context_expiry);
  write_u64_be(pair, options->pair_id);
  write_u64_be(execution, options->execution_id);
  write_u64_be(arc, options->context_arc_index);
  return canonical_hash("OASIS-CONTEXT-v1", fields, lengths, 8, out);
}

static int item_digest(const bench_options_t *options, unsigned ordinal,
                       const uint8_t context[BENCH_DIGEST_BYTES],
                       const uint8_t message[BENCH_DIGEST_BYTES],
                       const ec_t statement, const ec_t client_key,
                       const ec_t server_key, const ec_t joint_key,
                       uint8_t out[BENCH_DIGEST_BYTES]) {
  static const uint8_t withdraw[] = "Withdraw";
  static const uint8_t relock[] = "Re-lock";
  const uint8_t *type = ordinal < options->context_participants
                            ? withdraw : relock;
  size_t type_length = ordinal < options->context_participants
                           ? sizeof(withdraw) - 1 : sizeof(relock) - 1;
  uint8_t encoded_ordinal[4];
  uint8_t address_index[4];
  uint8_t timeout[8];
  uint8_t statement_encoded[BENCH_POINT_BYTES];
  uint8_t client_encoded[BENCH_POINT_BYTES];
  uint8_t server_encoded[BENCH_POINT_BYTES];
  uint8_t joint_encoded[BENCH_POINT_BYTES];
  const uint8_t *fields[] = {
      context, type, encoded_ordinal, address_index, timeout, message,
      statement_encoded, client_encoded, server_encoded, joint_encoded};
  const size_t lengths[] = {
      BENCH_DIGEST_BYTES, type_length, sizeof(encoded_ordinal), sizeof(address_index),
      sizeof(timeout), BENCH_DIGEST_BYTES, BENCH_POINT_BYTES,
      BENCH_POINT_BYTES, BENCH_POINT_BYTES, BENCH_POINT_BYTES};
  write_u32_be(encoded_ordinal, ordinal);
  write_u32_be(address_index,
               ordinal < options->context_participants
                   ? ordinal : ordinal - options->context_participants);
  write_u64_be(timeout, options->context_expiry);
  if (point_bytes(statement_encoded, statement) != RLC_OK ||
      point_bytes(client_encoded, client_key) != RLC_OK ||
      point_bytes(server_encoded, server_key) != RLC_OK ||
      point_bytes(joint_encoded, joint_key) != RLC_OK) {
    return RLC_ERR;
  }
  return canonical_hash("OASIS-ITEM-v1", fields, lengths, 10, out);
}

static int ordered_batch_digest(const bench_transcript_t *transcript,
                                uint8_t out[BENCH_DIGEST_BYTES]) {
  canonical_buffer_t buffer = {0};
  uint8_t count[4];
  unsigned i;
  int status = RLC_ERR;
  write_u32_be(count, transcript->count);
  if (append_field(&buffer, (const uint8_t *) "OASIS-ORDERED-BATCH-v1",
                   sizeof("OASIS-ORDERED-BATCH-v1") - 1) != RLC_OK ||
      append_field(&buffer, transcript->context_digest,
                   BENCH_DIGEST_BYTES) != RLC_OK ||
      append_field(&buffer, count, sizeof(count)) != RLC_OK) {
    goto cleanup;
  }
  for (i = 0; i < transcript->count; i++) {
    if (append_field(&buffer,
                     transcript->item_digests +
                         (size_t) i * BENCH_DIGEST_BYTES,
                     BENCH_DIGEST_BYTES) != RLC_OK) {
      goto cleanup;
    }
  }
  md_map(out, buffer.data, buffer.length);
  status = RLC_OK;
cleanup:
  free(buffer.data);
  return status;
}

static int parent_session_digest(const bench_transcript_t *transcript,
                                 uint8_t out[BENCH_DIGEST_BYTES]) {
  uint8_t zero[4] = {0};
  const uint8_t empty = 0;
  const uint8_t *fields[] = {transcript->context_digest,
                             transcript->batch_digest, zero, &empty, &empty};
  const size_t lengths[] = {BENCH_DIGEST_BYTES, BENCH_DIGEST_BYTES,
                            sizeof(zero), 0, 0};
  return canonical_hash("OASIS-SESSION-ID-v1", fields, lengths, 5, out);
}

static int item_session_digest(const bench_transcript_t *transcript,
                               unsigned ordinal,
                               uint8_t out[BENCH_DIGEST_BYTES]) {
  uint8_t index[4];
  uint8_t retry[4] = {0};
  const uint8_t *item = transcript->item_digests +
                        (size_t) ordinal * BENCH_DIGEST_BYTES;
  const uint8_t *fields[] = {transcript->context_digest,
                             transcript->batch_digest, index, item, retry,
                             transcript->parent_sid};
  const size_t lengths[] = {BENCH_DIGEST_BYTES, BENCH_DIGEST_BYTES,
                            sizeof(index), BENCH_DIGEST_BYTES, sizeof(retry),
                            BENCH_DIGEST_BYTES};
  write_u32_be(index, ordinal);
  return canonical_hash("OASIS-ITEM-SESSION-ID-v1", fields, lengths, 6, out);
}

int bench_transcript_init(bench_transcript_t *transcript,
                          const bench_options_t *options,
                          const ec_t base_client_public,
                          const ec_t base_server_public) {
  unsigned initialized = 0;
  unsigned i;
  int status = RLC_ERR;
  if (transcript == NULL || options == NULL || options->count == 0 ||
      options->context_participants < 2 ||
      options->count != 2 * options->context_participants - 1 ||
      bench_validate_secp256k1() != RLC_OK) {
    return RLC_ERR;
  }
  memset(transcript, 0, sizeof(*transcript));
  transcript->count = options->count;
  transcript->message_digests = calloc(options->count, BENCH_DIGEST_BYTES);
  transcript->item_digests = calloc(options->count, BENCH_DIGEST_BYTES);
  transcript->item_sids = calloc(options->count, BENCH_DIGEST_BYTES);
  transcript->statements = calloc(options->count, sizeof(ec_t));
  transcript->client_public_keys = calloc(options->count, sizeof(ec_t));
  transcript->server_public_keys = calloc(options->count, sizeof(ec_t));
  transcript->joint_public_keys = calloc(options->count, sizeof(ec_t));
  if (transcript->message_digests == NULL || transcript->item_digests == NULL ||
      transcript->item_sids == NULL || transcript->statements == NULL ||
      transcript->client_public_keys == NULL ||
      transcript->server_public_keys == NULL ||
      transcript->joint_public_keys == NULL) {
    goto cleanup;
  }
  RLC_TRY {
    if (context_digest(options, transcript->context_digest) != RLC_OK) {
      RLC_THROW(ERR_NO_VALID);
    }
    for (i = 0; i < options->count; i++) {
      ec_null(transcript->statements[i]);
      ec_null(transcript->client_public_keys[i]);
      ec_null(transcript->server_public_keys[i]);
      ec_null(transcript->joint_public_keys[i]);
      ec_new(transcript->statements[i]);
      ec_new(transcript->client_public_keys[i]);
      ec_new(transcript->server_public_keys[i]);
      ec_new(transcript->joint_public_keys[i]);
      initialized++;
      if (message_digest(options, i,
                         transcript->message_digests +
                             (size_t) i * BENCH_DIGEST_BYTES) != RLC_OK ||
          (options->host_statements[0]
            ? host_read_statement(transcript->statements[i],
                                  options->host_statements, options->count, i)
            : statement_from_digest(
              transcript->statements[i],
              transcript->message_digests +
                  (size_t) i * BENCH_DIGEST_BYTES)) != RLC_OK ||
          host_item_public(transcript->client_public_keys[i],base_client_public,
                           options,i,BENCH_KEY_ROLE_INITIATOR)!=RLC_OK ||
          host_item_public(transcript->server_public_keys[i],base_server_public,
                           options,i,BENCH_KEY_ROLE_RESPONDER)!=RLC_OK) {
        RLC_THROW(ERR_NO_VALID);
      }
      ec_add(transcript->joint_public_keys[i],
             transcript->client_public_keys[i],
             transcript->server_public_keys[i]);
      ec_norm(transcript->joint_public_keys[i],
              transcript->joint_public_keys[i]);
      if (bench_validate_joint_public_key(
              transcript->client_public_keys[i],
              transcript->server_public_keys[i],
              transcript->joint_public_keys[i]) != RLC_OK ||
          item_digest(
              options, i, transcript->context_digest,
              transcript->message_digests +
                  (size_t) i * BENCH_DIGEST_BYTES,
              transcript->statements[i], transcript->client_public_keys[i],
              transcript->server_public_keys[i],
              transcript->joint_public_keys[i],
              transcript->item_digests +
                  (size_t) i * BENCH_DIGEST_BYTES) != RLC_OK) {
        RLC_THROW(ERR_NO_VALID);
      }
    }
    if (ordered_batch_digest(transcript, transcript->batch_digest) != RLC_OK ||
        parent_session_digest(transcript, transcript->parent_sid) != RLC_OK) {
      RLC_THROW(ERR_NO_VALID);
    }
    for (i = 0; i < options->count; i++) {
      if (item_session_digest(
              transcript, i,
              transcript->item_sids + (size_t) i * BENCH_DIGEST_BYTES) !=
          RLC_OK) {
        RLC_THROW(ERR_NO_VALID);
      }
    }
    status = RLC_OK;
  } RLC_CATCH_ANY {
    status = RLC_ERR;
  }
cleanup:
  if (status != RLC_OK) {
    for (i = 0; i < initialized; i++) {
      ec_free(transcript->statements[i]);
      ec_free(transcript->client_public_keys[i]);
      ec_free(transcript->server_public_keys[i]);
      ec_free(transcript->joint_public_keys[i]);
    }
    free(transcript->message_digests);
    free(transcript->item_digests);
    free(transcript->item_sids);
    free(transcript->statements);
    free(transcript->client_public_keys);
    free(transcript->server_public_keys);
    free(transcript->joint_public_keys);
    memset(transcript, 0, sizeof(*transcript));
  }
  return status;
}

void bench_transcript_free(bench_transcript_t *transcript) {
  unsigned i;
  if (transcript == NULL) return;
  for (i = 0; i < transcript->count; i++) {
    ec_free(transcript->statements[i]);
    ec_free(transcript->client_public_keys[i]);
    ec_free(transcript->server_public_keys[i]);
    ec_free(transcript->joint_public_keys[i]);
  }
  free(transcript->message_digests);
  free(transcript->item_digests);
  free(transcript->item_sids);
  free(transcript->statements);
  free(transcript->client_public_keys);
  free(transcript->server_public_keys);
  free(transcript->joint_public_keys);
  memset(transcript, 0, sizeof(*transcript));
}

const uint8_t *bench_active_sid(const bench_transcript_t *transcript,
                                bench_mode_t mode, unsigned ordinal) {
  if (transcript == NULL || ordinal >= transcript->count) return NULL;
  return bench_mode_is_bjp(mode)
             ? transcript->parent_sid
             : transcript->item_sids + (size_t) ordinal * BENCH_DIGEST_BYTES;
}

static int pedersen_generator(ec_t generator) {
  static const uint8_t encoded[BENCH_POINT_BYTES] = {
      0x02, 0x9b, 0xba, 0x45, 0xe1, 0xcc, 0x9b, 0x95,
      0x14, 0xcd, 0x52, 0x0d, 0x79, 0xf6, 0x16, 0xe0,
      0xb5, 0xc6, 0x3c, 0xbd, 0x5f, 0xad, 0x9c, 0xdf,
      0x5a, 0xf2, 0x91, 0x00, 0xa6, 0xd2, 0xc2, 0x03,
      0xda};
  if (generator == NULL) return RLC_ERR;
  ec_read_bin(generator, encoded, (int) sizeof(encoded));
  if (ec_is_infty(generator) || !ec_on_curve(generator)) {
    return RLC_ERR;
  }
  return RLC_OK;
}

int bench_pedersen_generator_kat(void) {
  static const uint8_t expected[BENCH_POINT_BYTES] = {
      0x02, 0x9b, 0xba, 0x45, 0xe1, 0xcc, 0x9b, 0x95,
      0x14, 0xcd, 0x52, 0x0d, 0x79, 0xf6, 0x16, 0xe0,
      0xb5, 0xc6, 0x3c, 0xbd, 0x5f, 0xad, 0x9c, 0xdf,
      0x5a, 0xf2, 0x91, 0x00, 0xa6, 0xd2, 0xc2, 0x03,
      0xda};
  uint8_t actual[BENCH_POINT_BYTES];
  ec_t generator;
  int status = RLC_ERR;
  ec_null(generator);
  RLC_TRY {
    ec_new(generator);
    if (pedersen_generator(generator) != RLC_OK ||
        point_bytes(actual, generator) != RLC_OK ||
        memcmp(actual, expected, sizeof(expected)) != 0) {
      RLC_THROW(ERR_NO_VALID);
    }
    status = RLC_OK;
  } RLC_CATCH_ANY {
    status = RLC_ERR;
  } RLC_FINALLY {
    ec_free(generator);
  }
  return status;
}

static int commitment_message_scalar(
    bn_t scalar, const uint8_t sid[BENCH_DIGEST_BYTES],
    const uint8_t item_digest_value[BENCH_DIGEST_BYTES], const ec_t nonce,
    const bn_t order) {
  uint8_t nonce_encoded[BENCH_POINT_BYTES];
  uint8_t digest[BENCH_DIGEST_BYTES];
  const uint8_t *fields[] = {sid, item_digest_value, nonce_encoded};
  const size_t lengths[] = {BENCH_DIGEST_BYTES, BENCH_DIGEST_BYTES,
                            BENCH_POINT_BYTES};
  if (point_bytes(nonce_encoded, nonce) != RLC_OK ||
      canonical_hash("OASIS-NONCE-COMMIT-MESSAGE-v1", fields, lengths, 3,
                     digest) != RLC_OK) {
    return RLC_ERR;
  }
  return hash_to_scalar(scalar, digest, order, 1);
}

int bench_pedersen_commit(ec_t commitment, bn_t opening,
                          const uint8_t sid[BENCH_DIGEST_BYTES],
                          const uint8_t item_digest_value[BENCH_DIGEST_BYTES],
                          const ec_t nonce) {
  bn_t order;
  bn_t message;
  ec_t h;
  ec_t left;
  ec_t right;
  int status = RLC_ERR;
  bn_null(order);
  bn_null(message);
  ec_null(h);
  ec_null(left);
  ec_null(right);
  RLC_TRY {
    bn_new(order);
    bn_new(message);
    ec_new(h);
    ec_new(left);
    ec_new(right);
    ec_curve_get_ord(order);
    do {
      bn_rand_mod(opening, order);
    } while (bn_is_zero(opening));
    if (pedersen_generator(h) != RLC_OK ||
        commitment_message_scalar(message, sid, item_digest_value, nonce,
                                  order) != RLC_OK) {
      RLC_THROW(ERR_NO_VALID);
    }
    ec_mul_gen(left, message);
    ec_mul(right, h, opening);
    ec_add(commitment, left, right);
    ec_norm(commitment, commitment);
    status = RLC_OK;
  } RLC_CATCH_ANY {
    status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(order);
    bn_free(message);
    ec_free(h);
    ec_free(left);
    ec_free(right);
  }
  return status;
}

int bench_pedersen_verify(const ec_t commitment, const bn_t opening,
                          const uint8_t sid[BENCH_DIGEST_BYTES],
                          const uint8_t item_digest_value[BENCH_DIGEST_BYTES],
                          const ec_t nonce) {
  bn_t order;
  bn_t message;
  ec_t h;
  ec_t left;
  ec_t right;
  ec_t expected;
  int status = 0;
  bn_null(order);
  bn_null(message);
  ec_null(h);
  ec_null(left);
  ec_null(right);
  ec_null(expected);
  RLC_TRY {
    bn_new(order);
    bn_new(message);
    ec_new(h);
    ec_new(left);
    ec_new(right);
    ec_new(expected);
    ec_curve_get_ord(order);
    if (scalar_valid(opening, order) && pedersen_generator(h) == RLC_OK &&
        commitment_message_scalar(message, sid, item_digest_value, nonce,
                                  order) == RLC_OK) {
      ec_mul_gen(left, message);
      ec_mul(right, h, opening);
      ec_add(expected, left, right);
      ec_norm(expected, expected);
      status = ec_cmp(expected, commitment) == RLC_EQ;
    }
  } RLC_CATCH_ANY {
    status = 0;
  } RLC_FINALLY {
    bn_free(order);
    bn_free(message);
    ec_free(h);
    ec_free(left);
    ec_free(right);
    ec_free(expected);
  }
  return status;
}

int bench_joint_challenge(bn_t challenge,
                          const uint8_t transaction_digest[BENCH_DIGEST_BYTES],
                          const ec_t client_nonce, const ec_t server_nonce,
                          const ec_t statement) {
  bn_t order;
  bn_t x;
  ec_t aggregate;
  uint8_t input[BENCH_DIGEST_BYTES + RLC_FC_BYTES];
  uint8_t digest[BENCH_DIGEST_BYTES];
  int status = RLC_ERR;
  bn_null(order);
  bn_null(x);
  ec_null(aggregate);
  RLC_TRY {
    bn_new(order);
    bn_new(x);
    ec_new(aggregate);
    ec_curve_get_ord(order);
    if (ec_is_infty(client_nonce) || !ec_on_curve(client_nonce) ||
        ec_is_infty(server_nonce) || !ec_on_curve(server_nonce) ||
        ec_is_infty(statement) || !ec_on_curve(statement)) {
      RLC_THROW(ERR_NO_VALID);
    }
    ec_add(aggregate, client_nonce, server_nonce);
    ec_add(aggregate, aggregate, statement);
    ec_norm(aggregate, aggregate);
    ec_get_x(x, aggregate);
    bn_mod(x, x, order);
    /* The adaptor-signature message is the host transaction digest. */
    memcpy(input, transaction_digest, BENCH_DIGEST_BYTES);
    bn_write_bin(input + BENCH_DIGEST_BYTES, RLC_FC_BYTES, x);
    md_map(digest, input, sizeof(input));
    hash_to_scalar(challenge, digest, order, 0);
    if (bn_is_zero(challenge)) RLC_THROW(ERR_NO_VALID);
    status = RLC_OK;
  } RLC_CATCH_ANY {
    status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(order);
    bn_free(x);
    ec_free(aggregate);
  }
  return status;
}

int bench_joint_partial_sign(bn_t partial, const bn_t nonce_scalar,
                             const bn_t secret_scalar,
                             const bn_t challenge) {
  bn_t order;
  bn_t product;
  int status = RLC_ERR;
  bn_null(order);
  bn_null(product);
  RLC_TRY {
    bn_new(order);
    bn_new(product);
    ec_curve_get_ord(order);
    bn_mul(product, secret_scalar, challenge);
    bn_mod(product, product, order);
    bn_sub(partial, nonce_scalar, product);
    bn_mod(partial, partial, order);
    if (bn_sign(partial) == RLC_NEG) bn_add(partial, partial, order);
    if (!scalar_valid(partial, order)) RLC_THROW(ERR_NO_VALID);
    status = RLC_OK;
  } RLC_CATCH_ANY {
    status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(order);
    bn_free(product);
  }
  return status;
}

int bench_joint_partial_verify(const bn_t partial, const ec_t nonce,
                               const ec_t public_key, const bn_t challenge,
                               bench_verify_metrics_t *metrics) {
  bn_t order;
  ec_t reconstructed;
  long long started;
  int status = 0;
  bn_null(order);
  ec_null(reconstructed);
  RLC_TRY {
    bn_new(order);
    ec_new(reconstructed);
    ec_curve_get_ord(order);
    if (scalar_valid(partial, order) && scalar_valid(challenge, order) &&
        !ec_is_infty(nonce) && ec_on_curve(nonce) &&
        !ec_is_infty(public_key) && ec_on_curve(public_key)) {
      started = bench_monotonic_ns();
      ec_mul_sim_gen(reconstructed, partial, public_key, challenge);
      ec_norm(reconstructed, reconstructed);
      if (metrics != NULL) {
        metrics->equation_ns += bench_monotonic_ns() - started;
        metrics->equations++;
      }
      status = ec_cmp(reconstructed, nonce) == RLC_EQ;
    }
  } RLC_CATCH_ANY {
    status = 0;
  } RLC_FINALLY {
    bn_free(order);
    ec_free(reconstructed);
  }
  return status;
}

int bench_joint_full_verify(const bn_t full_scalar, const ec_t client_nonce,
                            const ec_t server_nonce, const ec_t statement,
                            const ec_t joint_public_key,
                            const bn_t challenge,
                            bench_verify_metrics_t *metrics) {
  ec_t expected;
  ec_t reconstructed;
  bn_t order;
  long long started;
  int status = 0;
  ec_null(expected);
  ec_null(reconstructed);
  bn_null(order);
  RLC_TRY {
    ec_new(expected);
    ec_new(reconstructed);
    bn_new(order);
    ec_curve_get_ord(order);
    if (scalar_valid(full_scalar, order) && scalar_valid(challenge, order) &&
        !ec_is_infty(statement) && ec_on_curve(statement)) {
      ec_add(expected, client_nonce, server_nonce);
      ec_norm(expected, expected);
      started = bench_monotonic_ns();
      ec_mul_sim_gen(reconstructed, full_scalar, joint_public_key, challenge);
      ec_norm(reconstructed, reconstructed);
      if (metrics != NULL) {
        metrics->equation_ns += bench_monotonic_ns() - started;
        metrics->equations++;
      }
      status = ec_cmp(reconstructed, expected) == RLC_EQ;
    }
  } RLC_CATCH_ANY {
    status = 0;
  } RLC_FINALLY {
    ec_free(expected);
    ec_free(reconstructed);
    bn_free(order);
  }
  return status;
}

int bench_derive_verifier_salt(
    uint8_t verifier_salt[BENCH_SALT_BYTES], const char *purpose,
    const uint8_t sid[BENCH_DIGEST_BYTES],
    const uint8_t batch_digest_value[BENCH_DIGEST_BYTES],
    const uint8_t fresh_random[BENCH_SALT_BYTES]) {
  const uint8_t *fields[] = {(const uint8_t *) purpose, sid,
                             batch_digest_value, fresh_random};
  const size_t lengths[] = {strlen(purpose), BENCH_DIGEST_BYTES,
                            BENCH_DIGEST_BYTES, BENCH_SALT_BYTES};
  return canonical_hash("OASIS-VERIFIER-SALT-v1", fields, lengths, 4,
                        verifier_salt);
}

static const char *equation_domain(bench_equation_t equation) {
  switch (equation) {
    case BENCH_EQUATION_SERVER_PARTIAL:
      return "OASIS-BATCH-COEFFICIENT-SERVER-PARTIAL-v1";
    case BENCH_EQUATION_CLIENT_PARTIAL:
      return "OASIS-BATCH-COEFFICIENT-CLIENT-PARTIAL-v1";
    case BENCH_EQUATION_FULL_PRESIGNATURE:
      return "OASIS-BATCH-COEFFICIENT-FULL-v1";
    default:
      return NULL;
  }
}

static int joint_coefficient(
    bn_t coefficient, bench_equation_t equation,
    const bench_transcript_t *transcript, bench_mode_t mode, unsigned ordinal,
    const ec_t client_nonce, const ec_t server_nonce, const bn_t challenge,
    const bn_t server_partial, const bn_t client_partial,
    const bn_t full_scalar, const uint8_t salt[BENCH_SALT_BYTES],
    const bn_t order) {
  const char *domain = equation_domain(equation);
  const uint8_t *sid = bench_active_sid(transcript, mode, ordinal);
  const uint8_t *item = transcript->item_digests +
                        (size_t) ordinal * BENCH_DIGEST_BYTES;
  uint8_t index[4];
  uint8_t ri[BENCH_POINT_BYTES];
  uint8_t rj[BENCH_POINT_BYTES];
  uint8_t statement[BENCH_POINT_BYTES];
  uint8_t client_key[BENCH_POINT_BYTES];
  uint8_t server_key[BENCH_POINT_BYTES];
  uint8_t joint_key[BENCH_POINT_BYTES];
  uint8_t e[BENCH_SCALAR_BYTES];
  uint8_t sj[BENCH_SCALAR_BYTES];
  uint8_t si[BENCH_SCALAR_BYTES];
  uint8_t full[BENCH_SCALAR_BYTES];
  uint8_t digest[BENCH_DIGEST_BYTES];
  const uint8_t *fields[] = {
      salt, sid, transcript->batch_digest, index, item, ri, rj, statement,
      client_key, server_key, joint_key, e, sj, si, full};
  const size_t lengths[] = {
      BENCH_SALT_BYTES, BENCH_DIGEST_BYTES, BENCH_DIGEST_BYTES, sizeof(index),
      BENCH_DIGEST_BYTES, BENCH_POINT_BYTES, BENCH_POINT_BYTES,
      BENCH_POINT_BYTES, BENCH_POINT_BYTES, BENCH_POINT_BYTES,
      BENCH_POINT_BYTES, BENCH_SCALAR_BYTES, BENCH_SCALAR_BYTES,
      BENCH_SCALAR_BYTES, BENCH_SCALAR_BYTES};
  if (domain == NULL || sid == NULL || point_bytes(ri, client_nonce) != RLC_OK ||
      point_bytes(rj, server_nonce) != RLC_OK ||
      point_bytes(statement, transcript->statements[ordinal]) != RLC_OK ||
      point_bytes(client_key, transcript->client_public_keys[ordinal]) != RLC_OK ||
      point_bytes(server_key, transcript->server_public_keys[ordinal]) != RLC_OK ||
      point_bytes(joint_key, transcript->joint_public_keys[ordinal]) != RLC_OK) {
    return RLC_ERR;
  }
  write_u32_be(index, ordinal);
  bn_write_bin(e, BENCH_SCALAR_BYTES, challenge);
  bn_write_bin(sj, BENCH_SCALAR_BYTES, server_partial);
  bn_write_bin(si, BENCH_SCALAR_BYTES, client_partial);
  bn_write_bin(full, BENCH_SCALAR_BYTES, full_scalar);
  if (canonical_hash(domain, fields, lengths, 15, digest) != RLC_OK) {
    return RLC_ERR;
  }
  return hash_to_scalar(coefficient, digest, order, 1);
}

int bench_joint_batch_verify(
    bench_equation_t equation, const bench_transcript_t *transcript,
    bench_mode_t mode, unsigned first_ordinal, unsigned count,
    const ec_t client_nonces[], const ec_t server_nonces[],
    const bn_t challenges[], const bn_t server_partials[],
    const bn_t client_partials[], const bn_t full_scalars[],
    const uint8_t salt[BENCH_SALT_BYTES],
    bench_verify_metrics_t *metrics) {
  bn_t order;
  bn_t coefficient;
  bn_t product;
  bn_t sum_s;
  ec_t result;
  ec_t generator;
  ec_t *points = NULL;
  bn_t *scalars = NULL;
  const unsigned point_count = 1 + 2 * count;
  unsigned initialized = 0;
  unsigned cursor = 0;
  unsigned i;
  long long started;
  int valid = 1;
  int status = 0;
  if (transcript == NULL || first_ordinal + count > transcript->count ||
      count == 0 || client_nonces == NULL || server_nonces == NULL ||
      challenges == NULL || server_partials == NULL || client_partials == NULL ||
      full_scalars == NULL || salt == NULL || equation_domain(equation) == NULL) {
    return 0;
  }
  bn_null(order);
  bn_null(coefficient);
  bn_null(product);
  bn_null(sum_s);
  ec_null(result);
  ec_null(generator);
  RLC_TRY {
    bn_new(order);
    bn_new(coefficient);
    bn_new(product);
    bn_new(sum_s);
    ec_new(result);
    ec_new(generator);
    ec_curve_get_ord(order);
    ec_curve_get_gen(generator);
    bn_zero(sum_s);
    points = calloc(point_count, sizeof(ec_t));
    scalars = calloc(point_count, sizeof(bn_t));
    if (points == NULL || scalars == NULL) RLC_THROW(ERR_NO_MEMORY);
    for (i = 0; i < point_count; i++) {
      ec_null(points[i]);
      bn_null(scalars[i]);
      ec_new(points[i]);
      bn_new(scalars[i]);
      initialized++;
    }
    started = bench_monotonic_ns();
    for (i = 0; i < count; i++) {
      unsigned ordinal = first_ordinal + i;
      const bn_t *selected_scalar = NULL;
      const ec_t *selected_nonce = NULL;
      const ec_t *selected_key = NULL;
      if (!scalar_valid(challenges[i], order) ||
          !scalar_valid(server_partials[i], order) ||
          !scalar_valid(client_partials[i], order) ||
          !scalar_valid(full_scalars[i], order) ||
          joint_coefficient(coefficient, equation, transcript, mode, ordinal,
                            client_nonces[i], server_nonces[i], challenges[i],
                            server_partials[i], client_partials[i],
                            full_scalars[i], salt, order) != RLC_OK) {
        valid = 0;
        break;
      }
      if (equation == BENCH_EQUATION_SERVER_PARTIAL) {
        selected_scalar = &server_partials[i];
        selected_nonce = &server_nonces[i];
        selected_key = &transcript->server_public_keys[ordinal];
      } else if (equation == BENCH_EQUATION_CLIENT_PARTIAL) {
        selected_scalar = &client_partials[i];
        selected_nonce = &client_nonces[i];
        selected_key = &transcript->client_public_keys[ordinal];
      } else {
        selected_scalar = &full_scalars[i];
        selected_key = &transcript->joint_public_keys[ordinal];
      }
      bn_mul(product, coefficient, *selected_scalar);
      bn_mod(product, product, order);
      bn_add(sum_s, sum_s, product);
      bn_mod(sum_s, sum_s, order);
      if (equation == BENCH_EQUATION_FULL_PRESIGNATURE) {
        ec_add(points[cursor], client_nonces[i], server_nonces[i]);
        ec_norm(points[cursor], points[cursor]);
      } else {
        ec_copy(points[cursor], *selected_nonce);
      }
      bn_sub(scalars[cursor], order, coefficient);
      bn_mod(scalars[cursor], scalars[cursor], order);
      cursor++;
      ec_copy(points[cursor], *selected_key);
      bn_mul(product, coefficient, challenges[i]);
      bn_mod(scalars[cursor], product, order);
      cursor++;
    }
    if (valid) {
      if (metrics != NULL) metrics->challenge_ns += bench_monotonic_ns() - started;
      ec_copy(points[cursor], generator);
      bn_copy(scalars[cursor], sum_s);
      cursor++;
      started = bench_monotonic_ns();
      ec_mul_sim_lot(result, (const ec_t *) points,
                     (const bn_t *) scalars, (int) cursor);
      ec_norm(result, result);
      if (metrics != NULL) {
        metrics->msm_ns += bench_monotonic_ns() - started;
        metrics->msm_calls++;
        metrics->equations += count;
      }
      status = ec_is_infty(result) ? 1 : 0;
    }
  } RLC_CATCH_ANY {
    status = 0;
  } RLC_FINALLY {
    for (i = 0; i < initialized; i++) {
      ec_free(points[i]);
      bn_free(scalars[i]);
    }
    free(points);
    free(scalars);
    bn_free(order);
    bn_free(coefficient);
    bn_free(product);
    bn_free(sum_s);
    ec_free(result);
    ec_free(generator);
  }
  return status;
}

int bench_completion_digest(
    const bench_transcript_t *transcript,
    const uint8_t status_digest[BENCH_DIGEST_BYTES],
    uint8_t out[BENCH_DIGEST_BYTES]) {
  const uint8_t *fields[] = {transcript->parent_sid,
                             transcript->batch_digest, status_digest};
  const size_t lengths[] = {BENCH_DIGEST_BYTES, BENCH_DIGEST_BYTES,
                            BENCH_DIGEST_BYTES};
  if (transcript == NULL || status_digest == NULL || out == NULL) return RLC_ERR;
  return canonical_hash("OASIS-COMPLETION-v1", fields, lengths, 3, out);
}

int bench_status_digest(const uint8_t *payload, size_t payload_length,
                        uint8_t out[BENCH_DIGEST_BYTES]) {
  const uint8_t empty = 0;
  const uint8_t *fields[] = {payload_length == 0 ? &empty : payload};
  const size_t lengths[] = {payload_length};
  if ((payload_length != 0 && payload == NULL) || out == NULL) return RLC_ERR;
  return canonical_hash("OASIS-FINAL-STATUS-v1", fields, lengths, 1, out);
}
