#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "preswap_protocol.h"
#ifdef BENCH_ALLOCATION_PROFILE
#include "allocation_counter.h"
#endif

static void write_u32(uint8_t *buffer, uint32_t value) {
  buffer[0] = (uint8_t) (value >> 24);
  buffer[1] = (uint8_t) (value >> 16);
  buffer[2] = (uint8_t) (value >> 8);
  buffer[3] = (uint8_t) value;
}

static int scalar_from_hash(bn_t scalar, const uint8_t hash[RLC_MD_LEN],
                            const bn_t order) {
  size_t length = RLC_MD_LEN;
  if (8 * RLC_MD_LEN > bn_bits(order)) {
    length = (size_t) RLC_CEIL(bn_bits(order), 8);
    bn_read_bin(scalar, hash, (int) length);
    bn_rsh(scalar, scalar, 8 * RLC_MD_LEN - bn_bits(order));
  } else {
    bn_read_bin(scalar, hash, RLC_MD_LEN);
  }
  bn_mod(scalar, scalar, order);
  return RLC_OK;
}

static int schnorr_challenge(bn_t challenge, const uint8_t *message,
                             size_t message_length, const ec_t nonce,
                             const bn_t order) {
  bn_t x;
  bn_t reduced_x;
  uint8_t hash[RLC_MD_LEN];
  uint8_t *input = NULL;
  int status = RLC_ERR;

  bn_null(x);
  bn_null(reduced_x);
  RLC_TRY {
    bn_new(x);
    bn_new(reduced_x);
    input = malloc(message_length + RLC_FC_BYTES);
    if (input == NULL || ec_is_infty(nonce) || !ec_on_curve(nonce)) {
      RLC_THROW(ERR_NO_VALID);
    }
    ec_get_x(x, nonce);
    bn_mod(reduced_x, x, order);
    memcpy(input, message, message_length);
    bn_write_bin(input + message_length, RLC_FC_BYTES, reduced_x);
    md_map(hash, input, message_length + RLC_FC_BYTES);
    scalar_from_hash(challenge, hash, order);
    status = RLC_OK;
  } RLC_CATCH_ANY {
    status = RLC_ERR;
  } RLC_FINALLY {
    free(input);
    bn_free(x);
    bn_free(reduced_x);
  }
  return status;
}

static int signature_scalars_valid(const schnorr_signature_t signature,
                                   const bn_t order) {
  return bn_sign(signature->e) == RLC_POS &&
         bn_sign(signature->s) == RLC_POS &&
         !bn_is_zero(signature->s) &&
         bn_cmp(signature->e, order) == RLC_LT &&
         bn_cmp(signature->s, order) == RLC_LT;
}

int bench_random_salt(uint8_t salt[BENCH_SALT_BYTES]) {
  bn_t order;
  bn_t value;
  int status = RLC_ERR;
  bn_null(order);
  bn_null(value);
  RLC_TRY {
    bn_new(order);
    bn_new(value);
    ec_curve_get_ord(order);
    do {
      bn_rand_mod(value, order);
    } while (bn_is_zero(value));
    bn_write_bin(salt, BENCH_SALT_BYTES, value);
    status = RLC_OK;
  } RLC_CATCH_ANY {
    status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(order);
    bn_free(value);
  }
  return status;
}

int bench_schnorr_sign_explicit(schnorr_signature_t signature, ec_t nonce,
                                const uint8_t *message, size_t message_length,
                                const ec_t adaptor, int has_adaptor,
                                const bn_t secret_scalar) {
  bn_t order;
  bn_t randomizer;
  bn_t product;
  int status = RLC_ERR;

  bn_null(order);
  bn_null(randomizer);
  bn_null(product);
  RLC_TRY {
    bn_new(order);
    bn_new(randomizer);
    bn_new(product);
    ec_curve_get_ord(order);
    do {
      bn_rand_mod(randomizer, order);
    } while (bn_is_zero(randomizer));
    ec_mul_gen(nonce, randomizer);
    if (has_adaptor) {
      ec_add(nonce, nonce, adaptor);
      ec_norm(nonce, nonce);
    }
    if (schnorr_challenge(signature->e, message, message_length, nonce,
                          order) != RLC_OK) {
      RLC_THROW(ERR_NO_VALID);
    }
    bn_mul(product, secret_scalar, signature->e);
    bn_mod(product, product, order);
    bn_sub(signature->s, order, product);
    bn_add(signature->s, signature->s, randomizer);
    bn_mod(signature->s, signature->s, order);
    if (!signature_scalars_valid(signature, order)) {
      RLC_THROW(ERR_NO_VALID);
    }
    status = RLC_OK;
  } RLC_CATCH_ANY {
    status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(order);
    bn_free(randomizer);
    bn_free(product);
  }
  return status;
}

int bench_schnorr_verify_explicit(const schnorr_signature_t signature,
                                  const ec_t nonce,
                                  const uint8_t *message,
                                  size_t message_length,
                                  const ec_t adaptor, int has_adaptor,
                                  const ec_t public_key,
                                  bench_verify_metrics_t *metrics) {
  bn_t order;
  bn_t expected_challenge;
  ec_t reconstructed;
  long long started;
  int status = 0;

  bn_null(order);
  bn_null(expected_challenge);
  ec_null(reconstructed);
  RLC_TRY {
    bn_new(order);
    bn_new(expected_challenge);
    ec_new(reconstructed);
    ec_curve_get_ord(order);
    if (signature_scalars_valid(signature, order)) {
      started = bench_monotonic_ns();
      if (schnorr_challenge(expected_challenge, message, message_length, nonce,
                            order) == RLC_OK &&
          bn_cmp(expected_challenge, signature->e) == RLC_EQ) {
        if (metrics != NULL) metrics->challenge_ns += bench_monotonic_ns() - started;
        started = bench_monotonic_ns();
        ec_mul_sim_gen(reconstructed, signature->s, public_key, signature->e);
        if (has_adaptor) ec_add(reconstructed, reconstructed, adaptor);
        ec_norm(reconstructed, reconstructed);
        if (metrics != NULL) {
          metrics->equation_ns += bench_monotonic_ns() - started;
          metrics->equations++;
        }
        status = ec_cmp(reconstructed, nonce) == RLC_EQ ? 1 : 0;
      }
    }
  } RLC_CATCH_ANY {
    status = 0;
  } RLC_FINALLY {
    bn_free(order);
    bn_free(expected_challenge);
    ec_free(reconstructed);
  }
  return status;
}

static int batch_coefficient(bn_t coefficient,
                             const uint8_t salt[BENCH_SALT_BYTES],
                             const char *equation_domain, unsigned index,
                             const uint8_t *message, size_t message_length,
                             const ec_t nonce, const ec_t adaptor,
                             int has_adaptor, const ec_t public_key,
                             const schnorr_signature_t signature,
                             const bn_t order) {
  static const char prefix[] = "PARASWAP-OASIS-BATCH-COEFFICIENT-v1";
  size_t domain_length = strlen(equation_domain);
  size_t point_count = has_adaptor ? 3u : 2u;
  size_t length = sizeof(prefix) - 1 + 4 + domain_length + BENCH_SALT_BYTES +
                  4 + message_length +
                  point_count * RLC_EC_SIZE_COMPRESSED + 2 * RLC_BN_SIZE;
  uint8_t hash[RLC_MD_LEN];
  uint8_t *input = malloc(length);
  uint8_t *cursor;
  if (input == NULL) return RLC_ERR;
  cursor = input;
  memcpy(cursor, prefix, sizeof(prefix) - 1);
  cursor += sizeof(prefix) - 1;
  write_u32(cursor, (uint32_t) domain_length);
  cursor += 4;
  memcpy(cursor, equation_domain, domain_length);
  cursor += domain_length;
  memcpy(cursor, salt, BENCH_SALT_BYTES);
  cursor += BENCH_SALT_BYTES;
  write_u32(cursor, index);
  cursor += 4;
  memcpy(cursor, message, message_length);
  cursor += message_length;
  ec_write_bin(cursor, RLC_EC_SIZE_COMPRESSED, nonce, 1);
  cursor += RLC_EC_SIZE_COMPRESSED;
  ec_write_bin(cursor, RLC_EC_SIZE_COMPRESSED, public_key, 1);
  cursor += RLC_EC_SIZE_COMPRESSED;
  if (has_adaptor) {
    ec_write_bin(cursor, RLC_EC_SIZE_COMPRESSED, adaptor, 1);
    cursor += RLC_EC_SIZE_COMPRESSED;
  }
  bn_write_bin(cursor, RLC_BN_SIZE, signature->e);
  cursor += RLC_BN_SIZE;
  bn_write_bin(cursor, RLC_BN_SIZE, signature->s);
  md_map(hash, input, length);
  free(input);
  scalar_from_hash(coefficient, hash, order);
  if (bn_is_zero(coefficient)) bn_set_dig(coefficient, 1);
  return RLC_OK;
}

int bench_schnorr_batch_verify(schnorr_signature_t const signatures[],
                               const ec_t nonces[], const uint8_t *messages,
                               size_t message_stride, const ec_t adaptors[],
                               int has_adaptor, const ec_t public_keys[],
                               unsigned count,
                               const uint8_t salt[BENCH_SALT_BYTES],
                               const char *equation_domain,
                               bench_verify_metrics_t *metrics) {
  bn_t order;
  bn_t expected;
  bn_t sum_s;
  bn_t coefficient;
  bn_t product;
  ec_t result;
  ec_t generator;
  ec_t *points = NULL;
  bn_t *scalars = NULL;
  unsigned point_count = count * (has_adaptor ? 3u : 2u) + 1u;
  unsigned initialized = 0;
  unsigned cursor = 0;
  unsigned i;
  long long started;
  int inputs_valid = 1;
  int status = 0;

  if (count == 0 || signatures == NULL || nonces == NULL || messages == NULL ||
      public_keys == NULL || salt == NULL || equation_domain == NULL) {
    return 0;
  }
  bn_null(order);
  bn_null(expected);
  bn_null(sum_s);
  bn_null(coefficient);
  bn_null(product);
  ec_null(result);
  ec_null(generator);
  RLC_TRY {
    bn_new(order);
    bn_new(expected);
    bn_new(sum_s);
    bn_new(coefficient);
    bn_new(product);
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
      const uint8_t *message = messages + (size_t) i * message_stride;
      if (!signature_scalars_valid(signatures[i], order) ||
          ec_is_infty(public_keys[i]) || !ec_on_curve(public_keys[i]) ||
          schnorr_challenge(expected, message, BENCH_DIGEST_BYTES,
                            nonces[i], order) != RLC_OK ||
          bn_cmp(expected, signatures[i]->e) != RLC_EQ ||
          batch_coefficient(coefficient, salt, equation_domain, i,
                            message, BENCH_DIGEST_BYTES, nonces[i],
                            has_adaptor ? adaptors[i] : nonces[i], has_adaptor,
                            public_keys[i], signatures[i], order) != RLC_OK) {
        inputs_valid = 0;
        break;
      }
      ec_copy(points[cursor], nonces[i]);
      bn_copy(scalars[cursor], coefficient);
      bn_mul(product, coefficient, signatures[i]->s);
      bn_mod(product, product, order);
      bn_add(sum_s, sum_s, product);
      bn_mod(sum_s, sum_s, order);
      cursor++;
      if (has_adaptor) {
        ec_copy(points[cursor], adaptors[i]);
        bn_sub(scalars[cursor], order, coefficient);
        bn_mod(scalars[cursor], scalars[cursor], order);
        cursor++;
      }
      ec_copy(points[cursor], public_keys[i]);
      bn_mul(product, coefficient, signatures[i]->e);
      bn_mod(product, product, order);
      bn_sub(scalars[cursor], order, product);
      bn_mod(scalars[cursor], scalars[cursor], order);
      cursor++;
    }
    if (inputs_valid) {
      if (metrics != NULL) metrics->challenge_ns += bench_monotonic_ns() - started;
      ec_copy(points[cursor], generator);
      bn_sub(scalars[cursor], order, sum_s);
      bn_mod(scalars[cursor], scalars[cursor], order);
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
    bn_free(expected);
    bn_free(sum_s);
    bn_free(coefficient);
    bn_free(product);
    ec_free(result);
    ec_free(generator);
  }
  return status;
}
