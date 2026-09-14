#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "preswap_protocol.h"

#define TEST_ITEMS 16u

static int run_case(int has_adaptor) {
  ec_secret_key_t secret_key;
  ec_public_key_t public_key;
  schnorr_signature_t *signatures = NULL;
  ec_t *nonces = NULL;
  ec_t *adaptors = NULL;
  bn_t *secret_scalars = NULL;
  ec_t *public_keys = NULL;
  bn_t order;
  bn_t adaptor_scalar;
  bn_t saved_scalar;
  bn_t adapted_scalar;
  bn_t extracted_witness;
  ec_t expected_public;
  ec_t saved_public;
  ec_t base_public;
  uint8_t messages[TEST_ITEMS * BENCH_DIGEST_BYTES];
  uint8_t salt[BENCH_SALT_BYTES];
  bench_verify_metrics_t metrics;
  unsigned initialized = 0;
  unsigned i;
  int status = RLC_ERR;

  ec_secret_key_null(secret_key);
  ec_public_key_null(public_key);
  bn_null(order);
  bn_null(adaptor_scalar);
  bn_null(saved_scalar);
  bn_null(adapted_scalar);
  bn_null(extracted_witness);
  ec_null(expected_public);
  ec_null(saved_public);
  ec_null(base_public);
  memset(&metrics, 0, sizeof(metrics));
  signatures = calloc(TEST_ITEMS, sizeof(*signatures));
  nonces = calloc(TEST_ITEMS, sizeof(*nonces));
  adaptors = calloc(TEST_ITEMS, sizeof(*adaptors));
  secret_scalars = calloc(TEST_ITEMS, sizeof(*secret_scalars));
  public_keys = calloc(TEST_ITEMS, sizeof(*public_keys));
  if (signatures == NULL || nonces == NULL || adaptors == NULL ||
      secret_scalars == NULL || public_keys == NULL) goto cleanup;

  RLC_TRY {
    ec_secret_key_new(secret_key);
    ec_public_key_new(public_key);
    bn_new(order);
    bn_new(adaptor_scalar);
    bn_new(saved_scalar);
    bn_new(adapted_scalar);
    bn_new(extracted_witness);
    ec_new(expected_public);
    ec_new(saved_public);
    ec_new(base_public);
    ec_curve_get_ord(order);
    do {
      bn_rand_mod(secret_key->sk, order);
    } while (bn_is_zero(secret_key->sk));
    ec_mul_gen(base_public, secret_key->sk);
    for (i = 0; i < TEST_ITEMS; i++) {
      uint8_t seed[8];
      schnorr_signature_null(signatures[i]);
      ec_null(nonces[i]);
      ec_null(adaptors[i]);
      bn_null(secret_scalars[i]);
      ec_null(public_keys[i]);
      schnorr_signature_new(signatures[i]);
      ec_new(nonces[i]);
      ec_new(adaptors[i]);
      bn_new(secret_scalars[i]);
      ec_new(public_keys[i]);
      initialized++;
      memset(seed, 0, sizeof(seed));
      seed[3] = (uint8_t) has_adaptor;
      seed[7] = (uint8_t) i;
      md_map(messages + (size_t) i * BENCH_DIGEST_BYTES,
             seed, sizeof(seed));
      if (bench_derive_item_secret(
              secret_scalars[i], secret_key->sk, "TEST-SIGNING-KEY-v1", 7,
              i, TEST_ITEMS) != RLC_OK ||
          bench_derive_item_public(
              public_keys[i], base_public, "TEST-SIGNING-KEY-v1", 7,
              i, TEST_ITEMS) != RLC_OK) {
        RLC_THROW(ERR_NO_VALID);
      }
      ec_mul_gen(expected_public, secret_scalars[i]);
      ec_norm(expected_public, expected_public);
      if (ec_cmp(expected_public, public_keys[i]) != RLC_EQ) {
        RLC_THROW(ERR_NO_VALID);
      }
      ec_copy(public_key->pk, public_keys[i]);
      if (has_adaptor) {
        do {
          bn_rand_mod(adaptor_scalar, order);
        } while (bn_is_zero(adaptor_scalar));
        ec_mul_gen(adaptors[i], adaptor_scalar);
      } else {
        ec_set_infty(adaptors[i]);
      }
      if (bench_schnorr_sign_explicit(
              signatures[i], nonces[i],
              messages + (size_t) i * BENCH_DIGEST_BYTES,
              BENCH_DIGEST_BYTES, adaptors[i], has_adaptor,
              secret_scalars[i]) != RLC_OK ||
          !bench_schnorr_verify_explicit(
              signatures[i], nonces[i],
              messages + (size_t) i * BENCH_DIGEST_BYTES,
              BENCH_DIGEST_BYTES, adaptors[i], has_adaptor,
              public_keys[i], NULL)) {
        RLC_THROW(ERR_NO_VALID);
      }
      if (has_adaptor) {
        if (adaptor_schnorr_preverify(
                signatures[i],
                messages + (size_t) i * BENCH_DIGEST_BYTES,
                BENCH_DIGEST_BYTES, adaptors[i], public_key) != 1) {
          RLC_THROW(ERR_NO_VALID);
        }
        bn_add(adapted_scalar, signatures[i]->s, adaptor_scalar);
        bn_mod(adapted_scalar, adapted_scalar, order);
        if (cp_ecss_ver(signatures[i]->e, adapted_scalar,
                        messages + (size_t) i * BENCH_DIGEST_BYTES,
                        BENCH_DIGEST_BYTES, public_key->pk) != 1) {
          RLC_THROW(ERR_NO_VALID);
        }
        bn_sub(extracted_witness, adapted_scalar, signatures[i]->s);
        bn_mod(extracted_witness, extracted_witness, order);
        if (bn_cmp(extracted_witness, adaptor_scalar) != RLC_EQ) {
          RLC_THROW(ERR_NO_VALID);
        }
      } else if (cp_ecss_ver(
                     signatures[i]->e, signatures[i]->s,
                     messages + (size_t) i * BENCH_DIGEST_BYTES,
                     BENCH_DIGEST_BYTES, public_key->pk) != 1) {
        RLC_THROW(ERR_NO_VALID);
      }
    }
    if (bench_random_salt(salt) != RLC_OK ||
        !bench_schnorr_batch_verify(signatures, nonces, messages,
                                    BENCH_DIGEST_BYTES, adaptors, has_adaptor,
                                    public_keys, TEST_ITEMS, salt,
                                    has_adaptor ? "TEST-ADAPTOR-v1"
                                                : "TEST-PLAIN-v1",
                                    &metrics)) {
      RLC_THROW(ERR_NO_VALID);
    }

    bn_copy(saved_scalar, signatures[7]->s);
    bn_add_dig(signatures[7]->s, signatures[7]->s, 1);
    bn_mod(signatures[7]->s, signatures[7]->s, order);
    if (bn_is_zero(signatures[7]->s)) bn_set_dig(signatures[7]->s, 1);
    if (bench_schnorr_batch_verify(signatures, nonces, messages,
                                   BENCH_DIGEST_BYTES, adaptors, has_adaptor,
                                   public_keys, TEST_ITEMS, salt,
                                   has_adaptor ? "TEST-ADAPTOR-v1"
                                               : "TEST-PLAIN-v1",
                                   NULL)) {
      RLC_THROW(ERR_NO_VALID);
    }
    bn_copy(signatures[7]->s, saved_scalar);

    ec_copy(saved_public, public_keys[5]);
    ec_curve_get_gen(expected_public);
    ec_add(public_keys[5], public_keys[5], expected_public);
    ec_norm(public_keys[5], public_keys[5]);
    if (bench_schnorr_batch_verify(signatures, nonces, messages,
                                   BENCH_DIGEST_BYTES, adaptors, has_adaptor,
                                   public_keys, TEST_ITEMS, salt,
                                   has_adaptor ? "TEST-ADAPTOR-v1"
                                               : "TEST-PLAIN-v1",
                                   NULL)) {
      RLC_THROW(ERR_NO_VALID);
    }
    ec_copy(public_keys[5], saved_public);

    messages[3 * BENCH_DIGEST_BYTES + 5] ^= 0x01;
    if (bench_schnorr_batch_verify(signatures, nonces, messages,
                                   BENCH_DIGEST_BYTES, adaptors, has_adaptor,
                                   public_keys, TEST_ITEMS, salt,
                                   has_adaptor ? "TEST-ADAPTOR-v1"
                                               : "TEST-PLAIN-v1",
                                   NULL)) {
      RLC_THROW(ERR_NO_VALID);
    }
    status = RLC_OK;
  } RLC_CATCH_ANY {
    status = RLC_ERR;
  } RLC_FINALLY {
    for (i = 0; i < initialized; i++) {
      schnorr_signature_free(signatures[i]);
      ec_free(nonces[i]);
      ec_free(adaptors[i]);
      bn_free(secret_scalars[i]);
      ec_free(public_keys[i]);
    }
    if (secret_key != NULL) ec_secret_key_free(secret_key);
    if (public_key != NULL) ec_public_key_free(public_key);
    bn_free(order);
    bn_free(adaptor_scalar);
    bn_free(saved_scalar);
    bn_free(adapted_scalar);
    bn_free(extracted_witness);
    ec_free(expected_public);
    ec_free(saved_public);
    ec_free(base_public);
  }

cleanup:
  free(signatures);
  free(nonces);
  free(adaptors);
  free(secret_scalars);
  free(public_keys);
  return status;
}

int main(void) {
  int plain_status;
  int adaptor_status;
  if (init() != RLC_OK) return 1;
  plain_status = run_case(0);
  adaptor_status = run_case(1);
  clean();
  if (plain_status != RLC_OK || adaptor_status != RLC_OK) {
    fprintf(stderr, "batch verifier regression failed\n");
    return 1;
  }
  printf("BATCH_VERIFY_TEST\tplain=pass\tadaptor=pass\tmulti_key=pass\t"
         "reference=pass\tadapt_extract=pass\tinvalid=reject\n");
  return 0;
}
