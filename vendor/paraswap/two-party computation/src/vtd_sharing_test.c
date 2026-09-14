#include <stdio.h>
#include "util.h"
#include "vtd_sharing.h"

int main(void) {
  bn_t shares[8], selected[5], weights[5], secret, recovered, order;
  ec_t expected, combined, point, product;
  ec_t public_shares[5];
  unsigned indices[5], initialized = 0, selected_count = 0, checks = 0;
  int status = 1;
  if (init() != RLC_OK) return 1;
  bn_null(secret); bn_null(recovered); bn_null(order);
  ec_null(expected); ec_null(combined); ec_null(point); ec_null(product);
  RLC_TRY {
    bn_new(secret); bn_new(recovered); bn_new(order); ec_curve_get_ord(order);
    ec_new(expected); ec_new(combined); ec_new(point); ec_new(product);
    for (unsigned i = 0; i < 8; i++) {
      bn_null(shares[i]); bn_new(shares[i]); initialized++;
    }
    for (unsigned i = 0; i < 5; i++) {
      bn_null(selected[i]); bn_null(weights[i]);
      bn_new(selected[i]); bn_new(weights[i]); selected_count++;
      ec_null(public_shares[i]); ec_new(public_shares[i]);
    }
    /* Independent known-answer polynomial f(x)=7+3x+2x^2. */
    indices[0] = 1; indices[1] = 2; indices[2] = 3;
    bn_set_dig(selected[0], 12); bn_set_dig(selected[1], 21);
    bn_set_dig(selected[2], 34);
    if (vtd_recover(recovered, (const bn_t *)selected, indices, 3) != RLC_OK ||
        bn_cmp_dig(recovered, 7) != RLC_EQ ||
        vtd_weights(weights, indices, 3) != RLC_OK ||
        bn_cmp_dig(weights[0], 3) != RLC_EQ || bn_cmp_dig(weights[2], 1) != RLC_EQ)
      RLC_THROW(ERR_NO_VALID);
    bn_sub_dig(recovered, order, 3);
    if (bn_cmp(weights[1], recovered) != RLC_EQ) RLC_THROW(ERR_NO_VALID);
    for (unsigned round = 0; round < 16; round++) {
      bn_rand_mod(secret, order); ec_mul_gen(expected, secret);
      if (vtd_split(shares, 8, 5, secret) != RLC_OK) RLC_THROW(ERR_NO_VALID);
      /* Every threshold subset, including nonconsecutive and reversed indices. */
      for (unsigned mask = 0; mask < 256; mask++) {
        if (__builtin_popcount(mask) != 5) continue;
        unsigned at = 0;
        for (unsigned i = 8; i > 0; i--) if (mask & (1u << (i - 1))) {
          indices[at] = i; bn_copy(selected[at++], shares[i-1]);
        }
        if (vtd_recover(recovered, (const bn_t *)selected, indices, 5) != RLC_OK ||
            bn_cmp(secret, recovered) != RLC_EQ ||
            vtd_weights(weights, indices, 5) != RLC_OK) RLC_THROW(ERR_NO_VALID);
        ec_set_infty(combined);
        for (unsigned i = 0; i < 5; i++) {
          ec_mul_gen(point, selected[i]); ec_mul(product, point, weights[i]);
          ec_copy(public_shares[i], point);
          ec_add(combined, combined, product);
        }
        if (ec_cmp(combined, expected) != RLC_EQ) RLC_THROW(ERR_NO_VALID);
        if (vtd_check_points(expected, (const ec_t *)public_shares, indices, 5)
            != RLC_OK) RLC_THROW(ERR_NO_VALID);
        bn_add_dig(selected[0], selected[0], 1); bn_mod(selected[0], selected[0], order);
        if (vtd_recover(recovered, (const bn_t *)selected, indices, 5) != RLC_OK)
          RLC_THROW(ERR_NO_VALID);
        ec_mul_gen(point, recovered);
        if (ec_cmp(point, expected) == RLC_EQ) RLC_THROW(ERR_NO_VALID);
        ec_mul_gen(public_shares[0], selected[0]);
        if (vtd_check_points(expected, (const ec_t *)public_shares, indices, 5)
            == RLC_OK) RLC_THROW(ERR_NO_VALID);
        checks++;
      }
    }
    indices[0] = indices[1];
    if (vtd_recover(recovered, (const bn_t *)selected, indices, 5) == RLC_OK)
      RLC_THROW(ERR_NO_VALID);
    indices[0] = 0;
    if (vtd_weights(weights, indices, 5) == RLC_OK) RLC_THROW(ERR_NO_VALID);
    indices[0] = 257;
    if (vtd_weights(weights, indices, 5) == RLC_OK) RLC_THROW(ERR_NO_VALID);
    for (unsigned i = 0; i < 5; i++) indices[i] = i + 1;
    bn_copy(selected[0], order);
    if (vtd_recover(recovered, (const bn_t *)selected, indices, 5) == RLC_OK)
      RLC_THROW(ERR_NO_VALID);
    if (vtd_split(shares, 8, 9, secret) == RLC_OK ||
        vtd_split(shares, 8, 1, secret) == RLC_OK) RLC_THROW(ERR_NO_VALID);
    printf("{\"threshold_subsets_checked\":%u,\"scalar_and_point_reconstruction\":true,"
           "\"malformed_inputs_rejected\":true,\"full_vtd_proof\":false}\n", checks);
    status = 0;
  } RLC_CATCH_ANY { fprintf(stderr, "VTD sharing regression failed\n"); }
  RLC_FINALLY {
    for (unsigned i = 0; i < initialized; i++) { bn_zero(shares[i]); bn_free(shares[i]); }
    for (unsigned i = 0; i < selected_count; i++) {
      bn_zero(selected[i]); bn_free(selected[i]); bn_free(weights[i]);
      ec_free(public_shares[i]);
    }
    if (secret != NULL) bn_zero(secret);
    if (recovered != NULL) bn_zero(recovered);
    bn_free(secret); bn_free(recovered); bn_free(order);
    ec_free(expected); ec_free(combined); ec_free(point); ec_free(product);
  }
  clean();
  return status;
}
