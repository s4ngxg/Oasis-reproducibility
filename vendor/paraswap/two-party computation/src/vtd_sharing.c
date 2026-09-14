#include "vtd_sharing.h"

#define VTD_MAX_SHARES 256u

int vtd_check_points(const ec_t expected, const ec_t *shares,
                     const unsigned *indices, unsigned count) {
  bn_t weights[VTD_MAX_SHARES];
  ec_t sum, term;
  unsigned allocated = 0;
  int status = RLC_ERR;
  if (!shares || !indices || count < 2 || count > VTD_MAX_SHARES)
    return RLC_ERR;
  ec_null(sum); ec_null(term);
  RLC_TRY {
    ec_new(sum); ec_new(term); ec_set_infty(sum);
    if (ec_is_infty(expected) || !ec_on_curve(expected)) RLC_THROW(ERR_NO_VALID);
    for (unsigned i = 0; i < count; i++) {
      bn_null(weights[i]); bn_new(weights[i]); allocated++;
      if (!ec_is_infty(shares[i]) && !ec_on_curve(shares[i]))
        RLC_THROW(ERR_NO_VALID);
    }
    if (vtd_weights(weights, indices, count) != RLC_OK) RLC_THROW(ERR_NO_VALID);
    for (unsigned i = 0; i < count; i++) {
      ec_mul(term, shares[i], weights[i]); ec_add(sum, sum, term);
    }
    if (ec_cmp(sum, expected) == RLC_EQ) status = RLC_OK;
  } RLC_CATCH_ANY { status = RLC_ERR; }
  RLC_FINALLY {
    for (unsigned i = 0; i < allocated; i++) bn_free(weights[i]);
    ec_free(sum); ec_free(term);
  }
  return status;
}

int vtd_split(bn_t *shares, unsigned count, unsigned threshold, const bn_t secret) {
  bn_t order, coefficients[VTD_MAX_SHARES], x;
  unsigned allocated = 0;
  int status = RLC_ERR;
  if (!shares || count > VTD_MAX_SHARES || threshold < 2 || threshold > count)
    return RLC_ERR;
  bn_null(order); bn_null(x);
  RLC_TRY {
    bn_new(order); bn_new(x); ec_curve_get_ord(order);
    if (bn_sign(secret) == RLC_NEG || bn_cmp(secret, order) != RLC_LT)
      RLC_THROW(ERR_NO_VALID);
    for (unsigned i = 0; i < threshold; i++) {
      bn_null(coefficients[i]); bn_new(coefficients[i]); allocated++;
      if (i == 0) bn_copy(coefficients[i], secret);
      else bn_rand_mod(coefficients[i], order);
    }
    for (unsigned i = 0; i < count; i++) {
      bn_set_dig(x, i + 1);
      bn_copy(shares[i], coefficients[threshold - 1]);
      for (unsigned j = threshold - 1; j > 0; j--) {
        bn_mul(shares[i], shares[i], x);
        bn_add(shares[i], shares[i], coefficients[j - 1]);
        bn_mod(shares[i], shares[i], order);
      }
    }
    status = RLC_OK;
  } RLC_CATCH_ANY { status = RLC_ERR; }
  RLC_FINALLY {
    for (unsigned i = 0; i < allocated; i++) {
      bn_zero(coefficients[i]); bn_free(coefficients[i]);
    }
    bn_free(order); bn_free(x);
  }
  if (status != RLC_OK)
    for (unsigned i = 0; i < count; i++) bn_zero(shares[i]);
  return status;
}

int vtd_weights(bn_t *weights, const unsigned *indices, unsigned count) {
  bn_t order, numerator, denominator, term, inverse;
  int status = RLC_ERR;
  if (!weights || !indices || count < 2 || count > VTD_MAX_SHARES) return RLC_ERR;
  for (unsigned i = 0; i < count; i++) {
    if (indices[i] == 0 || indices[i] > VTD_MAX_SHARES) return RLC_ERR;
    for (unsigned j = 0; j < i; j++)
      if (indices[i] == indices[j]) return RLC_ERR;
  }
  bn_null(order); bn_null(numerator); bn_null(denominator);
  bn_null(term); bn_null(inverse);
  RLC_TRY {
    bn_new(order); bn_new(numerator); bn_new(denominator);
    bn_new(term); bn_new(inverse); ec_curve_get_ord(order);
    /* L_i(0) = product_{j != i} x_j / (x_j - x_i). */
    for (unsigned i = 0; i < count; i++) {
      bn_set_dig(numerator, 1); bn_set_dig(denominator, 1);
      for (unsigned j = 0; j < count; j++) {
        if (i == j) continue;
        bn_set_dig(term, indices[j]);
        bn_mul(numerator, numerator, term); bn_mod(numerator, numerator, order);
        bn_set_dig(inverse, indices[i]); bn_sub(term, term, inverse);
        bn_mul(denominator, denominator, term); bn_mod(denominator, denominator, order);
      }
      bn_mod_inv(inverse, denominator, order);
      bn_mul(weights[i], numerator, inverse); bn_mod(weights[i], weights[i], order);
    }
    status = RLC_OK;
  } RLC_CATCH_ANY { status = RLC_ERR; }
  RLC_FINALLY {
    bn_free(order); bn_free(numerator); bn_free(denominator);
    bn_free(term); bn_free(inverse);
  }
  return status;
}

int vtd_recover(bn_t secret, const bn_t *shares, const unsigned *indices,
                unsigned count) {
  bn_t weights[VTD_MAX_SHARES], order, term, result;
  unsigned allocated = 0;
  int status = RLC_ERR;
  if (!shares || !indices || count < 2 || count > VTD_MAX_SHARES) return RLC_ERR;
  bn_null(order); bn_null(term); bn_null(result);
  RLC_TRY {
    bn_new(order); bn_new(term); bn_new(result); ec_curve_get_ord(order);
    bn_zero(result);
    for (unsigned i = 0; i < count; i++) {
      bn_null(weights[i]); bn_new(weights[i]); allocated++;
      if (bn_sign(shares[i]) == RLC_NEG || bn_cmp(shares[i], order) != RLC_LT)
        RLC_THROW(ERR_NO_VALID);
    }
    if (vtd_weights(weights, indices, count) != RLC_OK) RLC_THROW(ERR_NO_VALID);
    for (unsigned i = 0; i < count; i++) {
      bn_mul(term, shares[i], weights[i]); bn_add(result, result, term);
      bn_mod(result, result, order);
    }
    bn_copy(secret, result); status = RLC_OK;
  } RLC_CATCH_ANY { status = RLC_ERR; }
  RLC_FINALLY {
    for (unsigned i = 0; i < allocated; i++) bn_free(weights[i]);
    if (term != NULL) bn_zero(term);
    if (result != NULL) bn_zero(result);
    bn_free(order); bn_free(term); bn_free(result);
  }
  if (status != RLC_OK) bn_zero(secret);
  return status;
}
