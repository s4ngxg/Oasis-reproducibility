#include "vtd_puzzle.h"
#include <errno.h>
#include <sys/random.h>

int vtd_random_below(mpz_t output, const mpz_t bound) {
  unsigned char bytes[2048];
  mpz_t candidate, maximum;
  size_t bits, length;
  int valid = 0;
  if (mpz_sgn(bound) <= 0 || mpz_sizeinbase(bound, 2) > 16384) return 0;
  mpz_inits(candidate, maximum, NULL);
  mpz_sub_ui(maximum, bound, 1);
  if (mpz_sgn(maximum) == 0) {
    mpz_set_ui(output, 0); valid = 1; goto cleanup;
  }
  bits = mpz_sizeinbase(maximum, 2); length = (bits + 7) / 8;
  /* Fail closed even if an abnormal entropy provider repeatedly produces
   * rejected candidates. The ordinary rejection probability is below 1/2. */
  for (unsigned attempt = 0; attempt < 1024; attempt++) {
    size_t offset = 0;
    while (offset < length) {
      ssize_t received = getrandom(bytes + offset, length - offset, 0);
      if (received < 0 && errno == EINTR) continue;
      if (received <= 0) goto cleanup;
      offset += (size_t)received;
    }
    if (bits % 8) bytes[0] &= (unsigned char)((1u << (bits % 8)) - 1u);
    mpz_import(candidate, length, 1, 1, 0, 0, bytes);
    if (mpz_cmp(candidate, bound) < 0) {
      mpz_set(output, candidate); valid = 1; break;
    }
  }
cleanup:
  /* Explicit volatile clearing prevents dead-store removal for entropy bytes.
   * GMP allocation clearing is not a secure-memory guarantee. */
  for (size_t i = 0; i < sizeof(bytes); i++) ((volatile unsigned char *)bytes)[i] = 0;
  mpz_clears(candidate, maximum, NULL);
  return valid;
}

static int unit(const mpz_t value, const mpz_t modulus) {
  mpz_t gcd;
  int valid;
  if (mpz_sgn(value) <= 0 || mpz_cmp(value, modulus) >= 0) return 0;
  mpz_init(gcd); mpz_gcd(gcd, value, modulus);
  valid = mpz_cmp_ui(gcd, 1) == 0; mpz_clear(gcd);
  return valid;
}

int vtd_range_check_row(const mpz_t modulus, const mpz_t g, const mpz_t h,
                        const mpz_t limit, const mpz_t commitment_u,
                        const mpz_t commitment_v, const mpz_t response,
                        const mpz_t random_response, const mpz_t *puzzle_u,
                        const mpz_t *puzzle_v, const unsigned char *challenge,
                        unsigned count) {
  mpz_t square, bound, left_u, left_v, right_u, right_v;
  int valid = 0;
  if (!puzzle_u || !puzzle_v || !challenge || count == 0 || count > 256 ||
      mpz_sgn(limit) <= 0 || mpz_sgn(random_response) < 0 ||
      mpz_cmp_ui(modulus, 3) <= 0 || mpz_even_p(modulus)) return 0;
  mpz_inits(square, bound, left_u, left_v, right_u, right_v, NULL);
  mpz_mul_ui(bound, limit, 2);
  if (mpz_cmp(bound, modulus) >= 0) goto cleanup;
  mpz_abs(bound, response); mpz_mul_ui(bound, bound, 2);
  if (mpz_cmp(bound, limit) > 0) goto cleanup;
  mpz_mul(square, modulus, modulus);
  if (!unit(commitment_u, modulus) || !unit(commitment_v, square)) goto cleanup;
  mpz_set(left_u, commitment_u); mpz_set(left_v, commitment_v);
  for (unsigned j = 0; j < count; j++) {
    /* Validate even unselected entries: the statement is one fixed vector. */
    if (challenge[j] > 1 || !unit(puzzle_u[j], modulus) ||
        !unit(puzzle_v[j], square)) goto cleanup;
    if (challenge[j]) {
      mpz_mul(left_u, left_u, puzzle_u[j]); mpz_mod(left_u, left_u, modulus);
      mpz_mul(left_v, left_v, puzzle_v[j]); mpz_mod(left_v, left_v, square);
    }
  }
  if (!vtd_puzzle_generate(right_u, right_v, modulus, g, h,
                           response, random_response)) goto cleanup;
  valid = mpz_cmp(left_u, right_u) == 0 && mpz_cmp(left_v, right_v) == 0;
cleanup:
  mpz_clears(square, bound, left_u, left_v, right_u, right_v, NULL);
  return valid;
}

int vtd_puzzle_generate(mpz_t u, mpz_t v, const mpz_t modulus,
                        const mpz_t g, const mpz_t h,
                        const mpz_t message, const mpz_t exponent) {
  mpz_t square, encoded, blind, power, out_u, out_v;
  int valid = 0;
  if (mpz_cmp_ui(modulus, 3) <= 0 || mpz_even_p(modulus) ||
      !unit(g, modulus) || !unit(h, modulus) || mpz_sgn(exponent) < 0)
    return 0;
  mpz_inits(square, encoded, blind, power, out_u, out_v, NULL);
  mpz_mul(square, modulus, modulus);
  /* Centered messages and arbitrary nonnegative exponent sums are needed by
   * the range proof. Exponents are NOT PRNG seeds and are not reduced mod N. */
  mpz_mod(encoded, message, modulus);
  mpz_mul(encoded, encoded, modulus); mpz_add_ui(encoded, encoded, 1);
  mpz_mul(power, exponent, modulus);
  mpz_powm(blind, h, power, square);
  mpz_powm(out_u, g, exponent, modulus);
  mpz_mul(out_v, encoded, blind); mpz_mod(out_v, out_v, square);
  if (unit(out_u, modulus) && unit(out_v, square)) {
    mpz_set(u, out_u); mpz_set(v, out_v); valid = 1;
  }
  mpz_clears(square, encoded, blind, power, out_u, out_v, NULL);
  return valid;
}

int vtd_puzzle_solve(mpz_t message, const mpz_t modulus,
                     const mpz_t u, const mpz_t v, uint64_t squarings) {
  mpz_t square, work, decoded, remainder;
  int valid = 0;
  if (mpz_cmp_ui(modulus, 3) <= 0 || mpz_even_p(modulus) || !unit(u, modulus))
    return 0;
  mpz_inits(square, work, decoded, remainder, NULL);
  mpz_mul(square, modulus, modulus);
  if (!unit(v, square)) goto cleanup;
  mpz_set(work, u);
  for (uint64_t i = 0; i < squarings; i++) {
    mpz_mul(work, work, work); mpz_mod(work, work, modulus);
  }
  mpz_powm(work, work, modulus, square);
  if (!mpz_invert(work, work, square)) goto cleanup;
  mpz_mul(decoded, v, work); mpz_mod(decoded, decoded, square);
  mpz_sub_ui(decoded, decoded, 1);
  /* Reject malformed puzzles rather than silently floor-dividing. */
  mpz_tdiv_qr(work, remainder, decoded, modulus);
  if (mpz_sgn(remainder) || mpz_sgn(work) < 0) goto cleanup;
  mpz_set(message, work); valid = 1;
cleanup:
  mpz_clears(square, work, decoded, remainder, NULL);
  return valid;
}
