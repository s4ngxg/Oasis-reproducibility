#ifndef OASIS_VTD_SHARING_H
#define OASIS_VTD_SHARING_H

#include <relic/relic.h>

/* Appendix E of Verifiable Timed Signatures Made Practical: field shares
 * at distinct nonzero indices. Callers allocate all output bn_t objects.
 * This module is not a VTD proof or a time-lock puzzle implementation. */
int vtd_split(bn_t *shares, unsigned count, unsigned threshold, const bn_t secret);
int vtd_weights(bn_t *weights, const unsigned *indices, unsigned count);
int vtd_recover(bn_t secret, const bn_t *shares, const unsigned *indices,
                unsigned count);
/* Returns RLC_OK only for a consistent, valid public-point interpolation.
 * Identity share points are valid (zero shares); the expected key is not. */
int vtd_check_points(const ec_t expected, const ec_t *shares,
                     const unsigned *indices, unsigned count);

#endif
