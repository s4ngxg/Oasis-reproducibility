# Cryptographic construction mapping

This document maps the measured native implementation to its cryptographic
assumptions and executable checks. It is not a new reduction and does not claim
that the artifact-specific round schedule is automatically covered by a cited
generic two-party adaptor-signature theorem.

## Component map

| Component | Native realization | Executable evidence | Security boundary |
|---|---|---|---|
| Curve setup | Pinned RELIC commit configured for secp256k1; points must be on curve, non-identity, canonically compressed, and in the prime-order subgroup | `bench_validate_secp256k1`, transcript KAT, point/scalar mutation tests | Assumes discrete-log hardness for secp256k1 |
| Preparation key ownership | Domain-separated Schnorr proof of knowledge over each master public share; the initiator proof is carried in the first `BATCH_INIT` and the responder proof in the first `SERVER_COMMIT` | `bench_key_ownership_prove`, `bench_key_ownership_verify`, runtime native exchange, and mutated-proof rejection | Proof generation precedes the measured protocol interval, peer verification is measured, and piggybacking adds no logical round |
| Proof binding | Challenge binds the Preparation digest, initiator/responder role, pair ID, key epoch, public key, and proof commitment | `joint_presign_test` rejects changed context, role, pair, epoch, key, identity key, and proof; native smoke rejects a mutated wire proof | Establishes artifact rejection behavior, not a general PKI or wallet-registration theorem |
| Joint-key consistency | Each item requires `P_ij = P_i + P_j`, with all three points validated | `bench_validate_joint_public_key` valid and mutation cases | Assumes the validated shares belong to the intended host identities |
| Nonce commitment | Pedersen-style commitment to the canonical SID/item/nonce encoding, using an independently derived public second generator | valid/opening mutation tests in `joint_presign_test` and native protocol smoke | Supplies hiding/binding under the stated discrete-log assumptions; it does not by itself provide adaptive security |
| Per-item partial relation | ParaSwap negative-sign convention `s_i=r_i-e*x_i`, `s_j=r_j-e*x_j`; full candidate `s=s_i+s_j` | every candidate is checked by the unchanged upstream `adaptor_schnorr_preverify`; Adapt/Extract regression | The wrapper theorem remains conditional on correctness, unforgeability, adaptability, and extractability of the per-item construction |
| Batch verification | Three direction-separated, verifier-salted equations for server partial, client partial, and full pre-signature | native batch verifier test, three-salt audit, mutation and fallback rejection | Random-oracle fixed-candidate soundness only; deterministic item-wise checks diagnose aggregate failure |
| Multi-scalar evaluation | One RELIC `ec_mul_sim_lot` call per aggregate equation | measured MSM-call and term-count invariants | Performance implementation only; it does not change the acceptance relation |
| Concurrent sessions | Pair, execution, arc, epoch, parent/item SID, and ordered transcript separate state; worker dispatch is session-affine | cloud loopback, wrong-execution and replay rejection | No general concurrent-composition theorem is claimed for shared keys |
| Abort and retry | Any invalid parent aborts without `DONE`; a host retry uses a new execution ID, parent SID, and nonce vector | malformed opening/partial/final tests and lifecycle gate | No selective reuse from a failed native parent and no fair-exchange guarantee |
| Completion recovery | Gateway atomically persists `DONE(SID, completionDigest)`, acknowledges the exact durable record to the affined worker, and only then forwards it; authenticated client queries replay only an exact stored record | completion-journal unit test and dropped-DONE/gateway-restart regression | Improves acknowledgement availability; it does not guarantee simultaneous endpoint output |

## Exact claim boundary

The native artifact demonstrates that all five measured configurations use the
same ParaSwap-compatible per-item relation, key set, transcript inputs, curve,
transport authentication, and process model. The aggregate verifier changes
how valid equations are evaluated, not which equations are accepted.

The artifact does not implement every proof-system component of an arbitrary
generic two-party adaptor-signature transformation, does not prove adaptive
corruption security, and does not establish a universally composable wrapper.
Any manuscript theorem must therefore remain a conditional wrapper refinement
unless a separate reduction for this exact construction is supplied.
