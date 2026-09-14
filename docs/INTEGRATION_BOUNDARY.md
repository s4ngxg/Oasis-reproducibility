# Integration Boundary

## ParaSwap phase mapping

| ParaSwap phase | Implementation in this artifact | Evidence level |
|---|---|---|
| Preparation | Directed cycle, chain-labelled arcs, `n` joint-address slots and `n` delayed-release records per arc | Executable lifecycle model |
| Pre-swap | `n` Withdraw and `n-1` Re-lock items per arc, with native or conformance backend | Native cryptographic execution |
| Witness Sharing | One domain-separated witness per participant | Executable lifecycle model |
| Swap | Atomic withdraw after complete witnesses, or `n-1` timed Re-lock transitions | Deterministic ledger adapter |
| Refund | Refund of every remaining locked arc after `t+n*Delta`, where `t=Delta+3*epsilon` | Deterministic ledger/VTD adapters |

JSON reports state that the ledger is not a public testnet. The coordinator does
not describe an adapter transition as an on-chain receipt.

## Shared workload and export contract

For a cycle of `n` participants, the coordinator creates `n` directed arcs.
Each arc has `n` Withdraw items and `n-1` Re-lock items, giving exactly
`k=2n-1` pre-signatures per pair and `n(2n-1)` overall.

Both cryptographic backends return the same `ArcPreSwapResult` contract. The
honest wrapper exports only if all `n` arc vectors are complete. A failed
Pre-swap vector triggers refund without entering Witness Sharing. An incomplete
Witness Sharing phase performs the Re-lock chain before refund.

## Integrated native benchmark backend

All five configurations run in the same C binaries with the same curve,
Bob/Tumbler fixture master keys, deterministic per-item key derivation,
canonical transcript, joint Schnorr adaptor equations, ZeroMQ transport,
process model, and compiler build. Each item exposes both nonce points so the
public linear equations can be checked either individually or with RELIC's
native multi-scalar multiplication API. The combined pre-signature uses
ParaSwap's `s=r-e*x` convention and is accepted by the published
`adaptor_schnorr_preverify` implementation under the derived joint public key.

The native configurations are:

1. `reference-itemwise`: reference per-item sessions and verification;
2. `phase-coalesced-itemwise`: independent item sessions coalesced by phase;
3. `batch-joint-presigning-itemwise`: one parent session with item-wise checks;
4. `phase-coalesced-batch-verification`: independent item sessions with
   randomized batch verification;
5. `batch-joint-presigning-batch-verification`: one parent session with
   randomized batch verification using multi-scalar multiplication.

Verifier coefficients bind canonical length-prefixed encodings, a direction
tag, parent/item SID, ordered-batch and item digests, both nonce points,
statement, all three public keys, challenge, and server/client/full scalars.
The initiator samples a salt after receiving `SERVER_OPEN`. After
`CLIENT_FINAL`, the responder independently samples salts for the client-
partial and full-pre-signature equations and publishes both in a session-bound
`FINAL_STATUS`. `DONE(parentSID,completionDigest)` identifies exactly one
completed parent batch. A failed aggregate is checked item by item for
diagnosis, then the complete native parent session aborts; retry requires a new
parent SID and no partial vector is exported by an honest wrapper.

Each item digest binds its Withdraw/Re-lock type, ordinal, address index,
timeout, message digest, adaptor statement, client key, server key, and joint
key. The context binds protocol, participant count, epoch, expiry, pair,
execution, arc index, and the host Preparation seed. Phase-coalesced modes also
carry item SIDs; BJP modes use one parent SID. The host Preparation seed is
mode-independent within a paired trial and determines the same transaction
messages and adaptor statements. Every mode receives a distinct execution ID
so it cannot reuse another mode's SID or replay state. Each role's fixture master key is
domain-separated by participant pair, item ordinal, and batch cardinality; the
derivation is fixed across configurations and is not production wallet
provisioning.

## Secondary OpenSSL/mTLS conformance backend

The secondary OASIS backend instantiates ParaSwap's repeated two-party Pre-swap interface
with linear Schnorr adaptor signatures. For each item it binds the transaction
digest, statement, client key, server key, joint key, arc, epoch, expiry, and
parent batch context through the pinned canonical encoding.

Each arc runs an initiator and responder as separate native processes over TCP
loopback. Mutual TLS 1.3 authenticates both endpoints. A canonical SHA-256
Preparation digest binds the swap identifier, ordered chain-labelled arcs,
joint-address slots, VTD purposes/deadlines, epoch, `Delta`, `epsilon`, and final
refund time into the OASIS context. The honest coordinator independently checks
this digest, item cardinality, statement mapping, TLS completion, and terminal
`DONE` before export.

The live transport creates random client/server master shares and derives
role/item/arc-separated address shares. Public adaptor statements use the
artifact-defined, domain-separated SHA-256 try-and-increment map over
secp256k1, so the Pre-swap peers are not given their discrete logarithms. The
variable-time map is used only for public benchmark inputs. A separate
deterministic conformance fixture
constructs known witnesses solely to test Adapt/Extract compatibility; those
fixture derivations are not wallet key-generation logic.

The complete configuration uses:

1. one parent BJP session for the ordered item vector;
2. commit-before-open server nonces;
3. separate server-partial, client-partial, and full-pre-signature equations;
4. fresh verifier salts and transcript-derived nonzero coefficients;
5. one Pippenger MSM evaluation per aggregate equation;
6. item-wise localization and session-separated retry on failure in the
   conformance/lifecycle path;
7. live item-wise fallback/localization and an independent Adapt/Extract
   conformance check for every workload item.

This secondary backend retains its pinned core's conformance-only `k>=8`
Pippenger activation threshold. The primary native C11/RELIC backend has no such
threshold and invokes native MSM in every aggregate-verification configuration.
Pippenger processes only public verification inputs; it is not used for
secret-scalar operations. Across `Q`
fresh-salted aggregate checks, the artifact states the cumulative false-accept
bound as `min(1,Q*2^-254)`. Reused salts and non-canonical transcripts are
outside that bound and are rejected by the protocol assumptions/tests.

## Lifecycle conformance boundary

Included:

- all five ParaSwap artifact phases;
- exact Pre-swap workload shape;
- BJP, batch verification, and native MSM in one benchmark backend;
- all-or-nothing honest-wrapper export;
- happy path, transcript retry, witness failure, Re-lock, and refund;
- native responder-side rejection and whole-session abort for malformed
  initiator partials, plus localization/retry in the separate conformance
  harness;
- local monotonic Pre-swap export cutoff; mutual TLS is exercised separately by
  the secondary transport backend;
- a common 2x2 ablation that isolates coordination and verifier effects;
- a phase-coalesced independent-session baseline that isolates generic gather
  writes from the BJP session contract.

Not included:

- chain-specific transaction serialization and RPC submission;
- funded public-testnet execution and confirmation/reorganization monitoring;
- production wallet, HSM, or pair-specific key provisioning;
- a formal proof that every host-lifecycle adapter detail refines the public
  chain implementation; executable transcript, verifier, and lifecycle
  compatibility tests are included instead.

The appropriate claim is “artifact-compatible five-phase lifecycle conformance
and a same-backend ablation of Batch Joint Pre-signing plus randomized batch
verification,” not “unchanged upstream end-to-end execution” or “full
public-chain deployment.”
