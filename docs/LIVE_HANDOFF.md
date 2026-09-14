# Live native pre-signature handoff

## Implemented boundary

This gate uses the actual preswap_client/preswap_server exchange for all five
configurations. It is not a second signing pass or an OpenSSL substitute.
The client retains the successful session after verified DONE, stops its
Pre-swap wall/CPU interval, and hands off the ordered vector through an inherited
Linux memfd. Native Adapt/Extract consumes exactly those signature responses.

The handoff contains context digest, parent SID, ordered-batch digest and, for
each item, the host transaction digest, canonical item digest, adaptor statement,
joint public key, challenge and pre-signature scalar. The transaction digest is
the message consumed by the ParaSwap adaptor verifier; the item digest binds the
surrounding protocol transcript. It contains no private signing key or nonce scalar.
It is an internal trusted-host interface, not a remote import or authentication
protocol. The host must not accept arbitrary user-supplied handoff buffers as
authenticated protocol outputs.

host_cycle_tool creates synthetic witness fixtures using the native RNG. For
withdrawals it implements the global-witness plus cyclic identifier-prefix
relations from the paper's Eq. 10/11. Re-lock witnesses are separate random
scalars. Only public points are passed to the signing peers. Witness-bearing
descriptors are inherited only by the host helper. Core dumps are disabled by
the runner; no secret fields are serialized into result JSON. This is not HSM
custody and does not claim to control OS swap or privileged memory inspection.

When host statements are supplied, Withdraw and Re-lock at the same source
address use the same derived key. Without --host-statements the historical
synthetic workload is unchanged. Do not combine the two types in a dataset.

The helper validates each pre-signature with the unchanged upstream verifier,
computes s_final = s_pre + witness modulo the curve order, verifies the final
Schnorr relation, and checks that extraction recovers the statement's witness.
The Adapt/Extract wrapper is new integration code, not an unchanged AE API.

## Host signing-key provisioning

The current correctness runner uses independent random address shares:
`--host-address-keys-fd` carries the owning endpoint's private `OASISA01`
vector; `--host-client-keys-fd` and `--host-server-keys-fd` carry sealed
`OASISAP1` public vectors with per-address ownership proofs. Generation uses
the actual session preparation digest, pair ID, role and epoch (the runner
fixes epoch to 1). The native signer verifies that its private share matches
the selected public key. Withdraw and Re-lock at the same address reuse that
address share, not a new share or a public-tweak derivative.

Standalone client/server admit these vectors before their measured Pre-swap
interval, retain owned in-memory key copies and check count/pair/epoch/context
on use. Signing does not reverify the proof vector per item. Admission cost is
in setup, and must remain in any full-lifecycle accounting. The current
admission loader may revalidate a vector while copying its entries, so setup
cost is not yet optimized. Independent-address mode is rejected for pool workers
until per-job key admission and custody are implemented; it must not silently
reuse one job's keys for another.

Below, the older single-base-key option remains documented for historical
fixtures; it is not the independent-address runner's signing-key mode.

`--host-key-fd` accepts `OASISK01` followed by a canonical nonzero 32-byte
big-endian secp256k1 scalar. The descriptor must be an `oasis-` Linux memfd
sealed against writes, growth and shrinking. `--host-peer-key` is required
together with this option and supplies a one-point `OASISP01` public vector.
Both endpoints still verify the existing context-bound key-ownership proofs.
No endpoint receives the other endpoint's private-key descriptor.

The local runner provisions fresh base keys for each pair execution. Native
key derivation still maps a base key to per-address keys. This derivation is
NOT suitable for a lifecycle that reveals one address share through VTD:
`x_level = x_base + public_tweak (mod q)` reveals the base by subtraction.
Committing the derived final share alone does not fix this. Full lifecycle
requires independently generated per-address recipient shares and matching
public-key vectors, with reuse only for Withdraw/Re-lock at the same address.
The host-key option overrides the signing keys after loading auxiliary AE
fixture parameters. It does not yet remove all fixture-loading dependencies.
Sealed secret descriptors are closed rather than truncated; this is memory-only
custody, not a secure-erasure guarantee for the kernel or the Python allocator.

The current v2 report uses `host_postprocess_ns` for the combined Adapt/Extract
and ledger checks. The ledger consumes live adapted signatures in separate
withdrawal and successive-relock paths. That ordinary gate does not recover a
refund key. The separate ordered VTD gate described below additionally connects
recovery to a signed refund consumed by the timed ledger adapter.

## Ordered final-address recovery gate

The handoff runner first invokes native `prepare-registry` with the admitted
independent key bundles and host statements. It uses `bench_transcript_init`,
the same canonical constructor as the live peers, before starting the VTD or
Pre-swap branch. `OASISRG2 || count_u32_be || context[32] || parent_sid[32] ||
batch_digest[32]` is followed by `count` records of transaction digest[32], item
digest[32], statement[33] and joint key[33]. The completed `OASISH02` handoff
extends each record with challenge[32] and pre-signature scalar[32]. This
public-only registry format contains no signature slots.
After native peer completion, every public handoff field must match this
pre-signing registry or the host clears and rejects the output before ledger
consumption. Equality does not replace native signature verification or
distributed validation of transaction semantics. The all-VTD single-arc gate
uses this registry for signed lock admission before starting Pre-swap.

`python3 scripts/test_live_vtd_key_binding.py` prepares and verifies a fresh
final-address VTD before starting the native Pre-swap. ForceOp starts at
Pre-swap entry. Its recovered scalar, rather than the prover's retained secret,
is used to sign the fixture refund digest. The digest is
SHA256(`OASIS-FIXTURE-REFUND-v1` without a NUL byte || completed handoff header).
It is a synthetic ledger identifier, not a serialized blockchain transaction.

The signer exports `OASISR01 || digest[32] || e[32] || s[32]` through a distinct
anonymous memory descriptor after the composition checks succeed. Scalars use
canonical big-endian encoding. The consumer checks the digest and signature,
rejects refund before the deadline, accepts it at the deadline and rejects a
repeat. A mutated signature must fail. The ledger clock is a controlled fixture.
In the default final-address gate, re-lock witnesses still come from the
preparation fixture, not n-1 VTD solvers.
This is one arc with centralized test custody, not a full distributed lifecycle.

The ordered gate now starts `vtd_public_solver` in a separate process. Only
sealed metadata/setup/proof descriptors and an empty anonymous result descriptor
are inherited through `pass_fds`; no prover private-key vectors are passed.
The host seals the solver result before the refund signer imports it, checks its
public point, and consumes that scalar without a fallback local ForceOp.
`external_solver_check.squarings` reports solver work; the composition helper's
own `squarings` is zero in this mode. The solver currently supports 256 shares,
128 proof rows and a one-million-squaring per-puzzle correctness-test cap.
These limits are not time calibration or setup-provenance validation. Setup
generation and proving still share the fixture process. The standalone rejection
test covers nine malformed/unsealed-input cases with no scalar export.

### All VTDs of one arc

`python3 scripts/test_live_vtd_key_binding.py --all-vtds` composes the two
re-lock VTDs and final-key VTD for n=3 around a single live Pre-swap execution.
It prepares and verifies every public proof before starting any solver or
Pre-swap. Each solver receives only its public inputs. The recovered delayed
values replace the fixture values before the native signed re-lock/refund
ledger checks; mutated re-lock values must be rejected. Preparation or recovery
failure aborts the gate and cleans up its child processes.

The all-VTD runner now zeroes the first withdrawal witness after Pre-swap and
uses `receive_live_witness` to reconstruct it through the authenticated native
transport gate before ledger consumption. `--mode` selects the same native
reference or improved path without changing host orchestration. This does not
yet implement the malicious withheld-witness recovery path across arcs.

After all proofs are prepared, a native `funded-check` process verifies the
fixture wallet's signed lock and acknowledges `LOCK_ACCEPTED`. Only then does
the runner start solvers and Pre-swap. That process retains its funded ledgers,
checks the actual handoff against the registry, and consumes adapted signatures
and the recovered refund receipt. Two ledger instances test alternative
withdrawal and re-lock/refund paths, not two spends of one asset. The gate
reports `lock_ack_before_preswap` and `funded_ledger_check` separately from
additional isolated-ledger mutation tests.

This is still a single-arc correctness test with centralized preparation,
32 squarings per VTD and a controlled ledger clock. It does not establish
calibrated recovery deadlines, distributed witness sharing,
all-party custody or full-lifecycle performance. The fast
`test_all_vtd_ordering.py` uses mocked cryptographic jobs to check orchestration
ordering and failure cleanup; it does not replace the live cryptographic gate.

## Running the local correctness gate

`python3 scripts/test_live_witness_handoff.py` runs all five modes for each of
the three arcs at n=3. The first withdrawal witness starts at zero. A native
CURVE/ZAP loopback gate receives the actual preparation witnesses, derives
the global witness plus the recipient's identifier, checks against the live
adaptor statement and pre-signature, and writes only the resulting withdrawal
witness into anonymous output. The ledger then consumes the adapted signature.
Wrong-recipient composition must reject with the output unchanged. This tests
authenticated delivery and actual signature composition, not distributed key
custody: all senders are in one native fixture process, and public witness
points are derived from the trusted centralized preparation fixture. This gate
is also invoked by the all-VTD single-arc runner.

`--host-export-deadline-ns` is a trusted absolute local `CLOCK_MONOTONIC`
cutoff, not a remote clock value. The native writer checks before and after
export and truncates a late buffer; the host must wait for writer completion
and recheck its own cutoff before consumption. This prevents late honest
wrapper admission, not malicious local retention or asymmetric peer output.
The correctness runner uses a 60-second test guard, not a calibrated ParaSwap
timeout. Production lifecycle must derive the cutoff from validated host policy.

    make native-build
    python3 scripts/run_native_handoff.py --participants 3 --negative-tests \
      --output results/native-handoff-check.json

Use a fresh output path; existing reports are not overwritten. This runs local
IPC only. All five modes share the same public preparation fixture. Negative
checks cover invalid witnesses, tampered pre-signatures, rejected client partials
with no host export, and refusal to write to a disk descriptor. The separate
public-vector test covers malformed, truncated and mismatched points.

## What this does not establish

`test_live_cross_arc_recovery.py` exercises Eq. 16/17 for every observer and
source level, using actual native handoffs. The outgoing ledger first accepts
the source withdrawal and stores its signature. Recovery calls the ledger's
Extract API, adds only the observer's identifier, performs incoming re-locks
and withdraws at the next level. The incoming withdrawal-witness slots are
zeroed, and the recovery code never reads them. It does not require a complete
set of y_i receipts. Wrong-identifier inputs must fail.

This cross-arc gate uses isolated pre-funded ledgers and fixture delayed
witnesses; it is not the retained funded all-VTD host. The controller selects
adjacent arcs from one trusted Preparation. Native point/signature checks do
not replace authenticated host topology admission or a real ledger event feed.
There is no distributed withholding schedule, actual chain or full-lifecycle
performance claim from this gate.

The native ledger exposes `host_ledger_create_unfunded` and
`host_ledger_lock_at` for signed funding. Funding is authorized by a
canonical Schnorr signature over SHA256(`OASIS-FIXTURE-LOCK-v1` without NUL ||
context[32] || compressed owner[33] || compressed destination[33] || amount[32]).
The amount is unsigned big-endian and nonzero. The immutable context must be
supplied by the validated host and identify the swap/arc. This is not a chain
transaction or evidence that the wallet has a real balance. The ordinary live
handoff checker still uses pre-funded fixture constructors. The standalone
ledger test covers signed lock admission; the all-VTD single-arc runner also
checks lock-before-Pre-swap ordering. Neither establishes the multi-party host.

- Distributed Witness Sharing or selective disclosure to actual participants.
- All n arcs with calibrated VTD timing and separate participant custody.
- Full-cycle timing, public-chain transactions or atomicity. The native ledger
  checks signatures and transitions but is not an actual chain implementation.
- Equivalence of the new native reference protocol to unchanged upstream TPC.
- A cryptographic security proof for the concrete construction.

The AE VTD source is a standalone timing program. Its library exports puzzle
generation and solving, not the full statement-linked VTD verification contract.
Source vtd.c also converts binary secret shares with mpz_init_set_str(..., 10)
and performs its proof-like checks within one process. An adapter must not treat
successful puzzle solving or those timing prints as a complete public proof.
This gate therefore explicitly reports full_lifecycle=false and
vtd_integrated=false. No new cloud or full-lifecycle measurement is claimed.
# Retained-ledger recovery interface

`run_retained_arc_coordinator.py --recover-cycle` selects one retained ledger
per arc in a single native process, instead of alternative per-arc branches.
All withdrawal and delayed witness slots are zeroed after VTD Preparation.
Only arc zero receives a witness-sharing result; subsequent withdrawal values
must come from accepted-signature extraction and local identifiers. Delayed
slots are filled exclusively from public-input solver results before consuming
the cycle. The BJP/MSM solver-fed run passed with three withdrawn arcs and two
recovery hops; see `results/solver-fed-cycle-validation.md`. The native CLI is
`funded-cycle-recovery COUNT` followed by five FDs
per arc: registry, wallet, handoff, witness, sender identifier. The reference
baseline also passed the solver-fed path; these are individual correctness
runs, not paired performance evidence. The faster native cycle gate passed
ten cases across five modes using delayed fixture values.

`test_funded_cross_arc_recovery.py` exercises native `funded-recovery`. Its FD
order is incoming/outgoing registry, incoming/outgoing wallet,
incoming/outgoing handoff, incoming/outgoing witness, and local identifier.
Registries, wallets, witnesses and identifier are sealed anonymous inputs.
Handoffs start empty and are sealed after live Pre-swap, before the `C` command.
The native process acknowledges `LOCK_ACCEPTED` only after both signed locks,
retains both ledgers, and binds handoffs back to those immutable registries.
Twenty local cases passed across five modes. This gate uses delayed witness
fixtures; it is not yet the solver-fed full coordinator.

`python3 scripts/run_retained_arc_coordinator.py --mode MODE` prepares all three
arc registries and nine VTDs before funding, retains each native funded ledger
process across Pre-swap, then consumes authenticated witness-sharing and solver
outputs. The mode is one of the five native modes. This slow local gate uses
centralized participant fixtures and alternative per-arc ledger branches; it
does not yet exercise cross-arc withholding in a shared ledger coordinator.
`test_retained_arc_ordering.py` checks its global ordering with mocks, not
cryptographic correctness. The slow gate is excluded from the smoke suite.

The Python `prepared_pair` context retains admitted independent address keys,
ownership bundles and the canonical registry without starting Pre-swap. The
cross-arc runner enters every arc context before executing its first pair;
`run_pair` remains the single-pair convenience wrapper. This separates registry
admission from network execution, but does not itself perform VTD preparation
or funding. Borrowed descriptors must not escape the context lifetime.

`host_recover_into` consumes two existing ledger instances. It requires an
accepted outgoing withdrawal and an incoming locked address at the next level,
extracts the observed witness, combines the local identifier, and submits the
adapted incoming signature to the same incoming ledger. It neither creates nor
resets a ledger. Adjacency and Preparation admission remain host obligations.
The cross-arc fixture exercises this interface, including corrupted destination
signature rejection without state advancement and repeated recovery rejection.
The fixture still creates its ledgers pre-funded; this interface alone is not
the complete multi-party funded lifecycle coordinator.
