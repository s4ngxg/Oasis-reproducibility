# Official ParaSwap Artifact Integration

## Upstream identity

The integration vendors the ParaSwap USENIX Security 2025 reproducibility
artifact identified by DOI `10.5281/zenodo.15594022` and source commit
`e817a33cf8d1efa54cc06d41927f82b0f3e4f4d2`. The cryptographic source files
used by the adapter are protected by `vendor/paraswap-artifact.lock.json`.

Run the provenance check with:

```bash
python3 scripts/verify_upstream.py
```

## Upstream entry points and equation compatibility

The integration does not modify ParaSwap's cryptographic implementations in
`bob.c` or `tumbler.c`, their public headers, or the Bob/Tumbler fixture bytes.
It makes a narrowly scoped path-resolution change in `util.c` so those same
fixture bytes can be loaded from either the source-tree or binary working
directory. The native adapter reuses the upstream key types and pinned
Bob/Tumbler fixtures. All
five measured configurations execute one joint two-party Schnorr adaptor
equation with ParaSwap's negative-sign convention,
`s_i=r_i-e*x_i`, `s_j=r_j-e*x_j`, and `s=s_i+s_j`. The standalone regression
test constructs the resulting `(e,s)` and checks every item with the published
`adaptor_schnorr_preverify` function and joint public key. This is an executable
compatibility check for the actual candidate exported by the adapter.

The published fixture provides one Bob/Tumbler master-key pair. The benchmark
adapter deterministically derives a distinct client and responder key for each
role, participant pair, ordinal, and item count. Secret and public derivations
are regression-tested for equality, and every compared configuration uses the
same derived key set. This supplies a genuine multi-key verification workload;
it is not a production wallet-key derivation scheme.

## Added native files

| File | Responsibility |
|---|---|
| `include/preswap_protocol.h` | Canonical native frame, mode, metric, and verifier interfaces |
| `src/preswap_client_v4.c` | Initiator state machine, commitment-opening checks, server-partial verification, and honest-wrapper completion gate |
| `src/preswap_server_v4.c` | Responder state machine, client/full-vector verification, failure localization, and session-bound completion |
| `src/preswap_gateway.c` | One-port CURVE admission, bounded worker dispatch, durable completion persistence, and authenticated acknowledgement replay |
| `src/preswap_common.c` | Fixed-width encoding, frame parsing, mode selection, and result accounting |
| `src/preswap_joint.c` | Canonical transcript, Preparation-bound key-ownership proofs, joint partials, Pedersen commitments, verifier salts, and RELIC multi-scalar multiplication |
| `src/completion_journal.c` | Atomic, idempotent, SID- and digest-bound completion records |
| `src/joint_presign_test.c` | Canonical known-answer vectors, key/joint-key rejection, upstream verifier compatibility, aggregate equations, and mutation rejection |
| `src/completion_journal_test.c` | Durable completion, duplicate-write, mismatch, and conflicting-write rejection |
| `src/batch_verifier.c`, `src/batch_verifier_test.c` | Independent legacy/plain adaptor-verifier regression coverage; not used by measured v4 client/server paths |

The root `CMakeLists.txt` is adapted only for repository-local dependency paths
and runtime search paths. `src/CMakeLists.txt` retains the reference targets and
adds separately named adapter, gateway, profiling, and test targets against the
same RELIC, PARI, GMP, and ZeroMQ dependencies. The lock manifest records both
the pristine and integrated SHA-256 digests and a purpose for these two build
files and `util.c`; all entries under `upstream_files` must remain byte-identical
to the pinned artifact.

## Lifecycle integration

`src/paraswap_lifecycle.py` is the host coordinator. It constructs the directed
ParaSwap cycle and drives Preparation, Pre-swap, Witness Sharing, Swap/Re-lock,
and Refund. For `n` participants it requires `n` Withdraw and `n-1` Re-lock
pre-signatures on each of `n` arcs. The honest wrapper exports no Pre-swap
vector until all `n(2n-1)` items are complete.

The ledger and verifiable-timed-discrete-log components are deterministic
adapters. They exercise lifecycle state transitions and timeout paths but do
not submit transactions to a public blockchain. Therefore the supported claim
is artifact-compatible five-phase lifecycle conformance, not unchanged upstream
end-to-end execution or funded testnet deployment.

## Verification procedure

```bash
make bootstrap
make test
```

The test command verifies upstream hashes, builds the native adapter, runs the
reference and four-cell ablation configurations, checks all three randomized
batch equations and native multi-scalar multiplication, rejects mutated client
partials, verifies CURVE/ZAP peer authentication, validates the cloud schema
and profiling pipeline on loopback, and tests the outer Re-lock/refund paths.
