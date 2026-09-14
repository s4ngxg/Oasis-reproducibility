# Correctness and cloud-readiness audit

## Verdict

The native ParaSwap Pre-swap campaign is ready for a controlled two-host cloud
run. The exact client/server path has been exercised over TCP and accepted by
the paired-result analyzer. This verdict applies to the source tree containing
this file, not to historical binaries or result archives.

The primary native transport is mutually authenticated ZeroMQ CURVE over TCP.
The initiator pins the responder public key, and the responder's ZeroMQ
Authentication Protocol (ZAP) handler authorizes one initiator public key.
Source-IP-restricted Security Groups remain defense in depth. Mutual TLS belongs
to the separate conformance transport and is not claimed for native timing.

## Version-2 delta audit

The version-2 changes were reviewed against the preceding
`paraswap-oasis-official-integration` tree before cloud deployment. The
cryptographic equations, item transcript derivation, five configurations, host
export gate, and lifecycle adapters remain unchanged except where the gateway
interface requires explicit frame-size and session-routing validation. The
measured wire protocol now also carries Preparation-bound key-ownership proofs
in its first request and response frames. The following implementation defects
were found and corrected:

1. Long-lived worker processes originally wrote results to an unread
   `subprocess.PIPE`. A high-load stage could fill the pipe before process exit
   and deadlock the runner. Worker output is now spooled to temporary files and
   consumed after `wait()`. A `p=128`, one-worker regression requires all 128
   sessions to complete, observes queueing, and permits no rejection.
2. A malformed public frame originally terminated the shared gateway and all
   unrelated sessions. Public parse, identity, protocol, and initial-frame
   violations are now isolated to the offending input. Internal worker-channel
   violations remain fatal. The gateway also enforces the exact plaintext
   `BATCH_INIT` layout and a CURVE/ZMTP-aware maximum transport-frame size.
3. The original transcript KAT had been generated with an untracked local
   RELIC build. Even at the pinned commit, RELIC's configured `ec_map` path
   produced different synthetic adaptor points across build environments. The
   artifact now verifies the actual RELIC Git commit before every measured
   campaign and derives public synthetic points with an artifact-defined,
   domain-separated SHA-256 try-and-increment map over secp256k1. Local,
   Virginia, Frankfurt, and Singapore builds produce the same statement bytes,
   item digests, ordered-batch digest, and parent SID. The map handles only
   public inputs and does not reveal the mapped point's discrete logarithm.
4. Preparation key-ownership proofs were previously exercised only by a unit
   test. The native initiator and responder now generate them before the timed
   interval, piggyback them on the first `BATCH_INIT` and `SERVER_COMMIT`, and
   verify the peer proof in the measured receive path. A wire-level mutation
   regression requires rejection without adding a logical round.
5. The provenance manifest previously classified three adapted upstream files
   as byte-identical. It now records separate pristine and integrated SHA-256
   digests for the root and source CMake files and `util.c`, with the exact
   adaptation purpose; the remaining upstream files are still checked for byte
   identity.

After these corrections, `make smoke` passes in the bootstrapped working tree.
A fresh Ubuntu extraction uses the single `make reproduce-smoke` entry point to
install the pinned dependency and execute the same gate. The checks include the
full Python unit suite, all native cryptographic and protocol tests, CURVE/ZAP
authentication and rejection, bounded queue and worker-reuse regressions,
differential tests, and five-phase lifecycle assertions.

## Paper and review alignment

The complete measured method preserves the three mechanisms proposed in the
earlier manuscript: one transcript-bound Batch Joint Pre-signing envelope,
fresh-salted randomized verification of all three joint Schnorr equations, and
RELIC multi-scalar multiplication. The five native configurations implement
the review's causal design:

| Configuration | Session organization | Verification |
|---|---|---|
| `phase-coalesced-itemwise` | Independent item sessions | Item-wise |
| `phase-coalesced-batch-verification` | Independent item sessions | Randomized batch/MSM |
| `batch-joint-presigning-itemwise` | Shared BJP parent | Item-wise |
| `batch-joint-presigning-batch-verification` | Shared BJP parent | Randomized batch/MSM |
| `reference-itemwise` | Independent item sessions, separately framed by item | Item-wise |

The first four rows are the required 2x2 ablation. The fifth row isolates
generic same-phase frame coalescing. All rows run the same added native adapter,
curve, derived keys, transaction workload, dependencies, and process model.
Within a paired trial the transaction-message digests, adaptor statements, and
keys are fixed; each mode receives a distinct execution ID so its transcript,
SID, and replay state remain disjoint.

The public topology is one authenticated ROUTER service port. Every concurrent
participant-pair session uses a distinct DEALER connection to that port and is
routed through a bounded admission queue to one member of a fixed,
process-isolated RELIC worker pool. Parameter `p` is concurrent pair load, not
a public-port or worker count. This preserves the single service endpoint while
allowing gateway, queue, and worker-pool costs to be measured explicitly.

The adapter is built inside a hash-verified ParaSwap artifact and every combined
candidate passes the unchanged upstream verifier. The deterministic ledger/VTD
harness establishes five-phase lifecycle conformance; it is not unchanged
upstream Bob/Tumbler execution or a funded public-testnet integration.

Only raw schema `oasis-preswap-cloud-v8` and analysis schema
`oasis-preswap-cloud-analysis-v5` may support final timing claims. Earlier
evidence predates durable completion recovery, Preparation-bound key-ownership
tests, explicit placement and randomization metadata, complete statistics, or
paired-workload checks and is historical only.

## Correctness evidence

- ParaSwap's unchanged cryptographic source, headers, and fixture keys are
  pinned by SHA-256 to commit
  `e817a33cf8d1efa54cc06d41927f82b0f3e4f4d2`; three build/path adaptations have
  separately recorded pristine and integrated hashes.
- Combined joint pre-signatures pass the published ParaSwap adaptor verifier;
  fixed known-answer transcript vectors and Adapt/Extract regressions are
  checked separately.
- Batch verification uses distinct per-item public keys and one native RELIC
  multi-scalar multiplication per aggregate equation.
- Coefficients bind the verifier salt, equation domain, parent/item SID,
  ordered-batch and item digests, both nonces, statement, all three public
  keys, challenge, and server/client/full scalars.
- Mutation tests reject changed scalars, public keys, and messages.
- The native full method performs three aggregate checks per arc with
  `6k+3` total MSM terms: one server-partial check at the initiator and the
  client-partial plus full-pre-signature checks at the responder.
- The honest lifecycle wrapper exports only a complete `n(2n-1)` vector before
  its local deadline; fault tests cover invalid final values, peer abort,
  witness failure, Re-lock, and refund.

`make test` passes the full Python suite, the native reference/multi-key batch test,
32 differential vectors, CURVE/ZAP acceptance and rejection, mutual-TLS
rejection, replay-cache pressure, all five same-backend configurations,
retry/fault paths, and lifecycle assertions.

## Cloud-path evidence

A loopback two-role regression campaign runs the same cloud runner and
CURVE/ZAP TCP binaries at `n=3`, `k=5`, and `p=4`. Four DEALER connections use
one public ROUTER port and are routed through a two-worker fixed pool. The test
requires all four assignments, observes queue use, caps active responder
processes at gateway plus two workers, and permits no rejection.
The analyzer accepts all
five paired configurations, finds zero verifier fallbacks, validates all three
direction-separated salts and batch digests, matches every pair and execution
ID, and confirms the same protocol-source and public-key fingerprints on both
roles. The rejection test also proves that an unlisted initiator key, a wrong
responder key, and missing credentials cannot complete.

The analyzer now rejects:

- missing or duplicate `(n, p, configuration, trial)` samples;
- client/server campaign, runtime, source, or provenance mismatches;
- invalid `k=2n-1`, arc IDs, execution IDs, or frame counts;
- missing/extra native MSM calls or any verifier fallback;
- unauthenticated, profiler-contaminated, or fingerprint-mismatched timing data.

The fixed final-evidence launcher runs every sequential profile through the same
service port `9000` and accepts an explicit `BASE_PORT` deployment override
without changing its workload. All
`p` pair connections share that port. At `p<=1024`, the runner enforces a
minimum soft file-descriptor limit of 2304.

## Evidence boundary

The cloud campaign measures native Pre-swap only. The five-phase lifecycle is
executed by the local artifact harness with deterministic ledger and VTD
adapters. No public blockchain RPC, funded testnet transaction, production
wallet key provisioning, or public-chain lifecycle is implemented. The current
native server is an event-driven gateway with bounded admission and a fixed
pool of long-lived cryptographic worker processes. Multi-day, second-VM-family,
and multi-cloud claims still require new runs.
These limitations must remain explicit in the paper.

Use `docs/CLOUD_DEPLOYMENT.md` for the final VM procedure. Only JSON accepted by
`scripts/analyze_cloud_results.py` should enter the paper.
