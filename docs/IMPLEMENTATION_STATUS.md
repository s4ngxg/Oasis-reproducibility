# Native integration revision status

## Current reading guide

The entries below are a chronological engineering log. Statements such as
"not connected", "unverified", or old unit-test counts describe the state at
that entry, not necessarily the current implementation. For branch evidence use
`FULL_CYCLE_COMPLETION_GATES.md`; for the funded early-abort limitation use
`EARLY_ABORT_PROTOCOL_DECISION.md`.

Latest local validation (2026-09-12): `make verify` and `make test` passed;
the default Python suite ran 199 tests, and the integration gate rebuilt the
native C/RELIC targets and passed the protocol, independent-oracle, differential
smoke, fault, CURVE/ZAP, mutual-TLS rejection, replay, loss, cloud-runner
loopback, and report-pipeline checks. The complete
`scripts/run_local_smoke.sh` previously passed after fixing stale VTD and
coordinator mocks, including native protocol modes, ledger checks, CURVE/ZAP,
lost-DONE replay, gateway restart and cloud-runner loopback. The separate
100,000-vector native differential campaign also passed for this revision:
100,000 valid checks and 100,000 mutation rejections were recorded for each of
the server-partial, client-partial, and full-pre-signature equations, together
with 300,000 subrange checks and 2,100,000 exact-localization checks. The report is
`results/native-differential-100000.json`; it used binary SHA-256
`8362081301ef6146e8ba47f4e69b990956d058e1f35e92f7c432e0b39a6a4aa1` and took
2,593.2504 seconds. It is local correctness evidence, not WAN or performance
evidence. Subsequent changes
move 21 orchestration tests into default discovery, harden funded-abort checks
against Python optimization, and reject invalid systems metrics at the final
report gate. The funded-abort script passed under
`python3 -O -B` for both modes, observing locked funds rather than refund.
This is not a new WAN campaign or a full-lifecycle security proof.

Recent changes relevant to new measurements:

- Completion journal compares the entire duplicate frame and re-syncs the
  directory before acknowledging an existing completion; error cleanup closes
  the temporary descriptor. Replay also re-syncs before sending DONE. Injected
  file/directory fsync failures and repeated retries reject without descriptor
  leaks in the native journal test.
- Snapshot decode rejects nonzero reserved bytes, inconsistent terminal levels,
  and withdrawn states without a valid stored withdrawal signature. The format
  still lacks authenticated freshness and does not implement durable recovery
  of the coordinator's secret-bearing state.
- CPU totals exclude guest counters already included in user/nice. Cgroup
  counters follow the runner's visible cgroup-v2 membership; missing/reset or
  changed-source intervals are unknown, not zero. Final-report validation
  rejects unavailable throttling evidence and nonfinite, negative or mistyped
  required systems metrics. Worker membership and ancestor
  limits still require deployment verification.
- Source archives use the current directory name, unique temporary files, and
  reject output inside the source tree. `SOURCE_DATE_EPOCH` (default 0) sets
  archive timestamps; repeated packaging with an explicit epoch passed a
  byte-for-byte comparison. This does not establish reproducible native builds.

The six successful local branch reports predate these maintenance changes.
Their original hashes must be retained. Rebuilt binaries may differ even when
the change affects only rejection of invalid inputs; do not present historical
reports as executions of the newly built revision.

Still outstanding: concrete construction proof, authenticated and fresh durable
host recovery, funded early-abort recovery, closest-comparator analysis, and
permanent publication of the exact release. The cloud records included with
this artifact are preserved measurement evidence; their scope and limitations
are defined in `results/cloud-evidence/README.md`.

This directory is the maintained reproducibility artifact. Earlier development
copies and their measurements are not silently merged into the included cloud
campaigns.

## Implemented in this revision

- Native `funded-cycle-recovery` retains exactly one funded ledger per arc and
  propagates accepted withdrawal extraction through the cycle. Ten local
  cases passed across five modes with only the first withdrawal witness
  supplied; corrupted delayed witnesses rejected. The nine-VTD coordinator
  now has `--recover-cycle`: it clears all witness slots after Preparation,
  receives the first withdrawal witness through authenticated delivery, and
  restores delayed slots only from solver outputs. Five mocked ordering tests
  pass. The solver-fed BJP/MSM run passed all three arcs and two recovery hops;
  see `results/solver-fed-cycle-validation.md`. The reference-itemwise baseline
  also passed this solver-fed cycle with identical script/binary hashes and
  timeout limits. These are correctness runs, not comparative performance
  measurements. Faster native cycle tests use delayed fixtures.
  This does not establish distributed custody
  or calibrated timed privacy.

- Native `funded-recovery` now admits signed locks for two arcs before waiting
  for live handoffs, checks both handoffs against immutable prepared registries,
  and runs recovery on the retained ledger instances. The local gate passed
  20 cases across five modes (two valid source levels, mutated handoff and wrong
  identifier rejection per mode). Incoming withdrawal witnesses were zeroed.
  Delayed witnesses remain fixtures in this gate, not VTD solver results; it is
  not yet connected to the nine-VTD coordinator. Funding helpers now share the
  registry/lock admission code and reject writable registries. Three admission
  tests pass. The earlier nine-VTD evidence predates this helper refactor.

- `run_retained_arc_coordinator.py` coordinates three admitted arc registries,
  prepares nine VTD jobs before funding, holds all funded native processes
  through Pre-swap, and feeds authenticated witness and public-solver outputs
  into their retained ledgers. Four mocked ordering/input tests pass, including
  proof failure before funding and partial funding failure before Pre-swap.
  The first full live attempt failed at Pre-swap. A rerun with explicit longer
  I/O limits passed all three arcs and nine VTDs in BJP/MSM mode; see
  `results/retained-coordinator-validation.md` and its JSON evidence. The
  baseline coordinator run remains unverified. This
  coordinator still uses centralized Preparation fixtures and alternative
  per-arc ledger paths. Retained cross-arc withholding recovery is not connected.

- `host_recover_into` exposes recovery over caller-owned retained ledger
  instances, with observed-withdrawal extraction and next-level checks. The
  live n=3 fixture passed 30 cases after this refactor, including corrupted
  destination-signature rejection without state advancement and repeated
  recovery rejection. The n=8 result below predates this API refactor.

- Native `host_check_recovery` now checks Eq. 16/17 with two live handoffs:
  accept an outgoing withdrawal, extract from that ledger's stored signature,
  add the observer's local identifier, and spend the next-level incoming
  withdrawal after the necessary re-locks. The n=3 gate passed 30 cases across
  all five modes; the n=8 gate also passed 280 cases. Incoming withdrawal
  witnesses were zeroed and wrong identifiers rejected in both runs. These
  are isolated controlled-ledger fixtures. Adjacent arc
  selection and Preparation admission remain caller responsibilities, and the
  recovery gate is not yet connected to the retained funded multi-party host.

- `test_live_witness_handoff.py` passed 15 vectors across five modes and all
  three arcs for n=3. The first withdrawal witness is initially zeroed; the
  native CURVE/ZAP gate reconstructs it from authenticated y_i deliveries plus
  the recipient's local identifier, validates the live pre-signature and Adapt,
  then the ledger checks the resulting withdrawal and Extract. Wrong-recipient
  composition rejects without modifying output. The senders remain in one
  native fixture process; this is not distributed participant custody. The
  all-VTD single-arc runner is now connected to this gate after Pre-swap and
  passed with authenticated witness composition, retained funded ledgers and
  recovered re-lock/refund values. Withheld-witness recovery now has a separate
  live cross-arc correctness gate, but still needs host integration; invalid
  delivery currently aborts this happy-path gate.

- The live runner now prepares a public registry using the native canonical
  transcript constructor before VTD/Pre-swap, and compares all public handoff
  fields before ledger consumption. Registry mismatch clears the output.
  The n=3 campaign passed all 15 vectors across five modes with
  `prepared_registry_matches_handoff=true`. Four registry regression tests
  passed. The n=16 campaign (`results/prepared-registry-handoff-n16.json`)
  also passed 80 vectors / 2,480 items with every registry match true. The tests
  cover changed fields and malformed lengths/counts; they explicitly do not
  claim signature verification. The all-VTD single-arc gate now uses this
  registry for signed lock admission before solvers and Pre-swap.

- The native ledger now has an explicit unfunded constructor and signature-
  checked lock admission. Its synthetic lock digest binds the admitted context,
  owner, initial joint address and nonzero 256-bit amount. The native ledger
  test passes wrong-key/context/destination/amount, pre-funding spend, early/late
  lock and duplicate-lock rejection, followed by a valid withdrawal. This
  constructor is connected to the all-VTD single-arc gate, which passed with
  `lock_ack_before_preswap=true`, `retained_funded_ledger=true` and a live refund.
  The native process retains the funded ledger across Pre-swap. Two instances
  represent alternative withdrawal versus re-lock/refund paths, not duplicate
  spends. This is not yet the multi-party host; legacy fixture paths still
  start locked.

- The live handoff consumer now uses a timed host-local ledger adapter.
  It rejects early re-locks, untimed API bypasses and repeated spends while
  validating actual adapted signatures. `results/timed-ledger-live-n3.json`
  records 15 vectors / 75 items across five modes. Its controlled fixture
  clock is not elapsed VTD time or blockchain consensus. The separate native
  ledger test checks signed refund at the deadline. The separate ordered gate
  `scripts/test_live_vtd_key_binding.py` now passes recovery-to-ledger refund:
  fresh final-address VTD, live Pre-swap, ForceOp, refund signature through an
  anonymous descriptor, timed ledger consumption and mutated-signature rejection.
  The selected-level re-lock gate (`--relock-level 0`) also passed with a fresh
  VTD, an external public-input solver, live Pre-swap statement binding and
  timed ledger consumption of the recovered witness. A mutated recovered
  witness is rejected. The new `--all-vtds` gate also passed for n=3: both
  re-lock VTDs and the refund VTD were prepared before a single Pre-swap,
  independently recovered and consumed in signed timed-ledger checks. Both
  mutated re-lock witnesses were rejected. All-party integration is unfinished.
  This uses 32 solver squarings for correctness, not calibrated
  timed privacy or performance evidence.
  Full lifecycle remains false.
- Admission verifies each endpoint's complete public ownership bundle once,
  caches the admitted points, and matches local private shares to those points.
  Private-vector parsing now occurs once per admission too, with full-vector
  canonical/duplicate validation before copying shares into owned staging.
  Every private share is matched against its admitted public key. The n=16 handoff
  campaign `results/address-admission-once-n16.json` contains 80 vectors;
  this is a correctness campaign, not full-lifecycle performance evidence.
- Completion journals reside under results/completion-journal, not /tmp.
- The campaign runner no longer deletes completion records before starting
  a stage or when exiting it. Use a distinct campaign ID for each fresh
  measurement. Reusing an ID is recovery, not an independent trial.
- Native lifecycle reports identify modelled and executable phases explicitly.
- Native peers accept an optional --host-statements public vector instead of
  synthetic hash-to-point statements. The points are included in the existing
  canonical item and batch bindings. Both endpoints must receive the same
  immutable public file for a campaign. No witness is derived from a public seed.
- Actual live pre-signatures are handed off after DONE through anonymous memory
  and consumed by the native Adapt/Extract checker. See LIVE_HANDOFF.md.
- Native VTD primitives now include sharing, homomorphic puzzles, range
  prover/verifier, transcript-derived openings, public-key binding, commitment
  generation and bounded sequential recovery. Fresh 2048-bit setup generation
  passed its standalone test. See VTD_IMPLEMENTATION.md for boundaries.
  The ordered single-arc gate connects all three VTDs for n=3 through re-lock
  and refund ledger consumption. The complete host lifecycle and cloud runner
  remain unconnected.

## Upstream boundary

The upstream ae/readme.md publishes two building blocks: two-party adaptor
signing and VTD, plus a separate HTLC comparison contract. It does not supply
a complete five-phase ParaSwap executable. Native Pre-swap uses upstream
verification routines; the enclosing lifecycle is still a conformance model.
This revision does not claim full cryptographic lifecycle integration.

## Remaining work before a full-lifecycle claim

0. Extend the standalone independent-address-key admission to per-job worker
   custody and the cloud host. Standalone signing now uses independently
   generated shares and checks preparation-bound proofs when configured by
   the handoff runner. The historical microbenchmark helper
   `bench_derive_item_secret` computes base+tweak mod q; disclosure of one such
   share reveals the base and hence other address shares (except its explicit
   zero-result remapping edge case). Supplying fresh base keys per execution
   does not eliminate this within-execution issue. Preserve historical Pre-swap
   fixtures as labelled microbenchmarks, not full-lifecycle security evidence.
1. Connect the new live in-memory handoff to the distributed witness-sharing
   and ledger state machine. The native checker already adapts/extracts the
   actual live pre-signatures; it is not yet a full host state machine.
2. Extend the host beyond its centralized synthetic-witness fixture. The
   current native preparation implements Eq. 10/11 statement prefixes, but
   does not implement distributed witness delivery or wallet provisioning.
3. Integrate the native VTD modules with explicit setup provenance, serialized
   public commitments, per-stage timing and host deadlines. Measure creation,
   verification and recovery separately from ledger simulation.
4. Run both reference and improved paths with identical host implementation,
   fixtures, authentication, worker limits and timing boundaries.
5. Exercise runner/gateway/worker restart and duplicate completion requests.
   Retention alone does not prove whole-campaign recovery or exactly-once export.
6. Add expiry-aware journal garbage collection using validated host deadlines.
   No automatic deletion is provided until that retention policy is specified.
7. Keep rebuilding and rerunning correctness gates after integration changes.
   The full local suite passed after the timed ledger, final-key refund and
   authenticated witness receiver changes (111 Python tests plus native and
   loopback gates). Later observed-withdrawal extraction has focused native
   and live handoff coverage; rerun the whole suite before release/cloud use.
   All builds must target this maintained artifact, never a preserved earlier
   development copy.
8. Security arguments remain conditional on the concrete per-item construction;
   tests are not a cryptographic security proof.

## Incremental development history

The entries below describe checkpoints at the time they were added. Statements
such as "not yet consumed" or "not yet rerun" in these historical entries are
not the current checklist; use the current implementation and remaining-work
sections above. No historical timing is promoted to final lifecycle evidence.

No cloud campaign was started as part of these edits.

## Verification of this revision

- After connecting authenticated witness composition to the all-VTD gate,
  `bash scripts/run_local_smoke.sh` exited 0 with its final PASS marker:
  111 Python tests, the added ordering/registry/funding gates, 15 live witness
  vectors, native cryptographic/ledger tests, five protocol modes, CURVE/ZAP
  worker tests and the cloud-runner loopback regression. An unauthorized PUSH
  sender can get EAGAIN before delivery; the negative test now accepts that
  rejection outcome while still requiring no frame at the receiver. This
  correction does not alter the authorization policy or cryptographic equations.
  A Matplotlib Axes3D availability warning remains non-fatal.

- Standalone independent-address signing now uses owned admitted key copies.
  Admission is before the Pre-swap resource/time interval; subsequent access
  checks the immutable count/pair/epoch/preparation context, with no repeated
  proof verification per item. Keys are released before RELIC shutdown.
  `results/address-admission-cache-n3.json` passed all five modes, 75 items,
  wrong-key/context negatives and expired-export checks. Setup verification
  still has redundant work and is not omitted from full-cycle cost. Independent
  address pool-worker use explicitly rejects until per-job admission exists.
- The live final-address VTD gate now creates/verifies its commitment before
  starting the Pre-swap peers. A control-pipe handshake starts ForceOp at entry;
  the helper waits for successful Pre-swap before checking the final joint key
  and signing the refund fixture. `test_live_vtd_key_binding.py` passed this
  ordered n=3 BJP+batch path with fresh 2048-bit setup, 256 shares and 128 rows.
  This supersedes the earlier post-Pre-swap commitment test for ordering only.
  Setup/prover/verifier still share a trusted local helper; only the final-key
  VTD is tested, not all delayed relock witnesses. No ledger lock/refund action,
  calibrated delay, distributed Preparation or complete five-phase run is proven.
- `results/host-export-cutoff-n3.json`: the five-mode independent-key gate
  passed with an added expired-export case per mode. The responder completes
  normally while the expired initiator fails with an empty handoff; no bad
  partial is injected in these expiry cases. The client checks local monotonic
  cutoff before/after writing, and the runner checks again at host admission.
  The current 60-second runner guard is test policy, not ParaSwap's calibrated
  schedule. Binding the production cutoff to validated schedule remains open.
- Re-read original ParaSwap Figures 4/5 (printed pp. 4081-4082): VTD commitment
  generation/verification precedes locking; ForceOp starts during Pre-swap,
  not on arrival at the refund deadline. For level x, re-lock is at x*Delta+t;
  refund is at n*Delta+t with t=Delta+3*epsilon. `host_schedule` implements
  these local-origin action cutoffs with checked u64 arithmetic. Boundary,
  overflow and ordering tests passed; the test is now in the smoke script.
  It is not yet wired into the lifecycle. Strict local export cutoff is an
  implementation policy, not synchronized clocks or calibrated timed privacy.
- Full native rebuild and `bash scripts/run_local_smoke.sh` passed after the
  independent-address integration. The first run found a zero-initialized
  joint-test options fixture incorrectly enabling descriptor mode; explicitly
  initializing its unused descriptors to -1 fixed that regression. The rerun
  passed 111 Python tests, native cryptographic/host tests, five protocol modes,
  CURVE/ZAP pool authentication/recovery and the cloud-runner loopback gate.
  This covers the checked local paths, not distributed lifecycle completion.
  Fresh-setup VTD integration remains a separate slow gate. A nonfatal local
  Matplotlib Axes3D import warning remains; no cloud campaign was executed.
- Live final-address key composition passed for n=3 in the BJP+batch mode:
  the final joint key from the actual handoff matched the two address shares,
  and VTD committed/recovered that responder share before refund signing.
  Parameters: fresh 2048-bit setup, 256 shares, 128 rows, 32 squarings;
  wrong-context rejection passed. Reproduction:
  `python3 scripts/test_live_vtd_key_binding.py`. This is not lifecycle ordering:
  the test generates VTD after Pre-swap, keeps centralized fixture custody,
  signs a test digest, and does not execute a timed ledger refund. No performance
  claim or full-lifecycle claim follows from this gate.
- `results/independent-address-rejection-n3.json` passed all five modes with
  15 successful vectors (75 items) plus live provisioning negatives: wrong
  initiator secret vector, wrong responder secret vector and wrong preparation
  context. No partial-fault flag is used in these 15 rejection executions;
  both peers must fail and the host output remain empty. The existing bad-final,
  invalid witness and mutated pre-signature tests remain enabled separately.
  Address parser/proof tests are now included in the common smoke script;
  the full smoke suite has not yet been rerun for this revision.
- Live independent-address-key gate passed at n=3 across all five modes:
  `results/independent-address-live-n3.json` contains 15 vectors and 75 verified
  items, signed ledger paths and negative cases. The runner now generates
  independent scalar vectors and actual role/pair/context-bound public proofs,
  with only the owning secret descriptor inherited by each endpoint.
  This replaces public-tweak keys for this runner; historical/default benchmark
  paths still use their previous derivation. Whole lifecycle and VTD-to-these-key
  integration remain incomplete, and repeated proof import is not optimized.
- Native transcript and both partial-signing paths now support independent
  address vectors via `--host-address-keys-fd`, `--host-client-keys-fd` and
  `--host-server-keys-fd`. All three plus host statements are required; partial
  provisioning fails closed. Signing checks the selected private share against
  the verified public key. Withdraw/relock map to the same address level.
  Client/server/helper builds passed and parser/proof regression was rerun.
  A complete live run exercising these three options is still required.
  Currently each access revalidates bundles; this correctness-first path is not
  performance-ready. Move validation to immutable Preparation admission before
  comparing timings. Legacy paths remain for historical microbenchmarks.
- Address public-key bundles use `OASISAP1 || count_u32_be ||
  repeated(compressed_point[33] || ownership_proof)`. Sealed anonymous imports
  verify every entry against caller-supplied preparation/role/pair/epoch,
  rejecting duplicate keys and noncanonical points before returning a key.
  Tests passed valid export/import, mutable import, truncation, trailing bytes,
  entry swapping, and a corrupt last proof while requesting the first key.
  These bundles are not yet consumed by the live transcript/signing paths.
- Per-address ownership proof wrappers bind SHA-256 of
  `OASIS-ADDRESS-OWNERSHIP-v1 || preparation[32] || count_u32_be || level_u32_be`
  through the existing role/pair/epoch-bound ownership proof. Correct proofs and
  rejection after role/pair/epoch/level/preparation changes were tested. The
  explicit `test-address-proofs` helper is separate from public-key export and
  is not benchmark work. Live protocol transport still needs the proof vectors.
- Independent address-share import is implemented as `OASISA01`, a big-endian
  u32 count, and canonical 32-byte scalars in sealed anonymous memory. It checks
  the entire vector, rejects duplicates and leaves no partial public output on
  failure. `scripts/test_host_address_keys.py` passed valid public-point export,
  zero/order scalars, duplicate, truncation, trailing bytes, wrong count and
  mutable-memory cases. The live signer still uses the legacy derivation;
  this parser is the replacement input boundary, not completion of that fix.
- Host-provisioned base signing keys passed the n=3 five-mode live gate
  (`results/host-provisioned-key-handoff-n3.json`): 15 vectors, 75 items,
  signed ledger paths and failed-parent checks. Zero/out-of-range scalars,
  malformed/truncated/extended encodings and unsealed key descriptors reject.
  Each peer gets only its own sealed private-key memfd and the other's public
  point. Existing key-ownership proofs remain enabled. Per-address derivation
  remains in use and must be replaced for VTD disclosure, as described above.
- Wallet-side `host_refund_sign` verifies the recovered recipient scalar against
  its prepared public key and the sum with the sender share against the final
  joint key, then signs and verifies the refund digest. Ledger tests passed for
  valid consumption and mismatched shares/keys without changing signature output.
  The fresh-setup 256-share/128-row VTD test also passed ForceOp-output refund
  signing (32 squarings). A subsequent const-correct digest copy was rebuilt and
  retested through the ledger test. These are separate composition gates; live
  Pre-swap handoff, timed recovery and refund are not one lifecycle yet.
- Native witness transport encoding is `OASISY01 || context[32] ||
  participant_u32_be || scalar_u256_be` (76 bytes). The receiver compares the
  encoded participant with a separately supplied authenticated channel identity
  and validates the scalar against the prepared public point. Tests passed for
  exact encoding, every truncation, trailing bytes, wrong peer, single-byte
  mutations, duplicates and incomplete receipt sets. The API itself does not
  establish authentication or confidentiality. Secret-bearing buffers must not
  enter result files/logs.
- `host_zap_start` now supports a distinct prepared CURVE public key for each
  participant and emits `participant:<index>` as authenticated ZAP User-Id.
  The legacy single-key Pre-swap service retains its `initiator` identity.
  Native loopback witness delivery passed with three identities; an unknown
  key and a permitted sender impersonating another participant were rejected.
  Credentials and witnesses in this test remain in memory. This is a transport
  gate with centralized fixtures, not distributed host lifecycle integration.
- Live handoff now consumes adapted signatures in two separate ledger paths:
  immediate withdrawal and successive relocks. The n=3 five-mode run passed
  (15 vectors, 75 items), including malformed witness/signature and failed-parent
  export checks: `results/host-ledger-handoff-n3.json`. The registry is supplied
  by the trusted local producer, not independently reconstructed Preparation.
  Live refund and timed witness release remain unintegrated. Handoff schema v2
  calls the combined check duration `host_postprocess_ns`, not Adapt-only time.
- `host_ledger_test` built and passed independently: prepared-digest Schnorr
  signatures authorize withdrawals, successive relocks and final refunds;
  invalid signatures and repeated spends are rejected. The test is now in
  the smoke script, but the complete gate has not been rerun after this addition.
  This is an in-memory directed-arc adapter with a trusted preparation registry,
  not a blockchain implementation. Witness delivery and VTD recovery are not
  connected; host deadline enforcement remains external.
- The local smoke gate was rerun after the standalone VTD/wire additions:
  111 unit tests, native protocol, VTD tests, CURVE/ZAP and loopback runner
  regression passed. The subsequently added native witness receiver passed
  its separate test and is now included in the smoke script.
- `host_witness` provides one receiver's native state: witness/public-point
  verification, immutable context binding, idempotent duplicate receipts and
  no global-witness export until every distinct participant is present.
  It does not yet replace the Python host's synthetic witness exchange and
  is not an authenticated network exchange on its own.

- Fresh-setup VTD integration passed at 2048-bit modulus, 256 shares and
  128 range rows: commit/verify/ForceOp round trip and wrong-context rejection.
  The test delay is 32 squarings, not a meaningful security timeout or cloud
  benchmark. This does not close the host lifecycle integration work.

- Python unit discovery: 111 tests passed.
- Upstream integrity check passed (11 unchanged files, 3 adapted files).
- The copied default build-full cache was moved to build-full-copied-v2.
  A fresh native build succeeded; it is not cloud performance evidence.
- scripts/test_host_statements.py passed: all five modes accept a public vector;
  truncated, extended, malformed and mismatched vectors fail. The generator used
  there is a public parser/protocol fixture, not a production witness setup.
- Before the subsequent VTD additions, the complete local smoke gate passed
  after rebuilding: unit, batch verifier,
  joint signing, completion journal, native protocol, CURVE/ZAP rejection and
  loopback campaign regression. Native tests include gateway restart recovery;
  this does not establish whole-runner recovery or full lifecycle.
- Live n=3 gate: 15 successful vectors / 75 verified items across five modes;
  invalid-witness, altered-signature and no-export-on-fault checks passed.
- Live n=16 gate: 80 successful vectors / 2480 verified items across five modes.
- The final negative gate also rejects a disk descriptor without writing data.
  These are correctness checks, not cloud performance measurements.
- Loopback regression uses unique campaign IDs per invocation so repeated tests
  do not reuse retained completion records as if they were fresh measurements.
- Full lifecycle cryptographic handoff and native restart fault injection remain
  pending. The unit gate does not establish either property.

## Public statement interface

The public file consists of eight ASCII bytes OASISP01 followed by exactly k
canonical compressed secp256k1 points (33 bytes each). Count is taken from the
validated native --count argument. Noncanonical, invalid and identity points
are rejected. The existing statement derivation remains the default when this
option is absent, so old workloads are not silently relabelled as lifecycle.

After user approval, --host-output-fd accepts only Linux anonymous memfd objects.
There is no on-disk output option. The client writes a complete ordered vector
only after verifying DONE and after stopping the Pre-swap wall/CPU measurement.
The helper checks those same pre-signatures with the upstream verifier, adapts
them under the negative-sign convention and verifies extracted witnesses.
The witness-bearing descriptors are never inherited by the signing peers.
No secret scalar or nonce is included in the JSON report. These are experiment
fixtures, not production secret custody (for example OS swap is not controlled).

Use make native-handoff to run the local gate. It does not run cloud or modify
the paper. Distributed Witness Sharing, refund signing and host lifecycle
integration are still NOT completed. New standalone VTD modules implement
the proof relations missing from the bundled puzzle-only API, but are not
yet wired into that host. Tests do not constitute a security proof or final
reproducible cloud evidence.

For host-statement runs, Withdraw and Re-lock at the same address level derive
the same source-address key. Default synthetic Pre-swap runs retain the old
per-item key derivation. Never pool the two workload types as identical trials.
