# Full-cycle completion gates

The target is the original ParaSwap lifecycle with the same host behavior for
the reference and BJP/batch-verification modes. A local ledger adapter is in
scope; a public testnet is not required. Passing Pre-swap or isolated ledger
tests does not establish completion of this target.

## Implemented changes awaiting complete integration validation

### Crash-recovery boundary

The snapshot codec is currently exercised by `host_ledger_test.c`, not by the
lifecycle coordinator. Process cleanup still discards retained ledger objects.
Snapshot round trips therefore do not establish host crash recovery. The DONE
journal protects a completion receipt; it does not persist the funded ledger.

A complete recovery implementation requires these separate gates:

1. Bind restored state to independently trusted Preparation context and registry,
   rather than trusting keys and digests supplied by the snapshot itself.
2. Specify an authoritative durable ledger and transition ordering: acknowledge
   funding, spending or refund only after its durable commit succeeds.
3. Persist all arcs consistently, with explicit handling of partially committed
   cross-arc operations; do not restore one arc from an arbitrary older snapshot.
4. Define freshness and rollback protection. A checksum, atomic rename, or MAC
   alone does not reject replacement with an older valid snapshot.
5. Retain or securely recover required handoffs without writing private keys or
   witnesses into an unprotected journal.
6. Kill and restart at commit boundaries for funding, re-lock, withdrawal and
   refund; verify no duplicate spend, lost acknowledged transition, or silent
   reset. Exercise both reference and BJP modes.

These gates remain open. They do not solve the missing-signature early-abort
case below, which requires a justified protocol terminal procedure.

- Reject invalid/nonfinite lifecycle budgets before funding.
- Apply one absolute deadline to worker creation, port allocation, and exit.
- Terminate worker process groups on failure, including surviving descendants.
- Check prepared VTD metadata against the expected re-lock statement or the
  admitted responder's final public key share before lock admission.
- Expose coordinator progress on smoke-test stderr.
- Observe the funded ledger state on a coordinator exception using the native
  abort command. Reporting an abort does not authorize a refund or persist the
  ledger for later recovery.

The VTD bundle parser consumes an already native-admitted bundle. Its proof
record width depends on the native build; this parser is not a replacement for
native ownership-proof verification. Its synthetic tests do not establish
cryptographic validity of arbitrary bundle bytes.

## Required unresolved failure path

Reproduce this case explicitly: funding succeeds, then a peer stops before a
complete re-lock pre-signature vector exists. Keep the same funded ledger and
attempt the host's documented terminal procedure.

Current implementation evidence:

- `host_cycle_tool.c:funded_cycle_recovery` accepts completion only with full
  registry-matching handoffs. Its `A` command reports current funded states
  without spending; process cleanup still destroys the local ledger objects.
- `host_ledger.c:refund` requires the final address level and a valid signature.
- `host_ledger.c:spend` requires a valid signature for each level transition.

Consequently, the existing runner does not demonstrate refund after incomplete
Pre-swap. The executable mechanism that supplies the missing transitions must
be resolved against the original protocol/AE before implementing this branch.
An ideal-functionality UnLock instruction alone is not an executable signature
or a justification for an unconditional ledger rollback. Do not move funding
after Pre-swap, synthesize signatures from centralized fixture secrets, or add
an unsigned refund and label it the original protocol.

## Evidence required before completion

Latest all-honest validation command:

```sh
python3 -B scripts/test_retained_full_cycle.py --outcome all-honest --results-dir results/retained-all-honest-validation-20260909
```

The reference run passed and saved its checked JSON and provenance. The BJP
run failed during arc 2 VTD Preparation, before funding, with native diagnostic
`setup generation failed (candidate budget or randomness)`. The overall command
exited 1; it is not a passing two-mode validation. No BJP success report was
saved. This reproduces a setup failure, but does not yet distinguish exhausted
candidate budget from randomness failure. `vtd_setup.c` shares a finite candidate
budget between safe-prime searches and retries the second prime until their
product has the requested bit length. Investigate this path without weakening
prime checks or reducing modulus size. The successful reference timing includes
fresh VTD setup and is not a cloud transaction-latency measurement.

Subsequent setup correction: resample both safe primes when their product has
the wrong bit length, rather than holding the first factor fixed. A first
factor close to its lower bound previously left a very narrow acceptable
interval for the second factor. The shared candidate budget, 64-round primality
checks, modulus size, and unchanged-output-on-failure behavior remain in place.
The native `vtd_setup_test` passed after this change (2048-bit modulus, delay
relation and puzzle round trip); zero-budget rejection also checks all outputs
remain unchanged. This does not establish reliability across repeated complete
cycles or prove the exact cause of the earlier generic setup failure. The saved
reference report predates this change and must not be attributed to the new
binary.

1. Run native all-honest withdrawal for both modes with all arcs on retained
   funded ledgers, after the VTD admission changes.
2. Run withheld-witness recovery for both modes using public VTD solver output.
3. Resolve and implement the funded incomplete-Pre-swap abort case above;
   demonstrate the justified terminal behavior without replacing the ledger.
4. Test malformed partials, missing completion, and local deadline expiry at
   the coordinator boundary; reject incomplete honest-wrapper export.
5. Record source and binary hashes with the new integration evidence. Keep
   interrupted or old runs separate from successful evidence.

Keep `full_lifecycle=false` until these gates are established. Distributed
custody, timed privacy, crash recovery, and WAN performance are distinct claims
and require their own evidence; do not infer them from these gates.

## Reproducible funded-abort check

Run `make retained-abort-test`. It creates native admitted registries and funds
three arcs, then injects an exception before Pre-swap for each mode. It requires
three locked arcs, zero withdrawals/refunds, no automatic refund, and propagation
of the original exception. It deliberately does not generate VTD proofs or
exercise network Pre-swap, and therefore cannot establish either full lifecycle
completion or the security of the VTD composition.

## Checked recovery evidence after setup correction

The following command completed with exit 0 for both modes:

```sh
python3 -B scripts/test_retained_full_cycle.py --outcome recover-cycle --results-dir results/retained-recovery-validation-20260909
```

Each saved report records `retained_cycle_recovery=true`, three withdrawn arcs
and two observed withdrawal hops for n=3. Each provenance object contains 81
source/configuration hashes and six binary hashes. This is one local recovery
run per mode, not repeated reliability or WAN evidence. Both reports retain
`full_lifecycle=false`; neither exercises abort with missing Pre-swap handoffs.
All-honest and refund evidence is recorded below. Source hashes do not prove source-to-binary build correspondence
or pin external compiler/library versions.

## Checked all-honest evidence

`results/retained-all-honest-validation-20260910/` contains a passing report
for each mode from `--outcome all-honest`. Both report three withdrawn arcs,
zero observed withdrawal hops, and withdrawal before solver join. The two
provenance objects are identical. The command exited 0.

A subsequent hash audit of all six recovery/refund/all-honest reports found no
changes in their six recorded binaries. All recorded all-honest source hashes
match. The sole recorded source mismatch in recovery/refund is
`src/host_ledger_test.c`, which subsequently gained a negative refund test.
Preserve the historical hashes; this comparison is not permission to relabel
old reports as having run against the later test source.

These six runs establish the tested n=3 local branches, not every fault boundary
or a full security construction. The funded early-abort gate remains unresolved;
see `EARLY_ABORT_PROTOCOL_DECISION.md`. No new long run is justified solely by
the test-only source mismatch above.

## Post-Pre-swap refund branch

The command below completed with exit 0 for both modes. The two saved reports
have identical provenance objects and each records three refunded arcs, zero
withdrawn arcs, `ledger_clock=controlled_fixture`, and `full_lifecycle=false`:

```sh
python3 -B scripts/test_retained_full_cycle.py --outcome refund-cycle --results-dir results/retained-refund-validation-20260910
```

Subsequent edits to coordinator and native ledger tests do not alter the
production transition implementation, but the saved hashes remain authoritative
for the exact tested source tree. Do not rewrite old provenance to match later
test-source changes.

`scripts/test_retained_full_cycle.py --outcome refund-cycle` exercises refund
after complete registry-bound Pre-swap handoffs, with withdrawal witnesses
withheld. The native transition uses the retained funded ledger, VTD-derived
delayed witnesses, and a validated final refund signature. It is not recovery
from missing Pre-swap signatures. Its schedule uses a controlled ledger clock,
not elapsed blockchain confirmation time.

Use `--results-dir <new-directory>` to save checked per-mode reports and the
tracked source/binary provenance. A successful local run without saved evidence
does not supply the reproducible final evidence required above. Python `-O` is
rejected because it would disable smoke assertions.

The all-honest/recovery/refund smoke remains `make full-cycle-smoke`. Its assertions
retain the explicit incomplete-lifecycle flags; a smoke PASS must not be
described as completion of every gate in this document.
