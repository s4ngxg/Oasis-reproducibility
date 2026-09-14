# Funded early-abort protocol decision

Status: unresolved protocol decision, not an implemented refund mechanism.

The user has subsequently authorized exploring an extension and explicitly
labeled symbolic components. Approval is no longer the blocker; a justified
cross-arc cancellation rule is still missing. A symbolic result must not change
the native artifact's `full_lifecycle` claim.

## Rejected simple extension

`tests/test_cancellation_model.py` models a proposed unconditional cancellation
after the cutoff. On three independent unspent outputs, one incoming withdrawal
and cancellations on the remaining arcs yield a mixed terminal state without
any local double spend. All six orders of these three accepted actions retain
the counterexample. A timeout by itself does not prevent competing transactions
on different chains from producing that outcome.

This is an executable counterexample to that deliberately weak extension, not
an execution or attack proof against the original ParaSwap protocol. Do not
implement unconditional timed cancellation as the missing recovery path. A
replacement needs a justified cross-arc condition or stronger explicitly stated
ledger/coordination assumptions before it can support a safety claim.

## Evidence and scope

The vendored, hash-verified `vendor/paraswap/README.upstream.md` describes the
AE as implementations of two building blocks: two-party adaptor-signature
computation and VTD. Its deployment instructions for timeout/refund belong to
the separately labeled HtlcSwap baseline, not to a ParaSwap lifecycle runner.
The inspected unchanged `bob.c` and `tumbler.c` do not supply a funded-abort
ledger cancellation API. This is evidence about the inspected AE components,
not a claim that no such construction can exist or that the paper is disproved.

Do not treat the HTLC timeout operation as the missing scriptless authorization:
it relies on that contract's spending rules. Importing those rules changes the
host construction and requires an explicit comparison and security argument.

The original paper (USENIX Security 2025, Figure 4, printed page 4081) places
funding before joint pre-signing. Section 5.2, Threat-1 says to halt the phase
and withhold the witness after verification failure. This prevents witness
release; it does not itself provide a signature authorizing return of funds.
Figure 9's ideal `UnLock` is not an executable signed transaction.

In the current retained adapter, spending from the first joint address requires
a valid signature under that address. Later VTDs reveal re-lock witnesses and
the final-address responder key share. These do not supply a missing first-level
pre-signature or the first-address responder key share. A funded abort therefore
leaves the ledger locked. This is an implementation coverage gap; it is not by
itself a proof that every implementation of the original construction fails.

The native funded-abort test observes this state for both reference and BJP.
Recovery/refund tests after complete Pre-swap are separate branches and cannot
close this gap. Public testnet deployment would not supply a missing signature.

## Changes that cannot silently count as a fix

- Moving lock admission after Pre-swap changes the original phase order.
- An unsigned adapter rollback assumes authority absent from the ledger model.
- Reading both key shares from a centralized fixture is not adversarial recovery.
- Releasing a first-address secret share adds spending authority and needs a new
  security argument, especially across partially completed arcs.
- A cooperative cancellation signature cannot guarantee cancellation when the
  peer is already unresponsive.

## Candidate extension requiring design review

A pre-authorized, delayed cancellation transaction may address first-address
abort on ledgers that enforce the needed transaction semantics. This is a
candidate, not a universal-chain solution or an established secure construction.

Before any funding, both peers would validate a cancellation authorization
bound to the exact funding output, original owner, amount, chain, and session.
It must be unusable before an agreed cutoff, remain available despite a peer
stopping, and be invalid after that output has been consumed. Both baseline
and BJP would receive the same outer-protocol change and its costs.

Design gates before implementation:

1. Specify the ledger's actual timelock and transaction-identifier semantics;
   do not emulate unsupported consensus rules only inside a test adapter.
2. Specify signature exchange before funding and refusal to fund if incomplete.
3. Analyze cancellation versus withdrawal near the deadline, and partially
   funded/completed cycles. Per-output double-spend rejection alone does not
   establish atomicity across chains.
4. Establish compatibility with later re-lock/refund transactions and existing
   witness-extraction dependencies. Prevent a new early-refund action.
5. Define the timing/network assumptions and recovery after process restart.
6. Test all fault boundaries on the same retained funded outputs for both modes,
   including reordered messages and competing spend/cancel transactions.
7. Label the resulting protocol as an extension and report its added work;
   do not describe it as an unchanged reproduction of the original AE.

Until the original executable recovery mechanism is located or an extension is
approved, specified, and verified, keep `full_lifecycle=false`. Do not inflate
successful normal/recovery/refund tests into unconditional funded-abort safety.
