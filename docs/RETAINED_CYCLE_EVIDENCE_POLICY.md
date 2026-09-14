# Retained-cycle evidence policy

Retained-cycle outputs are valid only for the exact implementation and binary
set recorded in the result manifest. A previous PASS, timing table, or
solver-fed JSON MUST NOT be used to certify a changed coordinator, transport
adapter, host ledger, VTD implementation, or native binary.

`compare_full_cycle_modes.py` records:

- the tested Git commit;
- SHA-256 for the coordinator, authenticated lifecycle Pre-swap adapter, native
  handoff runner, host-cycle/ledger/recovery code, and VTD code;
- SHA-256 for the native host, Pre-swap, CURVE keygen, and VTD binaries;
- the shared Preparation fixture identifier for each baseline/OASIS pair; and
- a SHA-256 over the canonical report payload.

A result is **stale evidence** when any recorded source/binary hash differs from
the implementation being reviewed. Stale results may be retained for history,
but they are not correctness or performance evidence for the new revision.

## Claim boundary

The retained coordinator currently provides local lifecycle **correctness
coverage**. Its Pre-swap path uses authenticated CURVE/TCP loopback with one
absolute host deadline shared by every concurrent arc. Loopback timing is not
WAN or transaction latency evidence. Network authentication negative tests are
kept outside the measured correctness path.

The following claims remain false until their dedicated work is complete and
re-tested:

- `full_lifecycle`;
- `distributed_participant_custody`;
- `timed_privacy`; and
- publication/WAN performance evidence from the retained local runner.

In particular, the native ledger still uses its logical fixture clock rather
than the coordinator's monotonic host deadline, participant Preparation custody
is centralized, and unified retained abort/refund plus participant isolation
remain separate milestones. Those limitations must not be hidden by a PASS in
the local retained-cycle smoke test.
