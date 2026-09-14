# Review 0209 completion map

Scope source: `review0209.pdf`, sections 5-7, especially the twelve detailed
comments on pages 4-5. This map separates reviewer requirements from the later
full-lifecycle engineering objective. No row is an acceptance or security proof.

| Review item | Current evidence / next required action |
| --- | --- |
| 1. Abstract security scope | Keep security conditional on the per-item interface. Manuscript update remains separate from this code maintenance. |
| 2. HTLC compatibility claim | Avoid unsupported deployed-ledger prevalence claims; manuscript audit needed. |
| 3. VTD attribution | Distinguish universal-swap VTD interface from homomorphic-puzzle foundations; manuscript audit needed. |
| 4. Encoding and validation | Native joint-presign and malformed-input tests pass. Exact construction-to-proof mapping remains open; tests cannot replace it. |
| 5. Retry sets and DONE | Native retry validation and gateway restart tests pass. Journal sync-failure tests pass; replay rejects mismatched stored count. Endpoint export/refinement argument still requires manuscript alignment with the exact code. |
| 6. Batch soundness | State coefficient sampling/domain and cumulative attempt bound for actual parent/child checks. Cryptographic assumptions and reduction still need independent scrutiny. |
| 7. Related-work accuracy | Preserve qualified ShiftHub and Rosler claims; manuscript audit needed. |
| 8. Statistics and interaction | Analysis/final-report gates exist and local tests pass. Final raw campaigns and regenerated intervals/effect sizes are not supplied by those tests. |
| 9. WAN controls | Runner captures system metrics; unavailable cgroup data remains unknown. Verify worker cgroup/ancestor limits, placement, RTT and authenticated transport on deployment, then run EU and Singapore sequentially. |
| 10. Cloud cost | Cost tooling exists; actual instance-hours, storage/transfer and failed/warm-up consumption require campaign/account evidence. |
| 11. Failure denominators | Derive every observation from the selected exact campaign. Do not reuse historical counts for rebuilt binaries. |
| 12. Permanent artifact | Local smoke passed; reduced WAN recipe and source packaging exist. Publish exact tested revision, dependencies and raw evidence to a permanent release; archive reproducibility is not binary reproducibility. |

## Additional major blockers in sections 5 and 7

- Concrete construction proof: the conditional wrapper argument does not prove
  the implemented per-item cryptographic construction.
- Closest comparator: see `CLOSEST_COMPARATOR.md`. Bibliographic metadata is
  verified; technical comparison requires the actual paper/artifact, not title
  inference.
- Official integration: identify the adapted upstream components and local
  ledger/transaction fixtures honestly. Component reuse does not demonstrate
  production-chain serialization or public-chain execution.

## Separate user-requested lifecycle objective

`FULL_CYCLE_COMPLETION_GATES.md` and `EARLY_ABORT_PROTOCOL_DECISION.md` cover
this additional objective. Normal withdrawal, withheld-witness recovery and
post-Pre-swap refund have historical local branch evidence. They do not establish
refund after funding with missing pre-signatures or durable host crash recovery.

Review 0209 does not require a public testnet, a particular worker count, or an
unconditional `full_lifecycle=true` flag. Its DONE persistence requirement must
still be satisfied. The additional lifecycle objective remains open rather than
being silently removed or counted as satisfied by a Pre-swap benchmark.
