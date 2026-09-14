# Review1008 compliance matrix

This matrix separates implemented evidence from claims that still require the
final cloud campaign. A limitation is not counted as completed evidence.

| Review requirement | Current resolution | Authoritative evidence | Status |
|---|---|---|---|
| Reposition novelty as a systems-security integration | Title, abstract, contributions, and limitations deny a new signature primitive or universal composition result | `paperv4.tex`, Sections 1, 6, and 8 | Complete |
| Complete 2x2 ablation | Independent/shared session organization is crossed with item-wise/aggregate verification; a phase-coalesced independent-session comparator is included | `preswap_protocol.h`, `preswap_client_v4.c`, `preswap_server_v4.c`; native v4 smoke test | Implemented; final WAN measurements pending |
| Same backend for every comparator | All five configurations use C11, RELIC, ParaSwap joint Schnorr equations, ZeroMQ DEALER, and the same key/transcript derivation | native CMake targets; `joint_presign_test`; cloud evidence analyzer | Complete in code |
| Early malicious-initiator output | Model distinguishes locally computable candidate, honest-wrapper export, and host-visible output; no fairness or simultaneous-output claim remains | `paperv4.tex`, Definitions 4.1/4.2 and Theorem 6.2 | Complete |
| Logical frames versus network flights | The paper separates application frames, send calls, CURVE transport, TCP segments, direction changes, and RTTs | `paperv4.tex`, Section 4 and evaluation accounting | Complete |
| Canonical byte transcript | Length-prefixed, big-endian encoding, point/scalar validation, domain tags, and known-answer vectors are normative | `preswap_joint.c`, `joint_presign_test.c`, `paperv4.tex` canonical table | Complete |
| Quantified batch soundness | Three independently salted equation families bind all canonical transcript fields; cumulative bound is `min(1,Q*2^-254)` in the stated random-oracle experiment | `batch_verifier.c`, `preswap_joint.c`, Theorem 6.2 | Complete for the stated model |
| Responder-side invalid initiator partial | Responder verifies client partial and full pre-signature equations; localization diagnoses indices and aborts the whole parent without `DONE` | `preswap_server_v4.c`; mutation smoke test; Algorithm 1 | Complete |
| Failure-path wire semantics and Figure 1 | Aggregate failure terminates with a nonempty `FINAL_STATUS`; earlier and item-wise failures use `ABORT`; no failed parent emits `DONE`. The figure shows the six-frame item-wise path and the aggregate-only seventh status frame | native v4 client/server; `paperv4.tex`; `image/oasis-session-architecture-academic.tex` | Complete |
| Retry semantics | Native v4 has no selective in-parent reuse: any confirmed invalid item aborts the parent; a later attempt uses a fresh parent SID and fresh nonce material | native v4 client/server, Figure 1, protocol documentation | Complete |
| Completion and crash recovery | The gateway persists a SID- and digest-bound `DONE`, returns an exact persistence acknowledgement to the affined worker, and only then forwards it; authenticated timeout queries replay the exact record, including after gateway restart with the same journal | `completion_journal.c`, native client/gateway/server, completion and restart regressions | Complete in code |
| Retry-set and key consistency | Canonical invalid-index decoding rejects wrong length, duplicates, descending/out-of-range indices, and excess cardinality; every joint key is recomputed from validated shares. Preparation-bound Schnorr key-ownership proofs are piggybacked on the first request/response frames and reject context, role, pair, epoch, key, identity, or proof mutation | `preswap_joint.c`, native client/server, `joint_presign_test.c`, and mutated-wire-proof smoke test | Complete in the measured native protocol |
| Both-endpoint transport authentication | Initiator pins responder CURVE key; one responder gateway ZAP-allowlists the initiator before routing multiple pair connections | `transport_auth.c`, `preswap_gateway.c`; CURVE/ZAP multi-client acceptance and rejection tests | Complete |
| P50/P95/P99, throughput, goodput | Collected and summarized for each timing configuration | `run_cloud_campaign.py`, `analyze_cloud_results.py` | Implemented; final WAN values pending |
| CPU, RSS, scheduler, context switches, run queue, fairness | Collected per endpoint and isolated by fresh configuration stages | same cloud runner/analyzer | Implemented; final WAN values pending |
| Allocation and syscall costs | Dedicated instrumented campaigns cannot be accepted as primary timing evidence | allocation targets, `analyze_system_profiles.py` | Implemented; final EU-to-US profile pending |
| TCP segment/retransmission accounting | Campaign-scoped PCAP capture and strict endpoint/port analyzer are separate from primary timing | `capture_native_campaign.sh`, `analyze_native_pcap.py` | Implemented; final reduced capture pending |
| Exact environment and burst-credit status | Runner records EC2 IMDS type/AZ/AMI, burstable flag, CPU details, compiler/CMake/RELIC/ZeroMQ versions, scheduler, affinity, governor, socket and resource limits | environment block in every role JSON; `cloud_collect_metadata.sh` | Implemented; final VM records pending |
| Official ParaSwap integration | Native extension is built inside a pinned, hash-verified copy of the official artifact and combined signatures pass its published verifier | `vendor/paraswap-artifact.lock.json`, `verify_upstream.py`, `joint_presign_test` | Complete at artifact level |
| Five-phase lifecycle integration | Preparation, Pre-swap export gate, Witness Sharing, Swap, Re-lock, and Refund transitions are executable with deterministic ledger/VTD adapters | `paraswap_lifecycle.py`, lifecycle tests | Complete as conformance, not public testnet |
| Public-testnet end-to-end timing | No funded-chain execution or measured confirmation component exists | explicit evidence boundary in paper and docs | Not claimed |
| One-port load topology | One event-driven CURVE ROUTER service port uses bounded admission and session-affine dispatch to a fixed pool of process-isolated RELIC workers; gateway and pool costs are measured | `preswap_gateway.c`, cloud runner, `p=4, W=2` loopback regression | Complete in code; final WAN measurements pending |
| Event-driven worker pool | Worker count is independent of concurrent pair load; workers register once, reuse initialized cryptographic state, process multiple sessions, and return to the pool after a terminal frame. Queue saturation has an explicit rejection path | native gateway/server; queue, reuse, and overload regressions | Complete in code; final WAN load measurements pending |
| Second VM family, multi-day/multi-cloud | The final plan uses two AWS cross-region routes but not a second VM family, multi-day campaign, or multi-cloud placement | explicit limitations | Not claimed; not evidence |
| Permanent artifact and claim traceability | Source archive is checksummed; the v8/v5 evidence pipeline generates CSV, figures, a paper-ready LaTeX fragment, checksums, and `CLAIM_TO_EVIDENCE.json` | package script, report-builder loopback regression | Final public release pending cloud evidence |

## Final evidence gate

The paper is not numerically final until all of the following are true:

1. EU-to-US and Singapore-to-US primary and load role pairs pass
   `analyze_cloud_results.py` from raw schema `oasis-preswap-cloud-v8` into
   analysis schema `oasis-preswap-cloud-analysis-v5`.
2. EU-to-US allocation and syscall role pairs pass
   `analyze_system_profiles.py`.
3. The reduced packet capture passes `analyze_native_pcap.py` schema v3 at both
   endpoints and contains a nonempty TCP ACK-derived RTT distribution.
4. `build_final_experiment_report.py` generates the paper tables, figures, and
   claim manifest from those accepted analyses with `--require-final-matrix`;
   this gate requires exactly one primary and one load campaign per route and
   rejects missing per-campaign factorial effects, profiles, endpoint packet
   captures, cost accounting, placement mismatch, or burstable-VM evidence.
   Numeric LaTeX cells come from the generated
   `paper_results.tex`, not manual transcription.
5. Historical prototype numbers and result images have been removed from
   `paperv4.tex`. Insert only the tables and figures generated by the accepted
   native-v4 report, then recompile and inspect the resulting PDF.
