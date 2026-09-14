# Secondary authenticated conformance experiment protocol

This document describes the C++/OpenSSL mutual-TLS conformance suite. It covers
authenticated transport, retry, injected faults, packet loss, and load. It is
separate from the primary same-backend native ParaSwap campaign in
`scripts/run_cloud_campaign.py`, which uses the official C/RELIC/ZeroMQ adapter
with ZeroMQ CURVE, responder-key pinning, and a ZAP initiator-key allowlist.
Results from these two suites must be labeled and analyzed separately.

## Fixed environment

- Responder: AWS Virginia (`us-east-1`).
- Initiators: AWS Frankfurt (`eu-central-1`) and Singapore
  (`ap-southeast-1`).
- Each VM has 2 vCPUs and 8 GB RAM.
- Native C++17 build uses `-O2 -pthread -Wall -Wextra -Wpedantic -Werror`.
- Every measured connection uses mutually authenticated TLS 1.3.
- Frankfurt and Singapore campaigns run sequentially. Results from overlapping
  route campaigns are invalid and must not enter the analysis.

The deployment archive, source files, compiler, OpenSSL version, kernel, VM
CPU, memory, limits, and native binary are identified by SHA-256 metadata.

## Objective configurations

| Artifact identifier | Paper-facing description |
|---|---|
| `persistent-pipelined-itemwise` | independent persistent sessions with item-wise verification |
| `phase-coalesced-itemwise` | independent sessions with phase-coalesced writes and item-wise verification |
| `batch-joint-presigning-itemwise` | Batch Joint Pre-signing with item-wise verification |
| `phase-coalesced-batch-verification` | independent sessions with randomized batch verification and Pippenger MSM |
| `batch-joint-presigning-batch-verification` | full method: Batch Joint Pre-signing, randomized batch verification, and Pippenger MSM |

The primary comparison is the full method against the realistic independent
persistent/pipelined baseline. The remaining configurations attribute gains to
session batching, generic write coalescing, and the aggregate verifier.

## Campaign matrix

| Campaign | Parameters | Measured trials | Warm-up |
|---|---|---:|---:|
| Primary/ablation | `n={3,5,8,16}`, `p=1`, all five configurations | 100 | 10 |
| Load | `n={8,16}`, `p={1,64,128,1024}`, all five configurations | 20 | 5 |
| Packet loss | `n=8`, `p=1`, loss `{0,2,5}%`, all five configurations | 50 | 5 |
| Fault directions | `n=8`, `p=1`, full method, one bad opening/server partial/client partial | 50 | 5 |
| Native | `n={3,5,8,16}`, all five configurations | 100 | 10 |
| Selective retry | `n={3,5,8,16}`, fault counts `{1,floor(k/4),k}` | 100 | 10 |

For ParaSwap participant count `n`, every pair processes `k=2n-1` items:
`n` Withdraw pre-signatures and `n-1` Re-lock pre-signatures. Load parameter
`p` is the number of concurrent participant-pair sessions, not the number of
participants in one swap.

## Acceptance gates

A result enters the final analysis only if:

1. its schema is `oasis-conformance-transport-v1`;
2. every paired trial contains all expected objective configurations;
3. `k=2n-1`, TLS is enabled, and a TLS 1.3 cipher is recorded;
4. no failed pair is present outside an explicitly failure-tolerant load run;
5. aggregate configurations at `k>=8`, where this pinned secondary backend
   activates Pippenger, contain canonical verifier-audit salts and transcript
   digests; this threshold is not used by the primary native backend;
6. logical-session/message and phase-coalescing accounting passes
   `scripts/validate_cloud_result.py`;
7. the source and binary hashes match across all three VMs.

Reported statistics include median, P95, P99, bootstrap 95% confidence
intervals, paired Wilcoxon signed-rank tests with Holm correction, throughput,
application goodput, CPU time/utilization, RSS, active connections, and TCP
retransmissions. Packet-loss qdisc evidence is retained beside the raw JSON.
