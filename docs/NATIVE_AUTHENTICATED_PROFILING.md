# Native authenticated profiling contract

This document is normative for the final native ParaSwap Pre-swap evidence.
Historical `oasis-preswap-cloud-v1` files used unauthenticated ZeroMQ TCP and
must not be presented as measurements of the final authenticated transport.

## Transport

TCP campaigns use ZeroMQ CURVE. The initiator pins the responder public key;
the responder enables a ZAP domain and authorizes exactly the configured
initiator public key. Source-IP filtering remains defense in depth and is not
the authentication mechanism. Every compared configuration uses the same
CURVE settings and the route's key pair. Different client placements use
distinct identities; all profiles within one route reuse that route's identity.

Secret keys are generated outside the source tree, stored with mode `0600`,
and excluded from source archives. Evidence records SHA-256 fingerprints of
public keys, never secret key material. IPC-only developer tests may remain
unauthenticated and cannot be cited as WAN evidence.

## Workload dimensions

- `n` is the number of participants in one ParaSwap cycle.
- `k = 2n - 1` is the number of Pre-swap items on one directed arc.
- `p` is the number of directed pair sessions executed concurrently.

Primary one-pair experiments use `p = 1`. Load experiments vary `p`
independently while holding `n` and therefore `k` fixed. The lifecycle harness
separately checks the complete `n`-arc ParaSwap state-machine workload.

## Timing campaign

The primary timing campaign does not run under `strace`, an allocation
interposer, or a sampling profiler. Each measured sample reports:

- stage and critical-pair wall time;
- process user and system CPU time at both endpoints;
- process CPU utilization and host CPU utilization at both endpoints;
- p50, p95, and p99 pair completion time;
- completed pairs/s, completed Pre-swap items/s, and application goodput;
- current and peak aggregate RSS, voluntary/involuntary context switches,
  Linux scheduler wait from `/proc/self/schedstat`, active processes, sampled
  run-queue depth, launch skew, and Jain fairness across pair completion rates;
- application frames, application bytes, and ZeroMQ send/receive calls.
- fixed worker count, assignments, rejected sessions, peak busy workers, peak
  admission-queue depth, and queue-wait time.

Server resource state is isolated per configuration stage. Worker processes are
long-lived only within that stage. Whole-stage CPU comes from gateway and worker
process-lifetime counters; peak aggregate RSS comes from process sampling and
is not obtained by summing repeated per-session observations of one worker.

## Separate profiling campaigns

Instrumentation that materially perturbs timing is run separately:

- syscall counts are collected in a syscall-counting campaign;
- allocation calls and requested bytes in the instrumented artifact sources are
  collected with a separate build; dynamically linked dependency allocations
  are outside that counter;
- exact campaign TCP segments, retransmissions, payload bytes, direction
  changes, and TCP ACK-derived RTT distributions are collected from a capture
  restricted to the single service port;
- interface and TCP host-counter deltas are retained as diagnostics only because
  they may include unrelated host traffic.

The primary native transport does not use TLS. Consequently TLS-record count
is reported as not applicable, not inferred as zero. The secondary OpenSSL
conformance transport reports TLS records separately and is not merged into
the native timing campaign.

## Evidence gate

Primary timing effects use critical-pair wall time at `p=1` and whole-stage wall
time at `p>1`. Paired Wilcoxon signed-rank tests and rank-biserial effects are
Holm-adjusted within declared primary or load families.

Final raw evidence uses `oasis-preswap-cloud-v8`, and accepted timing analyses
use `oasis-preswap-cloud-analysis-v5`. Client and server must agree on the
campaign schedule digest, blocked-randomization metadata, source and binary hashes, transport
mechanism, ZAP domain, peer public-key fingerprints, workload dimensions, and
runtime settings. The gate also checks role-specific AWS placement and records
TLS session reuse as not applicable because the native transport is CURVE,
not TLS. Missing samples, authentication failures, unexpected
verifier fallbacks, or profiler contamination of the timing campaign are hard
errors.
