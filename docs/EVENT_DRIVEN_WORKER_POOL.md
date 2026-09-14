# Event-driven responder worker pool

## Purpose

The cloud responder exposes one ZeroMQ CURVE `ROUTER` service port. Concurrent
participant-pair sessions (`p`) do not create responder processes. One gateway
event loop multiplexes public connections and dispatches admitted sessions to a
fixed pool of `W` long-lived, process-isolated RELIC workers over a private IPC
`ROUTER`/`DEALER` channel.

RELIC verification is CPU-bound, so the gateway is event-driven while the
cryptographic workers remain separate processes. This keeps connection handling
non-blocking, bounds CPU/RSS growth by `W`, and avoids relying on language-level
threads for elliptic-curve parallelism.

## Admission and dispatch

1. Every worker registers once as `worker:<index>` and initializes its pinned
   ParaSwap/RELIC state once.
2. The gateway accepts only a manifest-declared `(pair_id, execution_id)` from
   the CURVE-authenticated initiator.
3. If a worker is idle, the gateway sends an internal session assignment and
   forwards all buffered `BATCH_INIT` frames in order.
4. Otherwise the session enters a bounded FIFO queue. The item-wise reference
   path may send several initial frames, so all of its pre-assignment frames are
   buffered and validated by ordinal.
5. If the queue is full, the gateway returns `ABORT` and records a rejection;
   it never creates an extra worker.
6. A session stays affined to one worker through `DONE`, `ABORT`, or a nonempty
   terminal `FINAL_STATUS`. On `DONE`, the gateway durably records the exact
   completion, then sends the worker a private acknowledgement bound to the
   pair, execution, SID, and completion digest. Only after validating that
   acknowledgement does the worker mark the session complete and return to the
   idle pool. The gateway forwards `DONE` to the client and retains the route
   for the configured completion grace interval so an authenticated
   `COMPLETION_QUERY` can replay a lost acknowledgement. The private persistence
   acknowledgement is internal control traffic and is excluded from public
   logical-frame accounting.

The public socket also applies a CURVE/ZMTP-aware maximum message size. Before
an initial frame can enter the queue, the gateway checks its exact canonical
application length, count, and first ordinal. Malformed public frames are
dropped without terminating the shared gateway; internal worker protocol
violations remain fatal evidence errors.

The gateway sends `SHUTDOWN` only after every expected session has completed or
been explicitly rejected. A valid evidence campaign requires zero rejection.

## Configuration

`scripts/run_cloud_campaign.py` provides two responder controls:

- `--worker-count W`: fixed worker count; `0` selects the responder CPU count.
- `--max-queue Q`: maximum waiting sessions; `0` admits the complete stage
  workload.

The actual worker count for a stage is `min(W, p)`. Parameter `n` is the
ParaSwap cycle size, `k=2n-1` is the Pre-swap item count per directed arc, and
`p` is independent concurrent pair-session load.

## Evidence and invariants

Every server sample records:

- configured and registered workers;
- assignments, completed sessions, and rejected sessions;
- queue capacity, queued sessions, peak queue depth, and queue wait;
- peak busy workers and one worker index for every completed pair;
- gateway and worker process-lifetime CPU/RSS/scheduler telemetry;
- sampled peak aggregate RSS and active process count.
- durable completion records, replay requests, successful replays, internal
  control-frame counts, and the configured acknowledgement/replay timing
  policy.

`scripts/analyze_cloud_results.py` rejects a sample unless all `p` sessions are
assigned exactly once, no session is rejected, every worker index is valid,
worker totals match per-worker records, and queue/worker peaks remain within
their configured bounds.

The regressions use `p=4, W=2` to prove worker reuse and queueing. A separate
test suspends the single worker, fills a queue of capacity one, and verifies
explicit overload rejection without spawning another process.
An additional `p=128, W=1` regression forces one worker to emit more
per-session telemetry than a conventional pipe buffer. Worker output is
collected through anonymous temporary files so metric reporting cannot
deadlock the protocol pool.
