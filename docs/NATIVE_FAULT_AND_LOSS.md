# Native differential, fault, and packet-loss evidence

These campaigns test the same C11/RELIC/ZeroMQ implementation as the primary
timing and load experiments. They must not be combined with results from the
secondary C++/OpenSSL conformance backend.

## Differential campaign

`make native-exhaustive` generates 100,000 deterministic, domain-separated
vectors. Every vector must pass the unchanged ParaSwap full pre-signature
verifier and all three aggregate equations. The campaign then mutates one
server partial, one client partial, and one full pre-signature. Each aggregate
must reject, and one-item verification must identify exactly the changed
ordinal. Workers receive disjoint contiguous vector ranges, and the output
records binary and source hashes.

## Cryptographic fault campaign

`make native-fault` runs control and malformed-input cases over authenticated
CURVE/TCP loopback. It covers a mutated Preparation-bound key-ownership proof,
an invalid responder nonce opening, an invalid responder partial, and an
invalid initiator partial. A fault case passes only when both native endpoints
reject and no parent completion is accepted. The native v4 protocol does not
reuse cached items from a failed parent.

## Packet-loss campaign

Run the responder role first, then the matching initiator role. Both commands
must use the same route, campaign prefix, loss list, participant count,
concurrent-pair count, modes, trials, warm-ups, port, worker count, and queue
capacity. The responder applies no network impairment. The initiator uses
`tc netem` only on packets addressed to the shared service port.

The 0% control is observational: it records the existing qdisc and does not
replace or clear it. A nonzero loss case fails before measurement unless
passwordless `sudo` is available and the netem qdisc plus service-port filter
are installed successfully. The cleanup trap removes an active campaign qdisc
on normal exit, interruption, or error.

Each role writes raw schema-v8 native JSON, command-scoped qdisc evidence, and
a manifest binding those files by SHA-256. The manifest also records source,
campaign-runner, netem-runner, route, role, port, and schedule identity.

`analyze_native_loss_results.py` accepts a campaign only when both endpoint
manifests exist, their checksums and source provenance match, transport is
authenticated ZeroMQ CURVE, and every measured sample has an exact peer at the
other endpoint. It reports critical-arc median/P95, item throughput,
application goodput, and aggregate-verifier fallback count by configuration.
