# Native Pre-swap protocol v4

This document is normative for the measured native client/server path. The
implementation is in `preswap_client_v4.c`, `preswap_server_v4.c`, and
`preswap_joint.c`. Cross-host load experiments additionally use
`preswap_gateway.c`: one CURVE ROUTER listens on one public service port and
admits each authenticated `(connection, pair_id, execution_id)` into a bounded
FIFO queue. An event loop dispatches each admitted session to exactly one member
of a fixed, long-lived, process-isolated RELIC worker pool over local IPC.
Session affinity lasts through the terminal frame; the worker is then reused.

## Canonical values

All integers in hashes are unsigned big-endian values. Every hash field is
encoded as an eight-byte big-endian length followed by exactly that many
bytes. Curve points use the pinned RELIC backend's canonical 33-byte compressed
secp256k1 encoding, including its field-representation compression flag; scalars use
32-byte big-endian encoding and must be in `[1,q-1]`. Each hash begins with its
domain string as the first length-prefixed field.

`OASIS-CONTEXT-v1` hashes, in order: protocol (`ParaSwap`), participant count,
epoch, expiry, pair ID, execution ID, arc index, and the 32-byte host
Preparation seed. `OASIS-ITEM-v1` hashes: context digest, item type, zero-based ordinal, zero-based address index,
timeout, 32-byte message digest, adaptor statement, client public key, server
public key, and joint public key. `OASIS-ORDERED-BATCH-v1` hashes the context,
item count, and every item digest in ordinal order. Parent and item SIDs bind
the context and ordered batch. `OASIS-SESSION-ID-v1` hashes the context digest,
batch digest, four-byte retry counter, optional parent SID, and optional failed
ordinal. `OASIS-ITEM-SESSION-ID-v1` hashes the context digest, batch digest,
item ordinal, item digest, four-byte retry counter, and parent SID.

`OASIS-VERIFIER-SALT-v1` hashes the verification purpose, active SID,
ordered-batch digest, and a fresh 32-byte random value. The three coefficient
domains are `OASIS-BATCH-COEFFICIENT-SERVER-PARTIAL-v1`,
`OASIS-BATCH-COEFFICIENT-CLIENT-PARTIAL-v1`, and
`OASIS-BATCH-COEFFICIENT-FULL-v1`. Each hashes, in this exact order: verifier
salt, active SID, ordered-batch digest, four-byte ordinal, item digest, client
nonce, server nonce, adaptor statement, client public key, server public key,
joint public key, challenge, server partial, client partial, and full scalar.

`OASIS-FINAL-STATUS-v1` hashes the canonical final-status payload as one
field. `OASIS-COMPLETION-v1` hashes the parent SID, ordered-batch digest, and
final-status digest. These are the values bound into the terminal completion
receipt; they are distinct from transport framing and journal metadata.

The deterministic known-answer vectors are enforced by
`joint_presign_test.c`. That test fails if field order, width, endian, point
encoding, or a domain tag changes.

## Successful exchange

1. The first `BATCH_INIT` carries the initiator's Preparation-bound Schnorr
   key-ownership proof, followed by the context digest, ordered-batch digest,
   and ordered item digests. Later item-wise `BATCH_INIT` frames omit the proof.
   No `BATCH_INIT` carries a nonce point or partial signature.
2. The first `SERVER_COMMIT` carries the responder's corresponding
   key-ownership proof and one Pedersen-style commitment per server nonce.
   Later item-wise `SERVER_COMMIT` frames omit the proof.
3. `CLIENT_NONCE` reveals the client nonce points only after the commitments
   have been received.
4. `SERVER_OPEN` reveals each server nonce, commitment opening, and server
   partial.
5. `CLIENT_FINAL` carries the client partials.
6. Aggregate-verification configurations additionally return
   `FINAL_STATUS`, including independent responder salts for the client-partial
   and full-pre-signature equations.
7. `DONE(parentSID,completionDigest)` confirms exactly the parent SID, ordered
   batch, and final-status digest.

Each proof is a canonical compressed secp256k1 commitment followed by a
32-byte scalar response. Its challenge uses
`OASIS-PREPARATION-KEY-OWNERSHIP-v1` and binds the 32-byte host Preparation
digest, endpoint role, pair ID, key epoch, public key, and proof commitment.
Both endpoints generate their proof before the measured protocol interval and
verify the peer proof while processing the first incoming frame. Piggybacking
the proofs adds bytes and measured verification work, but no logical frame or
causal phase.

Before a gateway forwards `DONE`, it validates the complete frame and commits it
to a mode-0700 completion journal with write, file `fsync`, atomic link, and
directory `fsync`. The record key is `(pair ID, execution ID, parent SID)`, and
the stored completion digest must match exactly. Re-storing the same record is
idempotent; a conflicting record is rejected. After persistence succeeds, the
gateway returns an internal acknowledgement bound to the same pair, execution,
SID, and completion digest. A pool worker does not mark the session complete or
return to the idle set until it validates that acknowledgement. The
acknowledgement exists only on the private gateway-to-worker IPC channel and is
not a public application frame, socket write, or WAN message.

If the initiator does not receive `DONE` before its acknowledgement timeout, it
retries with `COMPLETION_QUERY(parentSID, completionDigest)` on the authenticated
pair connection. The gateway accepts a query only from the route's authorized
CURVE identity and only for the configured pair/execution/SID tuple. It then
loads and validates the durable record before replaying the original `DONE`.
The client exports only after receiving a matching replay. This supports a
gateway restart when the same completion directory and campaign route manifest
are supplied; it does not promise simultaneous endpoint output or guaranteed
delivery past the host deadline.

### Endpoint completion trace and limits

| Event | Responder / gateway | Initiator |
| --- | --- | --- |
| CLIENT_FINAL validated | Responder has verified protocol state; no peer receipt is implied. | Has its local candidate/verification state, not a completion acknowledgement. |
| Worker sends DONE to gateway | Pool worker waits for a matching internal persistence ACK. | No new export permission. |
| Journal commit succeeds | Gateway can ACK the worker and forward DONE. Worker completion is not evidence that the initiator received DONE. | May still be waiting. |
| Matching DONE received | No new knowledge of peer host export. | Completion receipt is satisfied; enclosing host checks, complete-vector validation and local deadline still apply. |
| DONE lost | Durable receipt can remain after the gateway restarts. | Bounded completion queries can recover the receipt; timeout is not a refund authorization. |
| Query after restart | Recheck authorized route, pair/execution/SID, digest and stored item count; re-sync the record before replay. Reject mismatches or storage failure. | Accept only a matching receipt; never infer success from a transport reconnect. |

This trace describes the pool/gateway path. The direct server path returns from
its DONE send without a gateway persistence ACK and does not inherit this
journal guarantee. A completion record contains the DONE frame, not all
pre-signatures, host export state, secrets, or funded ledger state. It cannot
reconstruct a restarted initiator's lost candidate vector or recover an entire
host lifecycle. Replaying arbitrary CLIENT_FINAL messages is not a supported
substitute for the explicit completion-query mechanism.

The remaining safety claim is endpoint-local: a receipt alone does not authorize
an incomplete or expired honest-host export. Neither endpoint can conclude that
the other endpoint exported merely from its own completion. Simultaneous output,
guaranteed delivery and durable host-ledger recovery are not established by this
trace or by the gateway restart test.

The item-wise path therefore has six logical frames. The aggregate path has
seven. The persistent independent-item reference pipelines `k` INIT frames,
`k` commitments, `k` client nonce frames, `k` openings, and `k` final frames,
then receives one parent DONE: `5k+1` logical frames. A logical frame is not a
TCP segment, TLS record, socket write, or WAN round trip.

Synthetic public adaptor statements and the secondary Pedersen generator use
the artifact-defined SHA-256 try-and-increment map over secp256k1 with distinct
domain tags. The variable-time map handles only public benchmark inputs. Its
canonical output is covered by the joint-transcript KAT and is independent of
RELIC's configured `ec_map` implementation.

## Joint pre-signature

For client/server secrets `x_i,x_j`, nonce scalars `r_i,r_j`, public keys
`P_i=x_iG`, `P_j=x_jG`, adaptor statement `S`, and host transaction digest
`d`, the challenge is the unchanged ParaSwap-compatible hash of `d` and the
fixed-width field-element encoding of the x-coordinate of `R_i+R_j+S`. The
challenge intentionally does not use the length-prefixed Oasis transcript
grammar, because the published host verifier hashes this exact message-plus-x
encoding. The item digest remains a separate
transcript-binding value; it is not substituted for the chain message in the
signature challenge. The partials and full candidate are

```text
s_i = r_i - e*x_i mod q
s_j = r_j - e*x_j mod q
s   = s_i + s_j mod q
```

Thus `sG + e(P_i+P_j) + S = R_i+R_j+S`. The regression test feeds `(e,s)`
to the pinned ParaSwap `adaptor_schnorr_preverify` implementation using `d` as
the message, and explicitly rejects verification with the item digest.

## Aggregate verification

The initiator checks the server-partial vector. The responder independently
checks the client-partial and full-pre-signature vectors. Each equation has a
fresh 32-byte random salt and a distinct coefficient domain. Every coefficient
binds the salt, active SID, ordered-batch digest, item digest and ordinal, both
nonces, statement, all three public keys, challenge, and all three scalar
values. Each aggregate equation is one RELIC `ec_mul_sim_lot` call with
`2k+1` points. The successful full path therefore performs three calls and
`6k+3` point terms.

If an aggregate fails, the responder performs deterministic item-wise checks
only to identify invalid ordinals. The entire parent session then aborts and
does not emit DONE. A retry is a new parent session with a new SID; native v4
does not reuse valid cached items inside the failed parent.

An initiator that rejects `SERVER_OPEN` sends a parent-session `ABORT` and waits
for the responder's session-bound `ABORT` acknowledgement. A responder that
rejects an earlier frame sends `ABORT`; aggregate failure after `CLIENT_FINAL`
uses nonempty `FINAL_STATUS`. These terminal paths let the gateway retire the
route without relying on socket-close timing.

## Export and timing boundary

A malicious initiator can locally retain a candidate after `SERVER_OPEN`.
The enforceable invariant is that an honest wrapper exports no incomplete
vector to the ParaSwap host state machine. Each honest endpoint applies its own
monotonic local deadline; clocks need not be synchronized. Delay may cause
asymmetric completion and abort, which is a liveness outcome handled by the
outer refund state machine, not a fairness guarantee.

Completion records are retained for the configured experiment lifetime. A
production deployment needs an expiry-aware retention policy tied to the host
deadline; deleting a live record can reduce recovery availability but cannot
make a mismatched completion pass the client's digest check.
