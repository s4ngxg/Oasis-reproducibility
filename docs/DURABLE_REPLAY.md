# Durable phase replay

The OASIS conformance transport supports a replay journal with
`--replay-journal PATH`. The supplied cloud-server launcher enables it by
default; local callers may pass the option explicitly. The server stores an atomic record for each
`(SID, logical_id, phase)` request and response. A reconnect must present the
same request bytes; an exact request receives the cached response and a
different request is rejected.

The journal covers `INIT/COMMIT`, `CLIENT_NONCE/SERVER_OPEN`, and
`CLIENT_FINAL/FINAL_STATUS` (an empty response is valid for an item-wise final).
Records are written to a temporary file, flushed and `fsync`ed, renamed into
place, and followed by a directory `fsync`. They therefore survive a normal
process restart. The journal is intentionally append-by-key and is not
garbage-collected automatically: the deployer must retain records through the
configured replay-validity and timeout window before archival/deletion.

The regression gate is:

```bash
python3 scripts/test_durable_phase_replay.py
```

It runs an exact transcript once, stops the server, starts a fresh server with
the same journal, and replays the transcript. The gate also verifies that
exactly three phase records exist. This is replay/idempotence evidence for the
OASIS conformance transport; it is not a phase-replay guarantee for the
separate native C11 direct-server path, not a cryptographic composition proof,
and not a proof of host-level ParaSwap atomicity. The native path's durable
guarantee is limited to the completion journal documented in
`docs/NATIVE_PROTOCOL_V4.md`.
