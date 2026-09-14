# Notices and provenance

The integration coordinator, protocol adapter, tests, and documentation in this
directory were developed for the OASIS evaluation and are distributed under the
top-level MIT license.

`vendor/paraswap` contains source and binary dependencies copied from the
ParaSwap USENIX Security 2025 reproducibility artifact. Its provenance is
recorded in `vendor/paraswap-artifact.lock.json`; upstream licensing terms apply
to those files. No new license is asserted over the vendored upstream work.

The integration does not claim that its deterministic ledger and verifiable
timed discrete logarithm adapters are public blockchain implementations.

`vendor/oasis-linear` contains the pinned OASIS linear Schnorr cryptographic
core from source commit
`b74cadf867add445b8e02fffdb2cd79a42bd78aa`. Its file hashes are recorded in
`vendor/oasis-linear.lock.json`; the included MIT license applies to that core.
