# OASIS Reproducibility Artifact

This repository contains the source code and validation harness for the OASIS
Pre-swap coordination artifact. It integrates the OASIS session design with a
pinned ParaSwap adaptor-signature implementation and provides executable
correctness tests, lifecycle checks, local ablations, and scripts for the
two-host measurements reported by the paper.

The artifact is intended to be readable and runnable by an independent user.
It does not require private cloud credentials, wallet keys, or access to the
author's machines.

## Contents

- Native C11 ParaSwap-compatible Pre-swap adapter.
- RELIC curve arithmetic and multi-scalar multiplication (MSM) for randomized
  aggregate verification.
- ZeroMQ transport, including CURVE authentication for cross-host runs.
- Secondary C++/OpenSSL mutual-TLS conformance backend.
- Five controlled native configurations using one workload and backend.
- Lifecycle and ledger/VTD adapter tests for success, abort, Re-lock, refund,
  retry, replay, and invalid-input handling.
- Pinned upstream snapshots, source locks, campaign scripts, analysis scripts,
  and tests.
- Compact generated paper assets under `results/paper-assets/`.
- Complete JSON/PCAP cloud records under `results/cloud-evidence/`.

The raw cloud records are included as evidence assets rather than build inputs.
They are not required to build or test the implementation. Their campaign
classification and the distinction between primary and supplementary records
are documented in `results/cloud-evidence/README.md`.

## Scope

The primary measured component is the Pre-swap coordination layer. The
artifact exercises this logical lifecycle:

1. Preparation creates a directed participant cycle and public records.
2. Pre-swap creates an ordered adaptor pre-signature vector per directed pair.
3. Witness Sharing supplies witnesses to the lifecycle adapter.
4. Swap withdraws after complete sharing, or follows the timed Re-lock path.
5. Refund returns assets that remain locked after the applicable deadline.

The ledger and verifiable timed discrete logarithm (VTD) components are
deterministic state-machine adapters. They are not blockchain nodes and do not
submit funded public-chain transactions. The benchmark uses deterministic
synthetic host seed and workload inputs; it does not implement production
chain-specific transaction serialization or RPC submission.

The artifact supports claims about transcript-bound Pre-swap execution,
compatibility with the pinned ParaSwap verifier, randomized aggregate
verification, honest-wrapper export gating, controlled lifecycle conformance,
and two-host component performance. It does not claim a production ParaSwap
deployment, fair exchange, universal composability, adaptive-corruption
security, or a general concurrent-composition theorem. High-load campaigns
measure capacity and performance, not security under concurrent composition.

## Terminology and versions

- **BJP** means Batch Joint Pre-signing: one ordered parent session covers a
  vector of items.
- **MSM** means multi-scalar multiplication over public verification inputs.
- **SID** means session identifier.
- **CURVE** is ZeroMQ's public-key authentication mechanism.
- **Pre-swap** is the component before Witness Sharing and Swap.

Protocol documentation uses `v4` for the wire revision. Raw campaign names
such as `preswap-eu-primary-v3-final` are immutable identifiers recorded when
the measurements ran; they are not artifact or product version names.

## Compared configurations

All configurations use the same curve, key fixtures, key derivation, joint
Schnorr equations, canonical transcript, workload, compiler path, and native
transport.

| Configuration | Session organization | Verification |
| --- | --- | --- |
| `reference-itemwise` | Independent item sessions on one persistent stream | Item-wise |
| `phase-coalesced-itemwise` | Independent item sessions grouped by phase | Item-wise |
| `batch-joint-presigning-itemwise` | One BJP session for the ordered vector | Item-wise |
| `phase-coalesced-batch-verification` | Independent item sessions grouped by phase | Randomized aggregate MSM |
| `batch-joint-presigning-batch-verification` | One BJP session for the ordered vector | Randomized aggregate MSM |

`reference-itemwise` is an artifact-defined same-backend comparator. It is not
presented as the original ParaSwap wire implementation.

## Repository layout

```text
Makefile                         Build and test entry points
src/                             Lifecycle coordinator and adapters
scripts/                         Campaign, analysis, and packaging tools
tests/                           Python regression tests
vendor/paraswap/                 Pinned ParaSwap source and native integration
vendor/oasis-linear/             Pinned conformance core and transport
vendor/*.lock.json               Upstream provenance and SHA-256 locks
config/                          Non-secret campaign templates
docs/                            Protocol, deployment, and evidence details
results/                         Generated reports and compact paper assets
LICENSE, NOTICE.md               License and third-party notices
```

Build trees, dependency caches, credentials, private keys, logs, and packet
captures are intentionally excluded from the source artifact.

## Requirements

The supported platform is Linux; Ubuntu is the tested environment. The
bootstrap script installs or checks CMake, GCC/build tools, Git, Python 3, GMP,
PARI/GP, OpenSSL, ZeroMQ, SciPy, Matplotlib, and optional profiling tools. It
fetches RELIC at the pinned commit and builds it into a repository-local
dependency prefix.

The bootstrap step requires Internet access and root or passwordless `sudo`.
Subsequent local tests do not reinstall dependencies.

## Quick start

On a fresh Ubuntu host:

```bash
make reproduce-smoke
```

On an already bootstrapped host:

```bash
make verify
make test
```

`make test` runs the Python suite, native cryptographic tests, canonical
encoding and mutation checks, reduced differential/fault checks, lifecycle
checks, authenticated transport tests, replay tests, and all five native
configurations. A failed assertion or unavailable required input produces a
nonzero exit status.

For a shorter local validation after dependencies are installed:

```bash
make smoke
```

## Local lifecycle and ablation

Run one native lifecycle:

```bash
python3 src/paraswap_lifecycle.py \
  --participants 5 \
  --backend native \
  --mode batch-joint-presigning-batch-verification \
  --output results/local-lifecycle.json
```

Run the five-cell paired ablation:

```bash
python3 scripts/run_local_ablation.py \
  --participants 3,5,8,16 \
  --trials 10 \
  --warmup 2 \
  --output results/local-ablation.json
```

The output records paired samples, latency, throughput, logical frames,
sessions, MSM calls, verifier fallbacks, source hashes, and effect summaries.
Local measurements are not WAN or public-chain measurements.

The lifecycle runner also supports controlled failures such as
`--fault preswap`, `--fault invalid-final`, `--fault peer-abort`, and
`--fault witness`.

## Native cryptographic validation

```bash
make native-exhaustive
make native-fault
make native-handoff
```

The exhaustive campaign checks valid and mutated server-partial,
client-partial, and full-pre-signature equations, canonical subranges, exact
item localization, and compatibility with ParaSwap's unchanged verifier. Use
`make test` for a reduced regression run.

## Two-host campaign

The native runner uses one CURVE-authenticated responder port and a bounded
worker queue. Concurrent pair sessions connect to the same service port. The
cloud firewall should allow that port only from the active client's address.
Private CURVE keys must be generated outside the repository and must never be
committed.

See `docs/CLOUD_DEPLOYMENT.md` for the complete procedure. Main entry points:

```bash
python3 scripts/run_cloud_campaign.py --help
bash scripts/run_final_evidence_role.sh --help
bash scripts/run_native_loss_role.sh --help
```

Run geographic routes as separate campaigns. Keep primary timing, allocation,
syscall, packet-capture, and loss outputs separate. Instrumented profile timing
must not be merged into primary latency evidence.

No cloud IP address, SSH key, TLS credential, or CURVE secret is stored in this
repository.

## Analysis and paper regeneration

Analyze campaign outputs with:

```bash
python3 scripts/analyze_cloud_results.py --help
python3 scripts/analyze_system_profiles.py --help
python3 scripts/analyze_native_loss_results.py --help
```

After the required analysis files are available, generate reader-facing
tables, figures, checksums, and the claim-to-evidence map with:

```bash
bash scripts/regenerate_compact_report.sh
```

Use `python3 scripts/build_final_experiment_report.py --help` when supplying
different evidence paths or a new campaign.

The report builder is schema-gated. It checks campaign metadata, source and
binary hashes, schedules, failure counts, and systems evidence. Results from
different source snapshots or binaries must not be combined or relabeled.

`results/paper-assets/` contains the compact generated report used by
the manuscript snapshot. Its `SHA256SUMS.txt` and `CLAIM_TO_EVIDENCE.json`
identify its generated files and analysis inputs. The complete raw cloud
records are under `results/cloud-evidence/` with a separate checksum manifest.
The source archive produced by `make package` intentionally excludes all
generated results; publish the raw cloud directory as a separate checksummed
release asset because individual JSON files exceed ordinary Git hosting
limits. Create that asset with:

```bash
SOURCE_DATE_EPOCH=0 make package-evidence
```

## Provenance

- ParaSwap artifact DOI: `10.5281/zenodo.15594022`
- ParaSwap source commit: `e817a33cf8d1efa54cc06d41927f82b0f3e4f4d2`
- OASIS linear-core commit: `b74cadf867add445b8e02fffdb2cd79a42bd78aa`
- RELIC commit: `e8b13783dbbe120cff5a68ff460f3bb9bec69666`

`vendor/paraswap-artifact.lock.json` and `vendor/oasis-linear.lock.json`
distinguish byte-identical upstream files from integration-specific changes.
The top-level source manifest identifies every source and documentation file.
Generated paper assets and cloud evidence have manifests in their respective
directories.

## Packaging

Create a deterministic source archive outside the repository:

```bash
SOURCE_DATE_EPOCH=0 make package
```

Create one complete artifact archive containing source, compact paper assets,
analysis inputs, and all raw cloud JSON/PCAP records:

```bash
SOURCE_DATE_EPOCH=0 make package-complete
```

The packager excludes Git metadata, dependencies, build outputs, generated
binaries, credentials, packet captures, logs, and cloud results. It retains
the pinned upstream test-vector keys required by the original tests; these are
fixtures, not deployment credentials. A SHA-256 file is written next to the
archive.

## Limitations

- Production Preparation transcript serialization is not implemented.
- Chain-specific transaction serialization and public RPC submission are not
  implemented.
- The ledger/VTD layer is an adapter, not a public blockchain.
- Security is conditional wrapper-level refinement under the stated security
  properties of the underlying two-party adaptor-signature protocol.
- A corrupted initiator may retain a locally computable candidate before the
  honest wrapper export gate; the artifact does not provide fair exchange.
- High-load experiments do not establish concurrent-composition security.
- The native server keeps completed replay records in a bounded in-process
  retention store when the hot session cache is pressured; if both bounds are
  full, it rejects a new session before nonce generation. Direct-server replay
  retention does not survive process restart; production restart recovery needs
  expiry-aware durable tombstones.
- Evidence from a different binary, commit, schedule, or environment requires
  a new manifest and analysis.

## License

Original integration code and documentation are under the MIT License in
`LICENSE`. Vendored components retain upstream terms; see `NOTICE.md` and the
files below `vendor/`.
