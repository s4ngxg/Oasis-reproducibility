# Generated evidence

Benchmark commands write raw JSON and Markdown summaries to this directory.
Generated files are intentionally excluded from the source archive unless
they are small, sanitized analysis snapshots or compact paper assets.

`cloud-evidence/` contains the complete JSON and PCAP records copied from the
cloud-results directory. `cloud-evidence/README.md` identifies the primary final
campaigns used by the compact report and separates them from diagnostic,
pilot, port-specific, and local regression records. The files are preserved
without rewriting; `cloud-evidence/SHA256SUMS.txt` provides byte-level checksums.

`raw-analysis/` contains the twelve small analysis inputs used by the compact
report snapshot: four timing analyses, four systems-profile analyses, and four
packet-accounting analyses. They contain no credentials or cloud addresses.
Run `bash scripts/regenerate_compact_report.sh` from the repository root to
regenerate the compact tables, figures, checksums, and claim manifest from
those inputs. Full raw JSON and packet captures are distributed separately
from the source-only archive; create that release asset with
`make package-evidence`.

The primary native C11/RELIC evidence uses exactly these five behavior-based
configuration names:

- `reference-itemwise`
- `phase-coalesced-itemwise`
- `batch-joint-presigning-itemwise`
- `phase-coalesced-batch-verification`
- `batch-joint-presigning-batch-verification`

The secondary C++/OpenSSL conformance suite uses
`persistent-pipelined-itemwise` for its own independent-session reference. Its
schema and results are not interchangeable with the primary native evidence.

Historical development evidence is preserved outside this source tree and is
not silently rewritten, because changing raw measurement records would break
their provenance.

Primary `oasis-preswap-cloud-v8` timing evidence must use authenticated ZeroMQ
CURVE and `profiling_mode=timing`. Allocation/syscall JSON and PCAP summaries
are separate evidence classes and must not be merged into primary latency.

Files carrying an earlier cloud schema are historical development evidence.
They predate the final one-port routing, position-counterbalanced schedule, or
mode-separated execution identifiers and must not support final paper claims.
