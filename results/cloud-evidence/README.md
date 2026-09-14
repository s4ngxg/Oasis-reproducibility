# Cloud Evidence

This directory contains the complete machine-readable records copied from the
two-host campaigns used to produce the compact paper report. JSON files retain
per-trial measurements, endpoint metadata, source and binary digests, and
failure counters. PCAP files retain the corresponding packet captures.

The directory also preserves machine-readable diagnostic records from the same
cloud-results collection, including port-specific runs, later setup checks,
and local correctness summaries. These supplementary records are kept for
auditability but are not silently combined with the primary timing tables.

## Campaign groups

- `final/downloaded-eu-primary-*`: EU-to-US primary timing campaign.
- `final/downloaded-eu-load-*`: EU-to-US concurrent-load timing campaign.
- `final/downloaded-eu-allocation-*`: EU-to-US allocation profile.
- `final/downloaded-eu-syscall-*`: EU-to-US syscall profile.
- `final/downloaded-eu-pcap-*`: EU-to-US packet captures and packet analysis.
- `final/downloaded-sg-primary-*`: Singapore-to-US primary timing campaign.
- `final/downloaded-sg-load-*`: Singapore-to-US concurrent-load timing campaign.
- `final/downloaded-sg-allocation-*`: Singapore-to-US allocation profile.
- `final/downloaded-sg-syscall-*`: Singapore-to-US syscall profile.
- `final/downloaded-sg-pcap-*`: Singapore-to-US packet captures and packet analysis.
- `native-loss/downloaded-eu-loss-*`: EU-to-US loss campaign at 0%, 2%, and 5%.
- `native-loss/downloaded-sg-loss-*`: Singapore-to-US loss campaign at 0%, 2%, and 5%.

Additional files under `final/20260830-port9000/`, `final-20260910/`, and
`pilot-20260910T060304Z/` are supplementary diagnostics. They document setup,
alternate port routing, or later checks and are not inputs to the compact
primary report.

The compact report under `../paper-assets/` is generated from the twelve
analysis JSON files under `../raw-analysis/`. The raw records are preserved
without rewriting. Their original machine-generated campaign identifiers are
part of the provenance and must not be edited or interpreted as artifact
version labels.

## Verification

From the repository root:

```bash
(cd results/cloud-evidence && sha256sum -c SHA256SUMS.txt)
```

These records describe a two-host Pre-swap component measurement. They are not
evidence of public-chain execution, production ParaSwap deployment, fair
exchange, or concurrent-composition security.
