#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INPUTS="$ROOT/results/raw-analysis"
OUTPUT="${1:-$ROOT/results/paper-assets}"

for file in \
  eu_primary.json eu_load.json sg_primary.json sg_load.json \
  eu_allocation.json sg_allocation.json eu_syscall.json sg_syscall.json \
  eu_client_pcap.json eu_server_pcap.json sg_client_pcap.json sg_server_pcap.json
do
  if [[ ! -f "$INPUTS/$file" ]]; then
    echo "error: missing analysis input $INPUTS/$file" >&2
    exit 1
  fi
done

python3 "$ROOT/scripts/build_final_experiment_report.py" \
  --timing "eu_primary=$INPUTS/eu_primary.json" \
  --timing "eu_load=$INPUTS/eu_load.json" \
  --timing "sg_primary=$INPUTS/sg_primary.json" \
  --timing "sg_load=$INPUTS/sg_load.json" \
  --system "eu_allocation=$INPUTS/eu_allocation.json" \
  --system "sg_allocation=$INPUTS/sg_allocation.json" \
  --system "eu_syscall=$INPUTS/eu_syscall.json" \
  --system "sg_syscall=$INPUTS/sg_syscall.json" \
  --pcap "eu_client=$INPUTS/eu_client_pcap.json" \
  --pcap "eu_server=$INPUTS/eu_server_pcap.json" \
  --pcap "sg_client=$INPUTS/sg_client_pcap.json" \
  --pcap "sg_server=$INPUTS/sg_server_pcap.json" \
  --out-dir "$OUTPUT"

echo "compact report: $OUTPUT"
