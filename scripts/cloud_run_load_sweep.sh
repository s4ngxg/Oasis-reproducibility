#!/usr/bin/env bash
set -euo pipefail

# Secondary C++/OpenSSL conformance load sweep, not a final native campaign.

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 SERVER_IP ROUTE" >&2
  exit 2
fi

SERVER_IP="$1"
ROUTE_LABEL="$2"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
CAMPAIGN="${CAMPAIGN_ID:-${ROUTE_LABEL}_load_${STAMP}}"

for pairs in ${PAIR_VALUES:-1 64 128 1024}; do
  OUT="$ROOT/results/cloud/load/${ROUTE_LABEL}_${STAMP}_p${pairs}.json" \
  PAIRS="$pairs" \
  N_VALUES="${N_VALUES:-8,16}" \
  VARIANTS="${VARIANTS:-persistent-pipelined-itemwise,batch-joint-presigning-itemwise,batch-joint-presigning-batch-verification,phase-coalesced-batch-verification,phase-coalesced-itemwise}" \
  TRIALS="${TRIALS:-20}" \
  WARMUP="${WARMUP:-5}" \
  IO_TIMEOUT_SECONDS="${IO_TIMEOUT_SECONDS:-600}" \
  CAMPAIGN_ID="$CAMPAIGN" \
  ALLOW_FAILURES=1 \
    "$ROOT/scripts/cloud_run_matrix.sh" "$SERVER_IP" "$ROUTE_LABEL"
done

echo "cloud_load=$ROOT/results/cloud/load/${ROUTE_LABEL}_${STAMP}_p*.json"
