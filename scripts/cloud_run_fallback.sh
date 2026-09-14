#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OASIS="$ROOT/vendor/oasis-linear"
OUT="${OUT:-$ROOT/results/cloud/fallback_final.json}"

mkdir -p "$(dirname "$OUT")"
make -C "$OASIS" -j "${BUILD_JOBS:-2}"
"$OASIS/bin/oasis_transport" fallback \
  --n-values "${N_VALUES:-3,5,8,16}" \
  --variants batch-joint-presigning-batch-verification \
  --trials "${TRIALS:-100}" \
  --warmup "${WARMUP:-10}" \
  --campaign-id "${CAMPAIGN_ID:-fallback_final}" \
  --route local \
  --fault-profile selective-retry \
  --fault-scope item \
  --out "$OUT"
echo "fallback_matrix=$OUT"
