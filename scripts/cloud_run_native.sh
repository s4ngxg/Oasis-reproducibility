#!/usr/bin/env bash
set -euo pipefail

# Secondary C++/OpenSSL conformance launcher. This is not the primary native
# C11/RELIC ParaSwap timing path; use run_final_evidence_role.sh for that path.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OASIS="$ROOT/vendor/oasis-linear"
OUT="${OUT:-$ROOT/results/cloud/native_final.json}"

mkdir -p "$(dirname "$OUT")"
make -C "$OASIS" -j "${BUILD_JOBS:-2}"
"$OASIS/bin/oasis_transport" local \
  --n-values "${N_VALUES:-3,5,8,16}" \
  --variants "${VARIANTS:-persistent-pipelined-itemwise,batch-joint-presigning-itemwise,batch-joint-presigning-batch-verification,phase-coalesced-batch-verification,phase-coalesced-itemwise}" \
  --trials "${TRIALS:-100}" \
  --warmup "${WARMUP:-10}" \
  --campaign-id "${CAMPAIGN_ID:-native_final}" \
  --route local \
  --out "$OUT"
echo "native_matrix=$OUT"
