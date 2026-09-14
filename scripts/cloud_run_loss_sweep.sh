#!/usr/bin/env bash
set -euo pipefail

# Secondary C++/OpenSSL conformance loss sweep, not a final native campaign.

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 SERVER_IP ROUTE" >&2
  exit 2
fi

SERVER_IP="$1"
ROUTE_LABEL="$2"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
CAMPAIGN="${CAMPAIGN_ID:-${ROUTE_LABEL}_loss_${STAMP}}"
INTERFACE="${INTERFACE:-$(ip route get "$SERVER_IP" | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')}"
EVIDENCE="$ROOT/results/cloud/loss/${ROUTE_LABEL}_${STAMP}_tc"
mkdir -p "$EVIDENCE"
tc -s qdisc show dev "$INTERFACE" > "$EVIDENCE/qdisc_before.txt"

cleanup() {
  "$ROOT/scripts/cloud_netem_loss.sh" clear "$INTERFACE" 0 || true
}
trap cleanup EXIT INT TERM

for loss in ${LOSS_VALUES:-0 2 5}; do
  cleanup
  "$ROOT/scripts/cloud_netem_loss.sh" apply "$INTERFACE" "$loss" \
    > "$EVIDENCE/qdisc_loss_${loss}.txt"
  OUT="$ROOT/results/cloud/loss/${ROUTE_LABEL}_${STAMP}_loss${loss}.json" \
  N_VALUES="${N_VALUES:-8}" \
  PAIRS="${PAIRS:-1}" \
  VARIANTS="${VARIANTS:-persistent-pipelined-itemwise,batch-joint-presigning-itemwise,batch-joint-presigning-batch-verification,phase-coalesced-batch-verification,phase-coalesced-itemwise}" \
  TRIALS="${TRIALS:-50}" \
  WARMUP="${WARMUP:-5}" \
  LOSS_PCT="$loss" \
  FAULT_PROFILE="loss${loss}" \
  FAULT_SCOPE="client-egress" \
  CAMPAIGN_ID="$CAMPAIGN" \
    "$ROOT/scripts/cloud_run_matrix.sh" "$SERVER_IP" "$ROUTE_LABEL"
done

cleanup
tc -s qdisc show dev "$INTERFACE" > "$EVIDENCE/qdisc_after.txt"
echo "cloud_loss=$ROOT/results/cloud/loss/${ROUTE_LABEL}_${STAMP}_loss*.json"
