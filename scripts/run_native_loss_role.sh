#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage:
  run_native_loss_role.sh server ROUTE CAMPAIGN_PREFIX AUTH_DIR
  run_native_loss_role.sh client ROUTE CAMPAIGN_PREFIX AUTH_DIR SERVER_IP

Run the native C/RELIC publication loss matrix. Start the server role first,
then the matching client role. Only the client applies netem, restricted to
the shared Pre-swap service port. LOSS_VALUES defaults to "0 2 5".
EOF
  exit 2
}

[[ $# -eq 4 || $# -eq 5 ]] || usage
ROLE=$1
ROUTE=$2
CAMPAIGN_PREFIX=$3
AUTH_DIR=$4
SERVER_IP=${5:-}
[[ $ROLE == server || $ROLE == client ]] || usage
[[ $ROUTE == eu_to_us || $ROUTE == sg_to_us ]] || usage
if [[ $ROLE == client ]]; then
  [[ $# -eq 5 && -n $SERVER_IP ]] || usage
else
  [[ $# -eq 4 ]] || usage
fi

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUTPUT_DIR=${OUTPUT_DIR:-"$ROOT/results/cloud/native-loss"}
BASE_PORT=${BASE_PORT:-9000}
LOSS_VALUES=${LOSS_VALUES:-"0 2 5"}
PARTICIPANTS=${PARTICIPANTS:-8}
PAIRS=${PAIRS:-1}
TRIALS=${TRIALS:-50}
WARMUP=${WARMUP:-5}
MODES=${MODES:-"reference-itemwise,phase-coalesced-itemwise,batch-joint-presigning-itemwise,phase-coalesced-batch-verification,batch-joint-presigning-batch-verification"}
mkdir -p "$OUTPUT_DIR"
ulimit -n 65535 2>/dev/null || true

NETWORK_INTERFACE=${NETWORK_INTERFACE:-}
if [[ $ROLE == client ]]; then
  if [[ -z $NETWORK_INTERFACE ]]; then
    NETWORK_INTERFACE=$(
      ip route get "$SERVER_IP" |
        awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
    )
  fi
  [[ -n $NETWORK_INTERFACE ]] || {
    echo "error: cannot determine client egress interface" >&2
    exit 1
  }
fi

cleanup() {
  if [[ $ROLE == client && -n $NETWORK_INTERFACE && ${NETEM_ACTIVE:-0} == 1 ]]; then
    PORT="$BASE_PORT" "$ROOT/scripts/cloud_netem_loss.sh" \
      clear "$NETWORK_INTERFACE" 0 >/dev/null 2>&1 || true
    NETEM_ACTIVE=0
  fi
}
trap cleanup EXIT INT TERM

NETEM_REQUIRED=0
for LOSS in $LOSS_VALUES; do
  [[ $LOSS =~ ^([0-9]+([.][0-9]+)?|[.][0-9]+)$ ]] || {
    echo "error: invalid loss percentage: $LOSS" >&2
    exit 2
  }
  if ! awk -v loss="$LOSS" 'BEGIN { exit(loss == 0 ? 0 : 1) }'; then
    NETEM_REQUIRED=1
  fi
done
if [[ $ROLE == client && $NETEM_REQUIRED == 1 ]]; then
  sudo -n true
fi

for LOSS in $LOSS_VALUES; do
  LOSS_CANON=$(awk -v loss="$LOSS" 'BEGIN { printf "%.12g", loss }')
  CAMPAIGN_ID="${CAMPAIGN_PREFIX}-loss${LOSS_CANON}"
  OUTPUT="$OUTPUT_DIR/${CAMPAIGN_ID}-${ROLE}.json"
  TC_EVIDENCE="$OUTPUT_DIR/${CAMPAIGN_ID}-${ROLE}-tc.txt"
  if [[ $ROLE == client ]]; then
    cleanup
    if awk -v loss="$LOSS" 'BEGIN { exit(loss == 0 ? 0 : 1) }'; then
      PORT="$BASE_PORT" "$ROOT/scripts/cloud_netem_loss.sh" \
        observe "$NETWORK_INTERFACE" "$LOSS_CANON" >"$TC_EVIDENCE"
    else
      PORT="$BASE_PORT" "$ROOT/scripts/cloud_netem_loss.sh" \
        apply "$NETWORK_INTERFACE" "$LOSS_CANON" >"$TC_EVIDENCE"
      NETEM_ACTIVE=1
    fi
  else
    printf 'role=server\nloss_applied_at=client-egress\nloss_pct=%s\n' \
      "$LOSS_CANON" >"$TC_EVIDENCE"
  fi

  ARGS=(
    --role "$ROLE"
    --route "$ROUTE"
    --campaign-id "$CAMPAIGN_ID"
    --auth-dir "$AUTH_DIR"
    --participants "$PARTICIPANTS"
    --concurrent-pairs "$PAIRS"
    --modes "$MODES"
    --trials "$TRIALS"
    --warmup "$WARMUP"
    --base-port "$BASE_PORT"
    --io-timeout-ms "${IO_TIMEOUT_MS:-900000}"
    --process-timeout-seconds "${PROCESS_TIMEOUT_SECONDS:-930}"
    --output "$OUTPUT"
  )
  if [[ $ROLE == server ]]; then
    ARGS+=(--bind 0.0.0.0)
  else
    ARGS+=(--host "$SERVER_IP")
  fi
  if [[ -n ${WORKER_COUNT:-} ]]; then
    ARGS+=(--worker-count "$WORKER_COUNT")
  fi
  if [[ -n ${MAX_QUEUE:-} ]]; then
    ARGS+=(--max-queue "$MAX_QUEUE")
  fi
  if [[ ${SKIP_BUILD:-0} == 1 ]]; then
    ARGS+=(--skip-build)
  fi

  python3 "$ROOT/scripts/run_cloud_campaign.py" "${ARGS[@]}"
  python3 "$ROOT/scripts/write_native_loss_manifest.py" \
    --role "$ROLE" --route "$ROUTE" --campaign-id "$CAMPAIGN_ID" \
    --loss-pct "$LOSS_CANON" --service-port "$BASE_PORT" \
    --result "$OUTPUT" --tc-evidence "$TC_EVIDENCE" \
    --out "$OUTPUT_DIR/${CAMPAIGN_ID}-${ROLE}-manifest.json"
done

cleanup
echo "native_loss_role_complete=$ROLE route=$ROUTE prefix=$CAMPAIGN_PREFIX"
