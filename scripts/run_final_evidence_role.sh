#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage:
  run_final_evidence_role.sh server ROUTE PROFILE CAMPAIGN_ID AUTH_DIR
  run_final_evidence_role.sh client ROUTE PROFILE CAMPAIGN_ID AUTH_DIR SERVER_IP

PROFILE is one of: primary, load, allocation, syscall, pcap.
Set DRY_RUN=1 to print and validate the schedule without starting it.
All profiles use public service port 9000 by default and must run sequentially.
Set BASE_PORT=N only when the deployment requires a different single port.
Set WORKER_COUNT=W to fix the responder pool size (default: responder CPU count).
Set MAX_QUEUE=Q to fix bounded admission capacity (default: full stage load).
EOF
  exit 2
}

[[ $# -eq 5 || $# -eq 6 ]] || usage
ROLE=$1
ROUTE=$2
PROFILE=$3
CAMPAIGN_ID=$4
AUTH_DIR=$5
SERVER_IP=${6:-}

[[ $ROLE == server || $ROLE == client ]] || usage
[[ $ROUTE == eu_to_us || $ROUTE == sg_to_us ]] || usage
if [[ $ROLE == client ]]; then
  [[ $# -eq 6 && -n $SERVER_IP ]] || usage
else
  [[ $# -eq 5 ]] || usage
fi
[[ -d $AUTH_DIR ]] || {
  echo "error: missing role-specific CURVE credential directory: $AUTH_DIR" >&2
  exit 1
}

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUTPUT_DIR="$ROOT/results/cloud/final"
mkdir -p "$OUTPUT_DIR"
ulimit -n 65535 2>/dev/null || true

BASE_PORT_OVERRIDE=${BASE_PORT:-}
DEFAULT_SERVICE_PORT=9000
if [[ -n $BASE_PORT_OVERRIDE ]]; then
  [[ $BASE_PORT_OVERRIDE =~ ^[0-9]+$ ]] &&
    (( BASE_PORT_OVERRIDE >= 1024 && BASE_PORT_OVERRIDE <= 65535 )) || {
      echo "error: BASE_PORT must be an integer in [1024, 65535]" >&2
      exit 2
    }
fi

ARGS=(
  --role "$ROLE"
  --route "$ROUTE"
  --campaign-id "$CAMPAIGN_ID"
  --auth-dir "$AUTH_DIR"
  --io-timeout-ms 900000
  --process-timeout-seconds 930
  --output "$OUTPUT_DIR/${CAMPAIGN_ID}-${ROLE}.json"
)

if [[ $ROLE == server ]]; then
  ARGS+=(--bind 0.0.0.0)
else
  ARGS+=(--host "$SERVER_IP")
fi

case "$PROFILE" in
  primary)
    ARGS+=(
      --participants 3,5,8,16
      --concurrent-pairs 1
      --trials 100
      --warmup 10
    )
    ;;
  load)
    ARGS+=(
      --participants 8,16
      --concurrent-pairs 1,64,128,1024
      --trials 20
      --warmup 5
    )
    ;;
  allocation)
    ARGS+=(
      --participants 8,16
      --concurrent-pairs 1,128
      --trials 10
      --warmup 2
      --profiling-mode allocation
    )
    ;;
  syscall)
    ARGS+=(
      --participants 8
      --concurrent-pairs 1,128
      --trials 5
      --warmup 1
      --profiling-mode syscall
      --profile-output-dir "$OUTPUT_DIR/${CAMPAIGN_ID}-${ROLE}-syscalls"
    )
    ;;
  pcap)
    ARGS+=(
      --participants 8
      --concurrent-pairs 1
      --trials 20
      --warmup 5
    )
    ;;
  *)
    usage
    ;;
esac

ARGS+=(--base-port "${BASE_PORT_OVERRIDE:-$DEFAULT_SERVICE_PORT}")
if [[ -n ${WORKER_COUNT:-} ]]; then
  ARGS+=(--worker-count "$WORKER_COUNT")
fi
if [[ -n ${MAX_QUEUE:-} ]]; then
  ARGS+=(--max-queue "$MAX_QUEUE")
fi

if [[ ${DRY_RUN:-0} == 1 ]]; then
  ARGS+=(--dry-run)
fi

exec python3 "$ROOT/scripts/run_cloud_campaign.py" "${ARGS[@]}"
