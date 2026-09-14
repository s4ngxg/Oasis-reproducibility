#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage:
  run_reduced_wan_role.sh server ROUTE CAMPAIGN_ID AUTH_DIR
  run_reduced_wan_role.sh client ROUTE CAMPAIGN_ID AUTH_DIR SERVER_IP

ROUTE must be eu_to_us or sg_to_us. Start the server role first, then run the
matching client role. Both roles must use the same campaign ID and overrides.

Optional environment overrides:
  BASE_PORT=9000 TRIALS=5 WARMUP=1 WORKER_COUNT=N MAX_QUEUE=N
EOF
  exit 2
}

[[ $# -eq 4 || $# -eq 5 ]] || usage
ROLE=$1
ROUTE=$2
CAMPAIGN_ID=$3
AUTH_DIR=$4
SERVER_IP=${5:-}

[[ $ROLE == server || $ROLE == client ]] || usage
[[ $ROUTE == eu_to_us || $ROUTE == sg_to_us ]] || usage
[[ $CAMPAIGN_ID =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$ ]] || {
  echo "error: campaign ID must be 1-128 letters, digits, underscores or hyphens, starting with a letter or digit" >&2
  exit 2
}
if [[ $ROLE == client ]]; then
  [[ $# -eq 5 && -n $SERVER_IP ]] || usage
else
  [[ $# -eq 4 ]] || usage
fi
[[ -d $AUTH_DIR ]] || {
  echo "error: missing role-specific CURVE credential directory: $AUTH_DIR" >&2
  exit 1
}

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUT="$ROOT/results/cloud/reduced"
mkdir -p "$OUT"
RESULT="$OUT/${CAMPAIGN_ID}-${ROLE}.json"
exec 9>"$RESULT.lock"
if ! flock -n 9; then
  echo "error: campaign role is already running: $CAMPAIGN_ID-$ROLE" >&2
  exit 1
fi
if [[ -e $RESULT || -L $RESULT ]]; then
  echo "error: result already exists; choose a new campaign ID: $RESULT" >&2
  exit 1
fi
ulimit -n 4096 2>/dev/null || true

ARGS=(
  --role "$ROLE"
  --route "$ROUTE"
  --campaign-id "$CAMPAIGN_ID"
  --participants 3,8
  --concurrent-pairs 1
  --trials "${TRIALS:-5}"
  --warmup "${WARMUP:-1}"
  --base-port "${BASE_PORT:-9000}"
  --io-timeout-ms 120000
  --process-timeout-seconds 150
  --auth-dir "$AUTH_DIR"
  --output "$RESULT"
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
if [[ ${DRY_RUN:-0} == 1 ]]; then
  ARGS+=(--dry-run)
fi

exec python3 "$ROOT/scripts/run_cloud_campaign.py" "${ARGS[@]}"
