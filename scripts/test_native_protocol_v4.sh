#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TPC_DIR="$ROOT_DIR/vendor/paraswap/two-party computation"
CLIENT="$TPC_DIR/bin/preswap_client"
SERVER="$TPC_DIR/bin/preswap_server"
COUNT="${COUNT:-5}"
PARTICIPANTS="${PARTICIPANTS:-3}"
BASE_PORT="${BASE_PORT:-19840}"
SEED="${CONTEXT_SEED_HEX:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
TMP_DIR="$(mktemp -d)"

MODES=(
  reference-itemwise
  phase-coalesced-itemwise
  batch-joint-presigning-itemwise
  phase-coalesced-batch-verification
  batch-joint-presigning-batch-verification
)

cleanup() {
  local pid
  for pid in $(jobs -pr); do kill "$pid" 2>/dev/null || true; done
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

if [[ "$COUNT" -ne $((2 * PARTICIPANTS - 1)) ]]; then
  echo "COUNT must equal 2*PARTICIPANTS-1" >&2
  exit 2
fi

cd "$TPC_DIR"

for index in "${!MODES[@]}"; do
  mode="${MODES[$index]}"
  port=$((BASE_PORT + index))
  common=(
    --mode "$mode"
    --count "$COUNT"
    --context-participants "$PARTICIPANTS"
    --context-epoch 7
    --context-expiry 3600
    --context-arc-index 1
    --context-seed-hex "$SEED"
    --execution-id 42
    --pair-id 0
    --port "$port"
    --io-timeout-ms 10000
  )

  "$SERVER" "${common[@]}" >"$TMP_DIR/$mode.server" 2>&1 &
  server_pid=$!
  sleep 0.15
  if ! "$CLIENT" "${common[@]}" >"$TMP_DIR/$mode.client" 2>&1; then
    cat "$TMP_DIR/$mode.server" >&2 || true
    cat "$TMP_DIR/$mode.client" >&2 || true
    exit 1
  fi
  if ! wait "$server_pid"; then
    cat "$TMP_DIR/$mode.server" >&2 || true
    cat "$TMP_DIR/$mode.client" >&2 || true
    exit 1
  fi

  grep -q '^RESULT' "$TMP_DIR/$mode.client"
  grep -q '^SERVER_RESULT' "$TMP_DIR/$mode.server"
  if [[ "$mode" == *batch-verification ]]; then
    grep -q '^CLIENT_VERIFIER_AUDIT' "$TMP_DIR/$mode.client"
    grep -q '^SERVER_VERIFIER_AUDIT' "$TMP_DIR/$mode.server"
  fi
  printf 'PASS\t%s\n' "$mode"
done

mode=batch-joint-presigning-batch-verification
port=$((BASE_PORT + 20))
fault_common=(
  --mode "$mode"
  --count "$COUNT"
  --context-participants "$PARTICIPANTS"
  --context-epoch 7
  --context-expiry 3600
  --context-arc-index 1
  --context-seed-hex "$SEED"
  --execution-id 43
  --pair-id 0
  --port "$port"
  --io-timeout-ms 2000
)
"$SERVER" "${fault_common[@]}" >"$TMP_DIR/fault.server" 2>&1 &
server_pid=$!
sleep 0.15
set +e
"$CLIENT" "${fault_common[@]}" --inject-bad-final \
  >"$TMP_DIR/fault.client" 2>&1
client_rc=$?
wait "$server_pid"
server_rc=$?
set -e
if [[ "$client_rc" -eq 0 || "$server_rc" -eq 0 ]]; then
  cat "$TMP_DIR/fault.server" >&2 || true
  cat "$TMP_DIR/fault.client" >&2 || true
  echo "mutated client partial was not rejected" >&2
  exit 1
fi
printf 'PASS\tmutated-client-partial-rejected\n'

port=$((BASE_PORT + 21))
proof_common=(
  --mode "$mode"
  --count "$COUNT"
  --context-participants "$PARTICIPANTS"
  --context-epoch 7
  --context-expiry 3600
  --context-arc-index 1
  --context-seed-hex "$SEED"
  --execution-id 44
  --pair-id 0
  --port "$port"
  --io-timeout-ms 2000
)
"$SERVER" "${proof_common[@]}" >"$TMP_DIR/proof.server" 2>&1 &
server_pid=$!
sleep 0.15
set +e
"$CLIENT" "${proof_common[@]}" --inject-bad-preparation-proof \
  >"$TMP_DIR/proof.client" 2>&1
client_rc=$?
wait "$server_pid"
server_rc=$?
set -e
if [[ "$client_rc" -eq 0 || "$server_rc" -eq 0 ]]; then
  cat "$TMP_DIR/proof.server" >&2 || true
  cat "$TMP_DIR/proof.client" >&2 || true
  echo "mutated Preparation key-ownership proof was not rejected" >&2
  exit 1
fi
printf 'PASS\tmutated-preparation-key-proof-rejected\n'

echo "Native protocol v4 smoke test passed."
