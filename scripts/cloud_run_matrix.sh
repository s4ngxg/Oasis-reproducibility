#!/usr/bin/env bash
set -euo pipefail

# Secondary C++/OpenSSL mutual-TLS conformance launcher. Its output must not be
# mixed with the primary native C11/RELIC cloud evidence.

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 SERVER_IP ROUTE" >&2
  exit 2
fi

SERVER_IP="$1"
ROUTE_LABEL="$2"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OASIS="$ROOT/vendor/oasis-linear"
BIN="$OASIS/bin/oasis_transport"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${OUT:-$ROOT/results/cloud/${ROUTE_LABEL}_${STAMP}.json}"

mkdir -p "$(dirname "$OUT")"
ulimit -n "${NOFILE_LIMIT:-65535}" 2>/dev/null || true
make -C "$OASIS" -j "${BUILD_JOBS:-2}"

ARGS=(
  client
  --host "$SERVER_IP"
  --port "${PORT:-9300}"
  --n-values "${N_VALUES:-3,5,8,16}"
  --variants "${VARIANTS:-persistent-pipelined-itemwise,batch-joint-presigning-itemwise,batch-joint-presigning-batch-verification,phase-coalesced-batch-verification,phase-coalesced-itemwise}"
  --pairs "${PAIRS:-1}"
  --trials "${TRIALS:-100}"
  --warmup "${WARMUP:-10}"
  --threads "${THREADS:-2}"
  --io-timeout-seconds "${IO_TIMEOUT_SECONDS:-600}"
  --listen-backlog "${LISTEN_BACKLOG:-4096}"
  --pair-thread-stack-kb "${PAIR_THREAD_STACK_KB:-128}"
  --campaign-id "${CAMPAIGN_ID:-${ROUTE_LABEL}_${STAMP}}"
  --route "$ROUTE_LABEL"
  --loss-pct "${LOSS_PCT:-0}"
  --fault-profile "${FAULT_PROFILE:-none}"
  --fault-scope "${FAULT_SCOPE:-none}"
  --out "$OUT"
)

if [[ "${TLS:-1}" == "1" ]]; then
  ARGS+=(
    --tls --mutual-tls
    --cert "${TLS_CERT:-$ROOT/tls/client.crt}"
    --key "${TLS_KEY:-$ROOT/tls/client.key}"
    --ca "${TLS_CA:-$ROOT/tls/ca.crt}"
    --server-name "${SERVER_NAME:-$SERVER_IP}"
  )
fi
if [[ "${ALLOW_FAILURES:-0}" == "1" ]]; then
  ARGS+=(--allow-failures)
fi
if [[ "${INJECT_BAD_CLIENT_PARTIALS:-0}" != "0" ]]; then
  ARGS+=(--inject-bad-client-partials "${INJECT_BAD_CLIENT_PARTIALS}")
fi

"$BIN" "${ARGS[@]}"
echo "cloud_matrix=$OUT"
