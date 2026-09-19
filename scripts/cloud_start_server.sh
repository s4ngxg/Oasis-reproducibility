#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OASIS="$ROOT/vendor/oasis-linear"
BIN="$OASIS/bin/oasis_transport"

mkdir -p "$ROOT/results/cloud/server"
ulimit -n "${NOFILE_LIMIT:-65535}" 2>/dev/null || true
make -C "$OASIS" -j "${BUILD_JOBS:-2}"

ARGS=(
  server
  --bind "${BIND:-0.0.0.0}"
  --port "${PORT:-9300}"
  --threads "${THREADS:-64}"
  --io-timeout-seconds "${IO_TIMEOUT_SECONDS:-600}"
  --listen-backlog "${LISTEN_BACKLOG:-4096}"
  --session-cache-capacity "${SESSION_CACHE_CAPACITY:-65536}"
  --replay-journal "${REPLAY_JOURNAL:-$ROOT/results/cloud/server/replay-journal}"
  --inject-bad-partials "${INJECT_BAD_PARTIALS:-0}"
  --inject-bad-openings "${INJECT_BAD_OPENINGS:-0}"
  --server-metrics "${SERVER_METRICS:-$ROOT/results/cloud/server/server_metrics.jsonl}"
)

if [[ "${TLS:-1}" == "1" ]]; then
  ARGS+=(
    --tls --mutual-tls
    --cert "${TLS_CERT:-$ROOT/tls/server.crt}"
    --key "${TLS_KEY:-$ROOT/tls/server.key}"
    --ca "${TLS_CA:-$ROOT/tls/ca.crt}"
  )
fi

exec "$BIN" "${ARGS[@]}"
