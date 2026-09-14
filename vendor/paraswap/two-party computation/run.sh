#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TUMBLER_BIN="$ROOT_DIR/bin/tumbler"
BOB_BIN="$ROOT_DIR/bin/bob"
TUMBLER_PID=""

cleanup() {
  if [[ -n "${TUMBLER_PID}" ]] && kill -0 "${TUMBLER_PID}" 2>/dev/null; then
    kill "${TUMBLER_PID}" 2>/dev/null || true
    wait "${TUMBLER_PID}" 2>/dev/null || true
  fi
}

trap cleanup EXIT INT TERM

if [[ ! -x "$TUMBLER_BIN" ]]; then
  echo "Missing executable: $TUMBLER_BIN" >&2
  exit 1
fi

if [[ ! -x "$BOB_BIN" ]]; then
  echo "Missing executable: $BOB_BIN" >&2
  exit 1
fi

cd "$ROOT_DIR"

"$TUMBLER_BIN" &
TUMBLER_PID=$!

sleep 0.2

"$BOB_BIN"
