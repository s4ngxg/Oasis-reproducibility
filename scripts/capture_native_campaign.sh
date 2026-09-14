#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: capture_native_campaign.sh INTERFACE SERVICE_PORT OUTPUT.pcap -- COMMAND [ARG...]

Captures only the native campaign TCP service port while COMMAND runs. The
capture is systems evidence and must be analyzed separately from primary
timing JSON.
EOF
  exit 2
}

[[ $# -ge 5 ]] || usage
INTERFACE=$1
SERVICE_PORT=$2
OUTPUT=$3
shift 3
[[ ${1:-} == -- ]] || usage
shift
[[ $# -gt 0 ]] || usage
[[ $SERVICE_PORT =~ ^[0-9]+$ ]] || usage
(( SERVICE_PORT >= 1 && SERVICE_PORT <= 65535 )) || usage

command -v tcpdump >/dev/null 2>&1 || {
  echo "error: tcpdump is required" >&2
  exit 1
}
sudo -n true >/dev/null 2>&1 || {
  echo "error: passwordless sudo is required for packet capture" >&2
  exit 1
}

mkdir -p "$(dirname "$OUTPUT")"
if [[ -e $OUTPUT ]]; then
  echo "error: capture output already exists: $OUTPUT" >&2
  exit 1
fi

TCPDUMP_PID=
cleanup() {
  local status=$?
  if [[ -n ${TCPDUMP_PID:-} ]] && kill -0 "$TCPDUMP_PID" 2>/dev/null; then
    sudo -n kill -INT "$TCPDUMP_PID" 2>/dev/null || true
    wait "$TCPDUMP_PID" 2>/dev/null || true
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

sudo -n tcpdump -i "$INTERFACE" -n -s 0 -U \
  -w "$OUTPUT" "tcp port $SERVICE_PORT" \
  >/dev/null 2>"${OUTPUT}.tcpdump.log" &
TCPDUMP_PID=$!
sleep 1
if ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then
  echo "error: tcpdump exited before the campaign started" >&2
  exit 1
fi

"$@"
sudo -n kill -INT "$TCPDUMP_PID"
wait "$TCPDUMP_PID" || true
TCPDUMP_PID=

[[ -s $OUTPUT ]] || {
  echo "error: packet capture is empty: $OUTPUT" >&2
  exit 1
}
printf 'pcap=%s\n' "$OUTPUT"
