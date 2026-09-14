#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 apply|clear|observe DEVICE LOSS_PERCENT" >&2
  exit 2
fi

ACTION="$1"
DEVICE="$2"
LOSS="$3"
PORT="${PORT:-9300}"

[[ "$DEVICE" =~ ^[[:alnum:]_.:-]+$ ]] || {
  echo "invalid device: $DEVICE" >&2
  exit 2
}
[[ "$PORT" =~ ^[0-9]+$ ]] && ((PORT >= 1 && PORT <= 65535)) || {
  echo "invalid port: $PORT" >&2
  exit 2
}
[[ "$LOSS" =~ ^([0-9]+([.][0-9]+)?|[.][0-9]+)$ ]] || {
  echo "invalid loss percentage: $LOSS" >&2
  exit 2
}
LOSS_CANON=$(awk -v loss="$LOSS" 'BEGIN { printf "%.12g", loss }')

clear_profile() {
  sudo -n tc qdisc del dev "$DEVICE" root 2>/dev/null || true
}

if [[ "$ACTION" == "clear" ]]; then
  clear_profile
  exit 0
fi
if [[ "$ACTION" == "observe" ]]; then
  printf 'oasis_netem_action=observe device=%s loss_pct=%s service_port=%s\n' \
    "$DEVICE" "$LOSS_CANON" "$PORT"
  tc -s qdisc show dev "$DEVICE"
  tc filter show dev "$DEVICE" parent 1: 2>/dev/null || true
  exit 0
fi
[[ "$ACTION" == "apply" ]] || {
  echo "unknown action: $ACTION" >&2
  exit 2
}
awk -v loss="$LOSS" 'BEGIN { exit(loss > 0 ? 0 : 1) }' || {
  echo "apply requires a loss percentage greater than zero" >&2
  exit 2
}

clear_profile
sudo -n tc qdisc replace dev "$DEVICE" root handle 1: prio bands 3
sudo -n tc qdisc replace dev "$DEVICE" parent 1:3 handle 30: \
  netem loss random "${LOSS_CANON}%"
sudo -n tc filter replace dev "$DEVICE" protocol ip parent 1: \
  prio 3 u32 match ip dport "$PORT" 0xffff flowid 1:3

printf 'oasis_netem_action=apply device=%s loss_pct=%s service_port=%s\n' \
  "$DEVICE" "$LOSS_CANON" "$PORT"
tc -s qdisc show dev "$DEVICE"
tc filter show dev "$DEVICE" parent 1: 2>/dev/null || true
