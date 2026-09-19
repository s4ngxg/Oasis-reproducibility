#!/usr/bin/env bash
set -euo pipefail

# Apply a documented one-way qdisc profile to the benchmark service port.
# Run this independently on the initiator and responder when both directions
# are required; the campaign manifest records the endpoint/scope labels.

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 apply|clear|observe DEVICE PROFILE" >&2
  echo "Profiles: loss5, burst5, delay20, jitter20, reorder10" >&2
  exit 2
fi

ACTION="$1"
DEVICE="$2"
PROFILE="$3"
PORT="${PORT:-9000}"

[[ "$DEVICE" =~ ^[[:alnum:]_.:-]+$ ]] || {
  echo "invalid device: $DEVICE" >&2
  exit 2
}
[[ "$PORT" =~ ^[0-9]+$ ]] && ((PORT >= 1 && PORT <= 65535)) || {
  echo "invalid port: $PORT" >&2
  exit 2
}

if [[ "$ACTION" == "clear" ]]; then
  sudo -n tc qdisc del dev "$DEVICE" root 2>/dev/null || true
  exit 0
fi
if [[ "$ACTION" == "observe" ]]; then
  tc -s qdisc show dev "$DEVICE"
  exit 0
fi
[[ "$ACTION" == "apply" ]] || {
  echo "unknown action: $ACTION" >&2
  exit 2
}

case "$PROFILE" in
  loss5) NETEM=(loss random 5%) ;;
  burst5) NETEM=(loss 5% 25) ;;
  delay20) NETEM=(delay 20ms) ;;
  jitter20) NETEM=(delay 20ms 10ms distribution normal) ;;
  reorder10) NETEM=(delay 20ms 10ms distribution normal reorder 10% 50%) ;;
  *) echo "unknown profile: $PROFILE" >&2; exit 2 ;;
esac

sudo -n tc qdisc del dev "$DEVICE" root 2>/dev/null || true
sudo -n tc qdisc replace dev "$DEVICE" root handle 1: prio bands 3
sudo -n tc qdisc replace dev "$DEVICE" parent 1:3 handle 30: netem "${NETEM[@]}"
sudo -n tc filter replace dev "$DEVICE" protocol ip parent 1: \
  prio 3 u32 match ip dport "$PORT" 0xffff flowid 1:3

printf 'oasis_netem_profile=apply device=%s profile=%s service_port=%s\n' \
  "$DEVICE" "$PROFILE" "$PORT"
tc -s qdisc show dev "$DEVICE"
