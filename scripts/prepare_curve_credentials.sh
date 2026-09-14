#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUTPUT=${1:-"$ROOT/auth/generated"}
KEYGEN="$ROOT/vendor/paraswap/two-party computation/bin/curve_keygen"

if [[ -e "$OUTPUT" ]]; then
  echo "error: credential directory already exists: $OUTPUT" >&2
  exit 1
fi
if [[ ! -x "$KEYGEN" ]]; then
  echo "error: missing curve_keygen; run make native-build" >&2
  exit 1
fi

mkdir -p "$OUTPUT"
"$KEYGEN" "$OUTPUT/.complete"
mkdir -p "$OUTPUT/initiator" "$OUTPUT/responder"

install -m 0644 "$OUTPUT/.complete/initiator_public.key" \
  "$OUTPUT/initiator/initiator_public.key"
install -m 0600 "$OUTPUT/.complete/initiator_secret.key" \
  "$OUTPUT/initiator/initiator_secret.key"
install -m 0644 "$OUTPUT/.complete/responder_public.key" \
  "$OUTPUT/initiator/responder_public.key"

install -m 0644 "$OUTPUT/.complete/initiator_public.key" \
  "$OUTPUT/responder/initiator_public.key"
install -m 0644 "$OUTPUT/.complete/responder_public.key" \
  "$OUTPUT/responder/responder_public.key"
install -m 0600 "$OUTPUT/.complete/responder_secret.key" \
  "$OUTPUT/responder/responder_secret.key"

rm -rf "$OUTPUT/.complete"
printf 'initiator_credentials=%s\n' "$OUTPUT/initiator"
printf 'responder_credentials=%s\n' "$OUTPUT/responder"
