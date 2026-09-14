#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PARENT=$(dirname "$ROOT")
OUTPUT=${1:-"$PARENT/oasis-cloud-evidence.tar.gz"}
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}

if [[ ! $SOURCE_DATE_EPOCH =~ ^[0-9]+$ ]]; then
  echo "error: SOURCE_DATE_EPOCH must be a nonnegative integer" >&2
  exit 1
fi

case "$OUTPUT" in
  /*) ;;
  *) OUTPUT="$PWD/$OUTPUT" ;;
esac

OUTPUT=$(realpath -m -- "$OUTPUT")
case "$OUTPUT" in
  "$ROOT"|"$ROOT"/*)
    echo "error: evidence archive must be outside the repository" >&2
    exit 1 ;;
esac

EVIDENCE="$ROOT/results/cloud-evidence"
if [[ ! -f "$EVIDENCE/SHA256SUMS.txt" ]]; then
  echo "error: missing evidence checksum manifest" >&2
  exit 1
fi

if find "$EVIDENCE" -type f \( -name '*.pem' -o -name '*.crt' -o -name '*.key' -o -name '*.log' -o -name '*.pid' \) | grep -q .; then
  echo "error: evidence directory contains credential or runtime files" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUTPUT")"
TEMPORARY=$(mktemp "$OUTPUT.tmp.XXXXXXXX")
trap 'rm -f -- "$TEMPORARY"' EXIT

tar \
  --sort=name \
  --mtime="@$SOURCE_DATE_EPOCH" \
  --owner=0 --group=0 --numeric-owner \
  -czf "$TEMPORARY" \
  -C "$ROOT/results" cloud-evidence

if tar -tzf "$TEMPORARY" | grep -E '(^|/)([^/]+\.(pem|crt|key|log|pid))$' >/dev/null; then
  echo "error: evidence archive contains forbidden runtime or credential files" >&2
  exit 1
fi

mv "$TEMPORARY" "$OUTPUT"
(cd "$(dirname "$OUTPUT")" && sha256sum "$(basename "$OUTPUT")" > "$(basename "$OUTPUT").sha256")
echo "wrote=$OUTPUT"
echo "wrote=$OUTPUT.sha256"
