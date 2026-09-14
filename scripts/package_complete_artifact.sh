#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PARENT=$(dirname "$ROOT")
BASE=$(basename "$ROOT")
OUTPUT=${1:-"$PARENT/oasis-reproducibility-artifact-complete.tar.gz"}
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
    echo "error: complete archive must be outside the repository" >&2
    exit 1 ;;
esac

for manifest in \
  "$ROOT/SOURCE_SHA256SUMS.txt" \
  "$ROOT/results/cloud-evidence/SHA256SUMS.txt" \
  "$ROOT/results/paper-assets/SHA256SUMS.txt"
do
  if [[ ! -f "$manifest" ]]; then
    echo "error: missing checksum manifest $manifest" >&2
    exit 1
  fi
done

if find "$ROOT" -type f \( -name '*.pem' -o -name '*.crt' -o -name '*_secret.key' -o -name '*.log' -o -name '*.pid' \) | grep -q .; then
  echo "error: artifact contains credential or runtime files" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUTPUT")"
TEMPORARY=$(mktemp "$OUTPUT.tmp.XXXXXXXX")
trap 'rm -f -- "$TEMPORARY"' EXIT

tar \
  --exclude="$BASE/.git" \
  --exclude="$BASE/.deps" \
  --exclude="$BASE/auth" \
  --exclude="$BASE/tls" \
  --exclude="$BASE/vendor/paraswap/two-party computation/.local-deps" \
  --exclude="$BASE/vendor/paraswap/two-party computation/build-*" \
  --exclude="$BASE/vendor/paraswap/two-party computation/bin" \
  --exclude="$BASE/vendor/oasis-linear/build" \
  --exclude="$BASE/vendor/oasis-linear/bin" \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --sort=name \
  --mtime="@$SOURCE_DATE_EPOCH" \
  --owner=0 --group=0 --numeric-owner \
  -czf "$TEMPORARY" -C "$PARENT" "$BASE"

if tar -tzf "$TEMPORARY" | grep -E '\.(pem|crt|log|pid|pyc)$' >/dev/null; then
  echo "error: complete archive contains forbidden runtime or credential files" >&2
  exit 1
fi

UNEXPECTED_KEYS=$(tar -tzf "$TEMPORARY" | grep -E '\.key$' | grep -Ev \
  "^$BASE/vendor/paraswap/two-party computation/keys/(alice|bob|tumbler)\.key$" || true)
if [[ -n $UNEXPECTED_KEYS ]]; then
  echo "error: complete archive contains non-fixture key material:" >&2
  printf '%s\n' "$UNEXPECTED_KEYS" >&2
  exit 1
fi

mv "$TEMPORARY" "$OUTPUT"
(cd "$(dirname "$OUTPUT")" && sha256sum "$(basename "$OUTPUT")" > "$(basename "$OUTPUT").sha256")
echo "wrote=$OUTPUT"
echo "wrote=$OUTPUT.sha256"
