#!/usr/bin/env bash
set -euo pipefail

# Retain this upstream-adjacent entry point while using the maintained v4
# regression. This avoids a second smoke harness drifting from the normative
# transcript and authentication behavior.
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
exec bash "$ROOT/scripts/test_native_protocol_v4.sh"
