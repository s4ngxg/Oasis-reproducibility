#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TPC="$ROOT/vendor/paraswap/two-party computation"

python3 "$ROOT/scripts/verify_upstream.py"
python3 "$ROOT/scripts/verify_oasis_core.py"
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s "$ROOT/tests" -p 'test_*.py' -q

"$TPC/bin/batch_verifier_test"
"$TPC/bin/joint_presign_test"
"$TPC/bin/vtd_sharing_test"
"$TPC/bin/vtd_puzzle_test"
"$TPC/bin/vtd_transcript_test"
"$TPC/bin/vtd_openings_test"
PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/scripts/test_public_solver_rejection.py"
PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/scripts/test_prepared_registry.py"
PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/scripts/test_funded_ledger_admission.py"
PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/scripts/test_funded_cross_arc_recovery.py"
PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/scripts/test_funded_cycle_recovery.py"
PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/scripts/test_live_witness_handoff.py"
PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/scripts/test_witness_transport_inputs.py"
PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/scripts/test_live_cross_arc_recovery.py"
"$TPC/bin/host_witness_test"
"$TPC/bin/host_witness_transport_test"
PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/scripts/test_preparation_participants.py"
"$TPC/bin/host_ledger_test"
"$TPC/bin/host_schedule_test"
PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/scripts/test_host_address_keys.py"
"$TPC/bin/completion_journal_test"
"$TPC/bin/worker_assignment_test"
bash "$ROOT/scripts/test_native_protocol_v4.sh"
python3 "$ROOT/scripts/test_curve_authentication.py"
bash "$ROOT/scripts/test_cloud_runner_v4.sh"

echo "Oasis local reproducibility smoke test: PASS"
