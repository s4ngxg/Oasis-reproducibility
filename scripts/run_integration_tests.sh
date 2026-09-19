#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TPC="$ROOT/vendor/paraswap/two-party computation"
OASIS="$ROOT/vendor/oasis-linear"

python3 "$ROOT/scripts/verify_upstream.py"
python3 "$ROOT/scripts/verify_oasis_core.py"
python3 -m unittest discover -s "$ROOT/tests" -v

cmake -S "$TPC" -B "$TPC/build-full"
cmake --build "$TPC/build-full" -j "${BUILD_JOBS:-2}"
"$TPC/bin/batch_verifier_test"
"$TPC/bin/joint_presign_test"
python3 "$ROOT/scripts/verify_independent_oracle.py"
"$TPC/bin/completion_journal_test"
python3 "$ROOT/scripts/run_native_differential_campaign.py" \
  --vectors 16 --workers 2 \
  --out "$ROOT/results/native-differential-regression.json"
python3 "$ROOT/scripts/run_native_fault_campaign.py" \
  --participants 3 --trials 1 --warmup 0 \
  --out "$ROOT/results/native-fault-regression.json"
bash "$ROOT/scripts/test_native_protocol_v4.sh"
python3 "$ROOT/scripts/test_curve_authentication.py"
bash "$ROOT/scripts/test_cloud_runner_v4.sh"
python3 "$ROOT/scripts/test_native_loss_runner.py"
make -C "$OASIS" -j "${BUILD_JOBS:-2}"
"$OASIS/bin/oasis_core_conformance" --vectors 32
python3 "$ROOT/scripts/test_mtls_rejection.py"
python3 "$ROOT/scripts/test_replay_cache_pressure.py"
python3 "$ROOT/scripts/test_durable_phase_replay.py"

python3 "$ROOT/src/paraswap_lifecycle.py" \
  --participants 3 --mode batch-joint-presigning-batch-verification --base-port 19700 \
  --output "$ROOT/results/integration-happy.json"

python3 "$ROOT/src/paraswap_lifecycle.py" \
  --participants 3 --mode batch-joint-presigning-batch-verification --base-port 19720 --fault preswap \
  --output "$ROOT/results/integration-preswap-fault.json"

python3 "$ROOT/src/paraswap_lifecycle.py" \
  --participants 3 --mode batch-joint-presigning-batch-verification --base-port 19740 --fault witness \
  --output "$ROOT/results/integration-witness-fault.json"

port=19800
for mode in \
  reference-itemwise phase-coalesced-itemwise batch-joint-presigning-itemwise \
  phase-coalesced-batch-verification batch-joint-presigning-batch-verification
do
  python3 "$ROOT/src/paraswap_lifecycle.py" \
    --participants 3 --backend native --mode "$mode" --base-port "$port" \
    --output "$ROOT/results/preswap-${mode}.json"
  port=$((port + 10))
done

python3 "$ROOT/src/paraswap_lifecycle.py" \
  --participants 3 --backend native --mode batch-joint-presigning-batch-verification --base-port 19860 \
  --timeout-seconds 10 --fault invalid-final \
  --output "$ROOT/results/preswap-invalid-final.json"

for configuration in \
  persistent-pipelined-itemwise phase-coalesced-itemwise \
  batch-joint-presigning-itemwise phase-coalesced-batch-verification batch-joint-presigning-batch-verification
do
  python3 "$ROOT/src/paraswap_lifecycle.py" \
    --participants 5 --backend oasis --configuration "$configuration" \
    --output "$ROOT/results/oasis-${configuration}.json"
done

python3 "$ROOT/src/paraswap_lifecycle.py" \
  --participants 5 --backend oasis --configuration batch-joint-presigning-batch-verification \
  --fault opening-retry \
  --output "$ROOT/results/oasis-opening-retry.json"

python3 "$ROOT/src/paraswap_lifecycle.py" \
  --participants 5 --backend oasis --configuration batch-joint-presigning-batch-verification \
  --fault partial-retry \
  --output "$ROOT/results/oasis-partial-retry.json"

python3 "$ROOT/src/paraswap_lifecycle.py" \
  --participants 5 --backend oasis --configuration batch-joint-presigning-batch-verification \
  --fault client-partial-retry \
  --output "$ROOT/results/oasis-client-partial-retry.json"

python3 "$ROOT/src/paraswap_lifecycle.py" \
  --participants 5 --backend oasis --configuration batch-joint-presigning-batch-verification \
  --fault peer-abort \
  --output "$ROOT/results/oasis-peer-abort.json"

python3 "$ROOT/src/paraswap_lifecycle.py" \
  --participants 5 --backend oasis --configuration batch-joint-presigning-batch-verification \
  --fault witness \
  --output "$ROOT/results/oasis-witness-fault.json"

python3 - "$ROOT/results" <<'PY'
import json
import sys
from pathlib import Path

results = Path(sys.argv[1])
happy = json.loads((results / "integration-happy.json").read_text())
preswap = json.loads((results / "integration-preswap-fault.json").read_text())
witness = json.loads((results / "integration-witness-fault.json").read_text())
assert happy["outputs_exported"] is True
assert {arc["asset_state"] for arc in happy["arcs"]} == {"withdrawn"}
assert preswap["outputs_exported"] is False
assert {arc["asset_state"] for arc in preswap["arcs"]} == {"refunded"}
assert witness["outputs_exported"] is True
assert {arc["asset_state"] for arc in witness["arcs"]} == {"refunded"}
assert all(item["accepted"] for item in happy["pre_swap"])
print("integration assertions: PASS")
PY

python3 - "$ROOT/results" <<'PY'
import json
import sys
from pathlib import Path

results = Path(sys.argv[1])
modes = (
    "reference-itemwise",
    "phase-coalesced-itemwise",
    "batch-joint-presigning-itemwise",
    "phase-coalesced-batch-verification",
    "batch-joint-presigning-batch-verification",
)
reports = {
    mode: json.loads((results / f"preswap-{mode}.json").read_text())
    for mode in modes
}
invalid_final = json.loads((results / "preswap-invalid-final.json").read_text())
assert invalid_final["outputs_exported"] is False
assert {arc["asset_state"] for arc in invalid_final["arcs"]} == {"refunded"}
for mode, report in reports.items():
    assert report["outputs_exported"] is True
    assert {row["mode"] for row in report["pre_swap"]} == {mode}
    assert all(row["verifier_fallbacks"] == 0 for row in report["pre_swap"])
    assert all(row["server_verifier_fallbacks"] == 0
               for row in report["pre_swap"])

assert reports["reference-itemwise"]["pre_swap"][0]["sent_frames"] == 15
for mode in modes[1:]:
    assert reports[mode]["pre_swap"][0]["sent_frames"] == 3
for mode in ("phase-coalesced-batch-verification", "batch-joint-presigning-batch-verification"):
    assert all(row["received_frames"] == 4
               for row in reports[mode]["pre_swap"])
    assert all(row["verifier_msm_calls"] == 1
               for row in reports[mode]["pre_swap"])
    assert all(row["server_verifier_msm_calls"] == 2
               for row in reports[mode]["pre_swap"])
    assert all(row["native_msm_calls"] == 3
               for row in reports[mode]["pre_swap"])
    assert all(row["native_msm_terms"] == 6 * row["item_count"] + 3
               for row in reports[mode]["pre_swap"])
assert (
    reports["phase-coalesced-batch-verification"]["pre_swap"][0]["sent_bytes"]
    > reports["batch-joint-presigning-batch-verification"]["pre_swap"][0]["sent_bytes"]
)
print("same-backend native ablation assertions: PASS")
PY

python3 - "$ROOT/results" <<'PY'
import json
import sys
from pathlib import Path

results = Path(sys.argv[1])
expected = {
    "persistent-pipelined-itemwise": (46, 9, False, 56),
    "phase-coalesced-itemwise": (46, 9, False, 5),
    "batch-joint-presigning-itemwise": (6, 1, False, 8),
    "phase-coalesced-batch-verification": (46, 9, True, 56),
    "batch-joint-presigning-batch-verification": (7, 1, True, 8),
}
for configuration, accounting in expected.items():
    report = json.loads((results / f"oasis-{configuration}.json").read_text())
    assert report["outputs_exported"] is True
    assert {arc["asset_state"] for arc in report["arcs"]} == {"withdrawn"}
    assert len(report["pre_swap"]) == 5
    for arc in report["pre_swap"]:
        assert arc["item_count"] == 9
        assert arc["adaptation_checks"] == 9
        assert arc["preparation_digest"] == report["preparation_digest"]
        assert arc["paraswap_statement_mapping_valid"] is True
        assert arc["transport_completed"] is True
        assert arc["transport_authenticated"] is True
        assert arc["tls_cipher"].startswith("TLS_")
        assert (
            arc["logical_messages"],
            arc["logical_sessions"],
            arc["aggregate_verification_active"],
        ) == accounting[:3]
        assert arc["application_write_calls"] == accounting[3]
        if accounting[2]:
            assert arc["aggregate_audit_valid"] is True
            assert arc["audit_pippenger_calls"] == 3
            assert arc["audit_pippenger_terms"] == 54

retry = json.loads((results / "oasis-opening-retry.json").read_text())
assert retry["outputs_exported"] is True
assert retry["pre_swap"][0]["opening_failures"] == 1
assert retry["pre_swap"][0]["retries"] == 1
assert retry["pre_swap"][0]["aggregate_reverification_performed"] is False
assert all(arc["accepted"] for arc in retry["pre_swap"])
partial = json.loads((results / "oasis-partial-retry.json").read_text())
assert partial["outputs_exported"] is True
assert partial["pre_swap"][0]["partial_failures"] == 1
assert partial["pre_swap"][0]["retries"] == 1
assert all(arc["accepted"] for arc in partial["pre_swap"])
client_partial = json.loads(
    (results / "oasis-client-partial-retry.json").read_text()
)
assert client_partial["outputs_exported"] is True
assert client_partial["pre_swap"][0]["client_partial_failures"] == 1
assert client_partial["pre_swap"][0]["transport_retries"] == 1
assert all(arc["accepted"] for arc in client_partial["pre_swap"])
abort = json.loads((results / "oasis-peer-abort.json").read_text())
assert abort["outputs_exported"] is False
assert {arc["asset_state"] for arc in abort["arcs"]} == {"refunded"}
witness = json.loads((results / "oasis-witness-fault.json").read_text())
assert witness["outputs_exported"] is True
assert {arc["asset_state"] for arc in witness["arcs"]} == {"refunded"}
assert len([event for event in witness["events"]
            if event["action"] == "assets_relocked"]) == 4
print("OASIS 2x2, retry, abort, and re-lock assertions: PASS")
PY
