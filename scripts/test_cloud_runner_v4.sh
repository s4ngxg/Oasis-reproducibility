#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TPC="$ROOT/vendor/paraswap/two-party computation"
TMP="$(mktemp -d)"
RUN_ID="${TMP##*/}"
PORT="${BASE_PORT:-25100}"

cleanup() {
  local pid
  for pid in $(jobs -pr); do kill "$pid" 2>/dev/null || true; done
  if [[ "${KEEP_TMP:-0}" == 1 ]]; then
    echo "preserved test artifacts: $TMP" >&2
  else
    rm -rf "$TMP"
  fi
}
trap cleanup EXIT INT TERM

"$TPC/bin/curve_keygen" "$TMP/auth" >/dev/null

common=(
  --host 127.0.0.1
  --bind 127.0.0.1
  --route loopback
  --campaign-id "native-v4-loopback-regression-$RUN_ID"
  --participants 3
  --concurrent-pairs 4
  --trials 1
  --warmup 0
  --base-port "$PORT"
  --io-timeout-ms 10000
  --process-timeout-seconds 20
  --bind-grace-ms 100
  --client-stage-delay-ms 100
  --profile-sample-interval-ms 2
  --worker-count 2
  --network-interface lo
  --auth-dir "$TMP/auth"
  --skip-build
)

python3 "$ROOT/scripts/run_cloud_campaign.py" \
  --role server "${common[@]}" --output "$TMP/server.json" \
  >"$TMP/server.log" 2>&1 &
server_pid=$!
sleep 0.4
python3 "$ROOT/scripts/run_cloud_campaign.py" \
  --role client "${common[@]}" --output "$TMP/client.json" \
  >"$TMP/client.log" 2>&1
wait "$server_pid"

python3 "$ROOT/scripts/analyze_cloud_results.py" \
  "$TMP/client.json" "$TMP/server.json" \
  --json-out "$TMP/summary.json" --md-out "$TMP/summary.md" >/dev/null

python3 - "$TMP/client.json" "$TMP/server.json" "$TMP/summary.json" <<'PY'
import json
import sys
from pathlib import Path

client = json.loads(Path(sys.argv[1]).read_text())
server = json.loads(Path(sys.argv[2]).read_text())
summary = json.loads(Path(sys.argv[3]).read_text())
assert client["schema"] == server["schema"] == "oasis-preswap-cloud-v8"
assert summary["schema"] == "oasis-preswap-cloud-analysis-v5"
assert len(client["samples"]) == len(server["samples"]) == 5
assert len(summary["summary"]) == 5
assert summary["analysis_plan"]["bootstrap_rounds"] == 10000
assert summary["analysis_plan"]["bootstrap_seed_domain"] == (
    "OASIS-STATISTICS-v1"
)
assert summary["experiment_identity"] == client["experiment_identity"]
assert summary["randomization"] == client["randomization"]
assert summary["transport_security"] == client["transport_security"]
comparisons = {row["comparison"] for row in summary["paired_effects"]}
assert "session_verification_interaction" in comparisons
assert len(summary["paired_effects"]) == 8
for row in summary["paired_effects"]:
    assert row["paired_trials"] == 1
    assert len(row["trial_ids"]) == 1
    assert len(row["raw_paired_differences_ms"]) == 1
    assert len(row["median_difference_ci95_ms"]) == 2
    assert len(row["median_reduction_ci95_pct"]) == 2
    assert len(row["rank_biserial_ci95"]) == 2
    assert 0.0 <= row["holm_adjusted_p"] <= 1.0
    assert set(row["bootstrap_seeds"]) == {
        "median_reduction", "median_difference", "rank_biserial"
    }
assert client["runtime"]["service_port"] == server["runtime"]["service_port"]
assert client["runtime"]["public_listener_count"] == 1
assert server["runtime"]["public_listener_count"] == 1
assert client["runtime"]["session_routing_key"] == (
    "authenticated connection + pair_id + execution_id"
)
assert client["runtime"]["connection_lifecycle"].startswith("one connection")
assert client["experiment_identity"] == server["experiment_identity"]
assert client["randomization"] == server["randomization"]
assert len(client["experiment_identity"]["schedule_sha256"]) == 64
assert all(len(row["randomization_block_id"]) == 64
           for row in client["samples"] + server["samples"])
assert all(len(row["paired_trial_id"]) == 64
           for row in client["samples"] + server["samples"])
assert "same public service port" in client["environment"]["client_architecture"]
assert all(row["concurrent_pairs"] == 4 for row in client["samples"])
assert all(row["process_profile"]["gateway"]["completed_sessions"] == 4
           for row in server["samples"])
assert all(row["process_profile"]["gateway"]["worker_count"] <= 4
           for row in server["samples"])
assert all(row["process_profile"]["gateway"]["worker_count"] == 2
           for row in server["samples"])
assert all(row["process_profile"]["gateway"]["assignments"] == 4
           for row in server["samples"])
assert all(row["process_profile"]["gateway"]["rejected_sessions"] == 0
           for row in server["samples"])
assert any(row["process_profile"]["gateway"]["queued_sessions"] > 0
           for row in server["samples"])
assert all(row["process_profile"]["worker_pool"]["completed_sessions"] == 4
           for row in server["samples"])
assert all(row["process_profile"]["max_active_processes"] <= 3
           for row in server["samples"])
assert all(row["host_profile"]["host_cpu_utilization_pct"] >= 0
           for row in client["samples"])
assert all(row["host_profile"]["host_cpu_steal_pct"] >= 0
           for row in client["samples"] + server["samples"])
assert all(row["host_profile"]["cgroup_cpu_nr_throttled"] >= 0
           for row in client["samples"] + server["samples"])
assert all(row["items_per_second"] > 0 for row in client["samples"])
assert all(row["application_goodput_mbps"] > 0 for row in client["samples"])
PY

# A long-lived worker can emit more than a pipe buffer of per-session metrics.
# This regression proves that runner-side output collection cannot deadlock the
# worker pool under a queued load.
high_output_args=(
  --host 127.0.0.1
  --bind 127.0.0.1
  --route loopback
  --campaign-id "native-v4-high-output-regression-$RUN_ID"
  --participants 3
  --concurrent-pairs 128
  --modes batch-joint-presigning-batch-verification
  --trials 1
  --warmup 0
  --base-port $((PORT + 50))
  --io-timeout-ms 120000
  --process-timeout-seconds 180
  --bind-grace-ms 100
  --client-stage-delay-ms 100
  --profile-sample-interval-ms 2
  --worker-count 1
  --max-queue 128
  --network-interface lo
  --auth-dir "$TMP/auth"
  --skip-build
)
python3 "$ROOT/scripts/run_cloud_campaign.py" --role server \
  "${high_output_args[@]}" --output "$TMP/high-output-server.json" \
  >"$TMP/high-output-server.log" 2>&1 &
high_output_server_pid=$!
sleep 0.4
python3 "$ROOT/scripts/run_cloud_campaign.py" --role client \
  "${high_output_args[@]}" --output "$TMP/high-output-client.json" \
  >"$TMP/high-output-client.log" 2>&1
wait "$high_output_server_pid"
python3 - "$TMP/high-output-server.json" <<'PY'
import json
import sys
from pathlib import Path

sample = json.loads(Path(sys.argv[1]).read_text())["samples"][0]
gateway = sample["process_profile"]["gateway"]
pool = sample["process_profile"]["worker_pool"]
assert gateway["worker_count"] == 1
assert gateway["assignments"] == 128
assert gateway["queued_sessions"] > 0
assert gateway["rejected_sessions"] == 0
assert pool["completed_sessions"] == 128
PY

run_profile() {
  local profile="$1"
  local profile_port="$2"
  local server_profile_dir="$TMP/$profile-server-profile"
  local client_profile_dir="$TMP/$profile-client-profile"
  local -a server_profile_option=()
  local -a client_profile_option=()
  local -a profile_args=(
    --host 127.0.0.1
    --bind 127.0.0.1
    --route loopback
    --campaign-id "native-v4-$profile-regression-$RUN_ID"
    --participants 3
    --concurrent-pairs 1
    --modes batch-joint-presigning-batch-verification
    --trials 1
    --warmup 0
    --base-port "$profile_port"
    --io-timeout-ms 10000
    --process-timeout-seconds 20
    --bind-grace-ms 100
    --client-stage-delay-ms 100
    --network-interface lo
    --auth-dir "$TMP/auth"
    --profiling-mode "$profile"
    --skip-build
  )
  if [[ "$profile" == syscall ]]; then
    mkdir -p "$server_profile_dir" "$client_profile_dir"
    server_profile_option=(--profile-output-dir "$server_profile_dir")
    client_profile_option=(--profile-output-dir "$client_profile_dir")
  fi
  python3 "$ROOT/scripts/run_cloud_campaign.py" --role server \
    "${profile_args[@]}" \
    "${server_profile_option[@]}" \
    --output "$TMP/$profile-server.json" >"$TMP/$profile-server.log" 2>&1 &
  local profile_server_pid=$!
  sleep 0.4
  python3 "$ROOT/scripts/run_cloud_campaign.py" --role client \
    "${profile_args[@]}" \
    "${client_profile_option[@]}" \
    --output "$TMP/$profile-client.json" >"$TMP/$profile-client.log" 2>&1
  wait "$profile_server_pid"
  python3 "$ROOT/scripts/analyze_system_profiles.py" \
    "$TMP/$profile-client.json" "$TMP/$profile-server.json" \
    --json-out "$TMP/$profile-summary.json" \
    --md-out "$TMP/$profile-summary.md" >/dev/null
}

run_profile allocation $((PORT + 100))
asset_args=(
  --timing "loopback=$TMP/summary.json"
  --system "allocation=$TMP/allocation-summary.json"
)
if command -v strace >/dev/null 2>&1; then
  run_profile syscall $((PORT + 200))
  asset_args+=(--system "syscall=$TMP/syscall-summary.json")
fi

python3 "$ROOT/scripts/build_final_experiment_report.py" \
  "${asset_args[@]}" --out-dir "$TMP/paper-assets" >/dev/null
python3 - "$TMP/paper-assets/CLAIM_TO_EVIDENCE.json" <<'PY'
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text())
assert manifest["schema"] == "oasis-paper-claim-evidence-v1", manifest
assert {row["kind"] for row in manifest["evidence"]} >= {"timing", "system"}, manifest["evidence"]
figures = Path(sys.argv[1]).parent / "figures"
assert any((figures / name).is_file() for name in (
    "primary_wall_reduction.png", "load_wall_reduction.png"
)), "missing timing plot"
assert (Path(sys.argv[1]).parent / "figures" /
        "systems_profile.png").is_file(), "missing systems profile plot"
latex = Path(sys.argv[1]).parent / "paper_results.tex"
assert latex.is_file()
assert "Do not edit numeric cells manually" in latex.read_text()
assert "paper_results.tex" in {
    asset
    for claim in manifest["claims"]
    for asset in claim.get("assets", [])
}
PY

echo "Native cloud runner v4 loopback regression: PASS"
