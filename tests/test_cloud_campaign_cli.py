import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run_cloud_campaign.py"
sys.path.insert(0, str(ROOT / "scripts"))

import run_cloud_campaign  # noqa: E402


class CloudCampaignCliTests(unittest.TestCase):
    def run_dry(self, *extra):
        return subprocess.run(
            [
                sys.executable,
                str(RUNNER),
                "--role",
                "server",
                "--route",
                "test_to_us",
                "--campaign-id",
                "dry-run-test",
                "--participants",
                "3",
                "--modes",
                "batch-joint-presigning-batch-verification",
                "--trials",
                "1",
                "--warmup",
                "0",
                "--base-port",
                "30000",
                "--output",
                "/tmp/oasis-cloud-dry-run-unused.json",
                "--dry-run",
                *extra,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_dry_run_reports_one_shared_service_port(self):
        process = self.run_dry()
        self.assertEqual(process.returncode, 0, process.stderr)
        report = json.loads(process.stdout)
        self.assertEqual(report["stage_count"], 1)
        self.assertEqual(report["service_port"], 30000)
        self.assertEqual(report["public_listener_count"], 1)
        self.assertEqual(report["maximum_parallel_pairs"], 3)
        expected_workers = min(max(1, os.cpu_count() or 1), 3)
        self.assertEqual(report["worker_pool_size"], expected_workers)
        self.assertEqual(
            report["server_process_upper_bound"], expected_workers + 1
        )

    def test_load_dimensions_are_independent(self):
        process = self.run_dry(
            "--participants", "8,16", "--concurrent-pairs", "1,128"
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        report = json.loads(process.stdout)
        self.assertEqual(report["stage_count"], 4)
        self.assertEqual(report["maximum_parallel_pairs"], 128)
        self.assertEqual(report["service_port"], 30000)
        self.assertEqual(report["public_listener_count"], 1)

    def test_worker_pool_is_capped_by_parallel_sessions(self):
        process = self.run_dry("--concurrent-pairs", "1", "--worker-count", "8")
        self.assertEqual(process.returncode, 0, process.stderr)
        report = json.loads(process.stdout)
        self.assertEqual(report["worker_pool_size"], 1)
        self.assertEqual(report["server_process_upper_bound"], 2)

    def test_cycle_rejects_two_participants(self):
        process = self.run_dry("--participants", "2")
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("integers >= 3", process.stderr)

    def test_duplicate_participants_are_rejected(self):
        process = self.run_dry("--participants", "3,3")
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("must not contain duplicates", process.stderr)

    def test_syscall_dry_run_has_no_filesystem_side_effect(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "must-not-be-created"
            process = self.run_dry(
                "--profiling-mode", "syscall",
                "--profile-output-dir", str(output),
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertFalse(output.exists())

    def test_mode_order_is_deterministic_and_position_counterbalanced(self):
        modes = list(run_cloud_campaign.DEFAULT_MODES)
        orders = [
            run_cloud_campaign.ordered_modes(
                "campaign-a", 8, 64, modes, trial, False
            )
            for trial in range(len(modes))
        ]
        self.assertEqual(
            orders,
            [
                run_cloud_campaign.ordered_modes(
                    "campaign-a", 8, 64, modes, trial, False
                )
                for trial in range(len(modes))
            ],
        )
        for position in range(len(modes)):
            self.assertEqual(
                {order[position] for order in orders}, set(modes)
            )

    def test_execution_id_is_fresh_per_mode_but_workload_seed_is_paired(self):
        first = run_cloud_campaign.Stage(8, 64, "reference-itemwise", 3, False)
        second = run_cloud_campaign.Stage(
            8, 64, "batch-joint-presigning-batch-verification", 3, False
        )
        self.assertNotEqual(
            run_cloud_campaign.execution_id("campaign-a", first, 7),
            run_cloud_campaign.execution_id("campaign-a", second, 7),
        )
        self.assertEqual(
            run_cloud_campaign.context_seed("campaign-a", first, 7),
            run_cloud_campaign.context_seed("campaign-a", second, 7),
        )

    def test_relic_provenance_accepts_only_the_pinned_commit(self):
        completed = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout=run_cloud_campaign.RELIC_COMMIT + "\n", stderr="",
        )
        with mock.patch.object(
            run_cloud_campaign.subprocess, "run", return_value=completed
        ):
            self.assertEqual(
                run_cloud_campaign.verified_relic_commit(Path("/unused")),
                run_cloud_campaign.RELIC_COMMIT,
            )

    def test_relic_provenance_rejects_a_different_commit(self):
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="0" * 40 + "\n", stderr="",
        )
        with mock.patch.object(
            run_cloud_campaign.subprocess, "run", return_value=completed
        ):
            with self.assertRaisesRegex(RuntimeError, "commit mismatch"):
                run_cloud_campaign.verified_relic_commit(Path("/unused"))


if __name__ == "__main__":
    unittest.main()
