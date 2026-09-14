from __future__ import annotations

import json
import os
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "scripts" / "run_final_evidence_role.sh"


class FinalEvidenceLauncherTests(unittest.TestCase):
    def dry_run(
        self, profile: str, overrides: dict[str, str] | None = None
    ) -> dict[str, object]:
        environment = dict(os.environ)
        environment["DRY_RUN"] = "1"
        environment.update(overrides or {})
        process = subprocess.run(
            [
                str(LAUNCHER),
                "server",
                "eu_to_us",
                profile,
                f"test-{profile}",
                str(ROOT),
            ],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(process.stdout)

    def test_final_profiles_have_fixed_workloads_and_one_shared_port(self) -> None:
        expected = {
            "primary": ([3, 5, 8, 16], [1], 100, 10, 9000),
            "load": ([8, 16], [1, 64, 128, 1024], 20, 5, 9000),
            "allocation": ([8, 16], [1, 128], 10, 2, 9000),
            "syscall": ([8], [1, 128], 5, 1, 9000),
            "pcap": ([8], [1], 20, 5, 9000),
        }
        for profile, values in expected.items():
            report = self.dry_run(profile)
            participants, pairs, trials, warmup, service_port = values
            self.assertEqual(report["participants"], participants)
            self.assertEqual(report["concurrent_pair_values"], pairs)
            self.assertEqual(report["measured_trials"], trials)
            self.assertEqual(report["warmup_trials"], warmup)
            self.assertEqual(report["service_port"], service_port)
            self.assertEqual(report["public_listener_count"], 1)
            self.assertEqual(len(report["modes"]), 5)

    def test_client_requires_server_address(self) -> None:
        process = subprocess.run(
            [
                str(LAUNCHER),
                "client",
                "eu_to_us",
                "primary",
                "missing-server",
                str(ROOT),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(process.returncode, 2)

    def test_shared_base_port_override_preserves_fixed_workloads(self) -> None:
        for profile in ("primary", "load", "allocation", "syscall", "pcap"):
            report = self.dry_run(
                profile, {"BASE_PORT": "9000"}
            )
            self.assertEqual(report["service_port"], 9000)


if __name__ == "__main__":
    unittest.main()
