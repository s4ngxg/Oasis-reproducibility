import subprocess
import fcntl
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ReducedWanInputTests(unittest.TestCase):
    def test_active_campaign_lock_rejects_second_runner(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            script = root / "scripts/run_reduced_wan_role.sh"
            shutil.copyfile(ROOT / "scripts/run_reduced_wan_role.sh", script)
            auth = root / "auth"
            auth.mkdir()
            output = root / "results/cloud/reduced/campaign-server.json"
            output.parent.mkdir(parents=True)
            with Path(str(output) + ".lock").open("w") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result = subprocess.run(
                    ["bash", str(script), "server", "eu_to_us", "campaign", str(auth)],
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 1)
                self.assertIn("already running", result.stderr)
                self.assertFalse(output.exists())

    def test_existing_result_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            script = root / "scripts/run_reduced_wan_role.sh"
            shutil.copyfile(ROOT / "scripts/run_reduced_wan_role.sh", script)
            auth = root / "auth"
            auth.mkdir()
            output = root / "results/cloud/reduced/campaign-server.json"
            output.parent.mkdir(parents=True)
            output.write_bytes(b"original evidence")
            result = subprocess.run(
                ["bash", str(script), "server", "eu_to_us", "campaign", str(auth)],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertIn("result already exists", result.stderr)
            self.assertEqual(output.read_bytes(), b"original evidence")

    def test_invalid_campaign_rejected_before_credentials_or_execution(self):
        for campaign in ("", "../escape", "/tmp/escape", "a/b", "has space", "-flag",
                         "a" * 129, "line\nbreak"):
            with self.subTest(campaign=campaign):
                result = subprocess.run(
                    ["bash", str(ROOT / "scripts/run_reduced_wan_role.sh"),
                     "server", "eu_to_us", campaign, "/nonexistent-oasis-auth"],
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 2)
                self.assertIn("campaign ID", result.stderr)

    def test_valid_campaign_reaches_credential_validation(self):
        for campaign in ("sg_run-01", "a" * 128):
            result = subprocess.run(
                ["bash", str(ROOT / "scripts/run_reduced_wan_role.sh"),
                 "server", "eu_to_us", campaign, "/nonexistent-oasis-auth"],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertIn("credential directory", result.stderr)
