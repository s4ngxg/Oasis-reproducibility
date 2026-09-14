import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import test_retained_full_cycle as smoke


class SmokeEvidenceTests(unittest.TestCase):
    def test_optimized_python_rejects_evidence_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "evidence"
            result = subprocess.run(
                [sys.executable, "-O", "-B", str(Path(smoke.__file__)),
                 "--quick", "--results-dir", str(destination)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("do not use -O", result.stderr)
            self.assertFalse(destination.exists())

    def test_checked_reports_are_saved_for_both_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "evidence"
            report = {"coordinator_timing": {"end_to_end_runner_ms": 1}}
            with patch.object(sys, "argv", ["smoke", "--quick", "--results-dir", str(destination)]), \
                 patch.object(smoke, "_run", return_value=report), \
                 patch.object(smoke, "_assert_report") as validate, \
                 patch.object(smoke, "_provenance", return_value={"test": "hash"}), \
                 contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                smoke.main()
            self.assertEqual(validate.call_count, 2)
            files = list(destination.glob("*.json"))
            self.assertEqual(len(files), 2)
            for path in files:
                self.assertEqual(json.loads(path.read_text()),
                                 {"provenance": {"test": "hash"}, "report": report})

    def test_changed_provenance_rejects_run_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "evidence"
            with patch.object(sys, "argv", ["smoke", "--quick", "--results-dir", str(destination)]), \
                 patch.object(smoke, "_run", return_value={}), \
                 patch.object(smoke, "_assert_report"), \
                 patch.object(smoke, "_provenance", side_effect=[{"hash": 1}, {"hash": 2}]), \
                 contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError, "changed during smoke"):
                    smoke.main()
            self.assertEqual(list(destination.iterdir()), [])
